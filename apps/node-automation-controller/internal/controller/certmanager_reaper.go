// certmanager-reaper — unstucks cert-manager ACME Orders wedged in
// "pending" by the known cert-manager self-check retry-forever bug:
// the http-01 Challenge is presented+processing but the propagation
// self-check keeps failing (e.g. DNS answer changed mid-issue), and
// cert-manager retries the SAME challenge forever instead of
// re-checking. The upstream fix is to delete the Order — cert-manager
// recreates it fresh and issuance proceeds.
//
// Candidacy: a Certificate that is Ready=False or has spec.renewalTime
// within the next 7d, owning an Order pending >30m, cross-checked
// against a Challenge that is presented+processing with no state
// transition for >30m. Deleting the Order is the reset.
//
// Safety: per-certificate reset budget — at most 1 Order deletion per
// cert per hour, and at most 3 total per cert; once the budget is
// exhausted the reaper stops acting on that cert and surfaces an error
// (a cert that burns through 3 resets has a config problem — continuing
// would burn the ACME rate limit). Per-item failures log + continue.
package controller

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
)

const (
	certReaperQueue    = "certmanager-reaper"
	orderPendingMinAge = 30 * time.Minute   // order/challenge must be wedged this long
	certRenewalWindow  = 7 * 24 * time.Hour // renewalTime within this window = candidate
	certReaperMinGap   = time.Hour          // max 1 order reset per cert per hour
	certReaperMaxReset = 3                  // stop acting after N resets on the same cert
)

var (
	certificateGVR = schema.GroupVersionResource{
		Group: "cert-manager.io", Version: "v1", Resource: "certificates"}
	orderGVR = schema.GroupVersionResource{
		Group: "acme.cert-manager.io", Version: "v1", Resource: "orders"}
	challengeGVR = schema.GroupVersionResource{
		Group: "acme.cert-manager.io", Version: "v1", Resource: "challenges"}
)

// certReset is the per-certificate reset budget tracked in memory
// (cleared when the cert reports Ready=True, on cert deletion, or on
// operator restart — all bias conservative).
type certReset struct {
	total  int
	last   time.Time
	gaveUp bool // IncError already fired for the exhausted budget
}

type certManagerReaper struct {
	cs     kubernetes.Interface // reserved for future typed reads
	dyn    dynamic.Interface
	resets map[string]*certReset
}

// SetupCertManagerReaper registers the 15m sweep. Disabled clusters
// (no cert-manager component / no ACME) skip registration entirely.
func SetupCertManagerReaper(mgr ctrl.Manager, cs kubernetes.Interface,
	dyn dynamic.Interface, enabled bool) error {
	if !enabled {
		logf.Log.WithName(certReaperQueue).Info("disabled — module not registered")
		return nil
	}
	r := &certManagerReaper{cs: cs, dyn: dyn, resets: map[string]*certReset{}}
	return addPeriodic(mgr, certReaperQueue, 15*time.Minute, r.run)
}

func (r *certManagerReaper) run(ctx context.Context) error {
	log := logf.FromContext(ctx)

	certs, err := r.dyn.Resource(certificateGVR).Namespace(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	candidates, reset := 0, 0
	for i := range certs.Items {
		cert := &certs.Items[i]
		key := cert.GetNamespace() + "/" + cert.GetName()
		seen[key] = true
		needsReap := certNeedsReap(cert)
		// A cert back to Ready=True earned a clean slate — drop its
		// reset budget so a few stuck-issuance episodes spread over
		// months cannot refuse it forever without a restart. The
		// needsReap guard is load-bearing: a renewal-window candidate
		// reports Ready=True the whole time its Order wedges (the old
		// cert is still valid), so clearing on Ready alone would wipe
		// the budget every sweep and defeat both the hourly gap and
		// the 3-reset cap.
		if _, tracked := r.resets[key]; tracked && !needsReap {
			if status, _ := readyCond(cert); status == "True" {
				delete(r.resets, key)
			}
		}
		if !needsReap {
			continue
		}
		candidates++
		if r.reapCert(ctx, cert) {
			reset++
		}
	}
	// Drop budgets for Certificates that vanished — the map is
	// otherwise append-only per cert ever reaped.
	for key := range r.resets {
		if !seen[key] {
			delete(r.resets, key)
		}
	}
	log.Info("sweep done", "candidates", candidates, "ordersReset", reset)
	return nil
}

// certNeedsReap mirrors the bash filter: Ready=False OR renewalTime
// within 7d — a healthy cert with no upcoming renewal cannot have a
// stuck issuance worth resetting.
func certNeedsReap(cert *unstructured.Unstructured) bool {
	if conds, found, _ := unstructured.NestedSlice(
		cert.Object, "status", "conditions"); found {
		for _, c := range conds {
			m, ok := c.(map[string]interface{})
			if !ok {
				continue
			}
			if m["type"] == "Ready" && m["status"] == "False" {
				return true
			}
		}
	}
	if rt, found, _ := unstructured.NestedString(
		cert.Object, "spec", "renewalTime"); found {
		if t, err := time.Parse(time.RFC3339, rt); err == nil &&
			!t.After(time.Now().Add(certRenewalWindow)) {
			return true
		}
	}
	return false
}

// reapCert finds the cert's stuck pending Order, verifies a Challenge
// is genuinely wedged (not just slow), applies the reset budget, then
// deletes the Order so cert-manager recreates it. Reports whether an
// Order was actually deleted.
func (r *certManagerReaper) reapCert(ctx context.Context, cert *unstructured.Unstructured) bool {
	log := logf.FromContext(ctx)
	ns, name := cert.GetNamespace(), cert.GetName()
	key := ns + "/" + name

	orders, err := r.dyn.Resource(orderGVR).Namespace(ns).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(certReaperQueue)
		log.Error(err, "order list failed", "cert", key)
		return false
	}
	var stuck *unstructured.Unstructured
	for i := range orders.Items {
		o := &orders.Items[i]
		if st, _, _ := unstructured.NestedString(o.Object, "status", "state"); st != "pending" {
			continue
		}
		if time.Since(o.GetCreationTimestamp().Time) <= orderPendingMinAge {
			continue
		}
		stuck = o
		break
	}
	if stuck == nil {
		return false
	}

	// Budget gate before the challenge call — no API work when the
	// cert is already refused.
	st := r.resets[key]
	if st == nil {
		st = &certReset{}
		r.resets[key] = st
	}
	if st.total >= certReaperMaxReset {
		if !st.gaveUp {
			st.gaveUp = true
			metrics.IncError(certReaperQueue)
			log.Info("REFUSE: reset budget exhausted — cert config is broken, "+
				"continuing would burn the ACME rate limit",
				"cert", key, "resets", st.total)
		}
		return false
	}
	if !st.last.IsZero() && time.Since(st.last) < certReaperMinGap {
		log.Info("SKIP: reset rate-limited (max 1/hour)", "cert", key)
		return false
	}

	chals, err := r.dyn.Resource(challengeGVR).Namespace(ns).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(certReaperQueue)
		log.Error(err, "challenge list failed", "cert", key)
		return false
	}
	if !stuckChallengeForOrder(stuck, chals.Items) {
		log.Info("KEEP: pending order but no wedged challenge — "+
			"issuance still progressing", "cert", key, "order", stuck.GetName())
		return false
	}

	log.Info("RESET: deleting stuck pending Order — cert-manager recreates fresh",
		"cert", key, "order", stuck.GetName())
	if err := r.dyn.Resource(orderGVR).Namespace(ns).
		Delete(ctx, stuck.GetName(), metav1.DeleteOptions{}); err != nil {
		metrics.IncError(certReaperQueue)
		log.Error(err, "order delete failed", "cert", key, "order", stuck.GetName())
		return false
	}
	st.total++
	st.last = time.Now()
	return true
}

// stuckChallengeForOrder reports whether any Challenge in the
// namespace is both wedged and attributable to this order. Challenges
// that carry linkage (ownerReference or the acme order-name label)
// must point at the order; fixtures/real objects without linkage fall
// back to the same-namespace match.
func stuckChallengeForOrder(order *unstructured.Unstructured,
	chals []unstructured.Unstructured) bool {
	for i := range chals {
		ch := &chals[i]
		if !challengeWedged(ch) {
			continue
		}
		if challengeLinkedToOrder(ch, order) {
			return true
		}
	}
	return false
}

// challengeWedged is the self-check-retry-forever signature: the
// challenge resource was presented to the ACME server and is still
// processing, with no state transition for over 30m. Uses
// status.lastTransitionTime when present (real objects do not carry
// it — fixtures may), else creationTimestamp.
func challengeWedged(ch *unstructured.Unstructured) bool {
	presented, _, _ := unstructured.NestedBool(ch.Object, "status", "presented")
	processing, _, _ := unstructured.NestedBool(ch.Object, "status", "processing")
	if !presented || !processing {
		return false
	}
	since := ch.GetCreationTimestamp().Time
	if ts, found, _ := unstructured.NestedString(
		ch.Object, "status", "lastTransitionTime"); found {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			since = t
		}
	}
	return time.Since(since) > orderPendingMinAge
}

func challengeLinkedToOrder(ch, order *unstructured.Unstructured) bool {
	linked := false
	for _, or := range ch.GetOwnerReferences() {
		linked = true
		if or.Name == order.GetName() {
			return true
		}
	}
	if ln, ok := ch.GetLabels()["acme.cert-manager.io/order-name"]; ok {
		linked = true
		if ln == order.GetName() {
			return true
		}
	}
	return !linked // no linkage fields → namespace-scoped match
}
