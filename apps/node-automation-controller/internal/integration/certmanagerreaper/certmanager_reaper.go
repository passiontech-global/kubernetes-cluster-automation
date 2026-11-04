// certmanager-reaper — unstucks cert-manager ACME Orders wedged in
// "pending" by the known cert-manager self-check retry-forever bug:
// the http-01 Challenge is presented+processing but the propagation
// self-check keeps failing (e.g. DNS answer changed mid-issue), and
// cert-manager retries the SAME challenge forever instead of
// re-checking. The upstream fix is to delete the Order — cert-manager
// recreates it fresh and issuance proceeds.
//
// Candidacy: a Certificate that is Ready=False or has status.renewalTime
// within the next 7d, owning an Order pending >30m, cross-checked
// against a Challenge that is presented+processing with no state
// transition for >30m. Deleting the Order is the reset.
//
// Safety: per-certificate reset budget — at most 1 Order deletion per
// cert per hour, and at most 3 total per cert; once the budget is
// exhausted the reaper stops acting on that cert and surfaces an error
// (a cert that burns through 3 resets has a config problem — continuing
// would burn the ACME rate limit). Per-item failures log + continue.
//
// Budget persistence: the counter lives in memory AND in the
// node.ops/acme-order-resets annotation ("<total>,<lastRFC3339>") on
// the Certificate itself — a controller restart cannot refund resets
// and hammer the ACME rate limit. A cert that heals (Ready=True and
// no longer a reap candidate) gets both halves wiped so its next
// renewal cycle starts with a full budget.
package certmanagerreaper

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

const (
	certReaperQueue    = "certmanager-reaper"
	orderPendingMinAge = 30 * time.Minute   // order/challenge must be wedged this long
	certRenewalWindow  = 7 * 24 * time.Hour // renewalTime within this window = candidate
	certReaperMinGap   = time.Hour          // max 1 order reset per cert per hour
	certReaperMaxReset = 3                  // stop acting after N resets on the same cert
	// W8 — the stuck-CertificateRequest path: a CR wedged Ready=False
	// (Pending/Failed) past crStuckMinAge under a Ready=False or
	// expiring cert gets deleted so cert-manager re-issues it. It
	// draws on the same acme-order-resets budget, on a wider 6h gap.
	crStuckMinAge     = 30 * time.Minute
	crReapMinGap      = 6 * time.Hour
	certExpirySoonWin = 14 * 24 * time.Hour
	// acmeResetsAnno persists the per-cert reset budget on the
	// Certificate — "<total>,<lastRFC3339>" — so the 3-per-cycle cap
	// survives controller restarts.
	acmeResetsAnno = "node.ops/acme-order-resets"
)

var (
	certificateGVR = schema.GroupVersionResource{
		Group: "cert-manager.io", Version: "v1", Resource: "certificates"}
	certificateRequestGVR = schema.GroupVersionResource{
		Group: "cert-manager.io", Version: "v1", Resource: "certificaterequests"}
	orderGVR = schema.GroupVersionResource{
		Group: "acme.cert-manager.io", Version: "v1", Resource: "orders"}
	challengeGVR = schema.GroupVersionResource{
		Group: "acme.cert-manager.io", Version: "v1", Resource: "challenges"}
)

// certReset is the per-certificate reset budget tracked in memory.
// The node.ops/acme-order-resets annotation on the Certificate is the
// durable half — hydrated into this map on first sight after a
// restart, written back on every reset, and wiped together with the
// map entry when the cert reports Ready=True and is no longer a reap
// candidate (all biases stay conservative).
type certReset struct {
	total  int
	last   time.Time
	gaveUp bool // IncError already fired for the exhausted budget
}

type certManagerReaper struct {
	cs     kubernetes.Interface // reserved for future typed reads
	dyn    dynamic.Interface
	resets map[string]*certReset
	// nowFn is the clock seam — tests pin it so the pending/wedged
	// windows, the renewal window and the hourly reset gap are
	// deterministic. nil → time.Now.
	nowFn func() time.Time
	// crReaped: cert key → last stuck-CertificateRequest delete —
	// the 6h in-RAM half of the W8 CR-reap cooldown (the durable
	// half shares node.ops/acme-order-resets).
	crReaped map[string]time.Time
	// crCache: per-run CertificateRequest list cache keyed by
	// namespace — the Order-attribution path and the W8 stuck-CR
	// path share ONE list per namespace per sweep (a failed list
	// IncErrors once, not twice).
	crCache map[string]crListResult
}

// crListResult is the cached outcome of one namespace's CR List.
type crListResult struct {
	list *unstructured.UnstructuredList
	err  error
}

// Setup registers the 15m sweep. Disabled clusters
// (no cert-manager component / no ACME) skip registration entirely.
func Setup(mgr ctrl.Manager, cs kubernetes.Interface,
	dyn dynamic.Interface, enabled bool) error {
	if !enabled {
		logf.Log.WithName(certReaperQueue).Info("disabled — module not registered")
		return nil
	}
	r := &certManagerReaper{cs: cs, dyn: dyn,
		resets: map[string]*certReset{}, crReaped: map[string]time.Time{}}
	return shared.AddPeriodic(mgr, certReaperQueue, 15*time.Minute, r.run)
}

func (r *certManagerReaper) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	// Lazily arm the zero-value struct — unit tests construct the
	// reaper literally without the Setup path.
	if r.nowFn == nil {
		r.nowFn = time.Now
	}
	if r.resets == nil {
		r.resets = map[string]*certReset{}
	}
	if r.crReaped == nil {
		r.crReaped = map[string]time.Time{}
	}
	r.crCache = map[string]crListResult{}
	now := r.nowFn()

	certs, err := r.dyn.Resource(certificateGVR).Namespace(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list certificates: %w", err)
	}
	seen := map[string]bool{}
	candidates, reset := 0, 0
	for i := range certs.Items {
		cert := &certs.Items[i]
		key := cert.GetNamespace() + "/" + cert.GetName()
		seen[key] = true
		needsReap := certNeedsReap(cert, now)
		// A cert back to Ready=True earned a clean slate — drop its
		// reset budget (memory AND persisted annotation) so a few
		// stuck-issuance episodes spread over months cannot refuse it
		// forever without a restart. The needsReap guard is load-
		// bearing: a renewal-window candidate reports Ready=True the
		// whole time its Order wedges (the old cert is still valid),
		// so clearing on Ready alone would wipe the budget every
		// sweep and defeat both the hourly gap and the 3-reset cap.
		// The hasAnno half covers the post-restart case where the
		// memory ledger is empty but the Certificate still carries
		// the annotation.
		_, tracked := r.resets[key]
		hasAnno := cert.GetAnnotations()[acmeResetsAnno] != ""
		if !needsReap && certReady(cert) && (tracked || hasAnno) {
			delete(r.resets, key)
			if hasAnno {
				if err := r.patchResetsAnnotation(ctx, cert, nil); err != nil {
					metrics.IncError(certReaperQueue)
					log.Error(err, "acme-resets annotation clear failed", "cert", key)
				}
			}
		}
		if !needsReap {
			// W8: a cert that is Ready=False or expires <14d may
			// carry a wedged CertificateRequest even with no stuck
			// Order — the CR path holds its own gates and cooldown.
			if r.reapStuckCR(ctx, cert, now) {
				reset++
			}
			continue
		}
		candidates++
		if r.reapCert(ctx, cert) {
			reset++
		}
		if r.reapStuckCR(ctx, cert, now) {
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

// certReady reports whether the Certificate's Ready condition is True.
func certReady(cert *unstructured.Unstructured) bool {
	status, _ := shared.ReadyCond(cert)
	return status == "True"
}

// certNeedsReap mirrors the bash filter: Ready=False OR renewalTime
// within 7d of now — a healthy cert with no upcoming renewal cannot
// have a stuck issuance worth resetting. cert-manager publishes the
// next renewal under STATUS.renewalTime (spec carries no such field).
func certNeedsReap(cert *unstructured.Unstructured, now time.Time) bool {
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
		cert.Object, "status", "renewalTime"); found {
		if t, err := time.Parse(time.RFC3339, rt); err == nil &&
			!t.After(now.Add(certRenewalWindow)) {
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
	now := r.nowFn()

	orders, err := r.dyn.Resource(orderGVR).Namespace(ns).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(certReaperQueue)
		log.Error(err, "order list failed", "cert", key)
		return false
	}

	// Attribute orders to THIS cert through the owner chain — an
	// Order's ownerRef names its CertificateRequest and the CR's
	// ownerRef names the Certificate (cert-manager also stamps the
	// cert-manager.io/certificate-name ref on the CR). Picking the
	// first pending order in the NAMESPACE would reap another cert's
	// order while charging the reset budget to this cert. A failed
	// CR list makes attribution impossible — fail closed.
	crs, err := r.listCRs(ctx, ns)
	if err != nil {
		log.Error(err, "certificaterequest list failed", "cert", key)
		return false
	}
	crToCert := make(map[string]string, len(crs.Items))
	for i := range crs.Items {
		if certName, ok := certNameForCR(&crs.Items[i]); ok {
			crToCert[crs.Items[i].GetName()] = certName
		}
	}

	var stuck *unstructured.Unstructured
	for i := range orders.Items {
		o := &orders.Items[i]
		if !orderOwnedByCert(o, name, crToCert) {
			continue // not this cert's order — never ours to reap
		}
		if st, _, _ := unstructured.NestedString(o.Object, "status", "state"); st != "pending" {
			continue
		}
		if now.Sub(o.GetCreationTimestamp().Time) <= orderPendingMinAge {
			continue
		}
		stuck = o
		break
	}
	if stuck == nil {
		return false
	}

	// Budget gate before the challenge call — no API work when the
	// cert is already refused. A restart empties r.resets, so the
	// first sight of a cert hydrates the budget back from its
	// persisted annotation — the 3-per-cycle cap survives restarts.
	st := r.resets[key]
	if st == nil {
		st = certResetFromAnnotation(cert)
		r.resets[key] = st
	}
	if st.total >= certReaperMaxReset {
		if !st.gaveUp {
			st.gaveUp = true
			metrics.IncError(certReaperQueue)
			log.Info("REFUSE: reset budget exhausted — cert config is broken, "+
				"continuing would burn the ACME rate limit",
				"cert", key, "order", stuck.GetName(), "resets", st.total)
		}
		return false
	}
	if !st.last.IsZero() && now.Sub(st.last) < certReaperMinGap {
		log.Info("SKIP: reset rate-limited (max 1/hour)",
			"cert", key, "order", stuck.GetName(),
			"lastResetAgo", now.Sub(st.last).Truncate(time.Minute))
		return false
	}

	chals, err := r.dyn.Resource(challengeGVR).Namespace(ns).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(certReaperQueue)
		log.Error(err, "challenge list failed", "cert", key)
		return false
	}
	if !stuckChallengeForOrder(stuck, chals.Items, now) {
		log.Info("KEEP: pending order but no wedged challenge — "+
			"issuance still progressing", "cert", key, "order", stuck.GetName())
		return false
	}

	log.Info("RESET: deleting stuck pending Order — cert-manager recreates fresh",
		"cert", key, "order", stuck.GetName())
	stuckUID := stuck.GetUID()
	if err := r.dyn.Resource(orderGVR).Namespace(ns).
		Delete(ctx, stuck.GetName(), metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &stuckUID}}); err != nil {
		metrics.IncError(certReaperQueue)
		log.Error(err, "order delete failed", "cert", key, "order", stuck.GetName())
		return false
	}
	st.total++
	st.last = now
	// Persist the consumed reset immediately — a controller restart
	// between sweeps must not refund it. Best-effort: the Order is
	// already deleted, so a failed write is flagged, not fatal.
	if err := r.patchResetsAnnotation(ctx, cert, st); err != nil {
		metrics.IncError(certReaperQueue)
		log.Error(err, "acme-resets annotation write failed", "cert", key)
	}
	return true
}

// listCRs returns the CertificateRequests of one namespace, caching
// the result (and the error) for the whole sweep — the Order-
// attribution path and the W8 stuck-CR path share a single List, so a
// shared API outage IncErrors once instead of once per consumer.
func (r *certManagerReaper) listCRs(ctx context.Context, ns string) (*unstructured.UnstructuredList, error) {
	if res, ok := r.crCache[ns]; ok {
		return res.list, res.err
	}
	list, err := r.dyn.Resource(certificateRequestGVR).Namespace(ns).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(certReaperQueue)
	}
	r.crCache[ns] = crListResult{list: list, err: err}
	return list, err
}

// certReadyFalse reports the Ready=False half of the W8 CR candidacy.
func certReadyFalse(cert *unstructured.Unstructured) bool {
	status, _ := shared.ReadyCond(cert)
	return status == "False"
}

// certExpiringSoon reports whether status.notAfter lands within the
// next 14 days — an expiring cert with a wedged child CR is a renewal
// that silently died.
func certExpiringSoon(cert *unstructured.Unstructured, now time.Time) bool {
	if v, found, _ := unstructured.NestedString(
		cert.Object, "status", "notAfter"); found {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t.Before(now.Add(certExpirySoonWin))
		}
	}
	return false
}

// reapStuckCR deletes a CertificateRequest wedged Ready=False
// (Pending/Failed) >30m under a Ready=False or expiring Certificate —
// cert-manager recreates the CR on the cert's next sync and issuance
// proceeds. Charged to the shared acme-order-resets budget; the wider
// 6h in-RAM gap keeps this path from racing the hourly Order reset.
func (r *certManagerReaper) reapStuckCR(ctx context.Context,
	cert *unstructured.Unstructured, now time.Time) bool {
	log := logf.FromContext(ctx)
	ns, name := cert.GetNamespace(), cert.GetName()
	key := ns + "/" + name
	if !certReadyFalse(cert) && !certExpiringSoon(cert, now) {
		return false
	}
	if last, ok := r.crReaped[key]; ok && now.Sub(last) < crReapMinGap {
		log.Info("SKIP: stuck-CR reap rate-limited (max 1/6h)",
			"cert", key, "lastReapAgo", now.Sub(last).Truncate(time.Minute))
		return false
	}
	crs, err := r.listCRs(ctx, ns)
	if err != nil {
		log.Error(err, "certificaterequest list failed", "cert", key)
		return false
	}
	var stuck *unstructured.Unstructured
	for i := range crs.Items {
		cr := &crs.Items[i]
		if cn, ok := certNameForCR(cr); !ok || cn != name {
			continue
		}
		st, _ := shared.ReadyCond(cr)
		if st == "True" {
			continue // issued — not stuck
		}
		// Ready=False (Pending/Failed) or never-reported: the wedge
		// age comes from the condition's lastTransitionTime when it
		// exists, else the CR's age.
		since := cr.GetCreationTimestamp().Time
		if lt, ok := shared.ReadySince(cr); ok {
			since = lt
		}
		if now.Sub(since) <= crStuckMinAge {
			continue
		}
		stuck = cr
		break
	}
	if stuck == nil {
		return false
	}
	// Same budget as an Order reset — a deleted CR re-issues the
	// request and draws the same ACME rate limit.
	st := r.resets[key]
	if st == nil {
		st = certResetFromAnnotation(cert)
		r.resets[key] = st
	}
	if st.total >= certReaperMaxReset {
		if !st.gaveUp {
			st.gaveUp = true
			metrics.IncError(certReaperQueue)
			log.Info("REFUSE: reset budget exhausted — cert config is broken, "+
				"continuing would burn the ACME rate limit",
				"cert", key, "certificaterequest", stuck.GetName(), "resets", st.total)
		}
		return false
	}
	if !st.last.IsZero() && now.Sub(st.last) < crReapMinGap {
		log.Info("SKIP: CR reap rate-limited (persisted budget, max 1/6h)",
			"cert", key, "certificaterequest", stuck.GetName(),
			"lastResetAgo", now.Sub(st.last).Truncate(time.Minute))
		return false
	}
	log.Info("RESET: deleting stuck CertificateRequest — cert-manager re-issues on next sync",
		"cert", key, "certificaterequest", stuck.GetName())
	uid := stuck.GetUID()
	if err := r.dyn.Resource(certificateRequestGVR).Namespace(ns).
		Delete(ctx, stuck.GetName(), metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid}}); err != nil {
		metrics.IncError(certReaperQueue)
		log.Error(err, "certificaterequest delete failed",
			"cert", key, "certificaterequest", stuck.GetName())
		return false
	}
	st.total++
	st.last = now
	r.crReaped[key] = now
	if err := r.patchResetsAnnotation(ctx, cert, st); err != nil {
		metrics.IncError(certReaperQueue)
		log.Error(err, "acme-resets annotation write failed", "cert", key)
	}
	return true
}

// certResetFromAnnotation hydrates the reset budget from the
// node.ops/acme-order-resets annotation ("<total>,<lastRFC3339>") on
// the Certificate. Malformed values hydrate to a zero budget — the
// reaper then re-earns its stamps one reset at a time, never the
// other way around.
func certResetFromAnnotation(cert *unstructured.Unstructured) *certReset {
	st := &certReset{}
	v := cert.GetAnnotations()[acmeResetsAnno]
	if v == "" {
		return st
	}
	total, last, ok := strings.Cut(v, ",")
	if !ok {
		return st
	}
	if n, err := strconv.Atoi(total); err == nil && n > 0 {
		st.total = n
	}
	if t, err := time.Parse(time.RFC3339, last); err == nil {
		st.last = t
	}
	return st
}

// patchResetsAnnotation merge-patches node.ops/acme-order-resets on
// the Certificate: "<total>,<lastRFC3339>" while st is non-nil, null
// (annotation removed) when the cert healed and the budget resets.
func (r *certManagerReaper) patchResetsAnnotation(ctx context.Context,
	cert *unstructured.Unstructured, st *certReset) error {
	var value any // nil → "annotation":null — merge-patch delete
	if st != nil {
		value = fmt.Sprintf("%d,%s", st.total, st.last.UTC().Format(time.RFC3339))
	}
	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"annotations": map[string]any{
			acmeResetsAnno: value,
		}},
	})
	if err != nil {
		return err
	}
	_, err = r.dyn.Resource(certificateGVR).Namespace(cert.GetNamespace()).
		Patch(ctx, cert.GetName(), types.MergePatchType, patch, metav1.PatchOptions{})
	return err
}

// certNameForCR resolves the Certificate a CertificateRequest serves:
// the CR's ownerRef (cert-manager always sets it) first, then the
// cert-manager.io/certificate-name label/annotation as fallback.
// ok=false means unattributable — the CR's Orders then match nothing.
func certNameForCR(cr *unstructured.Unstructured) (string, bool) {
	for _, or := range cr.GetOwnerReferences() {
		if or.Kind == "Certificate" && or.Name != "" {
			return or.Name, true
		}
	}
	if v := cr.GetLabels()["cert-manager.io/certificate-name"]; v != "" {
		return v, true
	}
	if v := cr.GetAnnotations()["cert-manager.io/certificate-name"]; v != "" {
		return v, true
	}
	return "", false
}

// orderOwnedByCert reports whether the Order's CertificateRequest
// ownerRef resolves — through the namespace's CR→Certificate map — to
// THIS cert. An Order with no ownerRef, or whose owning CR names a
// different cert (or resolves to nothing), is unattributable: it must
// never be reaped on this cert's candidacy or budget.
func orderOwnedByCert(o *unstructured.Unstructured, certName string,
	crToCert map[string]string) bool {
	for _, or := range o.GetOwnerReferences() {
		if or.Kind != "CertificateRequest" {
			continue
		}
		if owner, ok := crToCert[or.Name]; ok {
			return owner == certName
		}
	}
	return false
}

// stuckChallengeForOrder reports whether any Challenge in the
// namespace is both wedged and attributable to this order. Only
// explicit linkage (ownerReference or the acme order-name
// label/annotation naming this order) counts — a linkage-free
// challenge is ambiguous in a shared namespace and justifies nothing.
func stuckChallengeForOrder(order *unstructured.Unstructured,
	chals []unstructured.Unstructured, now time.Time) bool {
	for i := range chals {
		ch := &chals[i]
		if !challengeWedged(ch, now) {
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
// processing, with no state transition for over 30m before now. Uses
// status.lastTransitionTime when present (real objects do not carry
// it — fixtures may), else creationTimestamp.
func challengeWedged(ch *unstructured.Unstructured, now time.Time) bool {
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
	return now.Sub(since) > orderPendingMinAge
}

// challengeLinkedToOrder requires EXPLICIT linkage — an ownerReference
// or the acme.cert-manager.io/order-name label/annotation naming this
// order. A challenge carrying no linkage at all could belong to a
// different cert's order on a busy namespace: it does not count as
// cross-check evidence for THIS order (fail closed, matching the
// order-attribution rule above).
func challengeLinkedToOrder(ch, order *unstructured.Unstructured) bool {
	for _, or := range ch.GetOwnerReferences() {
		if or.Name == order.GetName() {
			return true
		}
	}
	if ln := ch.GetLabels()["acme.cert-manager.io/order-name"]; ln != "" &&
		ln == order.GetName() {
		return true
	}
	if an := ch.GetAnnotations()["acme.cert-manager.io/order-name"]; an != "" &&
		an == order.GetName() {
		return true
	}
	return false
}
