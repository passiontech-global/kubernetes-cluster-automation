// certificate_reap.go — the Certificate reap half of
// certmanager-reaper: the candidacy predicates (certReady,
// certNeedsReap, certReadyFalse, certExpiringSoon) and reapCert,
// which walks the Order→CertificateRequest→Certificate owner chain,
// applies the per-cert reset budget, cross-checks a wedged Challenge
// (wedged_challenge.go), then deletes the stuck pending Order so
// cert-manager recreates it fresh.
package certmanagerreaper

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/reap"
)

// certReady reports whether the Certificate's Ready condition is True.
func certReady(cert *unstructured.Unstructured) bool {
	c, _ := kube.ConditionOf(cert.Object, "Ready")
	return c.Status == "True"
}

// certNeedsReap mirrors the bash filter: Ready=False OR renewalTime
// within 7d of now — a healthy cert with no upcoming renewal cannot
// have a stuck issuance worth resetting. cert-manager publishes the
// next renewal under STATUS.renewalTime (spec carries no such field).
func certNeedsReap(cert *unstructured.Unstructured, now time.Time) bool {
	if conds, ok := kube.NestedSlice(
		cert.Object, "status", "conditions"); ok {
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
	if rt, ok := kube.NestedString(
		cert.Object, "status", "renewalTime"); ok {
		if t, err := time.Parse(time.RFC3339, rt); err == nil &&
			!t.After(now.Add(certRenewalWindow)) {
			return true
		}
	}
	return false
}

// orderIndex is the cached outcome of one namespace's ACME Order
// List, attributed to their owning Certificates: byCert maps cert
// name → that cert's Orders in list order (the same first-match order
// the per-cert scan always used). Built once per sweep per namespace
// — an N-candidate sweep previously paid one Order List per cert.
type orderIndex struct {
	byCert map[string][]unstructured.Unstructured
	err    error
}

// listOrdersForCert returns the cert's attributed Orders for ns,
// building the namespace's index on first use and caching it for the
// whole sweep (mirrors listCRs). A failed Order or CR List returns
// (nil, err) — attribution is impossible, fail closed.
func (r *certManagerReaper) listOrdersForCert(ctx context.Context,
	ns, certName string) ([]unstructured.Unstructured, error) {
	idx, ok := r.orderCache[ns]
	if !ok {
		idx = r.buildOrderIndex(ctx, ns)
		r.orderCache[ns] = idx
	}
	if idx.err != nil {
		return nil, idx.err
	}
	return idx.byCert[certName], nil
}

// buildOrderIndex lists the namespace's Orders once and attributes
// each through the Order→CR→Certificate owner chain (the same
// first-resolving-CR-ownerRef rule orderOwnedByCert enforced when the
// walk was per-cert). An Order whose CR ownerRef resolves to nothing
// — or whose CR names no cert — lands under no cert and is never
// reapable.
func (r *certManagerReaper) buildOrderIndex(ctx context.Context,
	ns string) *orderIndex {
	idx := &orderIndex{byCert: map[string][]unstructured.Unstructured{}}
	orders, err := kube.ListAllUnstructured(ctx,
		r.dyn.Resource(orderGVR).Namespace(ns),
		metav1.ListOptions{Limit: kube.DefaultListPageSize})
	if err != nil {
		metrics.IncError(r.queue)
		idx.err = err
		return idx
	}
	// Attribute orders through the owner chain — an Order's ownerRef
	// names its CertificateRequest and the CR's ownerRef names the
	// Certificate (cert-manager also stamps the
	// cert-manager.io/certificate-name ref on the CR). Picking the
	// first pending order in the NAMESPACE would reap another cert's
	// order while charging the reset budget to this cert. A failed
	// CR list makes attribution impossible — fail closed.
	crs, err := r.listCRs(ctx, ns)
	if err != nil {
		idx.err = err
		return idx
	}
	crToCert := make(map[string]string, len(crs.Items))
	for i := range crs.Items {
		if certName, ok := certNameForCR(&crs.Items[i]); ok {
			crToCert[crs.Items[i].GetName()] = certName
		}
	}
	for i := range orders.Items {
		o := orders.Items[i]
		for _, or := range o.GetOwnerReferences() {
			if or.Kind != "CertificateRequest" {
				continue
			}
			if certName, ok := crToCert[or.Name]; ok {
				idx.byCert[certName] = append(idx.byCert[certName], o)
				break
			}
		}
	}
	return idx
}

// reapCert finds the cert's stuck pending Order, verifies a Challenge
// is genuinely wedged (not just slow), applies the reset budget, then
// deletes the Order so cert-manager recreates it. Reports whether an
// Order was actually deleted.
func (r *certManagerReaper) reapCert(ctx context.Context, cert *unstructured.Unstructured) bool {
	log := logf.FromContext(ctx)
	ns, name := cert.GetNamespace(), cert.GetName()
	key := ns + "/" + name
	now := r.now.Now()

	orders, err := r.listOrdersForCert(ctx, ns, name)
	if err != nil {
		log.Error(err, "order attribution failed", "cert", key)
		return false
	}

	var stuck *unstructured.Unstructured
	for i := range orders {
		o := &orders[i]
		if st, _ := kube.NestedString(o.Object, "status", "state"); st != "pending" {
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
	r.armResets()
	st := r.resets[key]
	if st == nil {
		st = certResetFromAnnotation(cert)
		r.resets[key] = st
	}
	if st.total >= certReaperMaxReset {
		if !st.gaveUp {
			st.gaveUp = true
			metrics.IncError(r.queue)
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

	chals, err := kube.ListAllUnstructured(ctx,
		r.dyn.Resource(challengeGVR).Namespace(ns),
		metav1.ListOptions{Limit: kube.DefaultListPageSize})
	if err != nil {
		metrics.IncError(r.queue)
		log.Error(err, "challenge list failed", "cert", key)
		return false
	}

	// The wedged-challenge cross-check rides the sweep's Confirm
	// phase — the live re-vet right before the delete. A pending
	// Order with no wedged Challenge is kept (issuance still
	// progressing); the delete itself is UID-preconditioned on the
	// object the list vetted.
	deleted, _, _ := reap.Sweep(ctx, log, []*unstructured.Unstructured{stuck},
		reap.Options[*unstructured.Unstructured]{
			Confirm: func(ctx context.Context, o *unstructured.Unstructured) (bool, error) {
				if !stuckChallengeForOrder(o, chals.Items, now) {
					log.Info("KEEP: pending order but no wedged challenge — "+
						"issuance still progressing", "cert", key, "order", o.GetName())
					return false, nil
				}
				return true, nil
			},
			LogTarget: func(log logr.Logger, o *unstructured.Unstructured) {
				log.Info("RESET: deleting stuck pending Order — "+
					"cert-manager recreates fresh",
					"cert", key, "order", o.GetName())
			},
			Delete: func(ctx context.Context, o *unstructured.Unstructured) error {
				return r.dyn.Resource(orderGVR).Namespace(ns).
					Delete(ctx, o.GetName(), kube.UIDDeleteOptions(o.GetUID(), ""))
			},
			OnError: func(log logr.Logger, o *unstructured.Unstructured, err error) {
				metrics.IncError(r.queue)
				log.Error(err, "order delete failed", "cert", key, "order", o.GetName())
			},
		})
	if deleted == 0 {
		return false
	}
	st.total++
	st.last = now
	// Persist the consumed reset immediately — a controller restart
	// between sweeps must not refund it. Best-effort: the Order is
	// already deleted, so a failed write is flagged, not fatal.
	if err := r.patchResetsAnnotation(ctx, cert, st); err != nil {
		metrics.IncError(r.queue)
		log.Error(err, "acme-resets annotation write failed", "cert", key)
	}
	return true
}

// certReadyFalse reports the Ready=False half of the stuck-CR candidacy.
func certReadyFalse(cert *unstructured.Unstructured) bool {
	c, _ := kube.ConditionOf(cert.Object, "Ready")
	return c.Status == "False"
}

// certExpiringSoon reports whether status.notAfter lands within the
// next 14 days — an expiring cert with a wedged child CR is a renewal
// that silently died.
func certExpiringSoon(cert *unstructured.Unstructured, now time.Time) bool {
	if v, ok := kube.NestedString(
		cert.Object, "status", "notAfter"); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t.Before(now.Add(certExpirySoonWin))
		}
	}
	return false
}
