// stuck_certificaterequest_reap.go — the stuck-CertificateRequest
// path: a CR wedged Ready=False (Pending/Failed) past crStuckMinAge
// under a Ready=False or expiring cert gets deleted so cert-manager
// re-issues it on the cert's next sync. Also hosts the shared
// machinery both reap paths use: listCRs (the per-sweep per-namespace
// CR list cache), certNameForCR (CR→Certificate attribution), and the
// acme-order-resets budget persistence (certResetFromAnnotation /
// patchResetsAnnotation).
package certmanagerreaper

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/reap"
)

// listCRs returns the CertificateRequests of one namespace, caching
// the result (and the error) for the whole sweep — the Order-
// attribution path and the stuck-CR path share a single List, so a
// shared API outage IncErrors once instead of once per consumer.
func (r *certManagerReaper) listCRs(ctx context.Context, ns string) (*unstructured.UnstructuredList, error) {
	if res, ok := r.crCache[ns]; ok {
		return res.list, res.err
	}
	list, err := kube.ListAllUnstructured(ctx,
		r.dyn.Resource(certificateRequestGVR).Namespace(ns),
		metav1.ListOptions{Limit: kube.DefaultListPageSize})
	if err != nil {
		metrics.IncError(r.queue)
	}
	r.crCache[ns] = crListResult{list: list, err: err}
	return list, err
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
	if r.crReaped.CooledDown(key, crReapMinGap, now) {
		log.Info("SKIP: stuck-CR reap rate-limited (max 1/6h)", "cert", key)
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
		st, _ := kube.ConditionOf(cr.Object, "Ready")
		if st.Status == "True" {
			continue // issued — not stuck
		}
		// Ready=False (Pending/Failed) or never-reported: the wedge
		// age comes from the condition's lastTransitionTime when it
		// exists, else the CR's age.
		since := cr.GetCreationTimestamp().Time
		if !st.LastTransitionTime.IsZero() {
			since = st.LastTransitionTime
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
	// A CR that looks stuck may still own a pending Order whose
	// Challenge is progressing normally — deleting the CR
	// cascade-deletes that Order and undoes the keep decision
	// reapCert just made for it. Only reap when every owned pending
	// Order is itself wedged (or none exists).
	orders, oerr := r.listOrdersForCert(ctx, ns, name)
	if oerr != nil {
		log.Error(oerr, "order attribution failed", "cert", key)
		return false
	}
	var liveOrder *unstructured.Unstructured
	for i := range orders {
		o := &orders[i]
		owned := false
		for _, or := range o.GetOwnerReferences() {
			if or.Kind == "CertificateRequest" && or.Name == stuck.GetName() {
				owned = true
				break
			}
		}
		if !owned {
			continue
		}
		if st, _ := kube.NestedString(o.Object, "status", "state"); st == "pending" {
			liveOrder = o
			break
		}
	}
	if liveOrder != nil {
		chals, cerr := kube.ListAllUnstructured(ctx,
			r.dyn.Resource(challengeGVR).Namespace(ns),
			metav1.ListOptions{Limit: kube.DefaultListPageSize})
		if cerr != nil {
			metrics.IncError(r.queue)
			log.Error(cerr, "challenge list failed", "cert", key)
			return false
		}
		if !stuckChallengeForOrder(liveOrder, chals.Items, now) {
			log.Info("KEEP: stuck CertificateRequest owns a pending Order "+
				"whose challenge is still progressing — not reaping",
				"cert", key, "certificaterequest", stuck.GetName(),
				"order", liveOrder.GetName())
			return false
		}
	}
	// Same budget as an Order reset — a deleted CR re-issues the
	// request and draws the same ACME rate limit.
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
	// The stuck CR carries its UID from the list that vetted it —
	// the delete is preconditioned on that UID so a same-named CR
	// recreated since the list is not reaped.
	deleted, _, _ := reap.Sweep(ctx, log, []*unstructured.Unstructured{stuck},
		reap.Options[*unstructured.Unstructured]{
			LogTarget: func(log logr.Logger, cr *unstructured.Unstructured) {
				log.Info("RESET: deleting stuck CertificateRequest — "+
					"cert-manager re-issues on next sync",
					"cert", key, "certificaterequest", cr.GetName())
			},
			Delete: func(ctx context.Context, cr *unstructured.Unstructured) error {
				return r.dyn.Resource(certificateRequestGVR).Namespace(ns).
					Delete(ctx, cr.GetName(), kube.UIDDeleteOptions(cr.GetUID(), ""))
			},
			OnError: reap.DeleteErrorHandler("certificaterequest",
				func(cr *unstructured.Unstructured) string { return cr.GetNamespace() + "/" + cr.GetName() },
				func() { metrics.IncError(r.queue) }),
		})
	if deleted == 0 {
		return false
	}
	st.total++
	st.last = now
	r.crReaped.Stamp(key, now)
	if err := r.patchResetsAnnotation(ctx, cert, st); err != nil {
		metrics.IncError(r.queue)
		log.Error(err, "acme-resets annotation write failed", "cert", key)
	}
	return true
}

// certResetFromAnnotation hydrates the reset budget from the
// passiontech.dev/acme-order-resets annotation ("<total>,<lastRFC3339>") on
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

// patchResetsAnnotation merge-patches passiontech.dev/acme-order-resets on
// the Certificate: "<total>,<lastRFC3339>" while st is non-nil, null
// (annotation removed) when the cert healed and the budget resets.
func (r *certManagerReaper) patchResetsAnnotation(ctx context.Context,
	cert *unstructured.Unstructured, st *certReset) error {
	var value any // nil → "annotation":null — merge-patch delete
	if st != nil {
		value = fmt.Sprintf("%d,%s", st.total, st.last.UTC().Format(time.RFC3339))
	}
	patch, err := kube.MergePatchAnnos(map[string]any{
		acmeResetsAnno: value,
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
