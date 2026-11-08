// olm_subscription_scan.go — the audit collectors of the
// olm-subscription-health check (W7-C5): the CSV/Subscription
// signature scan, the persisted unhealthy-window evaluation + gauge
// emit, and the resolved-signature stamp clear. Split out of
// olm_subscription_health.go — see that file for the check, its
// knobs and the olm-operator heal.
package datastore

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// olmScan is one sweep's collected OLM audit state:
//   - live: signatures keyed "kind/ns/name/reason" — the value is
//     the exact gauge label tuple so emission never re-splits the key;
//   - objByKey: maps each live key to the object carrying its
//     first-seen stamp;
//   - audited: records every object evaluated this sweep (to its
//     GVR) so stamps whose signature resolved get cleared — the CSV
//     and Subscription lists are disjoint, so one object is never
//     audited under two GVRs.
type olmScan struct {
	live     map[string][]string
	objByKey map[string]*unstructured.Unstructured
	audited  map[*unstructured.Unstructured]schema.GroupVersionResource
}

// collectOLMSignatures lists and classifies the two audited OLM
// surfaces — ClusterServiceVersions and Subscriptions — into the
// sweep's live signatures. A missing CRD set (OLM not installed on
// this cluster) means nothing to audit; any other list failure is a
// run-level infra error, already wrapped for the Infra verdict.
func (p *olmHealthCheck) collectOLMSignatures(ctx context.Context,
	now time.Time) (*olmScan, error) {

	scan := &olmScan{
		live:     map[string][]string{},
		objByKey: map[string]*unstructured.Unstructured{},
		audited:  map[*unstructured.Unstructured]schema.GroupVersionResource{},
	}
	addLive := func(kind, ns, name, reason string,
		obj *unstructured.Unstructured) {
		k := kind + "/" + ns + "/" + name + "/" + reason
		scan.live[k] = []string{kind, ns, name, reason}
		scan.objByKey[k] = obj
	}
	csvs, err := p.Dyn.Resource(olmCSVGVR).List(ctx, metav1.ListOptions{})
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		// OLM not installed on this cluster — nothing to audit.
	case err != nil:
		return nil, fmt.Errorf("list clusterserviceversions: %w", err)
	default:
		for i := range csvs.Items {
			csv := &csvs.Items[i]
			scan.audited[csv] = olmCSVGVR
			phase, _ := kube.NestedString(csv.Object, "status", "phase")
			if phase != "Succeeded" {
				addLive(olmKindCSV, csv.GetNamespace(), csv.GetName(),
					olmReasonCSVStuck, csv)
			}
			if ts, found := kube.NestedString(
				csv.Object, "status", "certsRotateAt"); found && ts != "" {
				if t, err := time.Parse(time.RFC3339, ts); err == nil && now.After(t) {
					addLive(olmKindCSV, csv.GetNamespace(), csv.GetName(),
						olmReasonCertOverdue, csv)
				}
			}
		}
	}
	subs, err := p.Dyn.Resource(olmSubGVR).List(ctx, metav1.ListOptions{})
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
	case err != nil:
		return nil, fmt.Errorf("list subscriptions: %w", err)
	default:
		for i := range subs.Items {
			sub := &subs.Items[i]
			scan.audited[sub] = olmSubGVR
			for _, c := range kube.Conditions(sub.Object, "status", "conditions") {
				if c.Status != "True" {
					continue
				}
				switch c.Type {
				case "CatalogSourcesUnhealthy":
					addLive(olmKindSubscription, sub.GetNamespace(),
						sub.GetName(), olmReasonCatalogUnhealthy, sub)
				case "ResolutionFailed":
					addLive(olmKindSubscription, sub.GetNamespace(),
						sub.GetName(), olmReasonResolutionFailed, sub)
				}
			}
		}
	}
	return scan, nil
}

// olmCRPatch closes over the audited object the first-seen stamp
// rides — the durable half of the unhealthy window lives on the
// object itself, delivered as a merge patch on its own GVR. The
// patch closure mirrors each LANDED patch into the listed object
// (after the API call succeeds — a failed patch must not leave a
// phantom stamp the sweep then reads back): several live keys can
// share one object's map and each stamp re-reads it — an un-synced
// second stamp would clobber the first until the next List.
func (p *olmHealthCheck) olmCRPatch(gvr schema.GroupVersionResource,
	o *unstructured.Unstructured) func(context.Context, []byte) error {

	return func(ctx context.Context, data []byte) error {
		if _, err := p.Dyn.Resource(gvr).Namespace(o.GetNamespace()).Patch(ctx,
			o.GetName(), types.MergePatchType, data, metav1.PatchOptions{}); err != nil {
			return err
		}
		probefw.MergeAnnoPatchLocally(o, data)
		return nil
	}
}

// evaluateOLMUnhealthy persists each live signature's unhealthy
// window and emits the gauge for the keys that crossed
// olmUnhealthyMinAge, returning the CSV-scoped reasons past the heal
// window. The ledger prune runs first — keys still live survive it.
func (p *olmHealthCheck) evaluateOLMUnhealthy(ctx context.Context, log logr.Logger,
	scan *olmScan, now time.Time, rep *probefw.SweepReport) map[string]bool {

	healReasons := map[string]bool{} // reasons past the heal window (CSV only)
	p.olmFirstSeen.Prune(func(k string) bool {
		_, ok := scan.live[k]
		return ok
	})
	for k, lv := range scan.live {
		obj := scan.objByKey[k]
		gvr := olmCSVGVR
		if lv[0] == olmKindSubscription {
			gvr = olmSubGVR
		}
		// The unhealthy window gates the olm-operator pod delete (and
		// the gauge), so it runs the persisted (annotation-backed)
		// variant — the per-reason stamp map on the CR survives an
		// operator restart that would otherwise re-arm the full
		// 15m/20m windows.
		if !heal.FirstSeenPersisted(ctx, log, &p.olmFirstSeen, obj,
			kube.AnnoFirstSeenOLMUnhealthy, k, olmUnhealthyMinAge, now,
			p.olmCRPatch(gvr, obj)) {
			continue
		}
		rep.Emit(olmUnhealthyResourcesGauge, k, lv, k)
		// The heal is CSV-scoped: a subscription failure is the
		// catalog's problem, not olm-operator's queue. Seen reads
		// the same streak — never re-stamps — and reports the WIDER
		// window once FirstSeenPersisted Seeds a resumed persisted
		// stamp back into the ledger.
		if lv[0] == olmKindCSV {
			if age, _ := p.olmFirstSeen.Seen(k, now); age >= olmHealMinAge {
				healReasons[lv[3]] = true
			}
		}
	}
	return healReasons
}

// clearOLMResolvedStamps drops every anno'd key that left this
// sweep's live set from each audited object so a recurrence re-arms
// the full window — a stale stamp would fast-trip the gauge and the
// heal. Tolerated sub-failure: the ledger Forget already landed, the
// annotation retry is Warn-only.
func (p *olmHealthCheck) clearOLMResolvedStamps(ctx context.Context,
	log logr.Logger, scan *olmScan) {

	for obj, gvr := range scan.audited {
		stamped := map[string]string{}
		if raw := obj.GetAnnotations()[kube.AnnoFirstSeenOLMUnhealthy]; raw != "" {
			if err := json.Unmarshal([]byte(raw), &stamped); err != nil {
				continue // unparseable = absent — same posture as the helper
			}
		}
		for k := range stamped {
			if _, ok := scan.live[k]; ok {
				continue
			}
			if err := heal.ClearPersistedFirstSeen(ctx, log,
				&p.olmFirstSeen, obj, kube.AnnoFirstSeenOLMUnhealthy, k,
				p.olmCRPatch(gvr, obj)); err != nil {
				log.Info("WARN: olm first-seen clear failed — "+
					"a stale stamp could fast-trip a recurrence",
					"key", k, "error", err)
			}
		}
	}
}
