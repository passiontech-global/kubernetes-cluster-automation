// helpers.go — shared helpers for the self-healing probe checks:
//
//   - DeletePodHeal / SelfHealKey: the shared pod-delete heal shape —
//     per-target cooldown on the Deps Heals ledger, maintenance mutex
//     (fail closed), UID-preconditioned delete — and the
//     "selfheal/<check>/<target>" ledger key it stamps. Thin wrapper
//     over the platform heal package this file was the reference for.
//   - HealAllowed / HealAllowedPersisted: the shared heal preamble
//     every check's heal gate runs — per-target cooldown (plain or
//     persisted-stamp-widened) + maintenance mutex + heal budget,
//     memoized on the Deps-wide verdict.
//   - RequireDyn: the "no dynamic client" preamble every CR-scanning
//     check opens with.
//   - PodUnreadySince / PodFromList: pod readiness helpers.
//   - PromEndpoint / PromQuery: the Prometheus instant-query seam
//     every metrics-backed check shares, backed by internal/promq —
//     the HEALTH_PROMETHEUS_QUERY_URL override resolves ONCE at Deps
//     construction, never inside a run.
//   - LinkerdPodMatchesComponent: the generic Deployment-prefix/
//     label matcher. The linkerd identifiers it matches against and
//     the dragonfly operator namespace are domain consts — they live
//     in internal/platform/kube/domains.go (the cross-tree sharing
//     layer), not in the check-agnostic framework.
//
// The first-seen streak and emitted-gauge bookkeeping these checks
// used to share on deps.ledger lives per check as
// state.FirstSeenLedger / state.GaugeLedger[string] fields (the
// zero values are usable — the serial sweep needs no locking).
package probefw

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/maintenance"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
)

// The linkerd control-plane identifiers and the dragonfly operator
// namespace moved OUT of the framework — the framework must stay
// check-agnostic: they are cross-tree topology identifiers and live
// in internal/platform/kube/domains.go, imported by every consumer
// (health check subpackages AND integration auditors).
// LinkerdPodMatchesComponent stays: it is the generic
// Deployment-prefix/label matcher, not a domain identifier.

// PromEndpoint resolves the Prometheus /api/v1/query URL:
// HEALTH_PROMETHEUS_QUERY_URL (a full query URL) wins — the override
// was resolved ONCE at Deps construction (NewDeps), so mid-run env
// churn cannot flip it — else the endpoint derives from the
// http-content-check target's scheme://host, the same Prometheus
// that check health-probes. The derivation reads Cfg, not env, so a
// caller re-pointing Cfg (tests) keeps working.
func (d *Deps) PromEndpoint() (string, error) {
	return promq.ResolveEndpoint(
		d.promEndpointOverride, d.Cfg.HTTPContent.URL)
}

var errObsBackendUnknown = errors.New("observability backend undetermined")

// ObsTarget returns the active observability target for this sweep.
// When Cfg.HTTPContent.AutoDetect is true and HEALTH_HTTP_CONTENT_URL
// was not explicitly set, it probes candidate endpoints via
// promq.AutoDetectTarget (memoized per sweep — including negative
// detections — so concurrent checks in one sweep never amplify probes;
// promq.TargetDetector never caches negative detections across sweeps).
// Explicit configs and literal test Deps (probetest.NewDeps) return
// Cfg.HTTPContent verbatim with zero network probes.
func (d *Deps) ObsTarget(ctx context.Context) (promq.ObsTarget, bool) {
	if !d.Cfg.HTTPContent.AutoDetect || d.Cfg.HTTPContent.URLExplicit {
		endpoint, _ := d.PromEndpoint()
		return promq.ObsTarget{
			Backend:      promq.DetectBackendFromURL(endpoint),
			HealthURL:    d.Cfg.HTTPContent.URL,
			ExpectedBody: d.Cfg.HTTPContent.Expected,
			QueryURL:     endpoint,
		}, false
	}

	s := sweepSnap(ctx)
	res, _ := s.obsTarget.get(func(bool) (obsTargetMemo, error) {
		lctx, cancel := s.listCtx(ctx)
		defer cancel()
		target, detected := promq.AutoDetectTarget(lctx, d.HTTPClient, d.Cfg.ObsBackendMode)
		return obsTargetMemo{target: target, detected: detected}, nil
	})
	target := res.target
	if d.Cfg.HTTPContent.ExpectedExplicit {
		target.ExpectedBody = d.Cfg.HTTPContent.Expected
	}
	if d.promEndpointOverride != "" {
		target.QueryURL = d.promEndpointOverride
	}
	return target, res.detected
}

// PromEndpointCtx resolves the /api/v1/query URL for ctx: an explicit
// HEALTH_PROMETHEUS_QUERY_URL override wins verbatim, else when
// auto-detection is active it uses ObsTarget(ctx), otherwise it falls
// back to PromEndpoint().
func (d *Deps) PromEndpointCtx(ctx context.Context) (string, error) {
	if d.promEndpointOverride != "" {
		return d.promEndpointOverride, nil
	}
	if d.Cfg.HTTPContent.AutoDetect && !d.Cfg.HTTPContent.URLExplicit {
		if sweepSnap(ctx).promCircuitOpen() {
			return "", errPromCircuitOpen
		}
		target, _ := d.ObsTarget(ctx)
		if target.QueryURL != "" {
			return target.QueryURL, nil
		}
		return promq.ResolveEndpoint("", target.HealthURL)
	}
	return d.PromEndpoint()
}

// PromBackend returns the detected observability backend for the sweep,
// memoizing positive determinations in sweepSnapshot and leaving
// transient errors or undetermined results un-memoized.
func (d *Deps) PromBackend(ctx context.Context) promq.BackendKind {
	s := sweepSnap(ctx)
	backend, err := s.promBackend.getLive(func() (promq.BackendKind, error) {
		var endpoint string
		var err error
		if d.Cfg.HTTPContent.AutoDetect && !d.Cfg.HTTPContent.URLExplicit && d.promEndpointOverride == "" {
			target, detected := d.ObsTarget(ctx)
			if detected && target.Backend != promq.BackendUnknown {
				return target.Backend, nil
			}
			if s.promCircuitOpen() {
				return promq.BackendUnknown, errPromCircuitOpen
			}
			endpoint = target.QueryURL
			if endpoint == "" {
				endpoint, err = promq.ResolveEndpoint("", target.HealthURL)
			}
		} else {
			if s.promCircuitOpen() {
				return promq.BackendUnknown, errPromCircuitOpen
			}
			endpoint, err = d.PromEndpointCtx(ctx)
		}
		if err != nil {
			return promq.BackendUnknown, err
		}
		c := d.Prom
		c.HTTP = d.HTTPClient
		lctx, cancel := context.WithTimeout(ctx, snapshotListTimeout)
		defer cancel()
		kind, err := promq.DetectBackend(lctx, &c, endpoint)
		if err != nil {
			if ctx.Err() == nil {
				s.promNoteResult(err)
			}
			return promq.BackendUnknown, err
		}
		if kind == promq.BackendUnknown {
			return promq.BackendUnknown, errObsBackendUnknown
		}
		return kind, nil
	})
	if err != nil {
		return promq.BackendUnknown
	}
	return backend
}

// PromQuery runs an instant PromQL query against the resolved
// endpoint and returns the vector samples. d.Prom carries the client
// config; HTTP is re-read per call so the HTTPClient seam (tests
// swap it after construction) keeps working.
//
// Inside a sweep the query dedupes through the snapshot's promMemo:
// several checks issue byte-identical PromQL and each used to pay a
// full Prometheus round-trip — the first caller's (samples, err) is
// shared with every later identical query in the cycle. Outside a
// sweep the per-call snapshot means no dedup — the pre-cache
// semantics.
func (d *Deps) PromQuery(ctx context.Context, query string) ([]promq.Sample, error) {
	endpoint, err := d.PromEndpointCtx(ctx)
	if err != nil {
		return nil, err
	}
	c := d.Prom
	c.HTTP = d.HTTPClient
	s := sweepSnap(ctx)
	// Memo key is (endpoint, query): two checks pointing at
	// different Prometheus endpoints must never share a result,
	// and the same query text against a re-resolved endpoint is a
	// different question.
	m := s.promMemo(endpoint + "\x00" + query)
	// getLive, not get: a failed query must NOT be memoized — the
	// next identical query retries the wire. (The old get+reset
	// pair raced: a sibling get between the unlock and the reset
	// replayed the just-cached error to the whole sweep.)
	v, err := m.getLive(func() ([]promq.Sample, error) {
		// Per-sweep circuit breaker: once Prometheus has proven
		// unreachable (promCircuitThreshold consecutive transport
		// failures), every NEW query fast-fails for the rest of
		// the sweep instead of each of the ~40 Prom-backed checks
		// paying its own dial timeout. Already-memoized successes
		// still serve — the circuit only gates wire calls.
		if s.promCircuitOpen() {
			return nil, errPromCircuitOpen
		}
		// The query runs under the CALLING check's ctx bounded by
		// snapshotListTimeout — the PerCheck deadline is honored
		// (a check whose budget is nearly spent fails fast rather
		// than blocking the pool), and because failures are never
		// memoized an expiring check ctx cannot poison a later
		// identical query the way the old shared-ctx design could.
		lctx, cancel := context.WithTimeout(ctx, snapshotListTimeout)
		defer cancel()
		samples, queryErr := c.InstantQuery(lctx, endpoint, query)
		// Only feed the circuit when the CALLER's ctx is still
		// alive: a check whose own cctx deadline expired makes
		// lctx fail with a local timeout that promq wraps as
		// TransportError — counting those would let ONE slow
		// check's budget trip promOpen and blind the other ~54
		// checks for the rest of the sweep. With ctx alive, a
		// transport error is genuine endpoint evidence.
		if ctx.Err() == nil {
			s.promNoteResult(queryErr)
		}
		return samples, queryErr
	})
	return v, err
}

// errPromCircuitOpen is the fast-fail PromQuery returns once the
// sweep's Prometheus circuit has tripped — the endpoint produced
// promCircuitThreshold consecutive transport failures, so further
// queries this sweep skip the wire entirely. It is a plain error,
// not a sentinel callers match on: every Prom-backed check already
// treats a PromQuery error as inconclusive/infra, which is exactly
// the right verdict for "Prometheus is down".
var errPromCircuitOpen = errors.New(
	"prometheus circuit open: endpoint unreachable this sweep")

// SelfHealKey composes the shared heal-ledger key —
// "selfheal/<check>/<target>" — DeletePodHeal stamps on
// Deps.Heals. Four domain checks hand-compose the same format for
// their non-pod-delete heals (keda rescue, wedged-namespace
// finalizer sweep, cilium IPAM reap, linkerd template re-roll) so
// the keyspace stays unified: a heal under any spelling honors the
// same cooldown stamp.
func SelfHealKey(check, target string) string {
	return "selfheal/" + check + "/" + target
}

// RequireDyn implements the shared "no dynamic client" preamble —
// the CR-scanning checks treat a missing dynamic client as a wiring
// bug (Infra), never "no signal". Returns nil when Dyn is set, else
// the Infra result the sites build; what is the check's free-form
// description and the error stays byte-identical to the hand-rolled
// strings ("no dynamic client — <what> unverifiable"; what="" yields
// the bare "no dynamic client").
//
//	if r := d.RequireDyn("scylla health check"); r != nil {
//		return *r
//	}
func (d *Deps) RequireDyn(what string) *Result {
	if d.Dyn != nil {
		return nil
	}
	if what == "" {
		return &Result{Infra: errors.New("no dynamic client")}
	}
	return &Result{Infra: fmt.Errorf(
		"no dynamic client — %s unverifiable", what)}
}

// maintSnapshot adapts the Deps census getters to maintenance's
// MaintenanceSnapshotProvider — installed on the ctx every heal gate
// hands the verdict, so the mutex's node/daemonset evidence reads
// ride the per-sweep memoized census instead of paying their own
// LIST/GET per Verdict TTL. Outside a sweep the census getters
// degrade to fresh reads, preserving pre-snapshot semantics.
type maintSnapshot struct{ d *Deps }

func (m maintSnapshot) Nodes(ctx context.Context) ([]corev1.Node, error) {
	return m.d.AllNodes(ctx)
}

func (m maintSnapshot) DaemonSets(ctx context.Context) ([]appsv1.DaemonSet, error) {
	return m.d.AllDaemonSets(ctx)
}

// HealAllowed is the shared preamble every check's heal gate runs
// before picking its target: the per-target cooldown on heals (a nil
// ledger skips it, matching heal.AllowedV's nil-heals contract),
// then the maintenance mutex plus the global heal budget — one
// maintenance-mutex evaluation per Verdict TTL across ALL checks in
// the sweep (the memo lives on the sweep snapshot's local Verdict),
// instead of three API reads per target per check.
func (d *Deps) HealAllowed(ctx context.Context, log logr.Logger,
	heals *state.CooldownSet, key string, cooldown time.Duration,
	now time.Time) (proceed, unverifiable bool) {
	ctx, v := d.sweepHealGate(ctx)
	return heal.AllowedV(ctx, log, v, d.CS, d.Dyn,
		heals, key, cooldown, now)
}

// HealAllowedPersisted is HealAllowed with the cooldown widened to
// the target's persisted stamp: heal.AllowedVPersisted running on the
// sweep-local (or Deps-level outside a sweep) memoized verdict —
// same cooldown → mutex → budget order, the wider-of
// in-RAM+annotation window, and one maintenance-mutex evaluation per
// Verdict TTL across the whole sweep (never per target). The caller
// stamps the annotation itself, only after a delivered action; a nil
// obj/empty annoKey collapses to HealAllowed.
func (d *Deps) HealAllowedPersisted(ctx context.Context, log logr.Logger,
	heals *state.CooldownSet, obj metav1.Object, annoKey, key string,
	cooldown time.Duration, now time.Time) (proceed, unverifiable bool) {
	ctx, v := d.sweepHealGate(ctx)
	return heal.AllowedVPersisted(ctx, log, v, d.CS, d.Dyn,
		heals, obj, annoKey, key, cooldown, now)
}

// HealAllowedOnNode is HealAllowed's node-scoped sibling for heals
// that touch ONE node's DaemonSet pods: the maintenance Scope
// defers only on a cluster-wide hold or a hold naming nodeName —
// a drain scoped to a different node does not block the bounce.
// Cooldown/budget gates are unchanged; there is no persisted
// variant on Deps — callers needing the wider-of window call
// heal.AllowedOnNodePersisted through their own verdict.
func (d *Deps) HealAllowedOnNode(ctx context.Context, log logr.Logger,
	heals *state.CooldownSet, key, nodeName string,
	cooldown time.Duration, now time.Time) (proceed, unverifiable bool) {
	ctx, v := d.sweepHealGate(ctx)
	return heal.AllowedOnNode(ctx, log, v, d.CS, d.Dyn,
		heals, key, nodeName, cooldown, now)
}

// HealAllowedClusterWideOnly is HealAllowed's cluster-wide-only
// sibling for drain-unblock heals (pod deletes that exist to finish
// a cordon drain — rollout unstickers, zombie cleanup): the
// maintenance Scope defers ONLY on a cluster-wide hold, so an
// actively-cordoned node — itself a node-scoped hold under
// AllowedV — cannot deadlock the heal that exists to unblock it.
// Cooldown/budget gates are unchanged; pair the actuation with
// heal.RefundGrant on a clean (false, nil) deferral exactly like
// DeletePodHeal does.
func (d *Deps) HealAllowedClusterWideOnly(ctx context.Context, log logr.Logger,
	heals *state.CooldownSet, key string, cooldown time.Duration,
	now time.Time) (proceed, unverifiable bool) {
	ctx, v := d.sweepHealGate(ctx)
	return heal.AllowedClusterWideOnly(ctx, log, v, d.CS, d.Dyn,
		heals, key, cooldown, now)
}

// HealAllowedUpgradeOnly gates the annotation-only nudges: it
// defers ONLY on a cluster-wide maintenance hold — a node-scoped
// drain does not block a metadata write, and no heal-budget grant
// is consumed.
func (d *Deps) HealAllowedUpgradeOnly(ctx context.Context, log logr.Logger,
	key string, now time.Time) (proceed, unverifiable bool) {
	ctx, v := d.sweepHealGate(ctx)
	return heal.AllowedUpgradeOnly(ctx, log, v, d.CS, d.Dyn,
		key, now)
}

// HealAllowedUpgradeOnlyPersisted is HealAllowedUpgradeOnly with the
// cooldown widened to the target's persisted stamp — the gate every
// annotation-only nudge (Flux requestedAt stamps, ArgoCD sync
// requests, Kargo promotion stamps, force-sync annotations) runs:
// wider-of in-RAM+annotation cooldown first, then ONLY the
// cluster-wide maintenance Scope. Node-scoped drains do not defer a
// metadata write and no heal-budget grant is consumed.
func (d *Deps) HealAllowedUpgradeOnlyPersisted(ctx context.Context, log logr.Logger,
	heals *state.CooldownSet, obj metav1.Object, annoKey, key string,
	cooldown time.Duration, now time.Time) (proceed, unverifiable bool) {
	ctx, v := d.sweepHealGate(ctx)
	return heal.AllowedUpgradeOnlyPersisted(ctx, log, v, d.CS, d.Dyn,
		heals, obj, annoKey, key, cooldown, now)
}

// sweepHealGate resolves the ctx and Verdict for a heal gate: inside
// a sweep, it attaches maintSnapshot so the evaluation rides the
// sweep's memoized censuses and isolates the result onto the sweep's
// local Verdict (never writing sweep-frozen state into the
// process-global Deps.Maintenance shared with non-sweep modules).
// Outside a sweep, it leaves ctx unmodified (live reads) and uses
// d.Maintenance (or d.verdictFallback when nil).
func (d *Deps) sweepHealGate(ctx context.Context) (context.Context, *maintenance.Verdict) {
	if s, ok := ctx.Value(sweepCtxKey{}).(*sweepSnapshot); ok {
		return maintenance.WithMaintenanceSnapshot(ctx, maintSnapshot{d}), &s.verdict
	}
	if d.Maintenance != nil {
		return ctx, d.Maintenance
	}
	return ctx, &d.verdictFallback
}

// EvictPodV runs heal.EvictPodV against the sweep-scoped maintenance
// verdict so checks never read or mutate the process-global
// Deps.Maintenance directly.
func (d *Deps) EvictPodV(ctx context.Context, log logr.Logger,
	heals *state.CooldownSet, key string, cooldown time.Duration,
	pod *corev1.Pod, now time.Time) (proceed, unverifiable, evicted, refused bool, err error) {
	ctx, v := d.sweepHealGate(ctx)
	return heal.EvictPodV(ctx, log, v, d.CS, d.Dyn, heals, key, cooldown, pod, now)
}

// DeletePodHeal is the pod-delete heal shape the self-healing checks
// share — this body was the reference internal/platform/heal was
// extracted from, so it now delegates: heal.AllowedV runs the
// per-target cooldown on the shared heals ledger plus the
// maintenance mutex (fail closed on unverifiable), heal.DeletePod
// does the UID-preconditioned delete and stamps the ledger only on
// delivery, and the shared ControlPlanePodHealsTotal counter stays
// under the check name here (heal never touches metrics).
//
// The bool return reports whether a delete was actually DELIVERED —
// callers whose bookkeeping must not run on a denied/failed heal
// (agentHealed flags, "healed" result reasons) gate on it; cooldown
// gates, mutex refusals and the sweep overlay's quorum reservation
// all return false. Callers that don't care may ignore it.
func (d *Deps) DeletePodHeal(ctx context.Context, log logr.Logger,
	checkName, targetKey string, pod *corev1.Pod,
	cooldown time.Duration, now time.Time) bool {

	key := SelfHealKey(checkName, targetKey)
	proceed, unverifiable := d.HealAllowed(ctx, log,
		&d.Heals, key, cooldown, now)
	if unverifiable {
		metrics.IncError(d.Name)
		return false
	}
	if !proceed {
		return false
	}
	deleted, err := heal.DeletePod(ctx, d.CS, &d.Heals, key, pod, now)
	if err != nil {
		metrics.IncError(d.Name)
		log.Error(err, "heal pod delete failed",
			"check", checkName, "pod", pod.Namespace+"/"+pod.Name)
		return false
	}
	if !deleted {
		// Clean deferral — the L1 hold or the sweep overlay's
		// quorum reservation denied the delete before any mutation
		// ran, so the grant HealAllowed consumed bought no heal:
		// hand it back, exactly once, at this gate. An err!=nil
		// outcome above keeps the grant (an attempted delete that
		// failed spent a cheap token — budget.go contract).
		heal.RefundGrant(now)
		// The sweep overlay's quorum reservation denied the delete —
		// a sibling check already spent this workload's one-
		// disruption slot this sweep. Deferral, not a heal: no
		// tombstone, no metric, no ledger stamp (DeletePod only
		// stamps on delivery); the next sweep retries.
		log.Info("DEFER: workload disruption already reserved this sweep",
			"check", checkName, "pod", pod.Namespace+"/"+pod.Name)
		return false
	}
	// The pod census the next check reads must not contain the pod
	// this delete just removed — heal.DeletePod already dropped the
	// O(1) UID tombstone on the sweep overlay (AllPods filters it on
	// every later read), the InvalidatePods cluster-wide re-LIST
	// this used to pay per heal is gone.
	metrics.ControlPlanePodHealsTotal.WithLabelValues(checkName).Inc()
	log.Info("DELETE: pod heal — forcing pod restart",
		"check", checkName, "pod", pod.Namespace+"/"+pod.Name)
	return true
}

// DeletePodHealOnNode is DeletePodHeal's node-scoped sibling for
// DaemonSet pod bounces: the maintenance gate defers only on a
// cluster-wide hold or a hold naming pod.Spec.NodeName — a drain
// scoped to a different node does not block this pod's restart.
// Cooldown, budget, delete and metric contracts are identical.
func (d *Deps) DeletePodHealOnNode(ctx context.Context, log logr.Logger,
	checkName, targetKey string, pod *corev1.Pod,
	cooldown time.Duration, now time.Time) bool {

	key := SelfHealKey(checkName, targetKey)
	proceed, unverifiable := d.HealAllowedOnNode(ctx, log,
		&d.Heals, key, pod.Spec.NodeName, cooldown, now)
	if unverifiable {
		metrics.IncError(d.Name)
		return false
	}
	if !proceed {
		return false
	}
	deleted, err := heal.DeletePod(ctx, d.CS, &d.Heals, key, pod, now)
	if err != nil {
		metrics.IncError(d.Name)
		log.Error(err, "heal pod delete failed",
			"check", checkName, "pod", pod.Namespace+"/"+pod.Name)
		return false
	}
	if !deleted {
		heal.RefundGrant(now)
		log.Info("DEFER: workload disruption already reserved this sweep",
			"check", checkName, "pod", pod.Namespace+"/"+pod.Name)
		return false
	}
	metrics.ControlPlanePodHealsTotal.WithLabelValues(checkName).Inc()
	log.Info("DELETE: pod heal — forcing pod restart",
		"check", checkName, "pod", pod.Namespace+"/"+pod.Name)
	return true
}

// DeletePodHealScoped is the owner-aware dispatcher for heals whose
// pod population mixes DaemonSet agents with Deployment/StatefulSet
// workloads: a DaemonSet-owned pod bounces under the node-scoped
// hold (DeletePodHealOnNode — a drain of another node must not
// block it), everything else gates cluster-wide (DeletePodHeal).
// AllowedOnNode is only sound for DS pods: a Deployment replica's
// Spec.NodeName says nothing about where its SIBLINGS run, so a
// drain of worker-1 must never green-light deleting the last
// healthy replica sitting on worker-2.
func (d *Deps) DeletePodHealScoped(ctx context.Context, log logr.Logger,
	checkName, targetKey string, pod *corev1.Pod,
	cooldown time.Duration, now time.Time) bool {

	if ctrl := metav1.GetControllerOf(pod); ctrl != nil &&
		ctrl.Kind == "DaemonSet" {
		return d.DeletePodHealOnNode(ctx, log, checkName, targetKey,
			pod, cooldown, now)
	}
	return d.DeletePodHeal(ctx, log, checkName, targetKey, pod,
		cooldown, now)
}

// PodUnreadySince returns when the pod's Ready condition last went
// non-True — the persistence clock for "stuck unready" heals. Absent
// Ready condition falls back to pod creation (a pod that never
// reported Ready is unready since birth).
func PodUnreadySince(pod *corev1.Pod) (time.Time, bool) {
	for _, c := range pod.Status.Conditions {
		if c.Type != corev1.PodReady {
			continue
		}
		if c.Status == corev1.ConditionTrue {
			return time.Time{}, false
		}
		if !c.LastTransitionTime.IsZero() {
			return c.LastTransitionTime.Time, true
		}
		return pod.CreationTimestamp.Time, true
	}
	return pod.CreationTimestamp.Time, true
}

// PodFromList resolves ns/name inside an already-fetched pod
// list — kept tiny to avoid a second cluster-wide List in the
// fallback path.
func PodFromList(items []corev1.Pod, ns, name string) *corev1.Pod {
	for i := range items {
		if items[i].Namespace == ns && items[i].Name == name {
			return &items[i]
		}
	}
	return nil
}

// LinkerdPodMatchesComponent matches a Pod in the linkerd namespace
// against a control-plane Deployment name ("linkerd-destination" or
// "linkerd-identity") via exact name, Deployment/ReplicaSet prefix, or
// the linkerd.io/control-plane-component label.
func LinkerdPodMatchesComponent(pod *corev1.Pod, component string) bool {
	if pod.Name == component || strings.HasPrefix(pod.Name, component+"-") {
		return true
	}
	short := strings.TrimPrefix(component, "linkerd-")
	return short != "" && pod.Labels["linkerd.io/control-plane-component"] == short
}

// MergeAnnoPatchLocally applies a landed
// {"metadata":{"annotations":{k:v|null}}} merge patch so later
// readers this run see the post-patch state — the serial sweep sees
// no apiserver echo, so without the mirror a second annotation write
// this sweep would compute its patch from the pre-write state
// (several reason-keys share one object's annotation map, so a stale
// read can resurrect a cleared key or drop a just-stamped one).
// Delegates to kube.RecordAnnoPatch: inside a sweep the delta lands
// on the overlay (the shared object is NEVER mutated — readers use
// kube.EffectiveAnno/AnnoTimeCtx); outside a sweep the helper keeps
// the legacy in-place mirror on the caller-private object.
// Malformed payloads are ignored — the input is always
// kube.MergePatchAnnos output.
func MergeAnnoPatchLocally(ctx context.Context, obj metav1.Object, data []byte) {
	kube.RecordAnnoPatch(ctx, obj, data)
}

// Section renders one findings family into a Why part: "" when
// findings is empty, otherwise fmt.Sprintf(format, args...,
// strings.Join(findings, ", ")) — format always ends in the %s the
// sorted-joined findings fill.
func Section(format string, findings []string, args ...any) string {
	if len(findings) == 0 {
		return ""
	}
	return fmt.Sprintf(format, append(args, strings.Join(findings, ", "))...)
}

// WhyFold folds section strings (Section output) into a probe Result:
// the non-empty sections joined with " | " become the Why, and a fold
// with nothing to report is a pass — the standard tail every
// collect→sort→join sweep ends with.
func WhyFold(sections ...string) Result {
	var parts []string
	for _, s := range sections {
		if s != "" {
			parts = append(parts, s)
		}
	}
	if len(parts) == 0 {
		return Result{Pass: true}
	}
	return Result{Why: strings.Join(parts, " | ")}
}
