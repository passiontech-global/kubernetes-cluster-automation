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
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
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

// PromQuery runs an instant PromQL query against the resolved
// endpoint and returns the vector samples. d.Prom carries the client
// config; HTTP is re-read per call so the HTTPClient seam (tests
// swap it after construction) keeps working.
func (d *Deps) PromQuery(ctx context.Context, query string) ([]promq.Sample, error) {
	endpoint, err := d.PromEndpoint()
	if err != nil {
		return nil, err
	}
	c := d.Prom
	c.HTTP = d.HTTPClient
	return c.InstantQuery(ctx, endpoint, query)
}

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

// HealAllowed is the shared preamble every check's heal gate runs
// before picking its target: the per-target cooldown on heals (a nil
// ledger skips it, matching heal.AllowedV's nil-heals contract),
// then the maintenance mutex plus the global heal budget — one
// maintenance-mutex evaluation per Verdict TTL across ALL checks in
// the sweep (the memo lives on Deps.verdict), instead of three API
// reads per target per check.
func (d *Deps) HealAllowed(ctx context.Context, log logr.Logger,
	heals *state.CooldownSet, key string, cooldown time.Duration,
	now time.Time) (proceed, unverifiable bool) {
	return heal.AllowedV(ctx, log, &d.verdict, d.CS, d.Dyn,
		heals, key, cooldown, now)
}

// HealAllowedPersisted is HealAllowed with the cooldown widened to
// the target's persisted stamp: heal.AllowedVPersisted running on the
// Deps-wide memoized verdict — same cooldown → mutex → budget order,
// the wider-of in-RAM+annotation window, and one maintenance-mutex
// evaluation per Verdict TTL across the whole sweep (never per
// target). The caller stamps the annotation itself, only after a
// delivered action; a nil obj/empty annoKey collapses to HealAllowed.
func (d *Deps) HealAllowedPersisted(ctx context.Context, log logr.Logger,
	heals *state.CooldownSet, obj metav1.Object, annoKey, key string,
	cooldown time.Duration, now time.Time) (proceed, unverifiable bool) {
	return heal.AllowedVPersisted(ctx, log, &d.verdict, d.CS, d.Dyn,
		heals, obj, annoKey, key, cooldown, now)
}

// DeletePodHeal is the pod-delete heal shape the self-healing checks
// share — this body was the reference internal/platform/heal was
// extracted from, so it now delegates: heal.AllowedV runs the
// per-target cooldown on the shared heals ledger plus the
// maintenance mutex (fail closed on unverifiable), heal.DeletePod
// does the UID-preconditioned delete and stamps the ledger only on
// delivery, and the shared ControlPlanePodHealsTotal counter stays
// under the check name here (heal never touches metrics).
func (d *Deps) DeletePodHeal(ctx context.Context, log logr.Logger,
	checkName, targetKey string, pod *corev1.Pod,
	cooldown time.Duration, now time.Time) {

	key := SelfHealKey(checkName, targetKey)
	proceed, unverifiable := d.HealAllowed(ctx, log,
		&d.Heals, key, cooldown, now)
	if unverifiable {
		metrics.IncError(d.Name)
		return
	}
	if !proceed {
		return
	}
	if _, err := heal.DeletePod(ctx, d.CS, &d.Heals, key, pod, now); err != nil {
		metrics.IncError(d.Name)
		log.Error(err, "heal pod delete failed",
			"check", checkName, "pod", pod.Namespace+"/"+pod.Name)
		return
	}
	// The pod census the next check reads must not contain the pod
	// this delete just removed — drop the pod snapshot so it
	// re-lists. The other censuses (nodes/slices/services/
	// namespaces) cannot have gone stale from a pod delete, so they
	// keep their memoized reads.
	d.InvalidatePods(ctx)
	metrics.ControlPlanePodHealsTotal.WithLabelValues(checkName).Inc()
	log.Info("DELETE: pod heal — forcing pod restart",
		"check", checkName, "pod", pod.Namespace+"/"+pod.Name)
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
// {"metadata":{"annotations":{k:v|null}}} merge patch to the LISTED
// copy of obj — the serial sweep sees no apiserver echo, so without
// the mirror a second annotation write this sweep would compute its
// patch from the pre-write state (several reason-keys share one
// object's annotation map, so a stale read can resurrect a cleared
// key or drop a just-stamped one). Malformed payloads are ignored —
// the input is always kube.MergePatchAnnos output.
func MergeAnnoPatchLocally(obj metav1.Object, data []byte) {
	var doc struct {
		Metadata struct {
			Annotations map[string]*string `json:"annotations"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return
	}
	annos := obj.GetAnnotations()
	if annos == nil {
		annos = map[string]string{}
	}
	for k, v := range doc.Metadata.Annotations {
		if v == nil {
			delete(annos, k)
			continue
		}
		annos[k] = *v
	}
	obj.SetAnnotations(annos)
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
