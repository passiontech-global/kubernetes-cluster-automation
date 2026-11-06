// helpers.go — shared helpers for the self-healing probe checks:
//
//   - DeletePodHeal / SelfHealKey: the shared pod-delete heal shape —
//     per-target cooldown on the Deps Heals ledger, maintenance mutex
//     (fail closed), UID-preconditioned delete — and the
//     "selfheal/<check>/<target>" ledger key it stamps. Thin wrapper
//     over the platform heal package this file was the reference for.
//   - RequireDyn: the "no dynamic client" preamble every CR-scanning
//     check opens with.
//   - PodUnreadySince / PodFromList: pod readiness helpers.
//   - PromEndpoint / PromQuery: the Prometheus instant-query seam
//     every metrics-backed check shares, backed by internal/promq.
//   - LinkerdPodMatchesComponent plus the LinkerdNS /
//     LinkerdDestinationName / LinkerdIdentityName control-plane
//     identifiers the mesh watchdog and the endpoint-sync check both
//     match linkerd pods against.
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
	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// The linkerd control-plane identifiers two domain checks both key
// on: the mesh-controlplane watchdog (watchdogs) bounces wedged pods
// in this namespace, and the linkerd-endpoint-sync check (nethealth)
// picks its heal target the same way.
const (
	LinkerdNS              = "linkerd"
	LinkerdDestinationName = "linkerd-destination"
	LinkerdIdentityName    = "linkerd-identity"
)

// DragonflyOperatorNS is the dragonfly operator's namespace: the
// operator-workqueue watchdog (watchdogs) reads its leader Lease there
// and the stateful-masterless check (datastore) bounces operator pods
// in it.
const DragonflyOperatorNS = "dragonfly-operator-system"

// PromEndpoint resolves the Prometheus /api/v1/query URL for this
// call: HEALTH_PROMETHEUS_QUERY_URL (a full query URL) wins, else the
// endpoint is derived from the http-content-check target's
// scheme://host — the same Prometheus that check health-probes. The
// env var is re-read per call (tests Setenv mid-test).
func (d *Deps) PromEndpoint() (string, error) {
	return promq.ResolveEndpoint(
		envx.Getenv("HEALTH_PROMETHEUS_QUERY_URL", ""), d.Cfg.HTTPContent.URL)
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
	proceed, unverifiable := heal.AllowedV(ctx, log, &d.verdict,
		d.CS, d.Dyn, &d.Heals, key, cooldown, now)
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
