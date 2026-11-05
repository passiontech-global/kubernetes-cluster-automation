// helpers.go — shared helpers for the self-healing probe checks:
//
//   - DeletePodHeal: the shared pod-delete heal shape — per-target
//     cooldown on the Deps Heals ledger, maintenance mutex (fail
//     closed), UID-preconditioned delete.
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
// shared.FirstSeenLedger / shared.GaugeLedger[string] fields (the
// zero values are usable — the serial sweep needs no locking).
package probefw

import (
	"context"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
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
		shared.Getenv("HEALTH_PROMETHEUS_QUERY_URL", ""), d.Cfg.HTTPContent.URL)
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

// DeletePodHeal is the pod-delete heal shape the self-healing checks
// share: per-target cooldown on the shared heals ledger, the
// maintenance mutex (fail closed on unverifiable), a
// UID-preconditioned delete, and the shared ControlPlanePodHealsTotal
// counter under the check name.
func (d *Deps) DeletePodHeal(ctx context.Context, log logr.Logger,
	checkName, targetKey string, pod *corev1.Pod,
	cooldown time.Duration, now time.Time) {

	key := "selfheal/" + checkName + "/" + targetKey
	if d.Heals.CooledDown(key, cooldown, now) {
		log.Info("skip heal: inside cooldown", "check", checkName,
			"target", targetKey)
		return
	}
	held, why, err := shared.MaintenanceActive(ctx, d.CS, d.Dyn)
	if err != nil {
		metrics.IncError(d.Name)
		log.Info("WARN: maintenance check unverifiable — heal deferred (fail closed)",
			"check", checkName, "target", targetKey, "error", err)
		return
	}
	if held {
		log.Info("maintenance in progress — heal deferred",
			"check", checkName, "target", targetKey, "why", why)
		return
	}
	uid := pod.UID
	if err := d.CS.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
		metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid},
		}); err != nil {
		metrics.IncError(d.Name)
		log.Error(err, "heal pod delete failed",
			"check", checkName, "pod", pod.Namespace+"/"+pod.Name)
		return
	}
	d.Heals.Stamp(key, now)
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
