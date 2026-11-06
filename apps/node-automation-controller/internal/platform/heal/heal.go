// heal.go — the three helpers implementing the sequence doc.go
// describes, split at the points call sites differ: Allowed runs
// the preamble (cooldown + mutex), OldestRunningPod is the shared
// "bounce the operator" target pick, and DeletePod is the delete +
// stamp actuation. Modules that pick a different target (a leader
// pod, a wedged consumer) simply skip OldestRunningPod.
package heal

import (
	"context"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// Allowed runs the shared preamble every pod-kill heal repeats
// before picking its target: per-key cooldown on the heals ledger,
// then the maintenance mutex (kube.MaintenanceActive — fail closed:
// unverifiable counts as held). Returns proceed=true when the caller
// may proceed to target selection + delete.
//
// The second return distinguishes WHY a defer happened:
// unverifiable=true means the maintenance check itself errored —
// the caller IncErrors its own queue (this package never touches
// metrics, so the signal would otherwise be lost). Cooldown and
// held-mutex defers are normal operation and return (false, false).
// The defer reason is logged here with the heal's key; callers log
// only their own ACTION/defer wording.
//
// A nil heals pointer skips the cooldown check entirely — heals
// that persist their stamp on the object itself (the passiontech.dev/last-*
// annotations read via kube.AnnoTime) pass nil and keep only the
// mutex gate.
func Allowed(ctx context.Context, log logr.Logger,
	cs kubernetes.Interface, dyn dynamic.Interface,
	heals *state.CooldownSet, key string, cooldown time.Duration,
	now time.Time) (proceed bool, unverifiable bool) {
	return AllowedV(ctx, log, &kube.Verdict{}, cs, dyn,
		heals, key, cooldown, now)
}

// AllowedV is Allowed with a shared maintenance verdict — loops that
// run the preamble once per target pass the module's Verdict field
// so the whole sweep pays a single mutex evaluation instead of three
// API reads per pod.
func AllowedV(ctx context.Context, log logr.Logger, v *kube.Verdict,
	cs kubernetes.Interface, dyn dynamic.Interface,
	heals *state.CooldownSet, key string, cooldown time.Duration,
	now time.Time) (proceed bool, unverifiable bool) {

	if heals != nil && heals.CooledDown(key, cooldown, now) {
		log.Info("skip heal: inside cooldown", "target", key)
		return false, false
	}
	held, why, err := v.Active(ctx, cs, dyn, now)
	if err != nil {
		log.Info("WARN: maintenance check unverifiable — "+
			"heal deferred (fail closed)", "target", key, "error", err)
		return false, true
	}
	if held {
		log.Info("maintenance in progress — heal deferred",
			"target", key, "why", why)
		return false, false
	}
	return true, false
}

// DeletePod issues the UID-preconditioned delete the heals share —
// kube.UIDDeleteOptions with no propagation policy (the apiserver
// default, matching every reference implementation: Preconditions{UID}
// only) — and stamps the heals ledger ONLY when the delete is
// delivered: a failed delete leaves the target alive, and stamping
// anyway would let one transient error suppress the heal for the
// whole cooldown window.
//
// Returns (deleted, err): any API failure is (false, err) — the
// caller IncErrors its own queue and logs err in its own wording
// (each module phrases the failure with its own target context).
// A nil heals pointer skips the stamp, mirroring Allowed's
// nil-ledger contract.
func DeletePod(ctx context.Context, cs kubernetes.Interface,
	heals *state.CooldownSet, key string, pod *corev1.Pod,
	now time.Time) (bool, error) {

	if err := cs.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
		kube.UIDDeleteOptions(pod.UID, "")); err != nil {
		return false, err
	}
	if heals != nil {
		heals.Stamp(key, now)
	}
	return true, nil
}

// OldestRunningPod returns the oldest Running, non-terminating pod
// whose name matches any of prefixes as prefix+"-" — the
// cluster-wide operator-pod pick several heals repeat (datastore's
// db-operator bounce, the connect heal). The trailing dash is
// deliberate: operator pods are <deployment>-<rs-hash>-<suffix>, so
// requiring it keeps prefix "pxc-operator" from also swallowing a
// "pxc-operator2-..." pod. Returns nil when nothing qualifies —
// the caller logs "no target" in its own wording. The returned
// pointer aliases the input slice; do not mutate it.
func OldestRunningPod(pods []corev1.Pod, prefixes ...string) *corev1.Pod {
	var oldest *corev1.Pod
	for i := range pods {
		p := &pods[i]
		if p.Status.Phase != corev1.PodRunning || p.DeletionTimestamp != nil {
			continue
		}
		matched := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(p.Name, prefix+"-") {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if oldest == nil || p.CreationTimestamp.Before(&oldest.CreationTimestamp) {
			oldest = p
		}
	}
	return oldest
}
