// keda_scaledobject_guard.go — the keda-scaledobject-guard check:
// ScaledObjects reporting Ready=False or Active=Unknown past the
// persistence window, plus the cold-start rescue that scales a
// wedged-at-zero target back to max(minReplicaCount, 1) — unless the
// downscaler owns that zero.
package gitops

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// kedaScaledObjectGuardCheck is the KEDA ScaledObject watchdog with
// the zero-replica rescue.
type kedaScaledObjectGuardCheck struct {
	*probefw.Deps

	// seen tracks each unhealthy ScaledObject's first-seen sweep —
	// the 15m persistence window; pruned on recovery so a later
	// failure re-arms instead of instantly re-firing. The window
	// gates the zero-target rescue (a workload scale mutation), so
	// it runs the annotation-backed variant — stamped on the
	// ScaledObject under kube.AnnoFirstSeenKedaScaledObject.
	seen state.FirstSeenLedger
	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1 (zero value usable; the serial sweep needs no lock).
	emitted state.GaugeLedger[string]
}

// NewKedaScaledObjectGuardCheck builds the keda guard — its state is
// the seen/emitted ledgers; rescue cooldowns ride the shared
// Deps.Heals set.
func NewKedaScaledObjectGuardCheck(d *probefw.Deps) probefw.Check {
	return &kedaScaledObjectGuardCheck{Deps: d}
}

const (
	CheckNameKedaScaledObjectGuard = "keda-scaledobject-guard"

	// keda-scaledobject-guard knobs.
	kedaUnhealthyMinAge = 15 * time.Minute
	kedaRescueCooldown  = 30 * time.Minute
)

var (
	// ScaledObjects unhealthy past the persistence window.
	kedaScaledObjectUnhealthyGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_keda_scaledobject_unhealthy",
		Help: "1 while the KEDA ScaledObject reports Ready=False or Active=Unknown past the window.",
	}, []string{"namespace", "name", "reason"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		kedaScaledObjectUnhealthyGauge)
}

// checkKedaScaledObjectGuard audits keda.sh ScaledObjects: Ready=False
// or Active=Unknown persisting >=15m means the scaler loop cannot
// reconcile the target (missing scaler auth, broken trigger, target
// lookup failure) — reported per reason on the gauge. Past the same
// window a target wedged at spec.replicas==0 is the cold-start
// deadlock (KEDA scales 0->N only when it can evaluate triggers, and
// a broken scaler never wakes the workload): the target is patched
// back to max(minReplicaCount, 1), 30m cooldown, maintenance-gated —
// SKIPPED when kube.IsIntentionallyDownscaled proves the zero is the
// go-kube-downscaler's doing, not a wedge.
func (p *kedaScaledObjectGuardCheck) Run(ctx context.Context) probefw.Result {
	// The ScaledObject scan needs dyn — a missing client is a wiring
	// bug, not "no signal" (same posture as the scylla check).
	if r := p.RequireDyn("keda scaledobject guard"); r != nil {
		return *r
	}
	log := logf.FromContext(ctx)
	now := p.Now()
	sos, err := p.AllUnstructured(ctx, kube.GVRKedaScaledObject)
	switch {
	case kube.IsCRDAbsent(err):
		// KEDA absent — still reconcile the ledgers: a tuple/seen
		// entry held from when KEDA existed is resolved, and
		// returning Pass early leaks the series pinned at 1. (The
		// Infra path below deliberately skips the reconcile — an
		// unevaluated sweep carries last state, per Carry.)
		var rep probefw.SweepReport
		p.seen.Prune(func(string) bool { return false })
		return rep.Result(&p.emitted, kedaScaledObjectUnhealthyGauge.DeleteLabelValues,
			fmt.Sprintf("scaledobjects unhealthy >=%s: ", kedaUnhealthyMinAge), ", ")
	case err != nil:
		return probefw.Result{Infra: fmt.Errorf("list scaledobjects: %w", err)}
	}

	var rep probefw.SweepReport
	seenKeep := map[string]bool{}
	var unhealthy []*unstructured.Unstructured
	for i := range sos {
		so := &sos[i]
		key := so.GetNamespace() + "/" + so.GetName()
		// annoPatch delivers this ScaledObject's first-seen merge
		// patch — the durable half of the window below: the window
		// gates the zero-target rescue (a workload scale mutation),
		// so the stamp lives on the ScaledObject for a restarted
		// operator to resume rather than re-arming a signature that
		// already held.
		annoPatch := func(ctx context.Context, data []byte) error {
			_, err := p.Dyn.Resource(kube.GVRKedaScaledObject).
				Namespace(so.GetNamespace()).Patch(ctx, so.GetName(),
				types.MergePatchType, data, metav1.PatchOptions{})
			if err == nil {
				kube.RecordAnnoPatch(ctx, so, data)
			}
			return err
		}
		var reasons []string
		if c, ok := kube.ConditionOf(so.Object, "Ready"); ok && c.Status == "False" {
			reasons = append(reasons, "ready_false")
		}
		if c, ok := kube.ConditionOf(so.Object, "Active"); ok && c.Status == "Unknown" {
			reasons = append(reasons, "active_unknown")
		}
		if len(reasons) == 0 {
			// Resolved — the ScaledObject evaluated healthy, so the
			// stamp must leave BOTH clocks (a lingering annotation
			// would fast-trip the next failure's window). No-op when
			// never stamped; a failed clear is Warn'd inside and
			// tolerated — the ledger Forget already landed.
			_ = heal.ClearPersistedFirstSeen(ctx, logr.Discard(), &p.seen,
				so, kube.AnnoFirstSeenKedaScaledObject, key, annoPatch)
			continue
		}
		seenKeep[key] = true
		// Quiet site: first-seen tracking needs no log line. The
		// annotation-backed variant — the stamp on the ScaledObject
		// lets a restarted operator honor a window it never saw
		// in RAM.
		if !heal.FirstSeenPersisted(ctx, logr.Discard(), &p.seen, so,
			kube.AnnoFirstSeenKedaScaledObject, key,
			kedaUnhealthyMinAge, now, annoPatch) {
			continue
		}
		for _, reason := range reasons {
			rep.Flag(kedaScaledObjectUnhealthyGauge, key+"/"+reason,
				[]string{so.GetNamespace(), so.GetName(), reason})
		}
		rep.Find(key + "(" + strings.Join(reasons, ",") + ")")
		unhealthy = append(unhealthy, so)
	}
	p.seen.Prune(func(k string) bool { return seenKeep[k] })

	// Cap to at most ONE budgeted cold-start rescue per sweep (matching
	// hpa-scaling-guard) so a fleet-wide KEDA signature cannot drain
	// the entire heal budget in one pass; refunded grants keep trying.
	grantSpent := false
	for _, so := range unhealthy {
		if grantSpent {
			log.Info("SKIP: heal budget already spent this sweep — cold-start rescues deferred",
				"scaledobject", so.GetNamespace()+"/"+so.GetName())
			continue
		}
		if p.rescueZeroTarget(ctx, log, so, now) {
			grantSpent = true
		}
	}
	return rep.Result(&p.emitted, kedaScaledObjectUnhealthyGauge.DeleteLabelValues,
		fmt.Sprintf("scaledobjects unhealthy >=%s: ", kedaUnhealthyMinAge), ", ")
}

// rescueZeroTarget lifts a wedged-at-zero scale target back to
// max(minReplicaCount, 1). Deployment/StatefulSet targets resolve
// through the typed censuses; argoproj.io Rollout targets ride the
// unstructured census + dynamic patch (argo-rollout-gates) — the apiext kinds
// KEDA can scale beyond those carry no typed handle here. Resolution
// honors spec.scaleTargetRef.kind — only the declared kind is
// consulted, so a StatefulSet whose name collides with a Deployment
// never patches the namesake; an unknown/missing kind falls back to
// the census order, logged. A target
// the downscaler parked (any downscaler/* annotation on a 0-replica
// spec) is skipped: that zero
// is intent, and un-parking it fights the downscaler's own schedule.
func (p *kedaScaledObjectGuardCheck) rescueZeroTarget(ctx context.Context,
	log logr.Logger, so *unstructured.Unstructured, now time.Time) bool {

	ns := so.GetNamespace()
	target, ok := kube.NestedString(so.Object, "spec", "scaleTargetRef", "name")
	if !ok || target == "" {
		return false
	}
	minReplicas, _ := kube.NestedInt64(so.Object, "spec", "minReplicaCount")
	rescue := max(int32(minReplicas), 1)
	declared, _ := kube.NestedString(so.Object, "spec", "scaleTargetRef", "kind")
	return rescueZeroScaleTarget(ctx, p.Deps, log, zeroTargetRescueOpts{
		checkName:    CheckNameKedaScaledObjectGuard,
		sourceLabel:  "keda",
		ns:           ns,
		declaredKind: declared,
		targetName:   target,
		rescue:       rescue,
		allowRollout: true,
		cooldownKey:  ns + "/{kind}/" + target,
		cooldown:     kedaRescueCooldown,
	}, now)
}
