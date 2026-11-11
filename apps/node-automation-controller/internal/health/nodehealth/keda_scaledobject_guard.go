// keda_scaledobject_guard.go — the keda-scaledobject-guard check:
// ScaledObjects reporting Ready=False or Active=Unknown past the
// persistence window, plus the cold-start rescue that scales a
// wedged-at-zero target back to max(minReplicaCount, 1) — unless the
// downscaler owns that zero.
package nodehealth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
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
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
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
		p.rescueZeroTarget(ctx, log, so, now)
	}
	p.seen.Prune(func(k string) bool { return seenKeep[k] })
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
	log logr.Logger, so *unstructured.Unstructured, now time.Time) {

	ns := so.GetNamespace()
	target, ok := kube.NestedString(so.Object, "spec", "scaleTargetRef", "name")
	if !ok || target == "" {
		return
	}
	minReplicas, _ := kube.NestedInt64(so.Object, "spec", "minReplicaCount")
	rescue := minReplicas
	if rescue < 1 {
		rescue = 1
	}

	// scaleTargetRef.kind names the workload kind KEDA scales — a
	// ScaledObject targeting a StatefulSet whose name collides with a
	// same-namespace Deployment must patch the StatefulSet, not the
	// namesake. Resolve ONLY the declared kind; an unknown or missing
	// kind keeps the old census order (Deployment → StatefulSet →
	// Rollout) as a logged fallback — a guess, not an attribution. A
	// census read failure stays inconclusive, not "not at zero".
	declared, declaredOK := kube.NestedString(
		so.Object, "spec", "scaleTargetRef", "kind")
	want := ""
	if declaredOK {
		// EqualFold — a lowercase spelling ("deployment") must not
		// fall into the census-order fallback and patch the wrong
		// kind's namesake; canonical casing is kept so the want ==
		// checks below stay literal.
		switch {
		case strings.EqualFold(declared, "Deployment"):
			want = "Deployment"
		case strings.EqualFold(declared, "StatefulSet"):
			want = "StatefulSet"
		case strings.EqualFold(declared, "Rollout"):
			want = "Rollout"
		}
	}
	if want == "" {
		log.Info("WARN: keda zero-rescue — scaleTargetRef.kind unknown/missing, target resolution falls back to census order",
			"scaledobject", ns+"/"+so.GetName(), "kind", declared)
	}
	var annotations map[string]string
	var replicas *int32
	var rv string
	kind := ""
	if want == "" || want == "Deployment" {
		deps, err := p.AllDeployments(ctx)
		if err != nil {
			return // census unreadable — inconclusive, retry next sweep
		}
		for i := range deps {
			if deps[i].Namespace == ns && deps[i].Name == target {
				kind = "Deployment"
				annotations = deps[i].Annotations
				replicas = deps[i].Spec.Replicas
				rv = deps[i].ResourceVersion
				break
			}
		}
	}
	if kind == "" && (want == "" || want == "StatefulSet") {
		stss, serr := p.AllStatefulSets(ctx)
		if serr != nil {
			return // census unreadable — inconclusive
		}
		for i := range stss {
			if stss[i].Namespace == ns && stss[i].Name == target {
				kind = "StatefulSet"
				annotations = stss[i].Annotations
				replicas = stss[i].Spec.Replicas
				rv = stss[i].ResourceVersion
				break
			}
		}
	}
	if kind == "" && (want == "" || want == "Rollout") {
		// argo-rollout-gates — argoproj.io Rollout fallback: KEDA scales Rollouts
		// the same way (scaleTargetRef kind Rollout). Unstructured CR
		// — spec.replicas comes off the census object; a failed
		// census stays inconclusive, not "not at zero".
		ros, rerr := p.AllUnstructured(ctx, kube.GVRArgoRollout)
		if rerr != nil {
			return // census unreadable — inconclusive
		}
		for i := range ros {
			r := &ros[i]
			if r.GetNamespace() == ns && r.GetName() == target {
				kind = "Rollout"
				annotations = r.GetAnnotations()
				rv = r.GetResourceVersion()
				if reps, found := kube.NestedInt64(r.Object, "spec", "replicas"); found {
					v := int32(reps)
					replicas = &v
				}
				break
			}
		}
	}
	if kind == "" {
		return // target unresolvable this sweep — inconclusive
	}
	if replicas == nil || *replicas != 0 {
		return // not wedged at zero — nothing to rescue
	}
	if kube.IsIntentionallyDownscaled(annotations, replicas) {
		return // downscaler-managed zero — the workload is asleep on purpose
	}

	ck := probefw.SelfHealKey(CheckNameKedaScaledObjectGuard, ns+"/"+target)
	proceed, unverifiable := p.HealAllowed(ctx, log,
		&p.Heals, ck, kedaRescueCooldown, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return
	}
	if !proceed {
		return
	}
	// metadata.resourceVersion pins the write — a legitimate
	// scale-up (HPA, GitOps, manual) landing between the census
	// read and this patch becomes a 409 conflict instead of a
	// silent revert to the rescue floor.
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"resourceVersion": rv},
		"spec":     map[string]any{"replicas": rescue},
	})
	if err != nil {
		return
	}
	switch kind {
	case "Deployment":
		_, err = p.CS.AppsV1().Deployments(ns).Patch(ctx, target,
			types.MergePatchType, payload, metav1.PatchOptions{})
	case "StatefulSet":
		_, err = p.CS.AppsV1().StatefulSets(ns).Patch(ctx, target,
			types.MergePatchType, payload, metav1.PatchOptions{})
	case "Rollout":
		_, err = p.Dyn.Resource(kube.GVRArgoRollout).Namespace(ns).
			Patch(ctx, target, types.MergePatchType, payload, metav1.PatchOptions{})
	}
	if err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "keda zero-rescue scale patch failed",
			"target", kind+" "+ns+"/"+target, "replicas", rescue)
		return
	}
	p.Heals.Stamp(ck, now)
	log.Info("SCALE: keda cold-start rescue — target wedged at 0 while the scaler is unhealthy",
		"target", kind+" "+ns+"/"+target, "replicas", rescue)
}
