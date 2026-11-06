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
	"sort"
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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// kedaScaledObjectGuardCheck is the KEDA ScaledObject watchdog with
// the zero-replica rescue.
type kedaScaledObjectGuardCheck struct {
	*probefw.Deps

	// seen tracks each unhealthy ScaledObject's first-seen sweep —
	// the 15m persistence window; pruned on recovery so a later
	// failure re-arms instead of instantly re-firing.
	seen state.FirstSeenLedger
	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1 (zero value usable; the serial sweep needs no lock).
	emitted state.GaugeLedger[string]
	// verdict memoizes the maintenance-mutex evaluation the
	// per-target rescue preambles share — one evaluation per
	// Verdict TTL instead of three API reads per wedged ScaledObject.
	verdict kube.Verdict
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
	sos, err := p.Dyn.Resource(kube.GVRKedaScaledObject).List(ctx, metav1.ListOptions{})
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		return probefw.Result{Pass: true} // KEDA absent — nothing to guard
	case err != nil:
		return probefw.Result{Infra: fmt.Errorf("list scaledobjects: %w", err)}
	}

	current := map[string][]string{}
	seenKeep := map[string]bool{}
	var unhealthy []string
	for i := range sos.Items {
		so := &sos.Items[i]
		var reasons []string
		if c, ok := kube.ConditionOf(so.Object, "Ready"); ok && c.Status == "False" {
			reasons = append(reasons, "ready_false")
		}
		if c, ok := kube.ConditionOf(so.Object, "Active"); ok && c.Status == "Unknown" {
			reasons = append(reasons, "active_unknown")
		}
		if len(reasons) == 0 {
			continue
		}
		key := so.GetNamespace() + "/" + so.GetName()
		seenKeep[key] = true
		// Quiet site: first-seen tracking needs no log line.
		if !probefw.Persisted(&p.seen, key, now, kedaUnhealthyMinAge,
			logr.Discard()) {
			continue
		}
		for _, reason := range reasons {
			lv := []string{so.GetNamespace(), so.GetName(), reason}
			current[key+"/"+reason] = lv
			kedaScaledObjectUnhealthyGauge.WithLabelValues(lv...).Set(1)
		}
		unhealthy = append(unhealthy, key+"("+strings.Join(reasons, ",")+")")
		p.rescueZeroTarget(ctx, log, so, now)
	}
	p.seen.Prune(func(k string) bool { return seenKeep[k] })
	p.emitted.Reconcile(current, kedaScaledObjectUnhealthyGauge.DeleteLabelValues)
	if len(unhealthy) == 0 {
		return probefw.Result{Pass: true}
	}
	sort.Strings(unhealthy)
	return probefw.Result{Why: fmt.Sprintf(
		"scaledobjects unhealthy >=%s: %s",
		kedaUnhealthyMinAge, strings.Join(unhealthy, ", "))}
}

// rescueZeroTarget lifts a wedged-at-zero scale target back to
// max(minReplicaCount, 1). Only Deployment/StatefulSet targets are
// handled — the apiext kinds KEDA can scale beyond those carry no
// typed handle here. A target the downscaler parked (any
// downscaler/* annotation on a 0-replica spec) is skipped: that zero
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

	var annotations map[string]string
	var replicas *int32
	kind := ""
	if dep, err := p.CS.AppsV1().Deployments(ns).Get(ctx, target, metav1.GetOptions{}); err == nil {
		kind = "Deployment"
		annotations = dep.Annotations
		replicas = dep.Spec.Replicas
	} else if apierrors.IsNotFound(err) {
		if sts, serr := p.CS.AppsV1().StatefulSets(ns).Get(ctx, target, metav1.GetOptions{}); serr == nil {
			kind = "StatefulSet"
			annotations = sts.Annotations
			replicas = sts.Spec.Replicas
		} else {
			return // target unresolvable this sweep — inconclusive
		}
	} else {
		return // lookup failed — inconclusive, retry next sweep
	}
	if replicas == nil || *replicas != 0 {
		return // not wedged at zero — nothing to rescue
	}
	if kube.IsIntentionallyDownscaled(annotations, replicas) {
		return // downscaler-managed zero — the workload is asleep on purpose
	}

	ck := probefw.SelfHealKey(CheckNameKedaScaledObjectGuard, ns+"/"+target)
	proceed, unverifiable := heal.AllowedV(ctx, log, &p.verdict,
		p.CS, p.Dyn, &p.Heals, ck, kedaRescueCooldown, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return
	}
	if !proceed {
		return
	}
	payload, err := json.Marshal(map[string]any{
		"spec": map[string]any{"replicas": rescue},
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
