// rescue_zero_target.go — shared cold-start zero-replica target rescue
// used by hpa-scaling-guard and keda-scaledobject-guard when an
// unhealthy autoscaler leaves a non-downscaled Deployment, StatefulSet,
// or (for KEDA) argoproj.io Rollout wedged at spec.replicas==0.
package gitops

import (
	"context"
	json "encoding/json/v2"
	"strings"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

type zeroTargetRescueOpts struct {
	checkName    string
	sourceLabel  string // "hpa" or "keda" for log context
	ns           string
	declaredKind string
	targetName   string
	rescue       int32
	allowRollout bool
	cooldownKey  string
	cooldown     time.Duration
}

// rescueZeroScaleTarget lifts a scale target wedged at spec.replicas==0
// back to opts.rescue. Deployment/StatefulSet targets resolve through the
// typed snapshot censuses; Rollout targets (when allowRollout is true)
// ride the unstructured census. Returns true when a heal-budget grant was
// actually consumed and kept (per-sweep rescue cap accounting).
func rescueZeroScaleTarget(ctx context.Context, d *probefw.Deps,
	log logr.Logger, opts zeroTargetRescueOpts, now time.Time) bool {

	if opts.targetName == "" || opts.rescue < 1 {
		return false
	}

	want := ""
	if opts.declaredKind != "" {
		switch {
		case strings.EqualFold(opts.declaredKind, "Deployment"):
			want = "Deployment"
		case strings.EqualFold(opts.declaredKind, "StatefulSet"):
			want = "StatefulSet"
		case opts.allowRollout && strings.EqualFold(opts.declaredKind, "Rollout"):
			want = "Rollout"
		}
	}
	if opts.allowRollout && want == "" {
		log.Info("WARN: "+opts.sourceLabel+" zero-rescue — scaleTargetRef.kind unknown/missing, target resolution falls back to census order",
			"target", opts.ns+"/"+opts.targetName, "kind", opts.declaredKind)
	}

	var annotations map[string]string
	var replicas *int32
	var rv string
	var targetObj metav1.Object
	kind := ""

	if want == "" || want == "Deployment" {
		dep, err := d.Deployment(ctx, opts.ns, opts.targetName)
		if err != nil {
			return false
		}
		if dep != nil {
			kind = "Deployment"
			annotations = kube.EffectiveAnnos(ctx, dep)
			replicas = dep.Spec.Replicas
			rv = dep.ResourceVersion
			targetObj = dep
		}
	}
	if kind == "" && (want == "" || want == "StatefulSet") {
		sts, serr := d.StatefulSet(ctx, opts.ns, opts.targetName)
		if serr != nil {
			return false
		}
		if sts != nil {
			kind = "StatefulSet"
			annotations = kube.EffectiveAnnos(ctx, sts)
			replicas = sts.Spec.Replicas
			rv = sts.ResourceVersion
			targetObj = sts
		}
	}
	if kind == "" && opts.allowRollout && (want == "" || want == "Rollout") {
		r, rerr := d.Unstructured(ctx, kube.GVRArgoRollout, opts.ns, opts.targetName)
		if rerr != nil {
			return false
		}
		if r != nil {
			kind = "Rollout"
			annotations = kube.EffectiveAnnos(ctx, r)
			rv = r.GetResourceVersion()
			targetObj = r
			if reps, found := kube.NestedInt64(r.Object, "spec", "replicas"); found {
				v := int32(reps)
				replicas = &v
			}
		}
	}
	if kind == "" {
		return false
	}
	if replicas == nil || *replicas != 0 {
		return false
	}
	if kube.IsIntentionallyDownscaled(annotations, replicas) {
		return false
	}

	// Build concrete cooldown key once kind is known when template uses {kind}.
	cooldownTarget := strings.ReplaceAll(opts.cooldownKey, "{kind}", kind)
	ck := probefw.SelfHealKey(opts.checkName, cooldownTarget)
	proceed, unverifiable := d.HealAllowed(ctx, log,
		&d.Heals, ck, opts.cooldown, now)
	if unverifiable {
		metrics.IncError(d.Name)
		return false
	}
	if !proceed {
		return false
	}

	gateTarget := opts.checkName + ":" + opts.ns + "/" + kind + "/" + opts.targetName
	if targetObj != nil && !heal.FluxPatchGate(strings.ToLower(kind), targetObj, gateTarget, now) {
		heal.RefundGrant(now)
		log.Info("SKIP: "+opts.sourceLabel+" cold-start rescue blocked by flux conflict gate",
			"target", kind+" "+opts.ns+"/"+opts.targetName)
		return false
	}

	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"resourceVersion": rv},
		"spec":     map[string]any{"replicas": opts.rescue},
	})
	if err != nil {
		heal.RefundGrant(now)
		return false
	}

	var patchErr error
	switch kind {
	case "Deployment":
		_, patchErr = d.CS.AppsV1().Deployments(opts.ns).Patch(ctx, opts.targetName,
			types.MergePatchType, payload, metav1.PatchOptions{})
	case "StatefulSet":
		_, patchErr = d.CS.AppsV1().StatefulSets(opts.ns).Patch(ctx, opts.targetName,
			types.MergePatchType, payload, metav1.PatchOptions{})
	case "Rollout":
		_, patchErr = d.Dyn.Resource(kube.GVRArgoRollout).Namespace(opts.ns).
			Patch(ctx, opts.targetName, types.MergePatchType, payload, metav1.PatchOptions{})
	}
	if patchErr != nil {
		if apierrors.IsConflict(patchErr) || apierrors.IsNotFound(patchErr) {
			heal.RefundGrant(now)
			log.Info("SKIP: "+opts.sourceLabel+" cold-start rescue raced (target changed or gone)",
				"target", kind+" "+opts.ns+"/"+opts.targetName)
			return false
		}
		metrics.IncError(d.Name)
		log.Error(patchErr, opts.sourceLabel+" cold-start rescue scale patch failed",
			"target", kind+" "+opts.ns+"/"+opts.targetName, "replicas", opts.rescue)
		return true
	}

	switch kind {
	case "Deployment":
		d.InvalidateDeployments(ctx)
	case "StatefulSet":
		d.InvalidateStatefulSets(ctx)
	case "Rollout":
		d.InvalidateUnstructuredGVR(ctx, kube.GVRArgoRollout)
	}
	d.Heals.Stamp(ck, now)
	log.Info("SCALE: "+opts.sourceLabel+" cold-start rescue — target wedged at 0 while the scaler is unhealthy",
		"target", kind+" "+opts.ns+"/"+opts.targetName, "replicas", opts.rescue)
	return true
}
