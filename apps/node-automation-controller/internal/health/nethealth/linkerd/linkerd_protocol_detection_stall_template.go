// linkerd_protocol_detection_stall_template.go — the
// workload-template patch of the linkerd-protocol-detection-stall
// check (linkerd-protocol-detection-stall/template-patch-stamp): resolve the pod's controller owner to its
// Deployment/StatefulSet/DaemonSet/Job/CronJob and merge the missing
// ports into the pod template — carrying the durable patch stamp and
// the GitOps-drift guard that refuses the re-patch fight when
// Flux/ArgoCD provably reverted it.
package linkerd

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// linkerdGitOpsMarkers are the ownership stamps the GitOps
// controllers leave on applied workloads — flux kustomize/helm
// controller labels and the ArgoCD tracking annotation (checked on
// BOTH annotations and labels: helm-controller stamps labels, ArgoCD
// stamps the annotation). A workload carrying one is owned-by-Git —
// out-of-band template edits race its force/selfHeal reconcile.
var linkerdGitOpsMarkers = []string{
	"kustomize.toolkit.fluxcd.io/name",
	"helm.toolkit.fluxcd.io/name",
	"argocd.argoproj.io/tracking-id",
}

// template-patch-stamp — a GitOps-owned workload whose template keeps losing
// the opaque-ports annotation the check already patched: Flux/
// ArgoCD selfHeal is reverting it, and re-patching is a rollout
// fight the controller must refuse to join.
var linkerdGitOpsOpaqueDriftGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_linkerd_gitops_opaque_drift",
	Help: "1 while a GitOps-managed workload's pod template lost opaque-ports again inside the patch stamp window — fix the annotation in Git, the controller stops re-patching (template-patch-stamp).",
}, []string{"namespace", "kind", "name"})

func init() {
	ctrlmetrics.Registry.MustRegister(linkerdGitOpsOpaqueDriftGauge)
}

// linkerdGitOpsManaged reports whether the workload is owned by a
// Flux Kustomization, a Flux HelmRelease, or an ArgoCD Application —
// the three GitOps provenances that reconcile template drift back
// to the Git manifest (selfHeal / force).
func linkerdGitOpsManaged(obj metav1.Object) bool {
	annos, lbls := obj.GetAnnotations(), obj.GetLabels()
	for _, k := range linkerdGitOpsMarkers {
		if annos[k] != "" || lbls[k] != "" {
			return true
		}
	}
	return false
}

// linkerdTemplateTarget is one sweep's resolved patch target: the
// owning workload object (drift/stamp reads + patch destination),
// its kind label, ns/name and the template's effective annotations.
// cronJob marks the JobTemplate-nested patch shape.
type linkerdTemplateTarget struct {
	obj      metav1.Object
	kind     string
	ns, name string
	existing map[string]string
	cronJob  bool
}

// templateMissingPorts returns the subset of missing still absent
// from the template's effective annotations — opaque-ports plus the
// skip-inbound/skip-outbound spellings all count as coverage.
func templateMissingPorts(existing map[string]string, missing []int) []int {
	covers := parsePortSet(existing[linkerdOpaquePortsAnno])
	for pt := range parsePortSet(existing[linkerdSkipInboundAnno]) {
		covers[pt] = true
	}
	for pt := range parsePortSet(existing[linkerdSkipOutboundAnno]) {
		covers[pt] = true
	}
	var still []int
	for _, pt := range missing {
		if !covers[pt] {
			still = append(still, pt)
		}
	}
	return still
}

// linkerdTemplateDriftProbe is the READ-ONLY GitOps-drift half of the
// heal, run BEFORE the cooldown/maintenance/budget gates: a Flux/
// ArgoCD revert of our template patch is detection evidence, not a
// heal decision — gating it let a stamped controller key, a held
// maintenance mutex or an exhausted heal budget skip the evaluation
// entirely, and driftNow's reconcile then DeleteLabelValues'd a
// still-live node_automation_linkerd_gitops_opaque_drift series.
// The write path re-derives the same verdict inside
// patchTemplatePorts — emitting the tuple twice in one sweep is
// idempotent (same key, same labels, gauge stays 1) — so the caller
// early-exits on drifted=true instead of letting the write path
// re-detect and re-Find the same tuple a second time.
//
// drifted reports "this pod's workload is GitOps-reverting our
// template patch right now": the caller must stop — no gate, no
// patch, no pod kill — because the refusal IS the verdict and
// re-deriving it downstream would only duplicate the finding.
func (p *linkerdProtocolDetectionStallCheck) linkerdTemplateDriftProbe(ctx context.Context,
	log logr.Logger, pod *corev1.Pod, missing []int, now time.Time,
	rep *probefw.SweepReport, driftNow map[string][]string) bool {

	target, ok := p.resolveLinkerdTemplate(ctx, log, pod, missing)
	if !ok || len(templateMissingPorts(target.existing, missing)) == 0 {
		return false
	}
	stamped, ok := kube.AnnoTimeCtx(ctx, target.obj, kube.AnnoLastLinkerdOpaquePatch)
	if !ok || now.Sub(stamped) >= linkerdOpaquePatchCool ||
		!linkerdGitOpsManaged(target.obj) {
		return false
	}
	lv := []string{target.ns, target.kind, target.name}
	linkerdGitOpsOpaqueDriftGauge.WithLabelValues(lv...).Set(1)
	driftNow[target.ns+"/"+target.kind+"/"+target.name] = lv
	rep.Find(fmt.Sprintf("%s/%s %s opaque-ports reverted by GitOps — "+
		"last patch %s ago, not re-patching",
		target.ns, target.name, target.kind,
		now.Sub(stamped).Round(time.Minute)))
	log.Info("GITOPS-DRIFT: workload template lost opaque-ports after our patch — "+
		"Flux/ArgoCD selfHeal owns it, refusing the revert fight",
		"kind", target.kind, "workload", target.ns+"/"+target.name,
		"lastPatch", stamped)
	return true
}

// patchLinkerdTemplate resolves the pod's controller owner to
// its workload and merges the missing ports into the pod-template
// opaque-ports annotation. Returns covered=true when the template now
// covers the ports (patched now, or already covered — the pod just
// needs a restart) and patched=true only when THIS call landed the
// template patch — the caller lets the workload controller run the
// rolling update instead of deleting pods itself in that case.
// covered=false means no workload owner resolves or the patch fails
// (RBAC/not-found) — the caller must not delete the pod then. drift
// reports the GitOps-revert refusal specifically: the caller treats
// it as "keep evaluating, never cool down" (the read-only probe
// already emitted the drift tuple before the gates).
func (p *linkerdProtocolDetectionStallCheck) patchLinkerdTemplate(ctx context.Context,
	log logr.Logger, pod *corev1.Pod, missing []int, now time.Time,
	rep *probefw.SweepReport, driftNow map[string][]string) (covered, patched, drift bool) {

	target, ok := p.resolveLinkerdTemplate(ctx, log, pod, missing)
	if !ok {
		return false, false, false
	}
	return p.patchTemplatePorts(ctx, log, target, missing, now, rep, driftNow)
}

// patchTemplatePorts merge-patches the opaque-ports annotation
// into a workload's pod template. obj is the workload itself (the
// drift/cooldown reads — GitOps provenance and the durable patch
// stamp — live on ITS metadata, not the template's). existing is the
// template's current annotations — when they already cover `missing`
// the patch is skipped but the template is still reported covered
// (patched=false — the pod only needs a restart). Returns
// covered=false on patch failure or when the durable stamp says the
// template was patched inside linkerdOpaquePatchCool and already
// reverted — re-patching inside the window is a fight with whoever
// reverted it. drift=true ONLY on the GitOps-managed revert refusal —
// the caller treats it as "keep evaluating, never cool down".
func (p *linkerdProtocolDetectionStallCheck) patchTemplatePorts(ctx context.Context,
	log logr.Logger, target *linkerdTemplateTarget, missing []int,
	now time.Time, rep *probefw.SweepReport, driftNow map[string][]string,
) (covered, patched, drift bool) {

	obj, kind, ns, name := target.obj, target.kind, target.ns, target.name
	existing, cronJob := target.existing, target.cronJob

	covers := parsePortSet(existing[linkerdOpaquePortsAnno])
	for pt := range parsePortSet(existing[linkerdSkipInboundAnno]) {
		covers[pt] = true
	}
	for pt := range parsePortSet(existing[linkerdSkipOutboundAnno]) {
		covers[pt] = true
	}
	stillMissing := map[int]bool{}
	for _, pt := range missing {
		if !covers[pt] {
			stillMissing[pt] = true
		}
	}
	if len(stillMissing) == 0 {
		log.Info("linkerd heal: template already covers ports — pod restart suffices",
			"kind", kind, "workload", ns+"/"+name)
		return true, false, false
	}
	// template-patch-stamp durable stamp: a workload we already patched that lost
	// opaque-ports again inside the window was reverted by its owner.
	// GitOps-owned (Flux kustomize/helm labels, ArgoCD tracking-id)
	// means force/selfHeal is doing the revert — do NOT re-patch (the
	// 30m patch→revert→re-roll fight is the incident class); emit the
	// drift gauge + finding so the fix goes to Git. Unmanaged
	// workloads still honor the window silently.
	if stamped, ok := kube.AnnoTimeCtx(ctx, obj, kube.AnnoLastLinkerdOpaquePatch); ok &&
		now.Sub(stamped) < linkerdOpaquePatchCool {
		if linkerdGitOpsManaged(obj) {
			lv := []string{ns, kind, name}
			linkerdGitOpsOpaqueDriftGauge.WithLabelValues(lv...).Set(1)
			driftNow[ns+"/"+kind+"/"+name] = lv
			rep.Find(fmt.Sprintf("%s/%s %s opaque-ports reverted by GitOps — "+
				"last patch %s ago, not re-patching",
				ns, name, kind, now.Sub(stamped).Round(time.Minute)))
			log.Info("GITOPS-DRIFT: workload template lost opaque-ports after our patch — "+
				"Flux/ArgoCD selfHeal owns it, refusing the revert fight",
				"kind", kind, "workload", ns+"/"+name,
				"lastPatch", stamped)
			return false, false, true
		}
		// Not GitOps-owned: honor the window silently AND drop
		// any drift series this workload emitted earlier — a
		// workload whose GitOps marker was removed between
		// sweeps must not keep a stale drift=1 live.
		linkerdGitOpsOpaqueDriftGauge.DeleteLabelValues(ns, kind, name)
		log.Info("linkerd heal: template reverted inside patch cooldown — not re-patching",
			"kind", kind, "workload", ns+"/"+name, "lastPatch", stamped)
		return false, false, false
	}
	for pt := range stillMissing {
		covers[pt] = true
	}
	value := portSetString(covers)
	var payload []byte
	var err error
	anno := map[string]string{linkerdOpaquePortsAnno: value}
	// The patch stamp lands on the workload's OWN metadata in the
	// same merge — the template annotation is the heal, the stamp is
	// the durable "we touched this at T" the drift/cooldown reads
	// back next sweep.
	stamp := map[string]string{
		kube.AnnoLastLinkerdOpaquePatch: now.UTC().Format(time.RFC3339),
	}
	if cronJob {
		payload, err = json.Marshal(map[string]any{
			"metadata": map[string]any{"annotations": stamp},
			"spec": map[string]any{
				"jobTemplate": map[string]any{
					"spec": map[string]any{
						"template": map[string]any{
							"metadata": map[string]any{"annotations": anno},
						},
					},
				},
			},
		})
	} else {
		payload, err = json.Marshal(map[string]any{
			"metadata": map[string]any{"annotations": stamp},
			"spec": map[string]any{
				"template": map[string]any{
					"metadata": map[string]any{"annotations": anno},
				},
			},
		})
	}
	if err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "linkerd heal: marshal template patch failed",
			"kind", kind, "workload", ns+"/"+name)
		return false, false, false
	}
	var patchErr error
	switch kind {
	case "deployment":
		_, patchErr = p.CS.AppsV1().Deployments(ns).Patch(ctx, name,
			types.MergePatchType, payload, metav1.PatchOptions{})
	case "statefulset":
		_, patchErr = p.CS.AppsV1().StatefulSets(ns).Patch(ctx, name,
			types.MergePatchType, payload, metav1.PatchOptions{})
	case "daemonset":
		_, patchErr = p.CS.AppsV1().DaemonSets(ns).Patch(ctx, name,
			types.MergePatchType, payload, metav1.PatchOptions{})
	case "job":
		_, patchErr = p.CS.BatchV1().Jobs(ns).Patch(ctx, name,
			types.MergePatchType, payload, metav1.PatchOptions{})
	case "cronjob":
		_, patchErr = p.CS.BatchV1().CronJobs(ns).Patch(ctx, name,
			types.MergePatchType, payload, metav1.PatchOptions{})
	case "rollout":
		// rollout-scale-flap — unstructured argoproj.io/v1alpha1 Rollout: the
		// same merge-patch body through the dynamic client.
		_, patchErr = p.Dyn.Resource(kube.GVRArgoRollout).Namespace(ns).
			Patch(ctx, name, types.MergePatchType, payload, metav1.PatchOptions{})
	}
	if patchErr != nil {
		// Forbidden until the RBAC rollout lands patch on pods /
		// daemonsets / jobs — log and fail closed (no pod delete).
		log.Info("WARN: linkerd heal — template patch failed",
			"kind", kind, "workload", ns+"/"+name, "error", patchErr)
		return false, false, false
	}
	// Mirror the landed patch into the snapshot's in-memory workload
	// copy — the serial sweep sees no apiserver echo, so a second
	// stalled pod of the same workload must read the template
	// annotation (and the patch stamp) this call just wrote instead
	// of re-deriving the write from the stale pre-patch copy and
	// re-patching. mergeTemplateAnnos also allocates a missing
	// template-annotation map through the concrete workload: the
	// caller's `existing` binding cannot write nil back.
	probefw.MergeAnnoPatchLocally(ctx, obj, payload)
	// The template-annotation mirror rides the sweep overlay when
	// one is installed — the census object stays read-only and a
	// sibling check's EffectiveTemplateAnnos read resolves the
	// landed patch. Outside a sweep (direct GET, caller-private
	// object) RecordTemplateAnnos declines and the legacy in-place
	// mirror keeps same-run re-reads honest.
	if !kube.RecordTemplateAnnos(ctx, obj, anno) {
		mergeTemplateAnnos(obj, anno)
	}
	log.Info("PATCH: linkerd opaque-ports added to workload template",
		"kind", kind, "workload", ns+"/"+name, "ports", value)
	return true, true, false
}

// mergeTemplateAnnos writes anno into obj's pod-template annotation
// map in memory — the snapshot censuses alias these structs, so this
// is the apiserver echo the serial sweep never gets. Job/CronJob
// templates nest under jobTemplate; the unstructured Rollout goes
// through SetNestedMap (replacing the whole map is safe — it only
// runs when the template carried no annotations at all, the case the
// in-place update through `existing` cannot express).
func mergeTemplateAnnos(obj metav1.Object, anno map[string]string) {
	set := func(meta *metav1.ObjectMeta) {
		// Clone before merge: meta.Annotations may alias a shared
		// census object's map — writing into it in place corrupts
		// every other reader of the snapshot.
		merged := make(map[string]string, len(meta.Annotations)+len(anno))
		for k, v := range meta.Annotations {
			merged[k] = v
		}
		for k, v := range anno {
			merged[k] = v
		}
		meta.Annotations = merged
	}
	switch w := obj.(type) {
	case *appsv1.Deployment:
		set(&w.Spec.Template.ObjectMeta)
	case *appsv1.StatefulSet:
		set(&w.Spec.Template.ObjectMeta)
	case *appsv1.DaemonSet:
		set(&w.Spec.Template.ObjectMeta)
	case *batchv1.Job:
		set(&w.Spec.Template.ObjectMeta)
	case *batchv1.CronJob:
		set(&w.Spec.JobTemplate.Spec.Template.ObjectMeta)
	case *unstructured.Unstructured:
		var existing map[string]string
		if raw, _ := kube.NestedStringMap(w.Object,
			"spec", "template", "metadata", "annotations"); raw != nil {
			existing = make(map[string]string, len(raw)+len(anno))
			for k, v := range raw {
				existing[k] = v
			}
		} else {
			existing = map[string]string{}
		}
		for k, v := range anno {
			existing[k] = v
		}
		_ = unstructured.SetNestedStringMap(w.Object, existing,
			"spec", "template", "metadata", "annotations")
	}
}
