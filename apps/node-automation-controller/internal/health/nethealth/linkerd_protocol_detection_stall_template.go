// linkerd_protocol_detection_stall_template.go — the
// workload-template patch of the linkerd-protocol-detection-stall
// check (W10-NM3/W12-P0-6): resolve the pod's controller owner to its
// Deployment/StatefulSet/DaemonSet/Job/CronJob and merge the missing
// ports into the pod template — carrying the durable patch stamp and
// the GitOps-drift guard that refuses the re-patch fight when
// Flux/ArgoCD provably reverted it.
package nethealth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
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

// W12-P0-6 — a GitOps-owned workload whose template keeps losing
// the opaque-ports annotation the check already patched: Flux/
// ArgoCD selfHeal is reverting it, and re-patching is a rollout
// fight the controller must refuse to join.
var linkerdGitOpsOpaqueDriftGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_linkerd_gitops_opaque_drift",
	Help: "1 while a GitOps-managed workload's pod template lost opaque-ports again inside the patch stamp window — fix the annotation in Git, the controller stops re-patching (W12-P0-6).",
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

// patchLinkerdTemplate resolves the pod's controller owner to
// its workload and merges the missing ports into the pod-template
// opaque-ports annotation. Returns true when the template now covers
// the ports (patched now, or already covered — the pod just needs a
// restart). False when no workload owner resolves or the patch fails
// (RBAC/not-found) — the caller must not delete the pod then.
func (p *linkerdProtocolDetectionStallCheck) patchLinkerdTemplate(ctx context.Context,
	log logr.Logger, pod *corev1.Pod, missing []int, now time.Time,
	rep *probefw.SweepReport, driftNow map[string][]string) bool {

	ref := metav1.GetControllerOf(pod)
	if ref == nil {
		return false
	}
	ns := pod.Namespace
	switch ref.Kind {
	case "ReplicaSet":
		rs, err := p.CS.AppsV1().ReplicaSets(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			log.Info("WARN: linkerd heal — replicaset get failed",
				"rs", ns+"/"+ref.Name, "error", err)
			return false
		}
		dref := metav1.GetControllerOf(rs)
		if dref == nil || dref.Kind != "Deployment" {
			return false
		}
		dep, err := p.CS.AppsV1().Deployments(ns).Get(ctx, dref.Name, metav1.GetOptions{})
		if err != nil {
			log.Info("WARN: linkerd heal — deployment get failed",
				"deployment", ns+"/"+dref.Name, "error", err)
			return false
		}
		return p.patchTemplatePorts(ctx, log, dep, "deployment", ns, dep.Name,
			dep.Spec.Template.Annotations, missing, false, now, rep, driftNow)
	case "Deployment":
		dep, err := p.CS.AppsV1().Deployments(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			log.Info("WARN: linkerd heal — deployment get failed",
				"deployment", ns+"/"+ref.Name, "error", err)
			return false
		}
		return p.patchTemplatePorts(ctx, log, dep, "deployment", ns, dep.Name,
			dep.Spec.Template.Annotations, missing, false, now, rep, driftNow)
	case "StatefulSet":
		sts, err := p.CS.AppsV1().StatefulSets(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			log.Info("WARN: linkerd heal — statefulset get failed",
				"statefulset", ns+"/"+ref.Name, "error", err)
			return false
		}
		return p.patchTemplatePorts(ctx, log, sts, "statefulset", ns, sts.Name,
			sts.Spec.Template.Annotations, missing, false, now, rep, driftNow)
	case "DaemonSet":
		ds, err := p.CS.AppsV1().DaemonSets(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			log.Info("WARN: linkerd heal — daemonset get failed",
				"daemonset", ns+"/"+ref.Name, "error", err)
			return false
		}
		return p.patchTemplatePorts(ctx, log, ds, "daemonset", ns, ds.Name,
			ds.Spec.Template.Annotations, missing, false, now, rep, driftNow)
	case "Job":
		job, err := p.CS.BatchV1().Jobs(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			log.Info("WARN: linkerd heal — job get failed",
				"job", ns+"/"+ref.Name, "error", err)
			return false
		}
		return p.patchTemplatePorts(ctx, log, job, "job", ns, job.Name,
			job.Spec.Template.Annotations, missing, false, now, rep, driftNow)
	case "CronJob":
		cj, err := p.CS.BatchV1().CronJobs(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			log.Info("WARN: linkerd heal — cronjob get failed",
				"cronjob", ns+"/"+ref.Name, "error", err)
			return false
		}
		return p.patchTemplatePorts(ctx, log, cj, "cronjob", ns, cj.Name,
			cj.Spec.JobTemplate.Spec.Template.Annotations, missing, true, now, rep, driftNow)
	default:
		return false
	}
}

// patchTemplatePorts merge-patches the opaque-ports annotation
// into a workload's pod template. obj is the workload itself (the
// drift/cooldown reads — GitOps provenance and the durable patch
// stamp — live on ITS metadata, not the template's). existing is the
// template's current annotations — when they already cover `missing`
// the patch is skipped but the template is still reported covered
// (the pod only needs a restart). Returns false on patch failure or
// when the durable stamp says the template was patched inside
// linkerdOpaquePatchCool and already reverted — re-patching inside
// the window is a fight with whoever reverted it.
func (p *linkerdProtocolDetectionStallCheck) patchTemplatePorts(ctx context.Context,
	log logr.Logger, obj metav1.Object, kind, ns, name string,
	existing map[string]string, missing []int, cronJob bool,
	now time.Time, rep *probefw.SweepReport, driftNow map[string][]string) bool {

	covered := parsePortSet(existing[linkerdOpaquePortsAnno])
	for pt := range parsePortSet(existing[linkerdSkipInboundAnno]) {
		covered[pt] = true
	}
	for pt := range parsePortSet(existing[linkerdSkipOutboundAnno]) {
		covered[pt] = true
	}
	stillMissing := map[int]bool{}
	for _, pt := range missing {
		if !covered[pt] {
			stillMissing[pt] = true
		}
	}
	if len(stillMissing) == 0 {
		log.Info("linkerd heal: template already covers ports — pod restart suffices",
			"kind", kind, "workload", ns+"/"+name)
		return true
	}
	// W12-P0-6 durable stamp: a workload we already patched that lost
	// opaque-ports again inside the window was reverted by its owner.
	// GitOps-owned (Flux kustomize/helm labels, ArgoCD tracking-id)
	// means force/selfHeal is doing the revert — do NOT re-patch (the
	// 30m patch→revert→re-roll fight is the incident class); emit the
	// drift gauge + finding so the fix goes to Git. Unmanaged
	// workloads still honor the window silently.
	if stamped, ok := kube.AnnoTime(obj, kube.AnnoLastLinkerdOpaquePatch); ok &&
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
		} else {
			// Not GitOps-owned: honor the window silently AND drop
			// any drift series this workload emitted earlier — a
			// workload whose GitOps marker was removed between
			// sweeps must not keep a stale drift=1 live.
			linkerdGitOpsOpaqueDriftGauge.DeleteLabelValues(ns, kind, name)
			log.Info("linkerd heal: template reverted inside patch cooldown — not re-patching",
				"kind", kind, "workload", ns+"/"+name, "lastPatch", stamped)
		}
		return false
	}
	for pt := range stillMissing {
		covered[pt] = true
	}
	value := portSetString(covered)
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
		return false
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
	}
	if patchErr != nil {
		// Forbidden until the RBAC wave lands patch on pods /
		// daemonsets / jobs — log and fail closed (no pod delete).
		log.Info("WARN: linkerd heal — template patch failed",
			"kind", kind, "workload", ns+"/"+name, "error", patchErr)
		return false
	}
	log.Info("PATCH: linkerd opaque-ports added to workload template",
		"kind", kind, "workload", ns+"/"+name, "ports", value)
	return true
}
