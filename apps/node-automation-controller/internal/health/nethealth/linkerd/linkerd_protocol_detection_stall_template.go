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

// patchLinkerdTemplate resolves the pod's controller owner to
// its workload and merges the missing ports into the pod-template
// opaque-ports annotation. Returns covered=true when the template now
// covers the ports (patched now, or already covered — the pod just
// needs a restart) and patched=true only when THIS call landed the
// template patch — the caller lets the workload controller run the
// rolling update instead of deleting pods itself in that case.
// covered=false means no workload owner resolves or the patch fails
// (RBAC/not-found) — the caller must not delete the pod then.
func (p *linkerdProtocolDetectionStallCheck) patchLinkerdTemplate(ctx context.Context,
	log logr.Logger, pod *corev1.Pod, missing []int, now time.Time,
	rep *probefw.SweepReport, driftNow map[string][]string) (covered, patched bool) {

	ref := metav1.GetControllerOf(pod)
	if ref == nil {
		return false, false
	}
	ns := pod.Namespace
	switch ref.Kind {
	case "ReplicaSet":
		rs, err := p.CS.AppsV1().ReplicaSets(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			log.Info("WARN: linkerd heal — replicaset get failed",
				"rs", ns+"/"+ref.Name, "error", err)
			return false, false
		}
		dref := metav1.GetControllerOf(rs)
		if dref == nil {
			return false, false
		}
		if dref.Kind == "Rollout" {
			// rollout-scale-flap — a Rollout-owned ReplicaSet: patch the parent
			// Rollout (argoproj.io/v1alpha1, unstructured) exactly
			// like the Deployment path — same template annotation,
			// same patch stamp and GitOps drift guard via
			// patchTemplatePorts, just a dynamic-client patch. The
			// get goes through the per-sweep unstructured snapshot —
			// a cluster-wide LIST memoized per GVR, filtered
			// client-side to ns/name (the raw NoMatch/NotFound error
			// means no Rollout CRD or no such object: no heal).
			ros, err := p.AllUnstructured(ctx, kube.GVRArgoRollout)
			if err != nil {
				log.Info("WARN: linkerd heal — rollout census failed",
					"rollout", ns+"/"+dref.Name, "error", err)
				return false, false
			}
			var ro *unstructured.Unstructured
			for i := range ros {
				if ros[i].GetNamespace() == ns && ros[i].GetName() == dref.Name {
					ro = &ros[i]
					break
				}
			}
			if ro == nil {
				log.Info("WARN: linkerd heal — rollout gone from the census",
					"rollout", ns+"/"+dref.Name)
				return false, false
			}
			annos, _, _ := unstructured.NestedStringMap(ro.Object,
				"spec", "template", "metadata", "annotations")
			return p.patchTemplatePorts(ctx, log, ro, "rollout", ns, ro.GetName(),
				annos, missing, false, now, rep, driftNow)
		}
		if dref.Kind != "Deployment" {
			return false, false
		}
		// Workload Gets go through the per-sweep snapshot LISTs —
		// cluster-wide, memoized per kind, filtered client-side to
		// ns/name. The Patches below stay direct (writes never ride
		// the snapshot); a failed census fails the heal closed.
		depList, depErr := p.AllDeployments(ctx)
		if depErr != nil {
			log.Info("WARN: linkerd heal — deployment census failed",
				"deployment", ns+"/"+dref.Name, "error", depErr)
			return false, false
		}
		dep := findDeployment(depList, ns, dref.Name)
		if dep == nil {
			log.Info("WARN: linkerd heal — deployment not in the census",
				"deployment", ns+"/"+dref.Name)
			return false, false
		}
		return p.patchTemplatePorts(ctx, log, dep, "deployment", ns, dep.Name,
			dep.Spec.Template.Annotations, missing, false, now, rep, driftNow)
	case "Deployment":
		depList, depErr := p.AllDeployments(ctx)
		if depErr != nil {
			log.Info("WARN: linkerd heal — deployment census failed",
				"deployment", ns+"/"+ref.Name, "error", depErr)
			return false, false
		}
		dep := findDeployment(depList, ns, ref.Name)
		if dep == nil {
			log.Info("WARN: linkerd heal — deployment not in the census",
				"deployment", ns+"/"+ref.Name)
			return false, false
		}
		return p.patchTemplatePorts(ctx, log, dep, "deployment", ns, dep.Name,
			dep.Spec.Template.Annotations, missing, false, now, rep, driftNow)
	case "StatefulSet":
		stsList, stsErr := p.AllStatefulSets(ctx)
		if stsErr != nil {
			log.Info("WARN: linkerd heal — statefulset census failed",
				"statefulset", ns+"/"+ref.Name, "error", stsErr)
			return false, false
		}
		sts := findStatefulSet(stsList, ns, ref.Name)
		if sts == nil {
			log.Info("WARN: linkerd heal — statefulset not in the census",
				"statefulset", ns+"/"+ref.Name)
			return false, false
		}
		return p.patchTemplatePorts(ctx, log, sts, "statefulset", ns, sts.Name,
			sts.Spec.Template.Annotations, missing, false, now, rep, driftNow)
	case "DaemonSet":
		dsList, dsErr := p.AllDaemonSets(ctx)
		if dsErr != nil {
			log.Info("WARN: linkerd heal — daemonset census failed",
				"daemonset", ns+"/"+ref.Name, "error", dsErr)
			return false, false
		}
		ds := findDaemonSet(dsList, ns, ref.Name)
		if ds == nil {
			log.Info("WARN: linkerd heal — daemonset not in the census",
				"daemonset", ns+"/"+ref.Name)
			return false, false
		}
		return p.patchTemplatePorts(ctx, log, ds, "daemonset", ns, ds.Name,
			ds.Spec.Template.Annotations, missing, false, now, rep, driftNow)
	case "Job":
		job, err := p.CS.BatchV1().Jobs(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			log.Info("WARN: linkerd heal — job get failed",
				"job", ns+"/"+ref.Name, "error", err)
			return false, false
		}
		return p.patchTemplatePorts(ctx, log, job, "job", ns, job.Name,
			job.Spec.Template.Annotations, missing, false, now, rep, driftNow)
	case "CronJob":
		cj, err := p.CS.BatchV1().CronJobs(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			log.Info("WARN: linkerd heal — cronjob get failed",
				"cronjob", ns+"/"+ref.Name, "error", err)
			return false, false
		}
		return p.patchTemplatePorts(ctx, log, cj, "cronjob", ns, cj.Name,
			cj.Spec.JobTemplate.Spec.Template.Annotations, missing, true, now, rep, driftNow)
	default:
		return false, false
	}
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
// reverted it.
func (p *linkerdProtocolDetectionStallCheck) patchTemplatePorts(ctx context.Context,
	log logr.Logger, obj metav1.Object, kind, ns, name string,
	existing map[string]string, missing []int, cronJob bool,
	now time.Time, rep *probefw.SweepReport, driftNow map[string][]string,
) (covered, patched bool) {

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
		return true, false
	}
	// template-patch-stamp durable stamp: a workload we already patched that lost
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
		return false, false
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
		return false, false
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
		return false, false
	}
	// Mirror the landed patch into the snapshot's in-memory workload
	// copy — the serial sweep sees no apiserver echo, so a second
	// stalled pod of the same workload must read the template
	// annotation (and the patch stamp) this call just wrote instead
	// of re-deriving the write from the stale pre-patch copy and
	// re-patching. mergeTemplateAnnos also allocates a missing
	// template-annotation map through the concrete workload: the
	// caller's `existing` binding cannot write nil back.
	probefw.MergeAnnoPatchLocally(obj, payload)
	mergeTemplateAnnos(obj, anno)
	log.Info("PATCH: linkerd opaque-ports added to workload template",
		"kind", kind, "workload", ns+"/"+name, "ports", value)
	return true, true
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
		if meta.Annotations == nil {
			meta.Annotations = map[string]string{}
		}
		for k, v := range anno {
			meta.Annotations[k] = v
		}
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
		m := make(map[string]any, len(anno))
		for k, v := range anno {
			m[k] = v
		}
		_ = unstructured.SetNestedMap(w.Object, m,
			"spec", "template", "metadata", "annotations")
	}
}

// find{Deployment,StatefulSet,DaemonSet} resolve ns/name inside a
// snapshot census — the client-side equivalent of a namespace Get
// once the LIST came off the per-sweep snapshot. nil (or a failed
// census read, filtered before the call) means fail closed: no heal.
func findDeployment(items []appsv1.Deployment, ns, name string) *appsv1.Deployment {
	for i := range items {
		if items[i].Namespace == ns && items[i].Name == name {
			return &items[i]
		}
	}
	return nil
}

func findStatefulSet(items []appsv1.StatefulSet, ns, name string) *appsv1.StatefulSet {
	for i := range items {
		if items[i].Namespace == ns && items[i].Name == name {
			return &items[i]
		}
	}
	return nil
}

func findDaemonSet(items []appsv1.DaemonSet, ns, name string) *appsv1.DaemonSet {
	for i := range items {
		if items[i].Namespace == ns && items[i].Name == name {
			return &items[i]
		}
	}
	return nil
}
