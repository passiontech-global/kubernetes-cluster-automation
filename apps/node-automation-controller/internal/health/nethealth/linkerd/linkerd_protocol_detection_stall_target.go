package linkerd

import (
	"context"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// resolveLinkerdTemplate performs the READ-ONLY half of the heal:
// resolve the pod's controller owner to its workload and read the
// pod template's effective annotations. ok=false means no workload
// owner resolves or a census/get failed — the caller fails closed
// (no heal, and no drift verdict either: an unreadable template
// cannot prove a revert).
func (p *linkerdProtocolDetectionStallCheck) resolveLinkerdTemplate(ctx context.Context,
	log logr.Logger, pod *corev1.Pod, _ []int) (*linkerdTemplateTarget, bool) {

	ref := metav1.GetControllerOf(pod)
	if ref == nil {
		return nil, false
	}
	ns := pod.Namespace
	switch ref.Kind {
	case "ReplicaSet":
		rsList, rsErr := p.AllReplicaSets(ctx)
		if rsErr != nil {
			log.Info("WARN: linkerd heal — replicaset census failed",
				"rs", ns+"/"+ref.Name, "error", rsErr)
			return nil, false
		}
		rs := findReplicaSetMeta(rsList, ns, ref.Name)
		if rs == nil {
			log.Info("WARN: linkerd heal — replicaset not in the census",
				"rs", ns+"/"+ref.Name)
			return nil, false
		}
		dref := metav1.GetControllerOf(rs)
		if dref == nil {
			return nil, false
		}
		if dref.Kind == "Rollout" {
			ros, err := p.AllUnstructured(ctx, kube.GVRArgoRollout)
			if err != nil {
				log.Info("WARN: linkerd heal — rollout census failed",
					"rollout", ns+"/"+dref.Name, "error", err)
				return nil, false
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
				return nil, false
			}
			annos, _ := kube.NestedStringMap(ro.Object,
				"spec", "template", "metadata", "annotations")
			return &linkerdTemplateTarget{ro, "rollout", ns, ro.GetName(),
				kube.EffectiveTemplateAnnos(ctx, ro, annos), false}, true
		}
		if dref.Kind != "Deployment" {
			return nil, false
		}
		depList, depErr := p.AllDeployments(ctx)
		if depErr != nil {
			log.Info("WARN: linkerd heal — deployment census failed",
				"deployment", ns+"/"+dref.Name, "error", depErr)
			return nil, false
		}
		dep := findDeployment(depList, ns, dref.Name)
		if dep == nil {
			log.Info("WARN: linkerd heal — deployment not in the census",
				"deployment", ns+"/"+dref.Name)
			return nil, false
		}
		return &linkerdTemplateTarget{dep, "deployment", ns, dep.Name,
			kube.EffectiveTemplateAnnos(ctx, dep, dep.Spec.Template.Annotations), false}, true
	case "Deployment":
		depList, depErr := p.AllDeployments(ctx)
		if depErr != nil {
			log.Info("WARN: linkerd heal — deployment census failed",
				"deployment", ns+"/"+ref.Name, "error", depErr)
			return nil, false
		}
		dep := findDeployment(depList, ns, ref.Name)
		if dep == nil {
			log.Info("WARN: linkerd heal — deployment not in the census",
				"deployment", ns+"/"+ref.Name)
			return nil, false
		}
		return &linkerdTemplateTarget{dep, "deployment", ns, dep.Name,
			kube.EffectiveTemplateAnnos(ctx, dep, dep.Spec.Template.Annotations), false}, true
	case "StatefulSet":
		stsList, stsErr := p.AllStatefulSets(ctx)
		if stsErr != nil {
			log.Info("WARN: linkerd heal — statefulset census failed",
				"statefulset", ns+"/"+ref.Name, "error", stsErr)
			return nil, false
		}
		sts := findStatefulSet(stsList, ns, ref.Name)
		if sts == nil {
			log.Info("WARN: linkerd heal — statefulset not in the census",
				"statefulset", ns+"/"+ref.Name)
			return nil, false
		}
		return &linkerdTemplateTarget{sts, "statefulset", ns, sts.Name,
			kube.EffectiveTemplateAnnos(ctx, sts, sts.Spec.Template.Annotations), false}, true
	case "DaemonSet":
		dsList, dsErr := p.AllDaemonSets(ctx)
		if dsErr != nil {
			log.Info("WARN: linkerd heal — daemonset census failed",
				"daemonset", ns+"/"+ref.Name, "error", dsErr)
			return nil, false
		}
		ds := findDaemonSet(dsList, ns, ref.Name)
		if ds == nil {
			log.Info("WARN: linkerd heal — daemonset not in the census",
				"daemonset", ns+"/"+ref.Name)
			return nil, false
		}
		return &linkerdTemplateTarget{ds, "daemonset", ns, ds.Name,
			kube.EffectiveTemplateAnnos(ctx, ds, ds.Spec.Template.Annotations), false}, true
	case "Job":
		jobList, jobErr := p.AllJobs(ctx)
		if jobErr != nil {
			log.Info("WARN: linkerd heal — job census failed",
				"job", ns+"/"+ref.Name, "error", jobErr)
			return nil, false
		}
		job := findJob(jobList, ns, ref.Name)
		if job == nil {
			log.Info("WARN: linkerd heal — job not in the census",
				"job", ns+"/"+ref.Name)
			return nil, false
		}
		return &linkerdTemplateTarget{job, "job", ns, job.Name,
			kube.EffectiveTemplateAnnos(ctx, job, job.Spec.Template.Annotations), false}, true
	case "CronJob":
		cjList, cjErr := p.AllCronJobs(ctx)
		if cjErr != nil {
			log.Info("WARN: linkerd heal — cronjob census failed",
				"cronjob", ns+"/"+ref.Name, "error", cjErr)
			return nil, false
		}
		cj := findCronJob(cjList, ns, ref.Name)
		if cj == nil {
			log.Info("WARN: linkerd heal — cronjob not in the census",
				"cronjob", ns+"/"+ref.Name)
			return nil, false
		}
		return &linkerdTemplateTarget{cj, "cronjob", ns, cj.Name,
			kube.EffectiveTemplateAnnos(ctx, cj,
				cj.Spec.JobTemplate.Spec.Template.Annotations), true}, true
	default:
		return nil, false
	}
}

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

func findReplicaSetMeta(items []metav1.PartialObjectMetadata, ns, name string) *metav1.PartialObjectMetadata {
	for i := range items {
		if items[i].Namespace == ns && items[i].Name == name {
			return &items[i]
		}
	}
	return nil
}

func findCronJob(items []batchv1.CronJob, ns, name string) *batchv1.CronJob {
	for i := range items {
		if items[i].Namespace == ns && items[i].Name == name {
			return &items[i]
		}
	}
	return nil
}

func findJob(items []batchv1.Job, ns, name string) *batchv1.Job {
	for i := range items {
		if items[i].Namespace == ns && items[i].Name == name {
			return &items[i]
		}
	}
	return nil
}
