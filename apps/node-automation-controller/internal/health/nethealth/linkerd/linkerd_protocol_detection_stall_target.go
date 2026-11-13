package linkerd

import (
	"context"

	"github.com/go-logr/logr"
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
		rs, rsErr := p.ReplicaSet(ctx, ns, ref.Name)
		if rsErr != nil {
			log.Info("WARN: linkerd heal — replicaset census failed",
				"rs", ns+"/"+ref.Name, "error", rsErr)
			return nil, false
		}
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
		return p.deploymentTarget(ctx, log, ns, dref.Name)
	case "Deployment":
		return p.deploymentTarget(ctx, log, ns, ref.Name)
	case "StatefulSet":
		sts, stsErr := p.StatefulSet(ctx, ns, ref.Name)
		if stsErr != nil {
			log.Info("WARN: linkerd heal — statefulset census failed",
				"statefulset", ns+"/"+ref.Name, "error", stsErr)
			return nil, false
		}
		if sts == nil {
			log.Info("WARN: linkerd heal — statefulset not in the census",
				"statefulset", ns+"/"+ref.Name)
			return nil, false
		}
		return &linkerdTemplateTarget{sts, "statefulset", ns, sts.Name,
			kube.EffectiveTemplateAnnos(ctx, sts, sts.Spec.Template.Annotations), false}, true
	case "DaemonSet":
		ds, dsErr := p.DaemonSet(ctx, ns, ref.Name)
		if dsErr != nil {
			log.Info("WARN: linkerd heal — daemonset census failed",
				"daemonset", ns+"/"+ref.Name, "error", dsErr)
			return nil, false
		}
		if ds == nil {
			log.Info("WARN: linkerd heal — daemonset not in the census",
				"daemonset", ns+"/"+ref.Name)
			return nil, false
		}
		return &linkerdTemplateTarget{ds, "daemonset", ns, ds.Name,
			kube.EffectiveTemplateAnnos(ctx, ds, ds.Spec.Template.Annotations), false}, true
	case "Job":
		job, jobErr := p.Job(ctx, ns, ref.Name)
		if jobErr != nil {
			log.Info("WARN: linkerd heal — job census failed",
				"job", ns+"/"+ref.Name, "error", jobErr)
			return nil, false
		}
		if job == nil {
			log.Info("WARN: linkerd heal — job not in the census",
				"job", ns+"/"+ref.Name)
			return nil, false
		}
		return &linkerdTemplateTarget{job, "job", ns, job.Name,
			kube.EffectiveTemplateAnnos(ctx, job, job.Spec.Template.Annotations), false}, true
	case "CronJob":
		cj, cjErr := p.CronJob(ctx, ns, ref.Name)
		if cjErr != nil {
			log.Info("WARN: linkerd heal — cronjob census failed",
				"cronjob", ns+"/"+ref.Name, "error", cjErr)
			return nil, false
		}
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

// deploymentTarget resolves the named Deployment through the sweep's
// indexed census lookup — the snapshot equivalent of a per-name GET,
// O(1) after the first resolution instead of a linear census walk
// per resolved pod.
func (p *linkerdProtocolDetectionStallCheck) deploymentTarget(
	ctx context.Context, log logr.Logger, ns, name string) (*linkerdTemplateTarget, bool) {

	dep, depErr := p.Deployment(ctx, ns, name)
	if depErr != nil {
		log.Info("WARN: linkerd heal — deployment census failed",
			"deployment", ns+"/"+name, "error", depErr)
		return nil, false
	}
	if dep == nil {
		log.Info("WARN: linkerd heal — deployment not in the census",
			"deployment", ns+"/"+name)
		return nil, false
	}
	return &linkerdTemplateTarget{dep, "deployment", ns, dep.Name,
		kube.EffectiveTemplateAnnos(ctx, dep, dep.Spec.Template.Annotations), false}, true
}
