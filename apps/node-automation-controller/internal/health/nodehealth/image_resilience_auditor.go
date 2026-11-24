// image_resilience_auditor.go — Wave 4C #14 critical workload mutable-image
// resilience auditor (image-resilience-auditor): audits Deployments,
// StatefulSets, DaemonSets, and standalone/orphan Pods in configured critical
// namespaces (NODE_AUTOMATION_IMAGE_AUDIT_NAMESPACES) for imagePullPolicy=Always
// and mutable/unpinned image tags (:latest, :main, :master, or untagged
// without @sha256: digest), skipping terminating workloads and objects carrying
// passiontech.dev/mutable-image-exempt=true.
//
// Emits GaugeLedger-managed node_automation_workload_image_resilience_risk
// {namespace,workload,reason} via SweepReport.Flag and returns PASS by default
// unless NODE_AUTOMATION_IMAGE_RESILIENCE_FAIL_ON_RISK=true.
package nodehealth

import (
	"context"
	"fmt"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	CheckNameImageResilienceAuditor = "image-resilience-auditor"

	defaultImageAuditNamespaces = "kube-system,node-ops,linkerd,cilium,prometheus-operator,victoria-metrics,cert-manager,flux-system,argocd,medik8s"

	imageRiskPullPolicyAlways = "pull_policy_always"
	imageRiskMutableTag       = "mutable_tag"
)

var workloadImageResilienceRiskGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_workload_image_resilience_risk",
	Help: "1 while a critical-namespace workload uses imagePullPolicy=Always or a mutable/unpinned image tag.",
}, []string{"namespace", "workload", "reason"})

func init() {
	ctrlmetrics.Registry.MustRegister(workloadImageResilienceRiskGauge)
}

type imageResilienceAuditorCheck struct {
	*probefw.Deps

	auditNamespaces map[string]bool
	failOnRisk      bool
	emitted         state.GaugeLedger[string]
}

// NewImageResilienceAuditorCheck builds the image-resilience-auditor check,
// resolving its namespace allowlist and fail-on-risk gate once at construction.
func NewImageResilienceAuditorCheck(d *probefw.Deps) probefw.Check {
	nsRaw := envx.Getenv("NODE_AUTOMATION_IMAGE_AUDIT_NAMESPACES", defaultImageAuditNamespaces)
	return &imageResilienceAuditorCheck{
		Deps:            d,
		auditNamespaces: kube.ParseCommaSet(nsRaw),
		failOnRisk:      envx.Gate("NODE_AUTOMATION_IMAGE_RESILIENCE_FAIL_ON_RISK", false),
	}
}

func (c *imageResilienceAuditorCheck) Run(ctx context.Context) probefw.Result {
	deps, err := c.AllDeployments(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list deployments: %w", err)}
	}
	stss, err := c.AllStatefulSets(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list statefulsets: %w", err)}
	}
	dss, err := c.AllDaemonSets(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list daemonsets: %w", err)}
	}
	pods, err := c.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}

	var rep probefw.SweepReport
	flagged := map[string]bool{}

	audit := func(ns, kind, name string, spec corev1.PodSpec) {
		workload := kind + "/" + name
		checkContainer := func(ctr corev1.Container) {
			if ctr.ImagePullPolicy == corev1.PullAlways {
				c.recordRisk(&rep, flagged, ns, workload, imageRiskPullPolicyAlways)
			}
			if hasMutableImageTag(ctr.Image) {
				c.recordRisk(&rep, flagged, ns, workload, imageRiskMutableTag)
			}
		}
		for i := range spec.InitContainers {
			checkContainer(spec.InitContainers[i])
		}
		for i := range spec.Containers {
			checkContainer(spec.Containers[i])
		}
	}

	for i := range deps {
		dep := &deps[i]
		if !c.auditNamespaces[dep.Namespace] || dep.DeletionTimestamp != nil || isMutableImageExempt(ctx, dep) {
			continue
		}
		audit(dep.Namespace, "Deployment", dep.Name, dep.Spec.Template.Spec)
	}
	for i := range stss {
		sts := &stss[i]
		if !c.auditNamespaces[sts.Namespace] || sts.DeletionTimestamp != nil || isMutableImageExempt(ctx, sts) {
			continue
		}
		audit(sts.Namespace, "StatefulSet", sts.Name, sts.Spec.Template.Spec)
	}
	for i := range dss {
		ds := &dss[i]
		if !c.auditNamespaces[ds.Namespace] || ds.DeletionTimestamp != nil || isMutableImageExempt(ctx, ds) {
			continue
		}
		audit(ds.Namespace, "DaemonSet", ds.Name, ds.Spec.Template.Spec)
	}
	for i := range pods {
		pod := &pods[i]
		if !c.auditNamespaces[pod.Namespace] || pod.DeletionTimestamp != nil || isMutableImageExempt(ctx, pod) {
			continue
		}
		if metav1.GetControllerOf(pod) != nil {
			continue
		}
		if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		if _, mirror := pod.Annotations["kubernetes.io/config.mirror"]; mirror {
			continue
		}
		audit(pod.Namespace, "Pod", pod.Name, pod.Spec)
	}

	return rep.Result(&c.emitted, workloadImageResilienceRiskGauge.DeleteLabelValues,
		"workload image resilience risk: ", ", ")
}

func (c *imageResilienceAuditorCheck) recordRisk(
	rep *probefw.SweepReport,
	flagged map[string]bool,
	ns, workload, reason string,
) {
	key := ns + "/" + workload + "/" + reason
	if flagged[key] {
		return
	}
	flagged[key] = true
	rep.Flag(workloadImageResilienceRiskGauge, key, []string{ns, workload, reason})
	if c.failOnRisk {
		rep.Find(fmt.Sprintf("%s/%s (%s)", ns, workload, reason))
	}
}

func isMutableImageExempt(ctx context.Context, obj metav1.Object) bool {
	return strings.EqualFold(
		strings.TrimSpace(kube.EffectiveAnno(ctx, obj, kube.AnnoMutableImageExempt)),
		"true")
}

func hasMutableImageTag(image string) bool {
	img := strings.TrimSpace(image)
	if img == "" {
		return false
	}
	if idx := strings.Index(img, "@sha256:"); idx >= 0 && len(img) > idx+len("@sha256:") {
		return false
	}
	tail := img
	if slash := strings.LastIndexByte(img, '/'); slash >= 0 {
		tail = img[slash+1:]
	}
	colon := strings.LastIndexByte(tail, ':')
	if colon < 0 {
		return true
	}
	tag := tail[colon+1:]
	return tag == "" || tag == "latest" || tag == "main" || tag == "master"
}
