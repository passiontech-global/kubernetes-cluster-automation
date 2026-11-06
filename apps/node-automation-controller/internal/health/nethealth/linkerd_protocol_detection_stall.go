// linkerd_protocol_detection_stall.go — the
// linkerd-protocol-detection-stall check (W10-NM3): a meshed pod
// exposing a well-known binary/stateful port not covered by
// config.linkerd.io/opaque-ports or skip-inbound-ports gets
// protocol detection it cannot survive; the owning workload
// template is patched and the pod re-rolled.
package nethealth

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// linkerdProtocolDetectionStallCheck is the linkerd opaque-port /
// protocol-detection stall watchdog with linkerd template heal.
type linkerdProtocolDetectionStallCheck struct {
	*probefw.Deps

	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1 (zero value usable; the serial sweep needs no lock).
	emitted state.GaugeLedger[string]
	// verdict memoizes the maintenance-mutex evaluation the
	// per-pod heal preambles share — one evaluation per Verdict TTL
	// instead of three API reads per violating pod.
	verdict kube.Verdict
}

// newLinkerdProtocolDetectionStallCheck builds the W10-NM3 check —
// its only state is the emitted-gauge ledger; heal cooldowns ride
// the shared Deps.Heals set.
func NewLinkerdProtocolDetectionStallCheck(d *probefw.Deps) probefw.Check {
	return &linkerdProtocolDetectionStallCheck{Deps: d}
}

const (
	CheckNameLinkerdOpaqueStall = "linkerd-protocol-detection-stall"

	// W10-NM3 — linkerd-protocol-detection-stall knobs.
	linkerdProxyContainer  = "linkerd-proxy"
	linkerdOpaquePortsAnno = "config.linkerd.io/opaque-ports"
	linkerdSkipInboundAnno = "config.linkerd.io/skip-inbound-ports"
	linkerdOpaqueHealCool  = 30 * time.Minute
)

// linkerdBinaryPorts are the well-known binary/stateful server
// ports Linkerd protocol detection cannot classify — a meshed pod
// exposing one of these without an opaque/skip annotation stalls on
// every new connection (the W6.2/W9 linkerd port lists live in
// check-linkerd-stateful-ports; this is the pod-level audit mirror).
var linkerdBinaryPorts = map[int]bool{
	3306: true, 5432: true, 6379: true, 27017: true, 9042: true,
	4369: true, 25672: true, 7000: true, 7001: true, 9999: true,
}

var (
	// W10-NM3 — meshed pod exposing an unannotated binary port.
	linkerdOpaquePortMissingGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_linkerd_opaque_port_missing",
		Help: "1 while the meshed pod exposes a well-known binary port without opaque/skip-inbound annotation — W10-NM3.",
	}, []string{"namespace", "pod", "port"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		linkerdOpaquePortMissingGauge)
}

// parsePortSet parses a linkerd port annotation
// ("6379,8000-8010") into a set of concrete ports. Ranges are
// expanded — annotation values are small.
func parsePortSet(s string) map[int]bool {
	out := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			l, err1 := strconv.Atoi(strings.TrimSpace(lo))
			h, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil || h < l || h-l > 1024 {
				continue
			}
			for p := l; p <= h; p++ {
				out[p] = true
			}
			continue
		}
		if n, err := strconv.Atoi(part); err == nil {
			out[n] = true
		}
	}
	return out
}

// portSetString renders a port set back as a sorted
// comma-separated annotation value.
func portSetString(set map[int]bool) string {
	ports := make([]int, 0, len(set))
	for p := range set {
		ports = append(ports, p)
	}
	return joinPorts(ports)
}

// joinPorts renders an already-sorted port list as a
// comma-separated annotation value.
func joinPorts(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, strconv.Itoa(p))
	}
	return strings.Join(parts, ",")
}

// missingBinaryPorts returns the sorted well-known binary ports
// the pod's containers expose that are covered by NEITHER
// opaque-ports NOR skip-inbound-ports — either annotation makes the
// proxy treat the port as opaque TCP (skip-inbound is the inbound-only
// spelling of the same escape).
func missingBinaryPorts(pod *corev1.Pod) []int {
	covered := parsePortSet(pod.Annotations[linkerdOpaquePortsAnno])
	for p := range parsePortSet(pod.Annotations[linkerdSkipInboundAnno]) {
		covered[p] = true
	}
	seen := map[int]bool{}
	var missing []int
	for _, c := range pod.Spec.Containers {
		for _, port := range c.Ports {
			if port.Protocol != "" && port.Protocol != corev1.ProtocolTCP {
				continue
			}
			n := int(port.ContainerPort)
			if linkerdBinaryPorts[n] && !covered[n] && !seen[n] {
				seen[n] = true
				missing = append(missing, n)
			}
		}
	}
	sort.Ints(missing)
	return missing
}

// checkLinkerdProtocolDetectionStall audits running meshed pods for
// well-known binary/stateful ports missing the opaque/skip-inbound
// annotation — Linkerd's protocol detector cannot classify MySQL,
// Postgres, Redis, Mongo, Cassandra, RabbitMQ or Dragonfly wire
// protocols and stalls every new connection on them.
//
// Heal: patch config.linkerd.io/opaque-ports onto the owning
// workload's pod template (Deployment/StatefulSet/DaemonSet/Job/
// CronJob resolved through ownerReferences) AND the pod itself, then
// delete the pod so the proxy restarts with the corrected config — a
// running linkerd-proxy never re-reads its port annotations, so an
// annotation-only patch cannot heal. The pod is only deleted when the
// template patch succeeded (otherwise the replacement would inherit
// the same violation); 30m per-pod cooldown, maintenance-gated.
func (p *linkerdProtocolDetectionStallCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	pods, err := p.CS.CoreV1().Pods(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}
	var rep probefw.SweepReport
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
			continue
		}
		if !kube.PodSpecHasContainer(&pod.Spec, linkerdProxyContainer) {
			continue
		}
		missing := missingBinaryPorts(pod)
		if len(missing) == 0 {
			continue
		}
		for _, port := range missing {
			rep.Flag(linkerdOpaquePortMissingGauge,
				pod.Namespace+"/"+pod.Name+"/"+strconv.Itoa(port),
				[]string{pod.Namespace, pod.Name, strconv.Itoa(port)})
		}
		rep.Find(fmt.Sprintf("%s/%s ports=%s",
			pod.Namespace, pod.Name, joinPorts(missing)))
		p.healLinkerdOpaquePorts(ctx, log, pod, missing, now)
	}
	return rep.Result(&p.emitted, linkerdOpaquePortMissingGauge.DeleteLabelValues,
		"meshed pods exposing unannotated binary ports: ", ", ")
}

// healLinkerdOpaquePorts applies the opaque-ports heal for one
// violating pod: cooldown → maintenance gate → template patch → pod
// annotation patch → pod delete (only when the template took the
// annotation, else the replacement re-inherits the violation).
func (p *linkerdProtocolDetectionStallCheck) healLinkerdOpaquePorts(ctx context.Context,
	log logr.Logger, pod *corev1.Pod, missing []int, now time.Time) {

	ck := probefw.SelfHealKey(CheckNameLinkerdOpaqueStall, pod.Namespace+"/"+pod.Name)
	proceed, unverifiable := heal.AllowedV(ctx, log, &p.verdict,
		p.CS, p.Dyn, &p.Heals, ck, linkerdOpaqueHealCool, now)
	if unverifiable {
		metrics.IncError(p.Name)
		return
	}
	if !proceed {
		return
	}
	templateOK := p.patchLinkerdTemplate(ctx, log, pod, missing)
	p.patchLinkerdPodAnno(ctx, log, pod, missing)
	if !templateOK {
		log.Info("opaque-ports heal: owning workload template not patched — leaving pod running (annotation alone cannot reach a live proxy)",
			"pod", pod.Namespace+"/"+pod.Name, "ports", missing)
		return
	}
	if _, err := heal.DeletePod(ctx, p.CS, &p.Heals, ck, pod, now); err != nil {
		metrics.IncError(p.Name)
		log.Error(err, "linkerd opaque-ports pod delete failed",
			"pod", pod.Namespace+"/"+pod.Name)
		return
	}
	metrics.ControlPlanePodHealsTotal.WithLabelValues(CheckNameLinkerdOpaqueStall).Inc()
	log.Info("DELETE: linkerd protocol-detection stall — template patched, re-rolling pod",
		"pod", pod.Namespace+"/"+pod.Name, "ports", missing)
}

// patchLinkerdTemplate resolves the pod's controller owner to
// its workload and merges the missing ports into the pod-template
// opaque-ports annotation. Returns true when the template now covers
// the ports (patched now, or already covered — the pod just needs a
// restart). False when no workload owner resolves or the patch fails
// (RBAC/not-found) — the caller must not delete the pod then.
func (p *linkerdProtocolDetectionStallCheck) patchLinkerdTemplate(ctx context.Context,
	log logr.Logger, pod *corev1.Pod, missing []int) bool {

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
		return p.patchTemplatePorts(ctx, log, "deployment", ns, dep.Name,
			dep.Spec.Template.Annotations, missing, false)
	case "Deployment":
		dep, err := p.CS.AppsV1().Deployments(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			log.Info("WARN: linkerd heal — deployment get failed",
				"deployment", ns+"/"+ref.Name, "error", err)
			return false
		}
		return p.patchTemplatePorts(ctx, log, "deployment", ns, dep.Name,
			dep.Spec.Template.Annotations, missing, false)
	case "StatefulSet":
		sts, err := p.CS.AppsV1().StatefulSets(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			log.Info("WARN: linkerd heal — statefulset get failed",
				"statefulset", ns+"/"+ref.Name, "error", err)
			return false
		}
		return p.patchTemplatePorts(ctx, log, "statefulset", ns, sts.Name,
			sts.Spec.Template.Annotations, missing, false)
	case "DaemonSet":
		ds, err := p.CS.AppsV1().DaemonSets(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			log.Info("WARN: linkerd heal — daemonset get failed",
				"daemonset", ns+"/"+ref.Name, "error", err)
			return false
		}
		return p.patchTemplatePorts(ctx, log, "daemonset", ns, ds.Name,
			ds.Spec.Template.Annotations, missing, false)
	case "Job":
		job, err := p.CS.BatchV1().Jobs(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			log.Info("WARN: linkerd heal — job get failed",
				"job", ns+"/"+ref.Name, "error", err)
			return false
		}
		return p.patchTemplatePorts(ctx, log, "job", ns, job.Name,
			job.Spec.Template.Annotations, missing, false)
	case "CronJob":
		cj, err := p.CS.BatchV1().CronJobs(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			log.Info("WARN: linkerd heal — cronjob get failed",
				"cronjob", ns+"/"+ref.Name, "error", err)
			return false
		}
		return p.patchTemplatePorts(ctx, log, "cronjob", ns, cj.Name,
			cj.Spec.JobTemplate.Spec.Template.Annotations, missing, true)
	default:
		return false
	}
}

// patchTemplatePorts merge-patches the opaque-ports annotation
// into a workload's pod template. existing is the template's current
// annotations — when they already cover `missing` the patch is
// skipped but the template is still reported covered (the pod only
// needs a restart). Returns false on patch failure.
func (p *linkerdProtocolDetectionStallCheck) patchTemplatePorts(ctx context.Context,
	log logr.Logger, kind, ns, name string, existing map[string]string,
	missing []int, cronJob bool) bool {

	covered := parsePortSet(existing[linkerdOpaquePortsAnno])
	for pt := range parsePortSet(existing[linkerdSkipInboundAnno]) {
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
	for pt := range stillMissing {
		covered[pt] = true
	}
	value := portSetString(covered)
	var payload []byte
	var err error
	anno := map[string]string{linkerdOpaquePortsAnno: value}
	if cronJob {
		payload, err = json.Marshal(map[string]any{
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

// patchLinkerdPodAnno merge-patches the pod's own
// opaque-ports annotation — best-effort bookkeeping (a running
// proxy does not re-read it; the template patch + restart is the
// real heal). Failures are logged, never fatal.
func (p *linkerdProtocolDetectionStallCheck) patchLinkerdPodAnno(ctx context.Context,
	log logr.Logger, pod *corev1.Pod, missing []int) {

	set := parsePortSet(pod.Annotations[linkerdOpaquePortsAnno])
	changed := false
	for _, pt := range missing {
		if !set[pt] {
			set[pt] = true
			changed = true
		}
	}
	if !changed {
		return
	}
	payload, err := kube.MergePatchAnnos(map[string]any{
		linkerdOpaquePortsAnno: portSetString(set),
	})
	if err != nil {
		return
	}
	if _, err := p.CS.CoreV1().Pods(pod.Namespace).Patch(ctx, pod.Name,
		types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		log.Info("WARN: linkerd heal — pod annotation patch failed (RBAC?)",
			"pod", pod.Namespace+"/"+pod.Name, "error", err)
	}
}
