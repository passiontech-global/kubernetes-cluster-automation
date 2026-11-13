// linkerd_protocol_detection_stall.go — the
// linkerd-protocol-detection-stall check (linkerd-protocol-detection-stall): a meshed pod
// exposing a well-known binary/stateful port not covered by
// config.linkerd.io/opaque-ports, skip-inbound-ports or
// skip-outbound-ports gets protocol detection it cannot survive; the
// owning workload template is patched and the pod re-rolled.
//
// template-patch-stamp GitOps drift guard: the template patch carries a durable
// stamp (kube.AnnoLastLinkerdOpaquePatch, 6h cooldown) on the
// workload's own metadata. When a Flux/ArgoCD-managed workload's
// template loses opaque-ports again inside the window, its GitOps
// force/selfHeal is provably fighting the patch — the check stops
// re-patching (an infinite 30m rollout fight) and emits
// node_automation_linkerd_gitops_opaque_drift instead so the fix
// lands in Git, not in a revert loop.
package linkerd

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// linkerdProtocolDetectionStallCheck is the linkerd opaque-port /
// protocol-detection stall watchdog with linkerd template heal.
type linkerdProtocolDetectionStallCheck struct {
	*probefw.Deps

	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale 1 (zero value usable; the serial sweep needs no lock).
	emitted state.GaugeLedger[string]
	// driftEmitted is the same ledger for the GitOps-drift gauge —
	// kept apart from emitted because each GaugeLedger binds ONE
	// vec's DeleteLabelValues at reconcile time.
	driftEmitted state.GaugeLedger[string]
}

// The constructor lives in the package facade (linkerd.go).

const (
	CheckNameLinkerdOpaqueStall = "linkerd-protocol-detection-stall"

	// linkerd-protocol-detection-stall — linkerd-protocol-detection-stall knobs. The injected
	// sidecar container name lives in platform/kube
	// (kube.LinkerdProxyContainer) — the apiserver webhook guard
	// matches the same container.
	linkerdOpaquePortsAnno  = "config.linkerd.io/opaque-ports"
	linkerdSkipInboundAnno  = "config.linkerd.io/skip-inbound-ports"
	linkerdSkipOutboundAnno = "config.linkerd.io/skip-outbound-ports"
	linkerdOpaqueHealCool   = 30 * time.Minute
	// linkerdOpaquePatchCool is the durable-stamp window on the
	// owning workload (kube.AnnoLastLinkerdOpaquePatch): a template
	// that lost opaque-ports again inside 6h of our patch was
	// reverted by an external owner — re-patching immediately is a
	// fight, so the check waits the window out (and reports drift
	// when the owner is provably Flux/ArgoCD).
	linkerdOpaquePatchCool = 6 * time.Hour
)

var (
	// linkerd-protocol-detection-stall — meshed pod exposing an unannotated binary port.
	linkerdOpaquePortMissingGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_linkerd_opaque_port_missing",
		Help: "1 while the meshed pod exposes a well-known binary port without opaque/skip-inbound annotation — linkerd-protocol-detection-stall.",
	}, []string{"namespace", "pod", "port"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(linkerdOpaquePortMissingGauge)
}

// checkLinkerdProtocolDetectionStall audits running meshed pods for
// well-known binary/stateful ports missing the opaque/skip-inbound
// annotation — Linkerd's protocol detector cannot classify MySQL,
// Postgres, Redis, Mongo, Cassandra, RabbitMQ or Dragonfly wire
// protocols and stalls every new connection on them.
//
// Heal: patch config.linkerd.io/opaque-ports onto the owning
// workload's pod template (Deployment/StatefulSet/DaemonSet/Job/
// CronJob resolved through ownerReferences). When the patch just
// landed, the workload controller runs the rolling update — no
// mass pod delete; a pod is deleted only when the template ALREADY
// covered the ports but the running pod predates the annotation
// (the restart is then the heal). The cooldown keys on the pod's
// controller; maintenance-gated.
func (p *linkerdProtocolDetectionStallCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	pods, err := p.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}
	var rep probefw.SweepReport
	// driftNow carries this sweep's live GitOps-drift tuples —
	// reconciled on the SECOND gauge ledger below (the missing-port
	// ledger stays bound to its own vec).
	driftNow := map[string][]string{}
	for i := range pods {
		pod := &pods[i]
		if pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
			continue
		}
		if !kube.PodIsMeshed(&pod.Spec) {
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
		p.healLinkerdOpaquePorts(ctx, log, pod, missing, now, pods, &rep, driftNow)
	}
	p.driftEmitted.Reconcile(driftNow, linkerdGitOpsOpaqueDriftGauge.DeleteLabelValues)
	return rep.Result(&p.emitted, linkerdOpaquePortMissingGauge.DeleteLabelValues,
		"meshed pods exposing unannotated binary ports: ", ", ")
}
