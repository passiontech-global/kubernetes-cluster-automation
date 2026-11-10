// linkerd_endpoint_sync_socklb.go — the socket-lb-vs-linkerd half of the
// linkerd-endpoint-sync sweep: the Cilium socket-LB vs Linkerd
// compatibility audit — pod-netns bpf-lb-sock rewrites connect()
// before linkerd-init's iptables rules can steer into the proxy,
// silently killing SO_ORIGINAL_DST/mTLS; reported on
// node_automation_cilium_linkerd_socklb_conflict.
package linkerd

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// socket-lb-vs-linkerd — the socket-LB conflict signal: 1 while Cilium runs
// pod-netns bpf-lb-sock alongside Linkerd without either
// compatibility knob (cni-exclusive=false keeps linkerd-init's
// iptables redirect authoritative; bpf-lb-sock-hostns-only=true
// confines socket-LB to the host netns for the node-local-dns
// LRPs). A plain gauge — the conflict is cluster-wide, not
// per-object.
var ciliumLinkerdSockLBConflictGauge = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "node_automation_cilium_linkerd_socklb_conflict",
	Help: "1 while Cilium pod-netns socket-LB is enabled alongside Linkerd without cni-exclusive=false or bpf-lb-sock-hostns-only=true.",
})

func init() {
	ctrlmetrics.Registry.MustRegister(ciliumLinkerdSockLBConflictGauge)
}

// ---------------------------------------------------------------------------
// socket-lb-vs-linkerd — Cilium socket-LB vs Linkerd compatibility audit
// ---------------------------------------------------------------------------

// ciliumSockLBConflictsWithLinkerd reports whether the cilium-config
// data runs pod-netns Socket-LB in a shape that bypasses linkerd's
// iptables redirect: bpf-lb-sock="true" with NEITHER compatibility
// knob set. cni-exclusive="false" keeps linkerd-init's rules
// authoritative (Cilium shares the CNI chain instead of owning it);
// bpf-lb-sock-hostns-only="true" confines socket-LB to the host
// netns — the node-local-dns LRPs keep working while pod traffic
// still flows through linkerd-proxy.
func ciliumSockLBConflictsWithLinkerd(data map[string]string) bool {
	if data["bpf-lb-sock"] != "true" {
		return false
	}
	return data["cni-exclusive"] != "false" &&
		data["bpf-lb-sock-hostns-only"] != "true"
}

// auditCiliumLinkerdSockLB runs the socket-lb-vs-linkerd runtime half of the
// static socket-LB gate: with Linkerd installed AND Cilium's
// ConfigMap present, pod-netns bpf-lb-sock without a compatibility
// knob silently bypasses linkerd-proxy (SO_ORIGINAL_DST never sees
// the original ClusterIP). No mesh → no conflict; no cilium-config →
// no Cilium, so no socket-LB to conflict with. A ConfigMap read
// failure is tolerated (WARN + InfraErr) — "can't tell" must not
// read as resolved, so the gauge keeps its last value.
func (p *linkerdEndpointSyncCheck) auditCiliumLinkerdSockLB(
	ctx context.Context, log logr.Logger, linkerdInstalled bool,
	rep *probefw.SweepReport) {

	if !linkerdInstalled {
		ciliumLinkerdSockLBConflictGauge.Set(0)
		return
	}
	cm, err := p.CS.CoreV1().ConfigMaps(ciliumConfigNS).
		Get(ctx, ciliumConfigName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		ciliumLinkerdSockLBConflictGauge.Set(0)
		return
	case err != nil:
		log.Info("WARN: cilium-config get failed — socket-LB audit inconclusive",
			"error", err)
		rep.InfraErr(fmt.Errorf("get configmap %s/%s: %w",
			ciliumConfigNS, ciliumConfigName, err))
		return
	}
	if !ciliumSockLBConflictsWithLinkerd(cm.Data) {
		ciliumLinkerdSockLBConflictGauge.Set(0)
		return
	}
	ciliumLinkerdSockLBConflictGauge.Set(1)
	rep.Find(ciliumConfigNS + "/" + ciliumConfigName +
		": bpf-lb-sock=true without cni-exclusive=false or " +
		"bpf-lb-sock-hostns-only=true — pod-netns socket-LB bypasses linkerd-proxy")
}
