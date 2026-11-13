// linkerd_h2_stream_guard.go — the linkerd-h2-stream-guard check:
// meshed pods whose linkerd-proxy log shows an HTTP/2 stream storm
// (ENHANCE_YOUR_CALM / ping flood / concurrency-limit rejections) or
// an mTLS identity stall (leaf-certificate expiry / issuance loop)
// get deleted once a Ready sibling can absorb the traffic — an
// HTTP/1.1-ready probe can't see a wedged h2 stream table, and a
// proxy whose identity cert expired keeps serving "running" while
// every new connection fails TLS validation.
//
// linkerd-h2-stream-guard adds the outbound failure-accrual lockout: a client proxy
// whose balancer holds endpoints for a Service but NONE in
// state="ready" (outbound_http_balancer_endpoints) is circuit-broken
// long after the destination recovered — detected via Prometheus,
// cross-checked against live EndpointSlices so a genuine
// zero-endpoint outage is not misread as a wedge, and healed by the
// same Ready-sibling-gated pod delete. The sweep also reports
// linkerd-proxy OOM kills on
// node_automation_linkerd_proxy_oomkilled.
package linkerd

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// linkerdH2StreamGuardCheck is the linkerd HTTP/2 stream-storm and
// mTLS identity-stall watchdog — one proxy-log tail feeds both
// signature families.
type linkerdH2StreamGuardCheck struct {
	*probefw.Deps

	// emitted is the storm-gauge ledger and identityEmitted the
	// identity-gauge ledger — a tuple that stops being reported gets
	// DeleteLabelValues'd rather than leaking a stale 1 (zero value
	// usable; the serial sweep needs no lock).
	emitted         state.GaugeLedger[string]
	identityEmitted state.GaugeLedger[string]
	// linkerd-h2-stream-guard — balancerEmitted/oomEmitted are the emitted-gauge
	// ledgers for the outbound-balancer wedge and proxy-OOMKilled
	// gauges; balancerSeen tracks each wedged
	// "ns/pod/target_addr" tuple's first sighting for the >=10m
	// persistence window (in-RAM only — an operator restart costing
	// one re-armed window is the safe direction; the window gates a
	// pod delete but the pod itself is the delete target, so a
	// persisted stamp would die with it anyway).
	balancerEmitted state.GaugeLedger[string]
	oomEmitted      state.GaugeLedger[string]
	balancerSeen    state.FirstSeenLedger
}

// The constructor lives in the package facade (linkerd.go).

const (
	CheckNameLinkerdH2StreamGuard = "linkerd-h2-stream-guard"

	// linkerd-h2-stream-guard knobs.
	linkerdH2PodMinAge = 5 * time.Minute
	linkerdH2HealCool  = 30 * time.Minute
	// linkerdH2LogWorkers bounds the parallel proxy-log tails —
	// the kubelet log path is the sweep's slowest read, so the
	// scan runs on a small pool instead of serially.
	linkerdH2LogWorkers = 8

	// linkerd-h2-stream-guard — a balancer with no ready endpoint must hold that
	// shape this long before it counts as failure-accrual lockout
	// rather than ordinary failover churn.
	linkerdBalancerWedgeMinAge = 10 * time.Minute
)

var (
	// Pods whose linkerd-proxy reports an HTTP/2 stream storm.
	linkerdH2StreamStalledGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_linkerd_h2_stream_stalled",
		Help: "1 while the meshed pod's linkerd-proxy log shows an HTTP/2 stream-storm signature.",
	}, []string{"namespace", "pod"})

	// Pods whose linkerd-proxy reports an expired/stalled mTLS
	// identity leaf certificate — the pod is recreated so the proxy
	// is issued a fresh one.
	linkerdProxyIdentityStalledGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_linkerd_proxy_identity_stalled",
		Help: "1 while the meshed pod's linkerd-proxy log shows an mTLS identity leaf-certificate expiry or issuance-loop signature.",
	}, []string{"namespace", "pod"})

	// linkerd-h2-stream-guard — pods whose linkerd-proxy container last terminated
	// on OOMKilled: an OOM'd proxy loses its connection table and
	// balancer state on restart, the silent wedge seed.
	linkerdProxyOOMKilledGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_linkerd_proxy_oomkilled",
		Help: "1 while the meshed pod's linkerd-proxy container last terminated with Reason=OOMKilled.",
	}, []string{"namespace", "pod"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		linkerdH2StreamStalledGauge,
		linkerdProxyIdentityStalledGauge,
		linkerdProxyOOMKilledGauge)
}

// checkLinkerdH2StreamGuard scans Running meshed pods older than 5m
// for proxy-log failure signatures. A storming pod is deleted only
// while a Ready sibling under the same controller exists — replacing
// the pod rebuilds the proxy's stream table; without a sibling the
// outage is workload-level and a delete would blackhole the service
// entirely. An identity-stalled pod (expired leaf cert / wedged
// issuance loop) rides the same safe-evict path — the maintenance
// mutex via DeletePodHeal→heal.AllowedV and the 30m cooldown — gated
// on readyByOwner[ref.UID] >= 2 so at least one genuinely separate
// Ready replica survives the eviction; the replacement pod is issued
// a fresh leaf certificate.
func (p *linkerdH2StreamGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	pods, err := p.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}

	// Ready siblings per controller UID — the heal's "someone can
	// absorb the traffic" proof.
	readyByOwner := probefw.ReadyByOwner(pods)

	var rep, identityRep, oomRep, balancerRep probefw.SweepReport

	// Phase 1 — candidate collection plus the cheap OOM report.
	// The Prometheus prefilter narrows the per-pod log tails to
	// suspect pods only; nil is "inconclusive" and the legacy
	// full-mesh scan runs.
	suspect := p.linkerdSuspectPods(ctx, log)
	var cands []*corev1.Pod
	for i := range pods {
		pod := &pods[i]
		if pod.DeletionTimestamp != nil ||
			pod.Status.Phase != corev1.PodRunning ||
			now.Sub(pod.CreationTimestamp.Time) < linkerdH2PodMinAge ||
			!kube.PodIsMeshed(&pod.Spec) {
			continue
		}
		key := pod.Namespace + "/" + pod.Name
		lv := []string{pod.Namespace, pod.Name}
		// linkerd-h2-stream-guard — an OOM-killed linkerd-proxy loses its whole
		// connection table and balancer state on restart: report
		// the restart shape even when the replacement is already
		// serving (it is the silent wedge seed, and the restart
		// count alone never attributes the kill).
		if linkerdProxyOOMKilled(pod, now) {
			oomRep.Flag(linkerdProxyOOMKilledGauge, key, lv)
			rep.Find(key + "(linkerd-proxy OOMKilled)")
		}
		if suspect != nil && !suspect[key] {
			continue
		}
		cands = append(cands, pod)
	}

	// Phase 2 — parallel log tails on the shared kube.ScanPodLogs
	// pool bounded at linkerdH2LogWorkers: each fetch is a kubelet
	// round-trip (the sweep's slowest read), and a serial tail over
	// every meshed pod could eat the whole per-check budget on a
	// large cluster. One pod's panicked scan reads as that pod's
	// inconclusive result — never a process crash.
	h2sigs := kube.ScanPodLogs(ctx, p.CS, cands, linkerdH2LogWorkers,
		func(ctx context.Context, pod *corev1.Pod) (logSignals, error) {
			storm, identity, err := p.linkerdH2LogSignals(ctx, pod)
			return logSignals{storm: storm, identity: identity}, err
		})

	// Phase 3 — the serial verdict + heal pass over the fetched
	// signatures (gauge ledgers, the heal mutex and the cooldown
	// set are all single-writer by design).
	for i := range cands {
		pod := cands[i]
		key := pod.Namespace + "/" + pod.Name
		lv := []string{pod.Namespace, pod.Name}
		if err := h2sigs[i].Err; err != nil {
			// Inconclusive, not clean — a broken pod-log path must
			// not silently read as "no signature".
			log.Info("WARN: linkerd-proxy log fetch failed — log signatures inconclusive",
				"pod", pod.Namespace+"/"+pod.Name, "error", err)
			continue
		}
		storm, identity := h2sigs[i].Value.storm, h2sigs[i].Value.identity
		if !storm && !identity {
			continue
		}
		if storm {
			rep.Flag(linkerdH2StreamStalledGauge, key, lv)
			rep.Find(key)
			// The storming pod itself counts toward its owner's
			// Ready total when it is Ready — a h2 wedge does not
			// break the HTTP/1.1 probe. SafePodDelete's gate uses
			// ReadySiblings, which subtracts self so the guard
			// requires a GENUINELY separate sibling.
			p.SafePodDelete(ctx, log, CheckNameLinkerdH2StreamGuard,
				pod, readyByOwner, 1, linkerdH2HealCool, now)
		}
		if identity {
			identityRep.Flag(linkerdProxyIdentityStalledGauge, key, lv)
			if !storm {
				rep.Find(key)
			}
			// The safe-evict gate: the stalled pod may still report
			// Ready (a leaf-cert lapse does not break the HTTP/1.1
			// probe), so one genuinely separate Ready sibling under
			// the same controller means TWO Ready pods absorb the
			// traffic while the replacement is issued a fresh leaf
			// cert. Same 30m cooldown key as the storm path — one
			// delete heals both signatures.
			p.SafePodDelete(ctx, log, CheckNameLinkerdH2StreamGuard,
				pod, readyByOwner, 1, linkerdH2HealCool, now)
		}
	}
	rep.Close(&p.emitted, linkerdH2StreamStalledGauge.DeleteLabelValues)
	identityRep.Close(&p.identityEmitted, linkerdProxyIdentityStalledGauge.DeleteLabelValues)
	oomRep.Close(&p.oomEmitted, linkerdProxyOOMKilledGauge.DeleteLabelValues)

	// linkerd-h2-stream-guard — outbound balancer lockout: the client-side proxies
	// whose failure-accrual kept a target dead after it recovered.
	p.scanOutboundBalancers(ctx, log, now, pods, readyByOwner,
		&rep, &balancerRep)
	balancerRep.Close(&p.balancerEmitted,
		linkerdOutboundBalancerWedgedGauge.DeleteLabelValues)

	return rep.Verdict(
		"meshed pods with a linkerd-proxy failure signature (h2 stream storm / identity cert stall / OOM kill / outbound balancer wedge): ", ", ")
}
