// workload_connection_skew_guard.go — the workload-connection-skew-guard
// health check: watches the passiontech:workload_pod_net_bytes:rate10m
// recording rule (shared with alert WorkloadConnectionSkewDetected) for
// sustained (>=15m) L4 traffic skew across Ready pods of a Deployment
// (readyPods >= 3, median > 1000 B/s, max/median > 4.0).
//
// Long-lived L4 connections (e.g., Cloudflare Tunnel edge connections on
// controlled-cloudflared-connector) pin to older pods after a scale-out or
// rollout, creating severe per-pod imbalance that L4 load balancing never
// corrects on its own. For explicitly allowlisted Deployments (default:
// cloudflare-tunnel-ingress-controller/controlled-cloudflared-connector) when
// WORKLOAD_CONNECTION_SKEW_REBALANCE_ENABLED is on, the check deletes ONLY the
// single hottest Ready pod via probefw.SafePodDelete (requiring >=1 Ready
// sibling, maintenance mutex, global heal budget, and 30m per-controller
// cooldown) so edge connections redistribute without manual intervention.
package connectionskew

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const (
	// CheckNameWorkloadConnectionSkewGuard is the registry check name.
	CheckNameWorkloadConnectionSkewGuard = "workload-connection-skew-guard"

	connSkewQuery                = "passiontech:workload_pod_net_bytes:rate10m"
	connSkewMinReadyPods         = 3
	connSkewMinMedianBytesPerSec = 1000.0
	connSkewRatioThreshold       = 4.0
	connSkewMinAge               = 15 * time.Minute
	connSkewHealCooldown         = 30 * time.Minute
	connSkewDefaultAllowlist     = "cloudflare-tunnel-ingress-controller/controlled-cloudflared-connector"
)

var workloadConnectionSkewGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_workload_connection_skew",
	Help: "1 while a multi-replica Deployment exhibits sustained (>=15m) L4 network byte-rate skew (max/median > 4x at median > 1000 B/s).",
}, []string{"namespace", "deployment", "pod"})

func init() {
	ctrlmetrics.Registry.MustRegister(workloadConnectionSkewGauge)
}

type workloadConnectionSkewGuardCheck struct {
	*probefw.Deps

	rebalanceEnabled bool
	allowlist        map[string]bool

	firstSeen state.FirstSeenLedger
	emitted   state.GaugeLedger[string]
}

// NewWorkloadConnectionSkewGuardCheck builds the workload-connection-skew-guard
// check, resolving WORKLOAD_CONNECTION_SKEW_REBALANCE_ENABLED and
// WORKLOAD_CONNECTION_SKEW_REBALANCE_ALLOWLIST at construction.
func NewWorkloadConnectionSkewGuardCheck(d *probefw.Deps) probefw.Check {
	return &workloadConnectionSkewGuardCheck{
		Deps:             d,
		rebalanceEnabled: envx.Gate("WORKLOAD_CONNECTION_SKEW_REBALANCE_ENABLED", true),
		allowlist: parseAllowlist(envx.Getenv(
			"WORKLOAD_CONNECTION_SKEW_REBALANCE_ALLOWLIST", connSkewDefaultAllowlist)),
	}
}

func parseAllowlist(raw string) map[string]bool {
	out := map[string]bool{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		out[entry] = true
	}
	return out
}

type podRate struct {
	pod  *corev1.Pod
	rate float64
}

func medianF64(vals []float64) float64 {
	sorted := slices.Clone(vals)
	slices.Sort(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

// Run queries passiontech:workload_pod_net_bytes:rate10m, groups Ready
// Deployment-owned pods by namespace/deployment, flags sustained (>=15m)
// >4x max/median skew above 1000 B/s median, and rebalances allowlisted
// Deployments by deleting the single hottest Ready pod via SafePodDelete.
func (p *workloadConnectionSkewGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	now := p.Now()
	var rep probefw.SweepReport
	const why = "workload L4 connection skew persisted >=15m (>4x median, >1000 B/s): "

	done := func() probefw.Result {
		return rep.Result(&p.emitted, workloadConnectionSkewGauge.DeleteLabelValues, why, ", ")
	}
	doneFresh := func() probefw.Result {
		p.firstSeen.Prune(func(string) bool { return false })
		return done()
	}
	doneInconclusive := func() probefw.Result {
		for k, lv := range p.emitted.Last() {
			rep.Carry(k, lv)
			rep.Find(k + " (carried — prometheus inconclusive)")
		}
		return done()
	}

	if _, err := p.PromEndpointCtx(ctx); err != nil {
		return doneInconclusive()
	}
	samples, err := p.PromQuery(ctx, connSkewQuery)
	if err != nil {
		log.Info("WARN: connection-skew query failed — check inconclusive", "error", err)
		return doneInconclusive()
	}
	if len(samples) == 0 {
		// Recording rule absent or cluster idle — gracefully pass and clear ledger.
		return doneFresh()
	}

	pods, err := p.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}
	podByKey := make(map[string]*corev1.Pod, len(pods))
	for i := range pods {
		pod := &pods[i]
		podByKey[pod.Namespace+"/"+pod.Name] = pod
	}
	readyByOwner := probefw.ReadyByOwner(pods)

	// Group Ready, Deployment-owned (ReplicaSet-controlled) pods by
	// namespace/deployment. Deduplicate duplicate pod series by taking the max
	// observed rate for that pod.
	type depGroup struct {
		ns, deploy string
		byPod      map[string]podRate
	}
	groups := map[string]*depGroup{}
	for _, s := range samples {
		ns := s.Label("namespace")
		deploy := s.Label("deployment")
		podName := s.Label("pod")
		if ns == "" || deploy == "" || podName == "" ||
			math.IsNaN(s.Value) || math.IsInf(s.Value, 0) || s.Value < 0 {
			continue
		}
		pod := podByKey[ns+"/"+podName]
		if pod == nil || !probefw.PodRunningReady(pod) {
			continue
		}
		// Only Deployment-owned pods (ReplicaSet controller); exclude
		// StatefulSet/DaemonSet/standalone pods that may also appear in the
		// recording rule.
		ctrl := metav1.GetControllerOf(pod)
		if ctrl == nil || ctrl.Kind != "ReplicaSet" {
			continue
		}
		depKey := ns + "/" + deploy
		g := groups[depKey]
		if g == nil {
			g = &depGroup{ns: ns, deploy: deploy, byPod: map[string]podRate{}}
			groups[depKey] = g
		}
		if prev, exists := g.byPod[pod.Name]; !exists || s.Value > prev.rate {
			g.byPod[pod.Name] = podRate{pod: pod, rate: s.Value}
		}
	}

	depKeys := make([]string, 0, len(groups))
	for k := range groups {
		depKeys = append(depKeys, k)
	}
	slices.Sort(depKeys)

	liveSkew := map[string]bool{}
	for _, depKey := range depKeys {
		g := groups[depKey]
		if len(g.byPod) < connSkewMinReadyPods {
			continue
		}
		rates := make([]float64, 0, len(g.byPod))
		var hottest podRate
		first := true
		for _, pr := range g.byPod {
			rates = append(rates, pr.rate)
			if first || pr.rate > hottest.rate ||
				(pr.rate == hottest.rate && cmp.Compare(pr.pod.Name, hottest.pod.Name) < 0) {
				hottest = pr
				first = false
			}
		}
		med := medianF64(rates)
		if med <= connSkewMinMedianBytesPerSec {
			continue
		}
		ratio := hottest.rate / med
		if ratio <= connSkewRatioThreshold {
			continue
		}

		liveSkew[depKey] = true
		if !probefw.Persisted(&p.firstSeen, depKey, now, connSkewMinAge, log) {
			continue
		}

		rep.Emit(workloadConnectionSkewGauge, depKey+"/"+hottest.pod.Name,
			[]string{g.ns, g.deploy, hottest.pod.Name},
			fmt.Sprintf("%s hottest=%s ratio=%.1fx median=%.0fB/s",
				depKey, hottest.pod.Name, ratio, med))

		if p.rebalanceEnabled && p.allowlist[depKey] {
			p.SafePodDelete(ctx, log, CheckNameWorkloadConnectionSkewGuard,
				hottest.pod, readyByOwner, 1, connSkewHealCooldown, now)
		}
	}

	p.firstSeen.Prune(func(k string) bool { return liveSkew[k] })
	return done()
}
