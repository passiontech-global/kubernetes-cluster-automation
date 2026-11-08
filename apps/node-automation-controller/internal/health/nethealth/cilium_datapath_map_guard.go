// cilium_datapath_map_guard.go — the cilium-datapath-map-guard check:
// a cilium-agent can stay process-alive while its datapath silently
// degrades — BPF map update failures (policy/identity maps
// desyncing), endpoint regeneration failures (pods running stale
// programs), unreachable health endpoints (the agent's own
// connectivity probe failing), and drops stamped "Invalid identity"
// or "Unknown L3 target address" (stale ipcache entries dropping
// legitimate traffic — the classic post-mortem shape where the
// datapath lies while every readiness probe stays green). Each
// signature is a Prometheus query; any breached one emits
// node_automation_cilium_datapath_degraded{reason} and fails the
// check.
package nethealth

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// ciliumDatapathMapCheck is the cilium datapath-degradation watchdog.
type ciliumDatapathMapCheck struct {
	*probefw.Deps

	// emitted is the emitted-gauge ledger — a reason that stops
	// breaching gets its series deleted rather than pinning stale.
	emitted state.GaugeLedger[string]
}

// NewCiliumDatapathMapGuardCheck builds the
// cilium-datapath-map-guard check.
func NewCiliumDatapathMapGuardCheck(d *probefw.Deps) probefw.Check {
	return &ciliumDatapathMapCheck{Deps: d}
}

const CheckNameCiliumDatapathMapGuard = "cilium-datapath-map-guard"

// ciliumDatapathQueries is the degraded-signature table: each reason
// is the gauge label value, the query is a Prometheus instant query
// whose non-empty result means the signature is live (the >threshold
// comparison rides inside the query, same convention as
// cilium-bpf-map-pressure).
var ciliumDatapathQueries = []struct {
	reason string
	query  string
	desc   string
}{
	{"bpf_map_ops_fail",
		`sum(rate(cilium_bpf_map_ops_total{outcome="fail"}[5m])) > 0`,
		"BPF map operations failing"},
	{"endpoint_regeneration_fail",
		`sum(rate(cilium_endpoint_regeneration_total{outcome="fail"}[5m])) > 0`,
		"endpoint regenerations failing"},
	{"unreachable_health_endpoints",
		`sum(cilium_unreachable_health_endpoints) > 0`,
		"cilium health endpoints unreachable"},
	{"invalid_identity_drops",
		`sum(rate(cilium_drop_count_total{reason=~"Invalid identity|Unknown L3 target address"}[5m])) > 1`,
		"drops from stale ipcache identities"},
}

var (
	// cilium-datapath-map-guard — 1 while a datapath-degraded
	// signature is live, by reason.
	ciliumDatapathDegradedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_cilium_datapath_degraded",
		Help: "1 while the cilium datapath shows a degraded signature, by reason.",
	}, []string{"reason"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		ciliumDatapathDegradedGauge)
}

// checkCiliumDatapathMap runs each signature query against
// Prometheus. A query failure is inconclusive, not clear — the
// reason's last-verdict tuple is carried forward so one scrape flap
// cannot flap a live degraded series off (the carry-forward contract
// every emitted-gauge check holds).
func (p *ciliumDatapathMapCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	var rep probefw.SweepReport
	last := p.emitted.Last()
	for _, q := range ciliumDatapathQueries {
		series, err := p.PromQuery(ctx, q.query)
		if err != nil {
			log.Info("WARN: cilium datapath query failed — signature inconclusive",
				"reason", q.reason, "error", err)
			rep.InfraErr(err)
			if lv, held := last[q.reason]; held {
				rep.Carry(q.reason, lv)
			}
			continue
		}
		if len(series) == 0 {
			continue
		}
		rep.Emit(ciliumDatapathDegradedGauge, q.reason,
			[]string{q.reason},
			fmt.Sprintf("%s (%s)", q.reason, q.desc))
	}
	return rep.Result(&p.emitted, ciliumDatapathDegradedGauge.DeleteLabelValues,
		"cilium datapath degraded: ", ", ")
}
