// cilium_bpf_map_pressure.go — the cilium-bpf-map-pressure check
// (cilium-bpf-map-pressure): Prometheus max by (node, map_name)
// (cilium_bpf_map_pressure) above the fill threshold means a BPF
// map is approaching max_entries — a full map blackholes the
// traffic class it serves (conntrack full = all new flows
// dropped).
package nethealth

import (
	"context"
	"fmt"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// ciliumBPFMapPressureCheck is the cilium BPF map pressure watchdog.
type ciliumBPFMapPressureCheck struct {
	*probefw.Deps

	// emitted is the emitted-gauge ledger — a tuple that stops
	// being reported gets DeleteLabelValues'd rather than leaking a
	// stale value (zero value usable; the serial sweep needs no
	// lock).
	emitted state.GaugeLedger[string]
}

// newCiliumBPFMapPressureCheck builds the cilium-bpf-map-pressure check — its only
// state is the emitted-gauge ledger.
func NewCiliumBPFMapPressureCheck(d *probefw.Deps) probefw.Check {
	return &ciliumBPFMapPressureCheck{Deps: d}
}

const (
	CheckNameCiliumBPFMapPressure = "cilium-bpf-map-pressure"
)

var (
	// cilium-bpf-map-pressure — Cilium BPF map fill ratio per node/map.
	ciliumBPFMapPressureGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_cilium_bpf_map_pressure",
		Help: "Cilium BPF map fill ratio (used/max) per node and map_name — cilium-bpf-map-pressure.",
	}, []string{"node", "map_name"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		ciliumBPFMapPressureGauge)
}

// checkCiliumBPFMapPressure queries Prometheus for BPF maps whose fill
// ratio exceeds the threshold — a map at max_entries drops the traffic
// class it serves silently (full conntrack = every new flow refused).
// Prometheus-unreachable is inconclusive (http-content-check already
// owns Prometheus liveness) — the check passes with a WARN, never a
// false FAIL.
func (p *ciliumBPFMapPressureCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	// The CILIUM_BPF_MAP_PRESSURE_THRESHOLD knob resolves once at
	// sweep Setup (CiliumConfigFromEnv — >1 keeps working as
	// the documented "disable this check" escape).
	threshold := p.Cfg.Cilium.BPFMapPressureThreshold
	query := `max by (node, map_name) (cilium_bpf_map_pressure) > ` +
		strconv.FormatFloat(threshold, 'f', -1, 64)
	series, err := p.PromQuery(ctx, query)
	if err != nil {
		log.Info("WARN: cilium bpf map pressure query failed — check inconclusive",
			"error", err)
		return probefw.Result{Pass: true}
	}
	var rep probefw.SweepReport
	for _, s := range series {
		node := s.Label("node", "kubernetes_node", "instance")
		mapName := s.Metric["map_name"]
		if node == "" || mapName == "" {
			continue
		}
		rep.Set(ciliumBPFMapPressureGauge, s.Value, node+"/"+mapName,
			[]string{node, mapName})
		rep.Find(fmt.Sprintf("%s/%s=%.2f", node, mapName, s.Value))
	}
	return rep.Result(&p.emitted, ciliumBPFMapPressureGauge.DeleteLabelValues,
		fmt.Sprintf("cilium_bpf_map_pressure>%s: ",
			strconv.FormatFloat(threshold, 'f', -1, 64)), ", ")
}
