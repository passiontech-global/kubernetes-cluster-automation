// cilium_bpf_map_pressure.go — the cilium-bpf-map-pressure check
// (W10-NM1): Prometheus max by (node, map_name)
// (cilium_bpf_map_pressure) above the fill threshold means a BPF
// map is approaching max_entries — a full map blackholes the
// traffic class it serves (conntrack full = all new flows
// dropped).
package nethealth

import (
	"context"
	"fmt"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"sort"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
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

// newCiliumBPFMapPressureCheck builds the W10-NM1 check — its only
// state is the emitted-gauge ledger.
func NewCiliumBPFMapPressureCheck(d *probefw.Deps) probefw.Check {
	return &ciliumBPFMapPressureCheck{Deps: d}
}

const (
	CheckNameCiliumBPFMapPressure = "cilium-bpf-map-pressure"

	// W10-NM1 — cilium-bpf-map-pressure knobs.
	ciliumBPFDefaultThreshold = 0.85
)

var (
	// W10-NM1 — Cilium BPF map fill ratio per node/map.
	ciliumBPFMapPressureGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_cilium_bpf_map_pressure",
		Help: "Cilium BPF map fill ratio (used/max) per node and map_name — W10-NM1.",
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
	// GetenvFloatPositive keeps >1 (the documented "disable this
	// check" escape) and rejects <=0 — the same contract the retired
	// healthEnvFloat had.
	threshold := envx.GetenvFloatPositive("CILIUM_BPF_MAP_PRESSURE_THRESHOLD", ciliumBPFDefaultThreshold)
	query := `max by (node, map_name) (cilium_bpf_map_pressure) > ` +
		strconv.FormatFloat(threshold, 'f', -1, 64)
	series, err := p.PromQuery(ctx, query)
	if err != nil {
		log.Info("WARN: cilium bpf map pressure query failed — check inconclusive",
			"error", err)
		return probefw.Result{Pass: true}
	}
	current := map[string][]string{}
	var findings []string
	for _, s := range series {
		node := s.Label("node", "kubernetes_node", "instance")
		mapName := s.Metric["map_name"]
		if node == "" || mapName == "" {
			continue
		}
		lv := []string{node, mapName}
		current[node+"/"+mapName] = lv
		ciliumBPFMapPressureGauge.WithLabelValues(lv...).Set(s.Value)
		findings = append(findings,
			fmt.Sprintf("%s/%s=%.2f", node, mapName, s.Value))
	}
	sort.Strings(findings)
	p.emitted.Reconcile(current, ciliumBPFMapPressureGauge.DeleteLabelValues)
	if len(findings) == 0 {
		return probefw.Result{Pass: true}
	}
	return probefw.Result{Why: fmt.Sprintf(
		"cilium_bpf_map_pressure>%s: %s",
		strconv.FormatFloat(threshold, 'f', -1, 64),
		strings.Join(findings, ", "))}
}
