// cilium_bpf_map_pressure.go — the cilium-bpf-map-pressure check
// (W10-NM1): Prometheus max by (node, map_name)
// (cilium_bpf_map_pressure) above the fill threshold means a BPF
// map is approaching max_entries — a full map blackholes the
// traffic class it serves (conntrack full = all new flows
// dropped).
package clusterhealthprobes

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	checkNameCiliumBPFMapPressure = "cilium-bpf-map-pressure"

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
func (p *clusterHealthProber) checkCiliumBPFMapPressure(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	threshold := healthEnvFloat("CILIUM_BPF_MAP_PRESSURE_THRESHOLD", ciliumBPFDefaultThreshold)
	query := fmt.Sprintf(
		`max by (node, map_name) (cilium_bpf_map_pressure) > %s`,
		strconv.FormatFloat(threshold, 'f', -1, 64))
	series, err := p.promInstantQuery(ctx, query)
	if err != nil {
		log.Info("WARN: cilium bpf map pressure query failed — check inconclusive",
			"error", err)
		return probeResult{pass: true}
	}
	current := map[string][]string{}
	var findings []string
	for _, s := range series {
		node := promLabelValue(s, "node", "kubernetes_node", "instance")
		mapName := s.metric["map_name"]
		if node == "" || mapName == "" {
			continue
		}
		lv := []string{node, mapName}
		current[node+"/"+mapName] = lv
		ciliumBPFMapPressureGauge.WithLabelValues(lv...).Set(s.value)
		findings = append(findings,
			fmt.Sprintf("%s/%s=%.2f", node, mapName, s.value))
	}
	sort.Strings(findings)
	reconcileEmittedGauges(checkNameCiliumBPFMapPressure,
		ciliumBPFMapPressureGauge, current)
	if len(findings) == 0 {
		return probeResult{pass: true}
	}
	return probeResult{why: fmt.Sprintf(
		"cilium_bpf_map_pressure>%s: %s",
		strconv.FormatFloat(threshold, 'f', -1, 64),
		strings.Join(findings, ", "))}
}
