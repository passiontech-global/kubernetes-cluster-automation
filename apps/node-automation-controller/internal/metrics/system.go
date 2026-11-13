// system.go — series emitted by the internal/system modules:
// cftunnelproxywatchdog (the cloudflare-tunnel-gateway-controller
// sync-error audit). Var order and comments follow the domain-file
// layout of apiserver.go/integration.go.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// CFTunnelGatewaySyncError is 1 while the last
// cfTunnelSyncErrClearAfter window saw a sync-error signature in the
// cloudflare-tunnel-gateway-controller's log tail, 0 otherwise (set
// once the first sweep detects it — see
// cftunnelproxywatchdog.auditControllerSyncErrors). Single-check
// series (Wave 5.1 consolidated out of the module file into the
// system domain file).
var CFTunnelGatewaySyncError = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "node_automation_cftunnel_gateway_sync_error",
	Help: "1 while the cloudflare-tunnel-gateway-controller log tail (5m window) carries a tunnel-config sync error (failed to update tunnel configuration, 429, authentication error) — cf-gateway-sync-error.",
}, []string{"namespace"})

// systemCollectors lists every vector declared in this file, in
// declaration order; the single init() below registers the table, so
// registration order stays byte-stable and adding a metric touches
// only this file.
var systemCollectors = []prometheus.Collector{
	CFTunnelGatewaySyncError,
}

func init() {
	for _, c := range systemCollectors {
		ctrlmetrics.Registry.MustRegister(c)
	}
}
