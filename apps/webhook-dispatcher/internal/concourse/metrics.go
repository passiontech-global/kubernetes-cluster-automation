// Prometheus metrics for the Concourse index client. Like the handler
// metrics, they live on the DEDICATED registry main serves on the
// internal listener — never prometheus.DefaultRegisterer, so the
// GitHub-facing public listener exposes no index internals.
package concourse

import "github.com/prometheus/client_golang/prometheus"

var (
	// indexLastRefreshSeconds is the unix timestamp of the last
	// successful index fetch (Resources or Refresh). A value frozen
	// while wall-clock advances is the "everything answers 202 from a
	// stale index" alarm: it moves only when the ATC actually gave us
	// a fresh index, so a stalled ATC shows up as an aging gauge
	// rather than as silence.
	indexLastRefreshSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "webhook_dispatcher_concourse_index_last_refresh_timestamp_seconds",
		Help: "Unix timestamp of the last successful Concourse resource-index fetch — an aging value means deliveries are matching against a stale index.",
	})
	// indexFetchErrorsTotal counts every failed fetch attempt, folded
	// into the same paths that write the lastErr/lastErrAt negative
	// cache. It climbs even when a stale index was served instead —
	// deliveries keep flowing while it does, so it is a "look at the
	// ATC" signal, not a delivery-loss signal.
	indexFetchErrorsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "webhook_dispatcher_concourse_index_fetch_errors_total",
		Help: "Failed Concourse resource-index fetch attempts, including attempts whose stale index was served in place of the refresh.",
	})
)

// RegisterMetrics registers the client's freshness metrics on reg —
// main builds one dedicated registry for the internal listener and
// hands it to each package's RegisterMetrics. Panics on duplicate
// registration; called exactly once at boot.
func RegisterMetrics(reg *prometheus.Registry) {
	reg.MustRegister(indexLastRefreshSeconds, indexFetchErrorsTotal)
}
