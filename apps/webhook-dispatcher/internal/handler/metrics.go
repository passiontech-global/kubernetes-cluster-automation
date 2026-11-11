package handler

import "github.com/prometheus/client_golang/prometheus"

// Prometheus metrics for the delivery path — registered by main on
// the DEDICATED internal-listener registry (RegisterMetrics below),
// never on prometheus.DefaultRegisterer: the public listener faces
// GitHub and must not serve metrics.
var deliveriesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "webhook_dispatcher_deliveries_total",
	Help: "GitHub webhook deliveries handled, by event (normalized to " +
		"push|pull_request|release|create|none|other) and outcome " +
		"(dispatched|ignored|unauthorized|payload_too_large|bad_request|index_unavailable).",
}, []string{"event", "status"})

// metricEventLabel maps an X-GitHub-Event header value onto the fixed
// "event" label set of deliveriesTotal. The header is attacker-
// controlled and feeds WithLabelValues BEFORE the HMAC check runs, so
// an unbounded value space is a metrics-cardinality DoS (each distinct
// value grows a new time-series). Only the dispatched events keep
// their name; anything else collapses to "other" and a missing header
// reports "none".
func metricEventLabel(event string) string {
	switch event {
	case "push", "pull_request", "release", "create":
		return event
	case "":
		return "none"
	default:
		return "other"
	}
}

var fanoutTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "webhook_dispatcher_fanout_total",
	Help: "Concourse resource check webhooks dispatched, by result " +
		"(ok|rejected|error|budget — budget = target gave up its slot " +
		"queue when the fan-out budget expired, no POST was sent).",
}, []string{"result"})

// fanoutDuration buckets span a fast single-target fan-out up to a
// worst-case semaphore-serialized burst (16 workers x 15s per target).
var fanoutDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
	Name:    "webhook_dispatcher_fanout_duration_seconds",
	Help:    "Wall-clock seconds to dispatch every check webhook of one delivery.",
	Buckets: prometheus.ExponentialBuckets(0.05, 2, 12), // 50ms .. ~102s
})

// RegisterMetrics registers the delivery/fan-out metrics on reg —
// main builds one dedicated registry for the internal listener and
// hands it to each package's RegisterMetrics. Panics on duplicate
// registration; called exactly once at boot.
func RegisterMetrics(reg *prometheus.Registry) {
	reg.MustRegister(deliveriesTotal, fanoutTotal, fanoutDuration)
}
