package handler

import "github.com/prometheus/client_golang/prometheus"

// Prometheus metrics — registered on the default registry so main
// can serve them with promhttp.Handler() unchanged.
var deliveriesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "webhook_dispatcher_deliveries_total",
	Help: "GitHub webhook deliveries handled, by event and outcome " +
		"(dispatched|ignored|unauthorized|payload_too_large|bad_request|index_unavailable).",
}, []string{"event", "status"})

var fanoutTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "webhook_dispatcher_fanout_total",
	Help: "Concourse resource check webhooks dispatched, by result (ok|rejected|error).",
}, []string{"result"})

// fanoutDuration buckets span a fast single-target fan-out up to a
// worst-case semaphore-serialized burst (16 workers x 15s per target).
var fanoutDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
	Name:    "webhook_dispatcher_fanout_duration_seconds",
	Help:    "Wall-clock seconds to dispatch every check webhook of one delivery.",
	Buckets: prometheus.ExponentialBuckets(0.05, 2, 12), // 50ms .. ~102s
})

func init() {
	prometheus.MustRegister(deliveriesTotal, fanoutTotal, fanoutDuration)
}
