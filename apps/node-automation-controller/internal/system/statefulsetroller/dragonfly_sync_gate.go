// dragonfly_sync_gate.go — the D16 cold-start gate for Dragonfly/
// Valkey StatefulSets (roadmap D16): a replica pod's Ready=True only
// proves the port ANSWERS — while a replica is mid-FULL-SYNC (its
// master_link_status still down, the entire dataset streaming over),
// rolling the NEXT OnDelete member stacks a second cold replica on
// the master and turns one restart into the cache-stampede storm the
// dragonfly-replica-sync-storm check watches for. The gate reads the
// SAME Prometheus evidence that check uses —
// dragonfly_master_link_status / redis_master_link_status == 0 for
// any member pod — and defers the roll until every member's link is
// up (full-sync complete).
//
// Evidence posture: the gate is best-effort availability-preserving,
// not fail-closed — a Prometheus outage or an unresolvable endpoint
// defers to gates 1-3 (the roller must not lose its roll ability to
// a monitoring outage), while a PRESENT series reading 0 blocks
// hard. Members without a series (exporter not scraped yet) are not
// evidence either way and do not block.
package statefulsetroller

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/httpx"
)

var dragonflySyncHTTP = &http.Client{
	Transport: httpx.PooledTransport(16, nil),
	Timeout:   dragonflySyncQueryTimeout,
}

const (
	// dragonflySyncQueryTimeout bounds the master-link instant query
	// — a slow Prometheus must not stretch the roll sweep.
	dragonflySyncQueryTimeout = 8 * time.Second
	// dragonflyLinkDownQuery is the master-link evidence query — the
	// same series pair the dragonfly-replica-sync-storm check reads;
	// a sample means that pod's replica link is DOWN mid-sync.
	dragonflyLinkDownQuery = `(dragonfly_master_link_status{namespace="%s"} == 0) ` +
		`or (redis_master_link_status{namespace="%s"} == 0)`
	// dragonflyPromFallbackURL is the default http-content-check
	// target — the cluster's kube-prometheus-stack Prometheus. The
	// literal repeats ported.HTTPContentConfigFromEnv's default (the
	// system domain may not import the health domain — depguard
	// nac-domain-no-cross-system).
	dragonflyPromFallbackURL = "http://kube-prometheus-stack-prometheus.prometheus-operator.svc:9090/-/healthy"
)

// dragonflyPromSeam is the Setup-time Prometheus wiring the
// dragonfly gate reads: endpoint + client resolved ONCE (env inside
// a run is a bug — the probefw contract). ok=false leaves the gate
// inert (logged at Setup): no endpoint, no evidence source.
type dragonflyPromSeam struct {
	endpoint string
	client   promq.Client
	ok       bool
}

// newDragonflyPromSeam resolves the endpoint exactly like probefw's
// PromEndpoint derivation: HEALTH_PROMETHEUS_QUERY_URL (a full
// /api/v1/query URL) wins, else scheme://host of the
// http-content-check target.
func newDragonflyPromSeam() dragonflyPromSeam {
	endpoint, err := promq.ResolveEndpoint(
		envx.Getenv("HEALTH_PROMETHEUS_QUERY_URL", ""),
		envx.Getenv("HEALTH_HTTP_CONTENT_URL", dragonflyPromFallbackURL))
	if err != nil {
		return dragonflyPromSeam{}
	}
	return dragonflyPromSeam{
		endpoint: endpoint,
		client: promq.Client{
			HTTP:    dragonflySyncHTTP,
			Timeout: dragonflySyncQueryTimeout,
		},
		ok: true,
	}
}

// dragonflyReplicaSet reports whether the StatefulSet's pod template
// belongs to a Dragonfly workload — the same label family the
// dragonfly-replica-sync-storm check matches live pods with
// (app.kubernetes.io/name=dragonfly, part-of/created-by fallbacks,
// or any label value carrying the name). The template is the stable
// identity (live pods churn across rollouts).
func dragonflyReplicaSet(sts *appsv1.StatefulSet) bool {
	labels := sts.Spec.Template.Labels
	if labels["app.kubernetes.io/name"] == "dragonfly" ||
		labels["app.kubernetes.io/part-of"] == "dragonfly" ||
		labels["app.kubernetes.io/created-by"] == "dragonfly-operator" {
		return true
	}
	for _, v := range labels {
		if strings.Contains(v, "dragonfly") {
			return true
		}
	}
	return false
}

// dragonflyReplicasSynced runs the master-link query scoped to the
// StatefulSet's namespace and reports whether EVERY member pod's
// replica link is up (no series == 0 among them). true when the
// evidence shows sync complete or supplies none (query failure is
// warned and tolerated — the gate must not outvote gates 1-3 on a
// monitoring outage; a member without a series is unevidenceable,
// same posture as the storm check's label-less drop).
func (r *statefulSetOnDeleteRoller) dragonflyReplicasSynced(ctx context.Context,
	log logr.Logger, sts *appsv1.StatefulSet, pods []*corev1.Pod) bool {

	if !r.prom.ok {
		return true // no endpoint at Setup — gate inert
	}
	// Label-value escaping for the selector — namespaces are DNS
	// labels, but a hostile label must not break out of the string.
	ns := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(sts.Namespace)
	query := fmt.Sprintf(dragonflyLinkDownQuery, ns, ns)
	series, err := r.prom.client.InstantQuery(ctx, r.prom.endpoint, query)
	if err != nil {
		log.Info("WARN: dragonfly master-link query failed — sync gate skipped",
			"statefulset", sts.Namespace+"/"+sts.Name, "error", err)
		return true
	}
	members := map[string]bool{}
	for _, p := range pods {
		members[p.Name] = true
	}
	for _, s := range series {
		name := s.Label("pod", "pod_name")
		if !members[name] {
			continue // other workloads sharing the namespace
		}
		log.Info("skip: dragonfly replica not synced with master — deferring the OnDelete roll",
			"statefulset", sts.Namespace+"/"+sts.Name,
			"pod", name,
			"masterLinkStatus", s.Value)
		metrics.StatefulSetOnDeleteDragonflyUnsyncedSkipped.
			WithLabelValues(sts.Namespace, sts.Name).Inc()
		return false
	}
	return true
}
