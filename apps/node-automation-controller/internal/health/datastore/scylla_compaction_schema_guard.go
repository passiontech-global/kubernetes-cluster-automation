// scylla_compaction_schema_guard.go — the
// scylla-compaction-schema-guard check: scrapes each Ready member
// pod's :9180/metrics for a compaction backlog (>100 pending) and a
// coordinator schema-version split across members of the same
// cluster — both signatures the ScyllaCluster CR status can't see.
// W12-ST3 adds the Seastar shared-nothing signatures the same scrape
// already carries: a per-shard reactor-utilization skew (hot
// partition / tombstone avalanche saturating one shard while the
// pod stays Ready) and the per-sweep delta of the coordinator/
// sstable/querier-cache stall counters. Detection-only: no heals,
// the gauges are the alert contract.
package datastore

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

// scyllaCompactionSchemaGuardCheck is the compaction/schema
// split-brain watchdog.
type scyllaCompactionSchemaGuardCheck struct {
	*probefw.Deps

	// emittedBacklog/emittedSplit are the emitted-gauge ledgers —
	// tuples that stop being reported get DeleteLabelValues'd rather
	// than leaking stale values (zero value usable; the serial sweep
	// needs no lock). emittedShard/emittedOverload are the W12-ST3
	// twins for the shard-imbalance and overload-stall gauges.
	// shardImbalanceSeen is the W12-ST3 first-seen ledger —
	// "ns/pod" → first sweep the hot-partition skew showed; it must
	// persist scyllaShardImbalanceMinAge before the gauge fires.
	// overloadLast is the per-pod counter baseline —
	// "ns/pod" → last sweep's stall counters; an increase between
	// sweeps is a live stall, a reset means the pod restarted.
	emittedBacklog     state.GaugeLedger[string]
	emittedSplit       state.GaugeLedger[string]
	emittedShard       state.GaugeLedger[string]
	emittedOverload    state.GaugeLedger[string]
	shardImbalanceSeen state.FirstSeenLedger
	overloadLast       map[string]scyllaOverloadSample
}

// NewScyllaCompactionSchemaGuardCheck builds the guard — its only
// state is the two emitted-gauge ledgers; the check is
// detection-only and carries no heal state.
func NewScyllaCompactionSchemaGuardCheck(d *probefw.Deps) probefw.Check {
	return &scyllaCompactionSchemaGuardCheck{Deps: d}
}

const (
	CheckNameScyllaCompactionSchemaGuard = "scylla-compaction-schema-guard"

	// scylla-compaction-schema-guard knobs.
	scyllaCompactionBacklogMax = 100
	scyllaMetricsPort          = 9180
	scyllaMetricsTimeout       = 8 * time.Second

	// W12-ST3 — shard-imbalance signature: a Scylla pod's busiest
	// shard saturated while the average shard idles is the
	// hot-partition / tombstone-skew shape (a shard-per-core pod can
	// stall 1/8th of its coordinator work while staying Ready).
	scyllaShardHotUtil          = 0.98
	scyllaShardAvgUtilMax       = 0.50
	scyllaShardImbalanceMinAge  = 10 * time.Minute
	scyllaShardImbalanceMinSets = 2 // need >=2 shards for a skew to exist

	// W12-ST3 — overload stall counter names, all scraped off the
	// same :9180/metrics body: coordinator read timeouts, the
	// sstable read queue's overload drops and the querier cache's
	// drops. These are cumulative counters — a positive delta
	// between sweeps is a stall in progress.
	scyllaOverloadReasonReadTimeouts  = "read_timeouts"
	scyllaOverloadReasonQueueOverload = "sstable_queue_overloads"
	scyllaOverloadReasonCacheDrops    = "querier_cache_drops"
)

var (
	// Compaction backlog per member pod.
	scyllaCompactionBacklogGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_scylla_compaction_backlog",
		Help: "scylla_compaction_manager_pending_compactions per member pod — >100 means compaction cannot keep up.",
	}, []string{"namespace", "pod"})

	// Coordinator schema-version split across a cluster's members.
	scyllaSchemaSplitGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_scylla_schema_split",
		Help: "1 while members of the cluster report divergent coordinator schema versions.",
	}, []string{"namespace", "cluster"})

	// W12-ST3 — a member pod whose hottest shard is saturated while
	// the average shard idles: the hot-partition / tombstone skew
	// that stalls a fraction of coordinator work on a Ready pod.
	scyllaShardImbalanceGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_scylla_shard_imbalance",
		Help: "1 while a Scylla pod's max per-shard reactor utilization >=0.98 with shard-average <=0.50 for >=10m.",
	}, []string{"namespace", "pod"})

	// W12-ST3 — overload stalls in progress: per-sweep delta of the
	// coordinator/sstable/querier-cache stall counters.
	scyllaOverloadStallGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_scylla_overload_stall",
		Help: "Increase of a Scylla stall counter between sweeps (coordinator read timeouts, sstable read queue overloads, querier cache drops).",
	}, []string{"namespace", "pod", "reason"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		scyllaCompactionBacklogGauge,
		scyllaSchemaSplitGauge,
		scyllaShardImbalanceGauge,
		scyllaOverloadStallGauge)
}

// scyllaScrape is everything one :9180/metrics fetch yields for a
// member pod — the W12-ST3 additions read off the SAME body, so the
// pod pays zero extra HTTP calls for the shard/overload signatures.
type scyllaScrape struct {
	backlog  float64            // max scylla_compaction_manager_pending_compactions
	versions map[float64]bool   // coordinator schema versions reported
	shards   map[string]float64 // shard label -> scylla_reactor_utilization
	overload scyllaOverloadSample
}

// scyllaOverloadSample is the cumulative stall-counter snapshot used
// for the per-sweep delta: coordinator read timeouts, sstable read
// queue overloads, querier cache drops (each the max sample across
// series of that name — shard/shard-group split sums would
// double-count).
type scyllaOverloadSample struct {
	readTimeouts   float64
	queueOverloads float64
	cacheDrops     float64
}

// scyllaPodMetrics fetches the pod's :9180/metrics and returns every
// signature the page carries. ok=false on fetch/parse failure —
// inconclusive, not healthy (a dead endpoint and a sick pod are
// indistinguishable from here).
func (p *scyllaCompactionSchemaGuardCheck) scyllaPodMetrics(ctx context.Context,
	pod *corev1.Pod) (*scyllaScrape, bool) {

	body, err := probefw.FetchPodMetrics(ctx, p.HTTPClient,
		pod.Status.PodIP, scyllaMetricsPort, scyllaMetricsTimeout, 4<<20)
	if err != nil {
		return nil, false
	}
	text := string(body)
	sc := &scyllaScrape{
		versions: map[float64]bool{},
		shards:   map[string]float64{},
	}
	for _, v := range probefw.ParseMetricValues(text,
		"scylla_compaction_manager_pending_compactions") {
		if v > sc.backlog {
			sc.backlog = v
		}
	}
	for _, v := range probefw.ParseMetricValues(text,
		"scylla_storage_proxy_coordinator_schema_version") {
		sc.versions[v] = true
	}
	// W12-ST3 — same body, per-shard reactor utilization and the
	// overload stall counters.
	sc.shards = scyllaShardValues(text, "scylla_reactor_utilization", "shard")
	sc.overload = scyllaOverloadSample{
		readTimeouts: scyllaMaxMetricValue(text,
			"scylla_storage_proxy_coordinator_read_timeouts"),
		queueOverloads: scyllaMaxMetricValue(text,
			"scylla_database_sstable_read_queue_overloads"),
		cacheDrops: scyllaMaxMetricValue(text,
			"scylla_database_querier_cache_drops"),
	}
	return sc, true
}

// scyllaMaxMetricValue returns the largest sample of name in the
// exposition — the counters this check reads fan out per shard /
// scheduling group, and the max is the conservative "some shard is
// stalling" read (a sum would multiply-count overlapping series).
func scyllaMaxMetricValue(body, name string) float64 {
	var max float64
	for _, v := range probefw.ParseMetricValues(body, name) {
		if v > max {
			max = v
		}
	}
	return max
}

// scyllaShardValues parses `name{...label="X"...} v` samples into a
// label->value map — ParseMetricValues drops the labels, but the
// per-shard skew IS the labels.
func scyllaShardValues(body, name, label string) map[string]float64 {
	out := map[string]float64{}
	for _, line := range strings.Split(body, "\n") {
		v, ok := probefw.ParseMetricValue(line, name)
		if !ok {
			continue
		}
		if lv, ok := scyllaLabelValue(line, label); ok {
			out[lv] = v
		}
	}
	return out
}

// scyllaLabelValue extracts key="value" from a metric line's
// {label set} — a first-wins scan, which is fine because the scylla
// exposition writes each label key once per series.
func scyllaLabelValue(line, key string) (string, bool) {
	lb := strings.Index(line, "{")
	rb := strings.LastIndex(line, "}")
	if lb < 0 || rb <= lb {
		return "", false
	}
	for _, kv := range strings.Split(line[lb+1:rb], ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if ok && k == key {
			return strings.Trim(v, `"`), true
		}
	}
	return "", false
}

// checkScyllaCompactionSchemaGuard scrapes every Ready
// ScyllaCluster member's metrics endpoint: a pending-compactions
// count above scyllaCompactionBacklogMax means the cluster is
// drowning in compaction debt (sstable reads degrade every query
// path), and divergent coordinator schema versions across members
// mean a schema change stalled mid-propagation — the split-brain
// that drops writes on the minority side.
func (p *scyllaCompactionSchemaGuardCheck) Run(ctx context.Context) probefw.Result {
	log := logf.FromContext(ctx)
	pods, err := p.AllPods(ctx)
	if err != nil {
		return probefw.Result{Infra: fmt.Errorf("list pods: %w", err)}
	}

	// cluster -> namespace -> distinct schema versions across members.
	clusterVersions := map[string]map[string]map[float64]bool{}
	var backlogRep, shardRep, overloadRep probefw.SweepReport
	scrapedLive := map[string]bool{} // "ns/pod" successfully scraped — the baselines' keep set
	shardLive := map[string]bool{}   // "ns/pod" showing the skew THIS sweep — the imbalance ledger's
	for i := range pods {
		pod := &pods[i]
		cluster := pod.Labels[scyllaClusterLabel]
		if cluster == "" || pod.DeletionTimestamp != nil ||
			pod.Status.Phase != corev1.PodRunning ||
			!kube.PodReadyCond(pod) {
			continue
		}
		sc, ok := p.scyllaPodMetrics(ctx, pod)
		if !ok {
			// A dead metrics endpoint is inconclusive — the pod may
			// be mid-restart; never read as healthy OR sick.
			log.Info("WARN: scylla pod metrics fetch failed — compaction/schema evidence inconclusive",
				"pod", pod.Namespace+"/"+pod.Name)
			continue
		}
		podKey := pod.Namespace + "/" + pod.Name
		scrapedLive[podKey] = true
		if sc.backlog > scyllaCompactionBacklogMax {
			backlogRep.Set(scyllaCompactionBacklogGauge, sc.backlog,
				podKey,
				[]string{pod.Namespace, pod.Name})
			backlogRep.Find(fmt.Sprintf(
				"%s/%s=%.0f", pod.Namespace, pod.Name, sc.backlog))
		}
		// W12-ST3 — hot-partition skew: the busiest shard saturated
		// while the pod's average shard idles, persisting 10m.
		if max, avg, n := shardSkew(sc.shards); n >= scyllaShardImbalanceMinSets &&
			max >= scyllaShardHotUtil && avg <= scyllaShardAvgUtilMax {
			shardLive[podKey] = true
			if probefw.Persisted(&p.shardImbalanceSeen, podKey, p.Now(),
				scyllaShardImbalanceMinAge, log) {
				shardRep.Emit(scyllaShardImbalanceGauge, podKey,
					[]string{pod.Namespace, pod.Name},
					fmt.Sprintf("%s/%s max_shard=%.2f avg_shard=%.2f",
						pod.Namespace, pod.Name, max, avg))
			}
		}
		// W12-ST3 — stall counters: a positive delta since the last
		// scrape is a stall in progress; a drop means the pod
		// restarted its counters, not evidence either way.
		p.scyllaOverloadDelta(&overloadRep, pod, sc.overload)
		ck := pod.Namespace + "/" + cluster
		set := clusterVersions[ck]
		if set == nil {
			set = map[string]map[float64]bool{}
			clusterVersions[ck] = set
		}
		set[pod.Name] = sc.versions
	}
	// Resolved pods drop out of the imbalance window and the counter
	// baselines — a fresh occurrence re-arms both.
	p.shardImbalanceSeen.Prune(func(k string) bool { return shardLive[k] })
	if p.overloadLast != nil {
		for k := range p.overloadLast {
			if !scrapedLive[k] {
				delete(p.overloadLast, k)
			}
		}
	}

	var splitRep probefw.SweepReport
	for ck, members := range clusterVersions {
		distinct := map[float64]bool{}
		for _, versions := range members {
			for v := range versions {
				distinct[v] = true
			}
		}
		if len(distinct) <= 1 {
			continue
		}
		ns, cluster, _ := strings.Cut(ck, "/")
		splitRep.Set(scyllaSchemaSplitGauge, 1, ck, []string{ns, cluster})
		var vs []string
		for v := range distinct {
			vs = append(vs, strconv.FormatFloat(v, 'f', -1, 64))
		}
		sort.Strings(vs)
		splitRep.Find(fmt.Sprintf("%s versions=[%s]", ck, strings.Join(vs, ",")))
	}

	backlogRep.Close(&p.emittedBacklog, scyllaCompactionBacklogGauge.DeleteLabelValues)
	splitRep.Close(&p.emittedSplit, scyllaSchemaSplitGauge.DeleteLabelValues)
	shardRep.Close(&p.emittedShard, scyllaShardImbalanceGauge.DeleteLabelValues)
	overloadRep.Close(&p.emittedOverload, scyllaOverloadStallGauge.DeleteLabelValues)
	return probefw.WhyFold(
		probefw.Section("compaction backlog >%d: %s",
			backlogRep.Sorted(), scyllaCompactionBacklogMax),
		probefw.Section("schema splits: %s", splitRep.Sorted()),
		probefw.Section("shard imbalance: %s", shardRep.Sorted()),
		probefw.Section("overload stalls: %s", overloadRep.Sorted()))
}

// shardSkew folds a pod's per-shard reactor utilization into
// (max, avg, count) — the caller compares against the W12-ST3 hot /
// idle thresholds.
func shardSkew(shards map[string]float64) (max, avg float64, n int) {
	for _, u := range shards {
		if u > max {
			max = u
		}
		avg += u
		n++
	}
	if n > 0 {
		avg /= float64(n)
	}
	return max, avg, n
}

// scyllaOverloadDelta emits the stall-counter increases one pod's
// counters made since the previous scrape — a live tombstone/overload
// stall. First sight of a pod only stores its baseline (a counter's
// absolute value says nothing; the DELTA is the evidence). A counter
// that decreased means the pod restarted — the baseline is simply
// replaced.
func (p *scyllaCompactionSchemaGuardCheck) scyllaOverloadDelta(
	rep *probefw.SweepReport, pod *corev1.Pod, cur scyllaOverloadSample) {

	podKey := pod.Namespace + "/" + pod.Name
	if p.overloadLast == nil {
		p.overloadLast = map[string]scyllaOverloadSample{}
	}
	last, have := p.overloadLast[podKey]
	p.overloadLast[podKey] = cur
	if !have {
		return
	}
	for _, d := range []struct {
		reason string
		delta  float64
	}{
		{scyllaOverloadReasonReadTimeouts, cur.readTimeouts - last.readTimeouts},
		{scyllaOverloadReasonQueueOverload, cur.queueOverloads - last.queueOverloads},
		{scyllaOverloadReasonCacheDrops, cur.cacheDrops - last.cacheDrops},
	} {
		if d.delta <= 0 {
			continue
		}
		key := podKey + "/" + d.reason
		rep.Set(scyllaOverloadStallGauge, d.delta, key,
			[]string{pod.Namespace, pod.Name, d.reason})
		rep.Find(fmt.Sprintf("%s/%s %s+%.0f", pod.Namespace, pod.Name,
			d.reason, d.delta))
	}
}
