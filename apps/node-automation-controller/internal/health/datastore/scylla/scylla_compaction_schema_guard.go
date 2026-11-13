// scylla_compaction_schema_guard.go — the
// scylla-compaction-schema-guard check: scrapes each Ready member
// pod's :9180/metrics for a compaction backlog (>100 pending) and a
// coordinator schema-version split across members of the same
// cluster — both signatures the ScyllaCluster CR status can't see.
// scylla-shard-imbalance adds the Seastar shared-nothing signatures the same scrape
// already carries: a per-shard reactor-utilization skew (hot
// partition / tombstone avalanche saturating one shard while the
// pod stays Ready) and the per-sweep delta of the coordinator/
// sstable/querier-cache stall counters. Detection-only: no heals,
// the gauges are the alert contract.
package scylla

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// scyllaCompactionSchemaGuardCheck is the compaction/schema
// split-brain watchdog.
type scyllaCompactionSchemaGuardCheck struct {
	*probefw.Deps

	// emittedBacklog/emittedSplit are the emitted-gauge ledgers —
	// tuples that stop being reported get DeleteLabelValues'd rather
	// than leaking stale values (zero value usable; the serial sweep
	// needs no lock). emittedShard/emittedOverload are the scylla-shard-imbalance
	// twins for the shard-imbalance and overload-stall gauges.
	// shardImbalanceSeen is the scylla-shard-imbalance first-seen ledger —
	// "ns/pod" → first sweep the hot-partition skew showed; it must
	// persist scyllaShardImbalanceMinAge before the gauge fires.
	// overloadLast is the per-pod counter baseline —
	// "ns/pod" → last sweep's stall counters; an increase between
	// sweeps is a live stall, a reset means the pod restarted.
	// A plain map, NOT state.CooldownSet: the value is a
	// scyllaOverloadSample (three counter readings to diff against),
	// and CooldownSet.Last carries only a time.Time — there is no
	// cooldown semantics here at all (the entry is read every sweep,
	// never suppressed), so the ledger types don't fit.
	emittedBacklog     state.GaugeLedger[string]
	emittedSplit       state.GaugeLedger[string]
	emittedShard       state.GaugeLedger[string]
	emittedOverload    state.GaugeLedger[string]
	shardImbalanceSeen state.FirstSeenLedger
	overloadLast       map[string]scyllaOverloadSample
	// carryLast is last sweep's per-pod evidence ("ns/pod" →
	// scyllaPodEvidence), re-asserted verbatim for pods whose
	// :9180 scrape failed this sweep — a dead metrics endpoint is
	// inconclusive, not resolved: without the carry one transient
	// fetch failure would prune live series, drop the split-brain
	// member's version set and reset the shard-imbalance window.
	carryLast map[string]scyllaPodEvidence
}

// scyllaPodEvidence is one member pod's last-sweep findings, kept so
// an inconclusive scrape can re-assert them — the gauge VALUES
// (backlog count, stall deltas) and the skew finding's detail text
// are not recoverable from the emitted ledger's label tuples alone.
type scyllaPodEvidence struct {
	backlog      float64            // last pending-compactions reading
	backlogHot   bool               // was over scyllaCompactionBacklogMax
	shardSkewed  bool               // skew signature present (keeps the first-seen stamp)
	shardEmitted bool               // past the window — the gauge tuple was live
	shardDetail  string             // skew finding detail
	overload     map[string]float64 // reason → last emitted stall delta
	versions     map[float64]bool   // last coordinator schema-version set
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

	// The per-pod metrics-scrape fan-out cap (Component 3 pool).
	scyllaScrapeWorkers = 4

	// scylla-shard-imbalance — shard-imbalance signature: a Scylla pod's busiest
	// shard saturated while the average shard idles is the
	// hot-partition / tombstone-skew shape (a shard-per-core pod can
	// stall 1/8th of its coordinator work while staying Ready).
	scyllaShardHotUtil          = 0.98
	scyllaShardAvgUtilMax       = 0.50
	scyllaShardImbalanceMinAge  = 10 * time.Minute
	scyllaShardImbalanceMinSets = 2 // need >=2 shards for a skew to exist

	// scylla-shard-imbalance — overload stall counter names, all scraped off the
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

	// scylla-shard-imbalance — a member pod whose hottest shard is saturated while
	// the average shard idles: the hot-partition / tombstone skew
	// that stalls a fraction of coordinator work on a Ready pod.
	scyllaShardImbalanceGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_automation_scylla_shard_imbalance",
		Help: "1 while a Scylla pod's max per-shard reactor utilization >=0.98 with shard-average <=0.50 for >=10m.",
	}, []string{"namespace", "pod"})

	// scylla-shard-imbalance — overload stalls in progress: per-sweep delta of the
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
// member pod — the scylla-shard-imbalance additions read off the SAME body, so the
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

// The six metric families one :9180/metrics body is scanned for —
// collected in a SINGLE bufio.Scanner pass (the previous shape ran
// six strings.Split passes + six ParseMetricValues scans over the
// same body, peaking ~180 MiB of line-slice allocations on a large
// exposition; the scanner peaks at one line buffer).
const (
	scyllaMetricBacklog      = "scylla_compaction_manager_pending_compactions"
	scyllaMetricSchemaVer    = "scylla_storage_proxy_coordinator_schema_version"
	scyllaMetricReactorUtil  = "scylla_reactor_utilization"
	scyllaMetricReadTimeouts = "scylla_storage_proxy_coordinator_read_timeouts"
	scyllaMetricSSTableQueue = "scylla_database_sstable_read_queue_overloads"
	scyllaMetricQuerierCache = "scylla_database_querier_cache_drops"
)

// scyllaPodMetrics fetches the pod's :9180/metrics and returns every
// signature the page carries. ok=false on fetch/parse failure —
// inconclusive, not healthy (a dead endpoint and a sick pod are
// indistinguishable from here).
func (p *scyllaCompactionSchemaGuardCheck) scyllaPodMetrics(ctx context.Context,
	pod *corev1.Pod) (*scyllaScrape, bool) {

	sc := &scyllaScrape{
		versions: map[float64]bool{},
		shards:   map[string]float64{},
	}
	// One pass, six families, streamed directly from resp.Body
	// without buffering up to 16 MiB per worker. Each case re-checks
	// the exact metric name through ParseMetricValue (CutPrefix +
	// value parse + NaN/Inf rejection) — the HasPrefix dispatch only
	// saves the parse call on non-matching lines; acceptance semantics
	// are byte-identical to the old per-family scans.
	var readTimeouts, queueOverloads, cacheDrops float64
	err := probefw.StreamPodMetrics(ctx, p.HTTPClient,
		pod.Status.PodIP, scyllaMetricsPort, scyllaMetricsTimeout, 16<<20,
		func(r io.Reader) error {
			scanner := bufio.NewScanner(r)
			// Exposition lines are small; the 4 MiB ceiling only
			// exists so a pathological single line degrades to
			// "inconclusive" instead of bufio's default 64 KiB
			// token error.
			scanner.Buffer(make([]byte, 64*1024), 4<<20)
			for scanner.Scan() {
				line := scanner.Text()
				switch {
				case strings.HasPrefix(line, scyllaMetricBacklog):
					if v, ok := probefw.ParseMetricValue(line, scyllaMetricBacklog); ok &&
						v > sc.backlog {
						sc.backlog = v
					}
				case strings.HasPrefix(line, scyllaMetricSchemaVer):
					if v, ok := probefw.ParseMetricValue(line, scyllaMetricSchemaVer); ok {
						sc.versions[v] = true
					}
				case strings.HasPrefix(line, scyllaMetricReactorUtil):
					// scylla-shard-imbalance — same body, per-shard
					// reactor utilization; the shard label IS the
					// series key.
					if v, ok := probefw.ParseMetricValue(line, scyllaMetricReactorUtil); ok {
						if lv, lok := scyllaLabelValue(line, "shard"); lok {
							sc.shards[lv] = v
						}
					}
				case strings.HasPrefix(line, scyllaMetricReadTimeouts):
					if v, ok := probefw.ParseMetricValue(line, scyllaMetricReadTimeouts); ok &&
						v > readTimeouts {
						readTimeouts = v
					}
				case strings.HasPrefix(line, scyllaMetricSSTableQueue):
					if v, ok := probefw.ParseMetricValue(line, scyllaMetricSSTableQueue); ok &&
						v > queueOverloads {
						queueOverloads = v
					}
				case strings.HasPrefix(line, scyllaMetricQuerierCache):
					if v, ok := probefw.ParseMetricValue(line, scyllaMetricQuerierCache); ok &&
						v > cacheDrops {
						cacheDrops = v
					}
				}
			}
			return scanner.Err()
		})
	if err != nil {
		// A fetch or scan failure yields a partial scrape —
		// inconclusive beats half-parsed evidence.
		return nil, false
	}
	// The counters fan out per shard / scheduling group — the max
	// is the conservative "some shard is stalling" read (a sum
	// would multiply-count overlapping series).
	sc.overload = scyllaOverloadSample{
		readTimeouts:   readTimeouts,
		queueOverloads: queueOverloads,
		cacheDrops:     cacheDrops,
	}
	return sc, true
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
	for kv := range strings.SplitSeq(line[lb+1:rb], ",") {
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
	memberLive := map[string]bool{} // "ns/pod" still a scrape candidate — inconclusive keeps baselines + carry evidence
	shardLive := map[string]bool{}  // "ns/pod" showing the skew THIS sweep (or carried) — the imbalance ledger's
	// Candidate pods scrape through a bounded worker pool (max
	// scyllaScrapeWorkers concurrent :9180 fetches); the signatures
	// apply serially below.
	var members []*corev1.Pod
	for i := range pods {
		pod := &pods[i]
		if pod.Labels[scyllaClusterLabel] == "" || pod.DeletionTimestamp != nil ||
			pod.Status.Phase != corev1.PodRunning ||
			!kube.PodReadyCond(pod) {
			continue
		}
		members = append(members, pod)
	}
	scrapes := make([]*scyllaScrape, len(members))
	g := errgroup.Group{}
	g.SetLimit(scyllaScrapeWorkers)
	for j, pod := range members {
		g.Go(func() (err error) {
			// A panic in one pod's metrics scrape reads as that
			// pod's inconclusive sample (nil scrape) — never a
			// process crash.
			defer func() {
				if r := recover(); r != nil {
					log.Info("WARN: scylla pod metrics scrape panicked — evidence inconclusive",
						"pod", pod.Namespace+"/"+pod.Name, "panic", r)
				}
			}()
			sc, ok := p.scyllaPodMetrics(ctx, pod)
			if ok {
				scrapes[j] = sc
			}
			return nil
		})
	}
	_ = g.Wait()
	if p.carryLast == nil {
		p.carryLast = map[string]scyllaPodEvidence{}
	}
	for j, pod := range members {
		podKey := pod.Namespace + "/" + pod.Name
		memberLive[podKey] = true
		sc := scrapes[j]
		if sc == nil {
			// A dead metrics endpoint is inconclusive — the pod may
			// be mid-restart; never read as healthy OR sick. Carry
			// last sweep's evidence so the flap can't prune live
			// series or reset first-seen windows.
			log.Info("WARN: scylla pod metrics fetch failed — compaction/schema evidence inconclusive",
				"pod", podKey)
			p.carryScyllaPod(pod, podKey, &backlogRep, &shardRep,
				&overloadRep, clusterVersions, shardLive)
			continue
		}
		ev := scyllaPodEvidence{backlog: sc.backlog, versions: sc.versions}
		if sc.backlog > scyllaCompactionBacklogMax {
			backlogRep.Set(scyllaCompactionBacklogGauge, sc.backlog,
				podKey,
				[]string{pod.Namespace, pod.Name})
			backlogRep.Find(fmt.Sprintf(
				"%s/%s=%.0f", pod.Namespace, pod.Name, sc.backlog))
			ev.backlogHot = true
		}
		// scylla-shard-imbalance — hot-partition skew: the busiest shard saturated
		// while the pod's average shard idles, persisting 10m.
		if max, avg, n := shardSkew(sc.shards); n >= scyllaShardImbalanceMinSets &&
			max >= scyllaShardHotUtil && avg <= scyllaShardAvgUtilMax {
			shardLive[podKey] = true
			ev.shardSkewed = true
			ev.shardDetail = fmt.Sprintf("%s/%s max_shard=%.2f avg_shard=%.2f",
				pod.Namespace, pod.Name, max, avg)
			if probefw.Persisted(&p.shardImbalanceSeen, podKey, p.Now(),
				scyllaShardImbalanceMinAge, log) {
				shardRep.Emit(scyllaShardImbalanceGauge, podKey,
					[]string{pod.Namespace, pod.Name}, ev.shardDetail)
				ev.shardEmitted = true
			}
		}
		// scylla-shard-imbalance — stall counters: a positive delta since the last
		// scrape is a stall in progress; a drop means the pod
		// restarted its counters, not evidence either way.
		ev.overload = p.scyllaOverloadDelta(&overloadRep, pod, sc.overload)
		p.carryLast[podKey] = ev
		ck := pod.Namespace + "/" + pod.Labels[scyllaClusterLabel]
		set := clusterVersions[ck]
		if set == nil {
			set = map[string]map[float64]bool{}
			clusterVersions[ck] = set
		}
		set[pod.Name] = sc.versions
	}
	// Resolved pods drop out of the imbalance window, the counter
	// baselines and the carry evidence — a fresh occurrence re-arms
	// all three. memberLive (not scrape success) is the keep set: a
	// pod still in the census but mid-scrape-failure keeps its
	// baseline so the post-gap delta still spans the stall.
	p.shardImbalanceSeen.Prune(func(k string) bool { return shardLive[k] })
	for k := range p.overloadLast {
		if !memberLive[k] {
			delete(p.overloadLast, k)
		}
	}
	for k := range p.carryLast {
		if !memberLive[k] {
			delete(p.carryLast, k)
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
		slices.Sort(vs)
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
