// scylla_shard_overload.go — the scylla-shard-imbalance evidence
// helpers of the compaction/schema-guard check: carried-evidence
// re-assertion for inconclusive scrapes, the per-shard skew fold
// and the overload stall-counter delta. Split from
// scylla_compaction_schema_guard.go to keep both under ~500 LOC.
package scylla

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
)

// carryScyllaPod re-asserts last sweep's evidence for one member
// pod whose metrics scrape failed this sweep — "can't tell" is not
// "resolved": the live tuples stay emitted, the skew first-seen
// stamp keeps counting through shardLive, and the pod's schema
// versions fold back into the split census so a one-sweep gap
// can't make a live split look healed.
func (p *scyllaCompactionSchemaGuardCheck) carryScyllaPod(
	pod *corev1.Pod, podKey string,
	backlogRep, shardRep, overloadRep *probefw.SweepReport,
	clusterVersions map[string]map[string]map[float64]bool,
	shardLive map[string]bool) {

	ev, ok := p.carryLast[podKey]
	if !ok {
		return // never scraped successfully — nothing to carry
	}
	ck := pod.Namespace + "/" + pod.Labels[scyllaClusterLabel]
	set := clusterVersions[ck]
	if set == nil {
		set = map[string]map[float64]bool{}
		clusterVersions[ck] = set
	}
	set[pod.Name] = ev.versions
	if ev.backlogHot {
		backlogRep.Set(scyllaCompactionBacklogGauge, ev.backlog, podKey,
			[]string{pod.Namespace, pod.Name})
		backlogRep.Find(fmt.Sprintf("%s/%s=%.0f",
			pod.Namespace, pod.Name, ev.backlog))
	}
	if ev.shardSkewed {
		// Keep the first-seen stamp alive either way; only a tuple
		// that was actually emitted re-asserts the gauge — an
		// inside-window skew must not fire early off carried state.
		shardLive[podKey] = true
		if ev.shardEmitted {
			shardRep.Emit(scyllaShardImbalanceGauge, podKey,
				[]string{pod.Namespace, pod.Name}, ev.shardDetail)
		}
	}
	for reason, delta := range ev.overload {
		key := podKey + "/" + reason
		overloadRep.Set(scyllaOverloadStallGauge, delta, key,
			[]string{pod.Namespace, pod.Name, reason})
		overloadRep.Find(fmt.Sprintf("%s/%s %s+%.0f",
			pod.Namespace, pod.Name, reason, delta))
	}
}

// shardSkew folds a pod's per-shard reactor utilization into
// (max, avg, count) — the caller compares against the scylla-shard-imbalance hot /
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
	rep *probefw.SweepReport, pod *corev1.Pod, cur scyllaOverloadSample) map[string]float64 {

	podKey := pod.Namespace + "/" + pod.Name
	if p.overloadLast == nil {
		p.overloadLast = map[string]scyllaOverloadSample{}
	}
	last, have := p.overloadLast[podKey]
	p.overloadLast[podKey] = cur
	deltas := map[string]float64{}
	if !have {
		return deltas
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
		deltas[d.reason] = d.delta
	}
	return deltas
}
