// etcd_quorum.go — Wave-3 #8: embedded etcd CORRUPT alarm rescue block,
// stuck learner detection, leader-change storm, and WAL fsync p99 guard.
package etcd

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

const (
	etcdQuorumPromFile       = "node-agent-etcd-quorum.prom"
	etcdQuorumConfirmCycles  = 3
	etcdLeaderChangeWindow   = 10 * time.Minute
	etcdLeaderChangeStormMin = 3
)

var (
	reFsyncBucket = regexp.MustCompile(`^etcd_disk_wal_fsync_duration_seconds_bucket\{[^}]*le="([^"]+)"[^}]*\}\s+([0-9eE.+\-]+)`)
	reLeaderChg   = regexp.MustCompile(`^etcd_server_leader_changes_seen_total(?:\{[^}]*\})?\s+([0-9eE.+\-]+)`)
)

type leaderChangeEvent struct {
	at    time.Time
	delta float64
}

type quorumTracker struct {
	mu sync.Mutex

	hasPrevLeader bool
	prevLeader    uint64

	hasPrevChanges bool
	prevChanges    float64
	changeEvents   []leaderChangeEvent

	hasPrevBuckets bool
	prevBuckets    map[float64]float64
	prevTotal      float64
	lastFsyncP99   float64
	fsyncMeasured  bool

	fsyncHighStreak int
	cleanStreak     int
}

func (c *GuardCheck) evalQuorumAndMetrics(ctx context.Context, st etcdStatusInfo,
	corrupt, alarmReadOK bool) {
	now := c.d.Cfg.Clock.Now()

	var (
		fsyncP99      float64
		fsyncMeasured bool
		leaderMetric  float64
		hasLeaderChg  bool
	)
	if !corrupt && c.d.Cfg.EtcdMetricsFn != nil && c.d.Cfg.EtcdGuard.MetricsURL != "" {
		if body, err := c.d.Cfg.EtcdMetricsFn(ctx, c.d.Cfg.EtcdGuard.MetricsURL); err == nil {
			buckets, total := parseFsyncBuckets(body)
			if len(buckets) > 0 {
				fsyncP99, fsyncMeasured = c.qt.computeFsyncP99(buckets, total)
			}
			if lc, ok := parseLeaderChanges(body); ok {
				leaderMetric = lc
				hasLeaderChg = true
			}
		}
	}

	c.qt.mu.Lock()
	defer c.qt.mu.Unlock()

	if fsyncMeasured {
		c.qt.fsyncMeasured = true
		c.qt.lastFsyncP99 = fsyncP99
		c.d.EtcdWALFsyncP99.Set(fsyncP99)
	}

	// Track stuck learner via persisted first-seen-etcd-learner marker.
	stuckLearner := false
	if st.isLearner {
		_, confirmed := c.d.State.ConfirmMarker(cdeps.FileFirstSeenEtcdLearner,
			c.d.Cfg.EtcdGuard.LearnerMaxAge)
		stuckLearner = confirmed
	} else {
		c.d.State.ClearBudget(cdeps.FileFirstSeenEtcdLearner)
	}

	// Track leader loss and Status.Leader transitions.
	lostLeader := st.leader != nil && *st.leader == 0
	var statusDelta float64
	if st.leader != nil && *st.leader != 0 {
		if c.qt.hasPrevLeader && *st.leader != c.qt.prevLeader {
			statusDelta = 1
		}
		c.qt.prevLeader = *st.leader
		c.qt.hasPrevLeader = true
	}

	var metricDelta float64
	if hasLeaderChg {
		if c.qt.hasPrevChanges && leaderMetric >= c.qt.prevChanges {
			metricDelta = leaderMetric - c.qt.prevChanges
		}
		c.qt.prevChanges = leaderMetric
		c.qt.hasPrevChanges = true
	}

	if d := math.Max(statusDelta, metricDelta); d > 0 {
		c.qt.changeEvents = append(c.qt.changeEvents, leaderChangeEvent{at: now, delta: d})
	}
	cutoff := now.Add(-etcdLeaderChangeWindow)
	kept := c.qt.changeEvents[:0]
	var changesInWindow float64
	for _, ev := range c.qt.changeEvents {
		if !ev.at.Before(cutoff) {
			kept = append(kept, ev)
			changesInWindow += ev.delta
		}
	}
	c.qt.changeEvents = kept
	leaderStorm := changesInWindow >= etcdLeaderChangeStormMin

	fsyncHigh := fsyncMeasured && fsyncP99 > c.d.Cfg.EtcdGuard.FsyncP99MaxSeconds
	if fsyncHigh {
		c.qt.fsyncHighStreak++
	} else {
		c.qt.fsyncHighStreak = 0
	}
	fsyncStorm := c.qt.fsyncHighStreak >= etcdQuorumConfirmCycles

	var enterReason string
	switch {
	case corrupt:
		enterReason = "corrupt-alarm"
	case stuckLearner:
		enterReason = fmt.Sprintf("stuck-learner>=%s", c.d.Cfg.EtcdGuard.LearnerMaxAge)
	case lostLeader:
		enterReason = "no-leader"
	case leaderStorm:
		enterReason = fmt.Sprintf("leader-changes=%.0f/10m", changesInWindow)
	case fsyncStorm:
		enterReason = fmt.Sprintf("wal-fsync-p99=%.3fs>%.3fs(%dx)",
			fsyncP99, c.d.Cfg.EtcdGuard.FsyncP99MaxSeconds, c.qt.fsyncHighStreak)
	}

	anyDegradedSignal := corrupt || stuckLearner || lostLeader || leaderStorm || fsyncHigh
	if enterReason != "" {
		c.qt.cleanStreak = 0
		c.d.State.Enter(cdeps.StateEtcdQuorumDegraded, enterReason)
	} else if !anyDegradedSignal {
		c.qt.cleanStreak++
		if c.qt.cleanStreak >= etcdQuorumConfirmCycles {
			c.d.StateExit(cdeps.StateEtcdQuorumDegraded)
		}
	} else {
		// Transient fsyncHigh (< 3 cycles) resets cleanStreak without entering yet.
		c.qt.cleanStreak = 0
	}

	c.emitQuorumTextfile(st.isLearner, corrupt, alarmReadOK, c.qt.fsyncMeasured, c.qt.lastFsyncP99)
}

func (c *GuardCheck) emitQuorumTextfile(isLearner, corrupt, alarmReadOK, fsyncMeasured bool, fsyncP99 float64) {
	var b promfile.Builder
	corruptHelp := "1 while the embedded etcd carries a CORRUPT alarm (embedded-etcd controllers only)."
	if alarmReadOK {
		v := 0.0
		if corrupt {
			v = 1
		}
		b.Gauge("node_host_agent_controllerhygiene_etcd_corrupt_alarm", corruptHelp, v)
	} else {
		b.Header("node_host_agent_controllerhygiene_etcd_corrupt_alarm", corruptHelp)
	}
	learnerHelp := "1 while the local embedded etcd member reports isLearner=true."
	learnerVal := 0.0
	if isLearner {
		learnerVal = 1
	}
	b.Gauge("node_host_agent_controllerhygiene_etcd_is_learner", learnerHelp, learnerVal)
	fsyncHelp := "Estimated p99 WAL fsync duration from embedded etcd /metrics."
	if fsyncMeasured {
		b.Gauge("node_host_agent_controllerhygiene_etcd_wal_fsync_p99_seconds", fsyncHelp, fsyncP99)
	} else {
		b.Header("node_host_agent_controllerhygiene_etcd_wal_fsync_p99_seconds", fsyncHelp)
	}
	c.d.WriteTextfileProm(etcdQuorumPromFile, b.String())
}

type histBucket struct {
	le    float64
	count float64
}

func parseFsyncBuckets(body string) (map[float64]float64, float64) {
	buckets := make(map[float64]float64)
	var total float64
	for rest := body; rest != ""; {
		line, after, _ := strings.Cut(rest, "\n")
		rest = after
		line = strings.TrimSpace(line)
		m := reFsyncBucket.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}
		var le float64
		if m[1] == "+Inf" {
			le = math.Inf(1)
		} else {
			v, err := strconv.ParseFloat(m[1], 64)
			if err != nil {
				continue
			}
			le = v
		}
		cnt, err := strconv.ParseFloat(m[2], 64)
		if err != nil {
			continue
		}
		buckets[le] = cnt
		if math.IsInf(le, 1) {
			total = cnt
		}
	}
	return buckets, total
}

func parseLeaderChanges(body string) (float64, bool) {
	for rest := body; rest != ""; {
		line, after, _ := strings.Cut(rest, "\n")
		rest = after
		line = strings.TrimSpace(line)
		m := reLeaderChg.FindStringSubmatch(line)
		if len(m) == 2 {
			v, err := strconv.ParseFloat(m[1], 64)
			if err == nil {
				return v, true
			}
		}
	}
	return 0, false
}

func (qt *quorumTracker) computeFsyncP99(cur map[float64]float64, curTotal float64) (float64, bool) {
	qt.mu.Lock()
	defer qt.mu.Unlock()

	if curTotal <= 0 {
		return 0, false
	}
	// First observation or etcd counter reset: record baseline only so we never
	// score lifetime cumulative buckets at boot.
	if !qt.hasPrevBuckets || curTotal < qt.prevTotal {
		qt.prevBuckets = cur
		qt.prevTotal = curTotal
		qt.hasPrevBuckets = true
		return 0, false
	}
	deltaTotal := curTotal - qt.prevTotal
	if deltaTotal == 0 {
		// Zero new WAL fsync samples in this interval — report 0s rather than
		// repeating an old high reading that would wedge fsyncHighStreak/latch.
		qt.prevBuckets, qt.prevTotal = cur, curTotal
		return 0, true
	}

	effective := make([]histBucket, 0, len(cur))
	for le, c := range cur {
		d := c - qt.prevBuckets[le]
		if d < 0 {
			d = 0
		}
		effective = append(effective, histBucket{le: le, count: d})
	}
	qt.prevBuckets, qt.prevTotal = cur, curTotal
	sort.Slice(effective, func(i, j int) bool {
		return effective[i].le < effective[j].le
	})
	return histogramQuantile(0.99, effective, deltaTotal), true
}

func histogramQuantile(q float64, buckets []histBucket, total float64) float64 {
	if len(buckets) == 0 || total <= 0 {
		return 0
	}
	rank := q * total
	for i, b := range buckets {
		if b.count < rank {
			continue
		}
		if math.IsInf(b.le, 1) {
			if i > 0 {
				return buckets[i-1].le
			}
			return 0
		}
		if i == 0 {
			if b.count == 0 {
				return 0
			}
			return b.le * (rank / b.count)
		}
		prev := buckets[i-1]
		if b.count == prev.count {
			return prev.le
		}
		frac := (rank - prev.count) / (b.count - prev.count)
		return prev.le + frac*(b.le-prev.le)
	}
	return 0
}
