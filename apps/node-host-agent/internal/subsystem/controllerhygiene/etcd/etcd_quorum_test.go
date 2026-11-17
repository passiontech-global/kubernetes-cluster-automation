package etcd_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
)

func etcdStatusFullJSON(dbSize, inUse int64, leader uint64, isLearner bool) string {
	return fmt.Sprintf(`[{"Endpoint":"https://127.0.0.1:2379",`+
		`"Status":{"header":{"revision":1},"dbSize":%d,"dbSizeInUse":%d,"leader":%d,"isLearner":%v}}]`,
		dbSize, inUse, leader, isLearner)
}

func TestEtcdCorruptAlarmBlocksRescueEvenAboveSizeLimit(t *testing.T) {
	e := fixture(t)
	g := &etcdGuardFake{
		status: etcdStatusFullJSON(cdeps.DefaultEtcdDBSizeLimit+100, 1<<30, 123, false),
		alarms: "memberID:1 alarm:NOSPACE\nmemberID:1 alarm:CORRUPT\n",
	}
	e.wireEtcdGuard(t, g)
	e.H.Cycle(context.Background())

	if g.purges != 0 || len(g.rescues) != 0 {
		t.Fatalf("CORRUPT alarm must block evpurge & rescue: purges=%d rescues=%d", g.purges, len(g.rescues))
	}
	if got := promtest.ToFloat64(e.H.EtcdCorrupt); got != 1 {
		t.Fatalf("EtcdCorrupt = %v, want 1", got)
	}
	if !e.H.State.Exists(cdeps.StateEtcdQuorumDegraded) {
		t.Fatal("expected StateEtcdQuorumDegraded latch to be entered on CORRUPT")
	}
	if !strings.Contains(e.LogLines(), "ACTION: etcdguard CORRUPT") {
		t.Fatalf("missing ACTION log for CORRUPT:\n%s", e.LogLines())
	}
	if got := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckEtcd, "corrupt_alarm")); got != 1 {
		t.Fatalf("cycles{corrupt_alarm} = %v, want 1", got)
	}
	// Verify textfile output too (default sibling node-exporter/textfile dir).
	promPath := filepath.Join(filepath.Dir(e.H.Cfg.K0sDir), "node-exporter", "textfile", "node-agent-etcd-quorum.prom")
	promBytes, err := os.ReadFile(promPath)
	if err != nil {
		t.Fatalf("read textfile: %v", err)
	}
	if !strings.Contains(string(promBytes), "node_host_agent_controllerhygiene_etcd_corrupt_alarm 1") {
		t.Fatalf("textfile missing corrupt_alarm=1:\n%s", string(promBytes))
	}
}

func TestEtcdStuckLearnerLatchesAfterMaxAge(t *testing.T) {
	e := fixture(t)
	now := time.Unix(1700000000, 0)
	e.H.Cfg.Clock.Set(func() time.Time { return now })
	g := &etcdGuardFake{
		status: etcdStatusFullJSON(1<<20, 1<<19, 123, true),
	}
	e.wireEtcdGuard(t, g)

	// First sight: records first-seen-etcd-learner, does not latch yet.
	e.H.Cycle(context.Background())
	if got := promtest.ToFloat64(e.H.EtcdIsLearner); got != 1 {
		t.Fatalf("EtcdIsLearner = %v, want 1", got)
	}
	if e.H.State.Exists(cdeps.StateEtcdQuorumDegraded) {
		t.Fatal("stuck learner latched immediately on first sight")
	}

	// Advance past 30m default EtcdLearnerMaxAge -> latches.
	now = now.Add(31 * time.Minute)
	e.H.Cycle(context.Background())
	if !e.H.State.Exists(cdeps.StateEtcdQuorumDegraded) {
		t.Fatal("expected StateEtcdQuorumDegraded after 31m as learner")
	}

	// Promote back to voter: requires 3 clean cycles hysteresis to exit.
	g.status = etcdStatusFullJSON(1<<20, 1<<19, 123, false)
	for i := 0; i < 2; i++ {
		e.H.Cycle(context.Background())
		if !e.H.State.Exists(cdeps.StateEtcdQuorumDegraded) {
			t.Fatalf("latch exited early on clean cycle %d", i+1)
		}
	}
	e.H.Cycle(context.Background())
	if e.H.State.Exists(cdeps.StateEtcdQuorumDegraded) {
		t.Fatal("latch did not exit after 3 clean cycles")
	}
}

func TestEtcdWALFsyncP99AndLeaderStormHysteresis(t *testing.T) {
	e := fixture(t)
	now := time.Unix(1700000000, 0)
	e.H.Cfg.Clock.Set(func() time.Time { return now })
	g := &etcdGuardFake{
		status: etcdStatusFullJSON(1<<20, 1<<19, 123, false),
	}
	e.wireEtcdGuard(t, g)

	fmtHistogram := func(b008, b1, b25, inf, lc int) string {
		return strings.Join([]string{
			fmt.Sprintf(`etcd_disk_wal_fsync_duration_seconds_bucket{le="0.008"} %d`, b008),
			fmt.Sprintf(`etcd_disk_wal_fsync_duration_seconds_bucket{le="0.1"} %d`, b1),
			fmt.Sprintf(`etcd_disk_wal_fsync_duration_seconds_bucket{le="0.25"} %d`, b25),
			fmt.Sprintf(`etcd_disk_wal_fsync_duration_seconds_bucket{le="+Inf"} %d`, inf),
			fmt.Sprintf(`etcd_server_leader_changes_seen_total %d`, lc),
		}, "\n")
	}

	// Cycle 0: baseline observation — even with lifetime historical high buckets,
	// first read records baseline only and does NOT trigger or measure p99.
	b008, b1, b25, inf, lc := 50, 90, 100, 100, 1
	metricsBody := fmtHistogram(b008, b1, b25, inf, lc)
	e.H.Cfg.EtcdMetricsFn = func(context.Context, string) (string, error) {
		return metricsBody, nil
	}
	e.H.Cycle(context.Background())
	if e.H.State.Exists(cdeps.StateEtcdQuorumDegraded) {
		t.Fatal("baseline cycle must not latch")
	}

	// Cycles 1 and 2 with incremental high fsync delta (50/90/100/100 -> ~0.235s > 0.10s): not yet 3 consecutive.
	for i := 0; i < 2; i++ {
		b008 += 50
		b1 += 90
		b25 += 100
		inf += 100
		metricsBody = fmtHistogram(b008, b1, b25, inf, lc)
		now = now.Add(time.Minute)
		e.H.Cycle(context.Background())
	}
	if e.H.State.Exists(cdeps.StateEtcdQuorumDegraded) {
		t.Fatal("fsync storm latched before 3 consecutive cycles")
	}
	if got := promtest.ToFloat64(e.H.EtcdWALFsyncP99); got < 0.20 || got > 0.25 {
		t.Fatalf("EtcdWALFsyncP99 = %v, want ~0.235", got)
	}

	// Cycle 3 (high delta) -> enters latch.
	b008 += 50
	b1 += 90
	b25 += 100
	inf += 100
	metricsBody = fmtHistogram(b008, b1, b25, inf, lc)
	now = now.Add(time.Minute)
	e.H.Cycle(context.Background())
	if !e.H.State.Exists(cdeps.StateEtcdQuorumDegraded) {
		t.Fatal("expected StateEtcdQuorumDegraded on 3rd high WAL fsync cycle")
	}

	// Quiet period (deltaTotal == 0, same cumulative counts) for 3 cycles ->
	// reports 0s (does not pin stale high p99) and exits latch.
	for i := 0; i < 3; i++ {
		now = now.Add(time.Minute)
		e.H.Cycle(context.Background())
	}
	if got := promtest.ToFloat64(e.H.EtcdWALFsyncP99); got != 0 {
		t.Fatalf("quiet delta==0 EtcdWALFsyncP99 = %v, want 0", got)
	}
	if e.H.State.Exists(cdeps.StateEtcdQuorumDegraded) {
		t.Fatal("expected latch to clear after 3 quiet/clean cycles")
	}

	// Leader change storm: +3 leader_changes within 10m -> latches immediately.
	b008 += 99
	b1 += 100
	b25 += 100
	inf += 100
	lc += 3
	metricsBody = fmtHistogram(b008, b1, b25, inf, lc)
	now = now.Add(time.Minute)
	e.H.Cycle(context.Background())
	if !e.H.State.Exists(cdeps.StateEtcdQuorumDegraded) {
		t.Fatal("expected StateEtcdQuorumDegraded on >= 3 leader changes in 10m")
	}
}
