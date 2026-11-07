// etcdguard_test.go — embedded-etcd quota guard: evpurge + compact/defrag rescue remediation.

package etcd_test

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/etcd"
	"os"

	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/etcdmaint"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/eventpurge"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// --- Guard e: etcdguard (embedded-etcd quota self-defence) ---

// etcdGuardFake scripts the etcdctl probe seam and records the
// evpurge/rescue remediation calls.
type etcdGuardFake struct {
	ctlCalls [][]string
	status   string // canned `endpoint status -w json`
	alarms   string // canned `alarm list`
	purges   int
	cutoffs  []time.Time
	rescues  []etcdmaint.Config
}

func (g *etcdGuardFake) ctl(_ context.Context, args ...string) ([]byte, error) {
	g.ctlCalls = append(g.ctlCalls, append([]string{}, args...))
	j := strings.Join(args, " ")
	switch {
	case strings.Contains(j, "endpoint status"):
		return []byte(g.status), nil
	case strings.Contains(j, "alarm list"):
		return []byte(g.alarms), nil
	}
	return nil, fmt.Errorf("fake: unexpected etcdctl args %q", j)
}

// mkEtcdHost fabricates <k0s>/{bin/etcdctl,pki/etcd/ca.crt} — the
// file pair the guard's presence gate keys on — and returns the
// fabricated K0sDir.
func (e *env) mkEtcdHost(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(filepath.Dir(e.State), "k0s")
	testutil.WriteFile(t, filepath.Join(dir, "bin", "etcdctl"), "#!/bin/sh\n")
	testutil.WriteFile(t, filepath.Join(dir, "pki", "etcd", "ca.crt"), "fake\n")
	return dir
}

// wireEtcdGuard points cfg.K0sDir at the fabricated host tree and
// installs the scripted seams.
func (e *env) wireEtcdGuard(t *testing.T, g *etcdGuardFake) {
	t.Helper()
	e.H.Cfg.K0sDir = e.MkEtcdHost(t)
	e.H.Cfg.EtcdctlFn = g.ctl
	e.H.Cfg.EvpurgeRunFn = func(_ context.Context, _ eventpurge.Config,
		cutoff time.Time, _ io.Writer) error {
		g.purges++
		g.cutoffs = append(g.cutoffs, cutoff)
		return nil
	}
	e.H.Cfg.EtcdRescueFn = func(_ context.Context,
		cfg etcdmaint.Config, _ io.Writer) error {
		g.rescues = append(g.rescues, cfg)
		return nil
	}
}

// wireEtcdSeamsOnly installs the seams WITHOUT fabricating the K0sDir
// tree — the no-op tests assert the probe is never even spawned.
func (e *env) wireEtcdSeamsOnly(g *etcdGuardFake) {
	e.H.Cfg.EtcdctlFn = g.ctl
	e.H.Cfg.EvpurgeRunFn = func(context.Context, eventpurge.Config,
		time.Time, io.Writer) error {
		g.purges++
		return nil
	}
	e.H.Cfg.EtcdRescueFn = func(_ context.Context,
		cfg etcdmaint.Config, _ io.Writer) error {
		g.rescues = append(g.rescues, cfg)
		return nil
	}
}

func etcdStatusJSON(dbSize, inUse int64) string {
	return fmt.Sprintf(`[{"Endpoint":"https://127.0.0.1:2379",`+
		`"Status":{"header":{"revision":1},"dbSize":%d,"dbSizeInUse":%d}}]`,
		dbSize, inUse)
}

func TestEtcdGuardAbsentEtcdctlNoop(t *testing.T) {
	e := fixture(t)
	g := &etcdGuardFake{status: etcdStatusJSON(1<<30, 1<<29)}
	e.wireEtcdSeamsOnly(g)
	// Point K0sDir at an empty dir — no bin/etcdctl.
	e.H.Cfg.K0sDir = filepath.Join(filepath.Dir(e.State), "absent-k0s")
	e.H.Cycle(context.Background())
	if len(g.ctlCalls) != 0 || g.purges != 0 || len(g.rescues) != 0 {
		t.Fatalf("etcdguard ran without etcdctl: calls=%v purges=%d rescues=%d",
			g.ctlCalls, g.purges, len(g.rescues))
	}
}

func TestEtcdGuardAbsentCANoop(t *testing.T) {
	e := fixture(t)
	g := &etcdGuardFake{status: etcdStatusJSON(1<<30, 1<<29)}
	e.wireEtcdSeamsOnly(g)
	// bin/etcdctl present but pki/etcd/ca.crt absent — a half-seeded
	// k0s dir must still no-op.
	dir := filepath.Join(filepath.Dir(e.State), "k0s")
	testutil.WriteFile(t, filepath.Join(dir, "bin", "etcdctl"), "#!/bin/sh\n")
	e.H.Cfg.K0sDir = dir
	e.H.Cycle(context.Background())
	if len(g.ctlCalls) != 0 || g.purges != 0 || len(g.rescues) != 0 {
		t.Fatalf("etcdguard ran without etcd CA: calls=%v purges=%d rescues=%d",
			g.ctlCalls, g.purges, len(g.rescues))
	}
}

func TestEtcdGuardBelowThreshold(t *testing.T) {
	e := fixture(t)
	g := &etcdGuardFake{
		status: etcdStatusJSON(100<<20, 90<<20), // ~100MiB — healthy
		alarms: "",
	}
	e.wireEtcdGuard(t, g)
	e.H.Cycle(context.Background())
	if g.purges != 0 || len(g.rescues) != 0 {
		t.Fatalf("healthy etcd triggered remediation: purges=%d rescues=%d",
			g.purges, len(g.rescues))
	}
	if got := promtest.ToFloat64(e.H.EtcdDBSize); got != float64(100<<20) {
		t.Fatalf("db_size gauge=%v want %v", got, 100<<20)
	}
	if got := promtest.ToFloat64(e.H.EtcdDBUse); got != float64(90<<20) {
		t.Fatalf("db_in_use gauge=%v want %v", got, 90<<20)
	}
	if got := promtest.ToFloat64(e.H.EtcdNospace); got != 0 {
		t.Fatalf("nospace gauge=%v want 0", got)
	}
	// Both probes ran exactly once.
	if len(g.ctlCalls) != 2 {
		t.Fatalf("etcdctl calls=%v want status+alarm", g.ctlCalls)
	}
}

func TestEtcdGuardNospaceTriggers(t *testing.T) {
	e := fixture(t)
	g := &etcdGuardFake{
		status: etcdStatusJSON(100<<20, 90<<20), // small db
		alarms: "memberID:8845123669947417847 alarm:NOSPACE\n",
	}
	e.wireEtcdGuard(t, g)
	e.H.Cycle(context.Background())
	// The alarm alone triggers even below the size threshold.
	if g.purges != 1 || len(g.rescues) != 1 {
		t.Fatalf("nospace alarm did not trigger: purges=%d rescues=%d",
			g.purges, len(g.rescues))
	}
	if !g.rescues[0].OnlineOnly {
		t.Fatal("rescue ran without OnlineOnly — offline path allowed")
	}
	if g.rescues[0].CallTimeout != cdeps.DefaultEtcdGuardCallTimeout {
		t.Fatalf("rescue CallTimeout=%v want %v (the short guard cap, "+
			"not etcdmaint's 10m interactive default)",
			g.rescues[0].CallTimeout, cdeps.DefaultEtcdGuardCallTimeout)
	}
	if g.rescues[0].K0sDir != e.H.Cfg.K0sDir {
		t.Fatalf("rescue K0sDir=%q want %q", g.rescues[0].K0sDir, e.H.Cfg.K0sDir)
	}
	if got := promtest.ToFloat64(e.H.EtcdNospace); got != 1 {
		t.Fatalf("nospace gauge=%v want 1", got)
	}
	// Rate budget spent.
	if h := e.H.State.Epoch(filepath.Join(e.State, cdeps.FileRateEtcdGuard)); h == 0 {
		t.Fatal("last-etcd-guard budget not spent")
	}
	// The purge cutoff is now - 1h (the apiserver event TTL).
	if len(g.cutoffs) != 1 ||
		g.cutoffs[0] != e.Now.Add(-cdeps.EventStaleAge) {
		t.Fatalf("evpurge cutoff=%v want %v", g.cutoffs,
			e.Now.Add(-cdeps.EventStaleAge))
	}
}

func TestEtcdGuardSizeTriggers(t *testing.T) {
	e := fixture(t)
	g := &etcdGuardFake{
		status: etcdStatusJSON(cdeps.DefaultEtcdDBSizeLimit, 1<<30), // at limit
		alarms: "",
	}
	e.wireEtcdGuard(t, g)
	e.H.Cycle(context.Background())
	if g.purges != 1 || len(g.rescues) != 1 {
		t.Fatalf("dbSize>=limit did not trigger: purges=%d rescues=%d",
			g.purges, len(g.rescues))
	}
	if !g.rescues[0].OnlineOnly {
		t.Fatal("rescue ran without OnlineOnly")
	}
	// dbSize already decided the trigger — the alarm-list probe is
	// skipped, so only `endpoint status` ran (hung-etcd probe
	// halving).
	if len(g.ctlCalls) != 1 ||
		!strings.Contains(strings.Join(g.ctlCalls[0], " "), "endpoint status") {
		t.Fatalf("etcdctl calls=%v want status only (alarm probe skipped)",
			g.ctlCalls)
	}
}

func TestEtcdGuardRateLimitSuppressesSecondRun(t *testing.T) {
	e := fixture(t)
	g := &etcdGuardFake{
		status: etcdStatusJSON(cdeps.DefaultEtcdDBSizeLimit+1, 1<<30),
		alarms: "memberID:1 alarm:NOSPACE\n",
	}
	e.wireEtcdGuard(t, g)
	e.H.Cycle(context.Background()) // run 1: spends the budget
	if g.purges != 1 || len(g.rescues) != 1 {
		t.Fatalf("first guard run missing: purges=%d rescues=%d",
			g.purges, len(g.rescues))
	}
	e.H.Cycle(context.Background()) // still tripped but in cooldown
	if g.purges != 1 || len(g.rescues) != 1 {
		t.Fatalf("cooldown did not suppress second run: purges=%d rescues=%d",
			g.purges, len(g.rescues))
	}
	// Past the 1h window the guard fires again.
	e.Now = e.Now.Add(2 * time.Hour)
	e.H.Cycle(context.Background())
	if g.purges != 2 || len(g.rescues) != 2 {
		t.Fatalf("post-window run missing: purges=%d rescues=%d",
			g.purges, len(g.rescues))
	}
}

func TestEtcdGuardEvpurgeFailRescueOkStillRemediated(t *testing.T) {
	// The rescue (compact+defrag) is the step that actually relieves
	// the quota — when it lands, the cycle verdict is ok even though
	// the upstream evpurge failed. The purge failure must still be
	// logged on its own.
	e := fixture(t)
	g := &etcdGuardFake{
		status: etcdStatusJSON(cdeps.DefaultEtcdDBSizeLimit+1, 1<<30),
	}
	e.wireEtcdGuard(t, g)
	e.H.Cfg.EvpurgeRunFn = func(context.Context, eventpurge.Config,
		time.Time, io.Writer) error {
		g.purges++
		return errors.New("purge boom")
	}
	e.H.Cycle(context.Background())
	if g.purges != 1 || len(g.rescues) != 1 {
		t.Fatalf("steps ran purges=%d rescues=%d want 1/1",
			g.purges, len(g.rescues))
	}
	if got := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckEtcd, "ok")); got != 1 {
		t.Fatalf("cycles{ok}=%v want 1 — a landed rescue must not "+
			"count as remediate_error", got)
	}
	if got := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckEtcd, "remediate_error")); got != 0 {
		t.Fatalf("cycles{remediate_error}=%v want 0", got)
	}
	if log := e.LogLines(); !strings.Contains(log, "evpurge failed") {
		t.Fatalf("evpurge failure not logged separately:\n%s", log)
	}
}

func TestEtcdGuardRescueFailCountsRemediateError(t *testing.T) {
	// The inverse verdict: a failed rescue means the quota fix did
	// NOT land — remediate_error even when evpurge succeeded.
	e := fixture(t)
	g := &etcdGuardFake{
		status: etcdStatusJSON(cdeps.DefaultEtcdDBSizeLimit+1, 1<<30),
	}
	e.wireEtcdGuard(t, g)
	e.H.Cfg.EtcdRescueFn = func(context.Context,
		etcdmaint.Config, io.Writer) error {
		g.rescues = append(g.rescues, etcdmaint.Config{})
		return errors.New("rescue boom")
	}
	e.H.Cycle(context.Background())
	if g.purges != 1 || len(g.rescues) != 1 {
		t.Fatalf("steps ran purges=%d rescues=%d want 1/1",
			g.purges, len(g.rescues))
	}
	if got := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckEtcd, "remediate_error")); got != 1 {
		t.Fatalf("cycles{remediate_error}=%v want 1", got)
	}
	if got := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckEtcd, "ok")); got != 0 {
		t.Fatalf("cycles{ok}=%v want 0 — failed rescue is not remediated", got)
	}
}

func TestEtcdGuardStatusErrorNoop(t *testing.T) {
	e := fixture(t)
	g := &etcdGuardFake{status: "not json"}
	e.wireEtcdGuard(t, g)
	e.H.Cycle(context.Background())
	if g.purges != 0 || len(g.rescues) != 0 {
		t.Fatalf("unparseable status triggered remediation: purges=%d rescues=%d",
			g.purges, len(g.rescues))
	}
}

func TestEtcdGuardRunCtxBounded(t *testing.T) {
	// Both remediation steps must run under a bounded ctx — the
	// guard budget (~10m), never the process-lifetime ctx.
	e := fixture(t)
	g := &etcdGuardFake{
		status: etcdStatusJSON(cdeps.DefaultEtcdDBSizeLimit+1, 1<<30),
	}
	e.H.Cfg.K0sDir = e.MkEtcdHost(t)
	e.H.Cfg.EtcdctlFn = g.ctl
	var purgeDL, rescueDL time.Time
	e.H.Cfg.EvpurgeRunFn = func(ctx context.Context, _ eventpurge.Config,
		_ time.Time, _ io.Writer) error {
		g.purges++
		d, ok := ctx.Deadline()
		if !ok {
			t.Error("evpurge ctx carries no deadline")
			return nil
		}
		purgeDL = d
		return nil
	}
	e.H.Cfg.EtcdRescueFn = func(ctx context.Context,
		cfg etcdmaint.Config, _ io.Writer) error {
		g.rescues = append(g.rescues, cfg)
		d, ok := ctx.Deadline()
		if !ok {
			t.Error("rescue ctx carries no deadline")
			return nil
		}
		rescueDL = d
		return nil
	}
	e.H.Cycle(context.Background())
	for _, d := range []time.Time{purgeDL, rescueDL} {
		rem := time.Until(d)
		if rem > cdeps.DefaultEtcdGuardBudget || rem < cdeps.DefaultEtcdGuardBudget-time.Minute {
			t.Fatalf("remediation ctx deadline in %s — want ~%s out",
				rem, cdeps.DefaultEtcdGuardBudget)
		}
	}
}

func TestEtcdGuardBudgetExhaustedDefers(t *testing.T) {
	// evpurge stalls until its ctx dies: the 80ms parent deadline
	// stands in for the guard budget (gctx inherits the earlier of
	// the two, and its Err() is still DeadlineExceeded). The guard
	// must abort cleanly — budget stays spent, the rescue is not
	// spawned on a dead ctx, and the deferral is logged.
	e := fixture(t)
	g := &etcdGuardFake{
		status: etcdStatusJSON(cdeps.DefaultEtcdDBSizeLimit+1, 1<<30),
	}
	e.H.Cfg.K0sDir = e.MkEtcdHost(t)
	e.H.Cfg.EtcdctlFn = g.ctl
	e.H.Cfg.EvpurgeRunFn = func(ctx context.Context, _ eventpurge.Config,
		_ time.Time, _ io.Writer) error {
		g.purges++
		<-ctx.Done()
		return ctx.Err()
	}
	e.H.Cfg.EtcdRescueFn = func(context.Context,
		etcdmaint.Config, io.Writer) error {
		g.rescues = append(g.rescues, etcdmaint.Config{})
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	e.H.Cycle(ctx)
	if g.purges != 1 {
		t.Fatalf("evpurge runs=%d want 1", g.purges)
	}
	if len(g.rescues) != 0 {
		t.Fatal("rescue spawned on an already-dead guard ctx")
	}
	// The rate budget stays spent — a timeout defers to the next
	// window, it does not refund.
	if v := e.H.State.Epoch(filepath.Join(e.State, cdeps.FileRateEtcdGuard)); v == 0 {
		t.Fatal("last-etcd-guard budget not spent")
	}
	if log := e.LogLines(); !strings.Contains(log, "budget") ||
		!strings.Contains(log, "deferred") {
		t.Fatalf("exhausted budget not logged clearly:\n%s", log)
	}
}

// --- W13-ST2: etcd snapshot verifier ---

func TestVerifySnapshots(t *testing.T) {
	e := fixture(t)
	snapDir := t.TempDir()
	e.H.Cfg.EtcdSnapshotDir = snapDir
	c := etcd.NewGuard(e.H.Deps)

	// No snapshot → suspect log, gauge stays 0.
	c.VerifySnapshots()
	if got := promtest.ToFloat64(e.H.Deps.EtcdSnapAge); got != 0 {
		t.Fatalf("etcdSnapAge=%v want 0 with no snapshot", got)
	}
	// A 2h-old non-empty snapshot → age ~7200s.
	snap := filepath.Join(snapDir, "snapshot.db")
	if err := os.WriteFile(snap, []byte("etcd-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := e.Now.Add(-2 * time.Hour)
	_ = os.Chtimes(snap, old, old)
	c.VerifySnapshots()
	got := promtest.ToFloat64(e.H.Deps.EtcdSnapAge)
	if got < 7100 || got > 7300 {
		t.Fatalf("etcdSnapAge=%v want ~7200", got)
	}
	// Empty snapshot → suspect path but age still reported.
	if err := os.WriteFile(snap, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(snap, old, old)
	c.VerifySnapshots()
	if got := promtest.ToFloat64(e.H.Deps.EtcdSnapAge); got < 7100 {
		t.Fatalf("etcdSnapAge=%v after empty snapshot", got)
	}
}
