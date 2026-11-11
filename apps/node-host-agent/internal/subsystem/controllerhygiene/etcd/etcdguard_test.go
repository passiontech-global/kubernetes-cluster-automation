// etcdguard_test.go — embedded-etcd quota guard: evpurge + compact/defrag rescue remediation.

package etcd_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/etcdmaint"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/domain/eventpurge"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/etcd"
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
	case strings.Contains(j, "snapshot save"):
		// The real seam lands a non-empty file at the argv path —
		// mirror it so the guard's post-save verify sees one.
		if err := os.WriteFile(args[len(args)-1],
			[]byte("fake-snapshot"), 0o600); err != nil {
			return nil, err
		}
		return []byte(`{"hash":1,"revision":1,"totalKey":1,"totalSize":16384}`), nil
	case strings.Contains(j, "snapshot status"):
		return []byte(`{"hash":1,"revision":1,"totalKey":1,"totalSize":16384}`), nil
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
// installs the scripted seams. EtcdBackupDir gets a writable tempdir
// — the pre-maintenance snapshot gate runs before every remediation
// and would otherwise try /var/backups/etcd on the test host — with
// the StatFSFn seam pinned to ample headroom: the real statfs makes
// the 30%-free ratio gate depend on the host's tempdir occupancy and
// flakes under parallel load (tests that exercise the gate itself
// override StatFSFn after wiring).
func (e *env) wireEtcdGuard(t *testing.T, g *etcdGuardFake) {
	t.Helper()
	e.H.Cfg.K0sDir = e.MkEtcdHost(t)
	e.H.Cfg.EtcdBackupDir = filepath.Join(filepath.Dir(e.State), "etcd-backups")
	e.H.Cfg.StatFSFn = func(string) (int64, int64, error) { return 1 << 30, 2 << 30, nil }
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
	// skipped (hung-etcd probe halving). The remediation's
	// pre-maintenance snapshot pair (save + status) is expected on
	// top of the endpoint-status probe; the alarm probe must not
	// appear.
	for _, call := range g.ctlCalls {
		if strings.Contains(strings.Join(call, " "), "alarm list") {
			t.Fatalf("alarm probe ran despite decided trigger: %v", g.ctlCalls)
		}
	}
	if len(g.ctlCalls) != 3 ||
		!strings.Contains(strings.Join(g.ctlCalls[0], " "), "endpoint status") {
		t.Fatalf("etcdctl calls=%v want status + snapshot save/status", g.ctlCalls)
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
	e.H.Cfg.EtcdBackupDir = filepath.Join(filepath.Dir(e.State), "etcd-backups")
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
	e.H.Cfg.EtcdBackupDir = filepath.Join(filepath.Dir(e.State), "etcd-backups")
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

// --- pre-maintenance snapshot (1.5) ---

func TestEtcdGuardPreMaintSnapshot(t *testing.T) {
	e := fixture(t)
	snapDir := t.TempDir()
	e.H.Cfg.EtcdBackupDir = snapDir
	// Pin the headroom gate — real statfs on the host tempdir makes
	// the 30%-free ratio host-dependent.
	e.H.Cfg.StatFSFn = func(string) (int64, int64, error) { return 1 << 30, 2 << 30, nil }
	snapSaved := false
	var order []string
	g := &etcdGuardFake{
		status: etcdStatusJSON(cdeps.DefaultEtcdDBSizeLimit+1, 1<<30),
	}
	e.H.Cfg.K0sDir = e.MkEtcdHost(t)
	e.H.Cfg.EtcdctlFn = func(_ context.Context, args ...string) ([]byte, error) {
		j := strings.Join(args, " ")
		switch {
		case strings.Contains(j, "endpoint status"):
			return []byte(g.status), nil
		case strings.Contains(j, "snapshot save"):
			// The real seam lands a file at the argv path — mirror it
			// so the verify sees a non-empty artifact.
			path := args[len(args)-1]
			if err := os.WriteFile(path, []byte("fake-snapshot"), 0o600); err != nil {
				return nil, err
			}
			snapSaved = true
			order = append(order, "snapshot")
			return []byte(`{"hash":1,"revision":1,"totalKey":1,"totalSize":16384}`), nil
		case strings.Contains(j, "snapshot status"):
			return []byte(`{"hash":1,"revision":1,"totalKey":1,"totalSize":16384}`), nil
		}
		return nil, fmt.Errorf("fake: unexpected etcdctl args %q", j)
	}
	e.H.Cfg.EvpurgeRunFn = func(context.Context, eventpurge.Config,
		time.Time, io.Writer) error {
		order = append(order, "evpurge")
		return nil
	}
	e.H.Cfg.EtcdRescueFn = func(context.Context,
		etcdmaint.Config, io.Writer) error {
		order = append(order, "rescue")
		return nil
	}
	e.H.Cycle(context.Background())
	if !snapSaved {
		t.Fatal("pre-maintenance snapshot not saved")
	}
	if len(order) != 3 || order[0] != "snapshot" || order[1] != "evpurge" || order[2] != "rescue" {
		t.Fatalf("remediation order = %v want [snapshot evpurge rescue]", order)
	}
	ents, _ := os.ReadDir(snapDir)
	if len(ents) != 1 || !strings.HasPrefix(ents[0].Name(), "premaint-") {
		t.Fatalf("snapshot file not in EtcdBackupDir: %v", ents)
	}
	// Second cycle inside the guard cooldown: no second snapshot
	// call and no remediation — the guard budget was spent.
	e.H.Cycle(context.Background())
	if got := len(order); got != 3 {
		t.Fatalf("cooldown re-ran remediation steps: %v", order)
	}
}

func TestEtcdGuardSnapshotInvalidAbortsRescue(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.EtcdBackupDir = t.TempDir()
	// Pin the headroom gate so the abort is attributable to the
	// invalid snapshot, not the host's tempdir occupancy.
	e.H.Cfg.StatFSFn = func(string) (int64, int64, error) { return 1 << 30, 2 << 30, nil }
	g := &etcdGuardFake{
		status: etcdStatusJSON(cdeps.DefaultEtcdDBSizeLimit+1, 1<<30),
	}
	e.H.Cfg.K0sDir = e.MkEtcdHost(t)
	e.H.Cfg.EtcdctlFn = func(_ context.Context, args ...string) ([]byte, error) {
		j := strings.Join(args, " ")
		switch {
		case strings.Contains(j, "endpoint status"):
			return []byte(g.status), nil
		case strings.Contains(j, "snapshot save"):
			// Save "succeeds" but lands a zero-byte artifact — the
			// verify must fail and the destructive half must NOT run.
			return []byte(""), nil
		case strings.Contains(j, "snapshot status"):
			return nil, errors.New("invalid snapshot")
		}
		return nil, fmt.Errorf("fake: unexpected etcdctl args %q", j)
	}
	e.H.Cfg.EvpurgeRunFn = func(context.Context, eventpurge.Config,
		time.Time, io.Writer) error {
		g.purges++
		return nil
	}
	e.H.Cfg.EtcdRescueFn = func(context.Context,
		etcdmaint.Config, io.Writer) error {
		g.rescues = append(g.rescues, etcdmaint.Config{})
		return nil
	}
	e.H.Cycle(context.Background())
	if g.purges != 0 || len(g.rescues) != 0 {
		t.Fatalf("remediation ran without a verified snapshot: purges=%d rescues=%d",
			g.purges, len(g.rescues))
	}
	if got := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckEtcd, "snapshot_error")); got != 1 {
		t.Fatalf("cycles{snapshot_error}=%v want 1", got)
	}
}

// The pre-maintenance snapshot refuses to write onto a backup fs
// without headroom (kine backup-gate parity) — with a previous
// premaint snapshot pinning the byte estimate, free < 1.1x its size
// aborts; parity with the ratio gate otherwise.
func TestEtcdGuardSnapshotHeadroom(t *testing.T) {
	for _, tc := range []struct {
		name        string
		free, total int64
		seed        int64 // byte size of a seeded premaint-*.db, 0 = none
		wantSave    bool
	}{
		{"ratio-gate-blocks-no-prev", 10, 1000, 0, false},
		{"byte-gate-blocks-prev", 1099, 1 << 30, 1000, false},
		{"byte-gate-passes-prev", 1100, 1 << 30, 1000, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := fixture(t)
			e.H.Cfg.EtcdBackupDir = t.TempDir()
			if tc.seed > 0 {
				if err := os.WriteFile(
					filepath.Join(e.H.Cfg.EtcdBackupDir, "premaint-100.db"),
					make([]byte, tc.seed), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			g := &etcdGuardFake{
				status: etcdStatusJSON(cdeps.DefaultEtcdDBSizeLimit+1, 1<<30),
			}
			e.H.Cfg.K0sDir = e.MkEtcdHost(t)
			e.H.Cfg.EtcdctlFn = g.ctl
			e.H.Cfg.StatFSFn = func(string) (int64, int64, error) {
				return tc.free, tc.total, nil
			}
			e.H.Cycle(context.Background())
			saved := false
			for _, c := range g.ctlCalls {
				if strings.Contains(strings.Join(c, " "), "snapshot save") {
					saved = true
				}
			}
			if saved != tc.wantSave {
				t.Fatalf("snapshot save ran=%v want %v (calls=%v)",
					saved, tc.wantSave, g.ctlCalls)
			}
			if !tc.wantSave && len(g.rescues) != 0 {
				t.Fatalf("rescue ran without headroom: %d", len(g.rescues))
			}
		})
	}
}

// A successful save prunes premaint-*.db down to the newest two —
// the fresh dump plus the previous window's.
func TestEtcdGuardSnapshotRetention(t *testing.T) {
	e := fixture(t)
	dir := t.TempDir()
	e.H.Cfg.EtcdBackupDir = dir
	for _, n := range []string{"premaint-1.db", "premaint-2.db", "premaint-3.db"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("snap"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	g := &etcdGuardFake{
		status: etcdStatusJSON(cdeps.DefaultEtcdDBSizeLimit+1, 1<<30),
	}
	e.H.Cfg.K0sDir = e.MkEtcdHost(t)
	e.H.Cfg.EtcdctlFn = g.ctl
	e.H.Cfg.StatFSFn = func(string) (int64, int64, error) { return 1 << 30, 2 << 30, nil }
	e.H.Cycle(context.Background())
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range ents {
		names = append(names, f.Name())
	}
	slices.Sort(names)
	if len(names) != 2 {
		t.Fatalf("retention kept %v want 2 files", names)
	}
	for _, gone := range []string{"premaint-1.db", "premaint-2.db"} {
		if slices.Contains(names, gone) {
			t.Fatalf("retention kept %s: %v", gone, names)
		}
	}
	if !slices.Contains(names, "premaint-3.db") {
		t.Fatalf("retention dropped the surviving premaint-3.db: %v", names)
	}
	if !strings.Contains(e.LogLines(), "pruned") {
		t.Fatalf("prune not logged:\n%s", e.LogLines())
	}
}

// Inside the hourly snapshot budget the fallback must verify the
// NEWEST premaint-*.db with `snapshot status` — remediation proceeds.
func TestEtcdGuardSnapshotFallbackVerifiesNewest(t *testing.T) {
	e := fixture(t)
	dir := t.TempDir()
	e.H.Cfg.EtcdBackupDir = dir
	if err := os.WriteFile(filepath.Join(dir, "premaint-100.db"),
		[]byte("snap"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.H.State.RateSpend(cdeps.FileRateEtcdPreMaintSnap)
	g := &etcdGuardFake{
		status: etcdStatusJSON(cdeps.DefaultEtcdDBSizeLimit+1, 1<<30),
	}
	e.H.Cfg.K0sDir = e.MkEtcdHost(t)
	e.H.Cfg.EtcdctlFn = g.ctl
	e.H.Cfg.StatFSFn = func(string) (int64, int64, error) { return 1 << 30, 2 << 30, nil }
	e.H.Cfg.EvpurgeRunFn = func(context.Context, eventpurge.Config,
		time.Time, io.Writer) error {
		return nil
	}
	e.H.Cfg.EtcdRescueFn = func(context.Context,
		etcdmaint.Config, io.Writer) error {
		g.rescues = append(g.rescues, etcdmaint.Config{})
		return nil
	}
	e.H.Cycle(context.Background())
	verified := false
	saved := false
	for _, c := range g.ctlCalls {
		j := strings.Join(c, " ")
		switch {
		case strings.Contains(j, "snapshot status") && strings.Contains(j, "premaint"):
			verified = true
		case strings.Contains(j, "snapshot save"):
			saved = true
		}
	}
	if saved {
		t.Fatal("budgeted cycle attempted a second save")
	}
	if !verified {
		t.Fatalf("fallback did not snapshot-status the premaint file: %v", g.ctlCalls)
	}
	if len(g.rescues) != 1 {
		t.Fatalf("verified fallback must let the rescue run: %d", len(g.rescues))
	}
}

// A non-premaint file under EtcdBackupDir is NOT a valid fallback —
// the destructive half must abort.
func TestEtcdGuardSnapshotFallbackRejectsNonPremaint(t *testing.T) {
	e := fixture(t)
	dir := t.TempDir()
	e.H.Cfg.EtcdBackupDir = dir
	if err := os.WriteFile(filepath.Join(dir, "some-other-backup.db"),
		[]byte("not-an-etcd-snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.H.State.RateSpend(cdeps.FileRateEtcdPreMaintSnap)
	g := &etcdGuardFake{
		status: etcdStatusJSON(cdeps.DefaultEtcdDBSizeLimit+1, 1<<30),
	}
	e.H.Cfg.K0sDir = e.MkEtcdHost(t)
	e.H.Cfg.EtcdctlFn = g.ctl
	e.H.Cfg.StatFSFn = func(string) (int64, int64, error) { return 1 << 30, 2 << 30, nil }
	e.H.Cycle(context.Background())
	for _, c := range g.ctlCalls {
		if strings.Contains(strings.Join(c, " "), "snapshot status") {
			t.Fatalf("snapshot status ran against a non-premaint dir: %v", g.ctlCalls)
		}
	}
	if len(g.rescues) != 0 || g.purges != 0 {
		t.Fatalf("remediation ran without a verified snapshot: purges=%d rescues=%d",
			g.purges, len(g.rescues))
	}
	if got := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckEtcd, "snapshot_error")); got != 1 {
		t.Fatalf("cycles{snapshot_error}=%v want 1", got)
	}
}

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

// Directory entries under a snapshot dir are not snapshots — the
// scan must skip them and keep ageing the newest real file.
func TestVerifySnapshotsSkipsDirectories(t *testing.T) {
	e := fixture(t)
	snapDir := t.TempDir()
	e.H.Cfg.EtcdSnapshotDir = snapDir
	c := etcd.NewGuard(e.H.Deps)

	// A stray directory plus a 1h-old snapshot file: only the file
	// may land on the age gauge.
	if err := os.MkdirAll(filepath.Join(snapDir, "staged-restore"), 0o755); err != nil {
		t.Fatal(err)
	}
	snap := filepath.Join(snapDir, "snapshot.db")
	if err := os.WriteFile(snap, []byte("etcd-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := e.Now.Add(-time.Hour)
	_ = os.Chtimes(snap, old, old)
	c.VerifySnapshots()
	if got := promtest.ToFloat64(e.H.Deps.EtcdSnapAge); got < 3500 || got > 3700 {
		t.Fatalf("etcdSnapAge=%v want ~3600 — dir entries must not feed the gauge", got)
	}
	if n := e.CountLogLines("no etcd snapshot"); n != 0 {
		t.Fatalf("real snapshot misreported as missing (%d lines)", n)
	}
}

// --- probe error paths (alarm list / endpoint status) ---

// A failed alarm read must not hide a real alarm NOR fabricate a
// clear one: the size signal stays authoritative, the gauge keeps
// its last value, and the healthy cycle still closes as ok.
func TestEtcdGuardAlarmListErrorKeepsGaugeAndOk(t *testing.T) {
	e := fixture(t)
	g := &etcdGuardFake{status: etcdStatusJSON(100<<20, 90<<20)} // below limit → probe runs
	e.wireEtcdGuard(t, g)
	e.H.Cfg.EtcdctlFn = func(_ context.Context, args ...string) ([]byte, error) {
		j := strings.Join(args, " ")
		switch {
		case strings.Contains(j, "endpoint status"):
			return []byte(g.status), nil
		case strings.Contains(j, "alarm list"):
			return nil, errors.New("alarm boom")
		}
		return nil, fmt.Errorf("fake: unexpected etcdctl args %q", j)
	}
	e.H.Cycle(context.Background())
	if got := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckEtcd, "ok")); got != 1 {
		t.Fatalf("cycles{ok}=%v want 1 — a failed alarm read is not a trigger", got)
	}
	if got := promtest.ToFloat64(e.H.EtcdNospace); got != 0 {
		t.Fatalf("nospace gauge=%v want 0 — keep last, never force-clear", got)
	}
	if g.purges != 0 || len(g.rescues) != 0 {
		t.Fatalf("alarm-read failure triggered remediation: purges=%d rescues=%d",
			g.purges, len(g.rescues))
	}
	if !strings.Contains(e.LogLines(), "alarm list failed") {
		t.Fatalf("alarm failure not logged:\n%s", e.LogLines())
	}
}

// A transport-level endpoint status failure (not just a parse
// failure) skips the cycle — nothing measurable, status_error.
func TestEtcdGuardStatusTransportErrorNoop(t *testing.T) {
	e := fixture(t)
	e.wireEtcdGuard(t, &etcdGuardFake{})
	e.H.Cfg.EtcdctlFn = func(context.Context, ...string) ([]byte, error) {
		return nil, errors.New("etcdctl boom")
	}
	e.H.Cycle(context.Background())
	if got := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckEtcd, "status_error")); got != 1 {
		t.Fatalf("cycles{status_error}=%v want 1", got)
	}
	if g := promtest.ToFloat64(e.H.EtcdDBSize); g != 0 {
		t.Fatalf("db_size gauge=%v want untouched 0", g)
	}
	if !strings.Contains(e.LogLines(), "endpoint status failed") {
		t.Fatalf("status failure not logged:\n%s", e.LogLines())
	}
}

// A well-formed but empty endpoint JSON list is a parse-level error
// too — element[0] does not exist, so the quota check must skip.
func TestEtcdGuardStatusEmptyEndpointListNoop(t *testing.T) {
	e := fixture(t)
	g := &etcdGuardFake{status: "[]"}
	e.wireEtcdGuard(t, g)
	e.H.Cycle(context.Background())
	if got := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckEtcd, "status_error")); got != 1 {
		t.Fatalf("cycles{status_error}=%v want 1", got)
	}
	if len(g.ctlCalls) != 1 {
		t.Fatalf("empty endpoint list probed again: %v", g.ctlCalls)
	}
	if g.purges != 0 || len(g.rescues) != 0 {
		t.Fatalf("empty endpoint list triggered remediation: purges=%d rescues=%d",
			g.purges, len(g.rescues))
	}
}

// --- pre-maintenance snapshot environment failure paths ---

// EtcdBackupDir impossible to create (its parent is a regular file)
// aborts before any etcdctl call — no rollback point, no destructive
// half.
func TestEtcdGuardSnapshotDirUncreatableAborts(t *testing.T) {
	e := fixture(t)
	blocker := filepath.Join(filepath.Dir(e.State), "not-a-dir")
	testutil.WriteFile(t, blocker, "regular file")
	e.H.Cfg.EtcdBackupDir = filepath.Join(blocker, "backups")
	g := &etcdGuardFake{
		status: etcdStatusJSON(cdeps.DefaultEtcdDBSizeLimit+1, 1<<30),
	}
	e.H.Cfg.K0sDir = e.MkEtcdHost(t)
	e.H.Cfg.EtcdctlFn = g.ctl
	e.H.Cycle(context.Background())
	if len(g.ctlCalls) != 1 { // endpoint status only
		t.Fatalf("etcdctl ran past the failed snapshot dir: %v", g.ctlCalls)
	}
	if g.purges != 0 || len(g.rescues) != 0 {
		t.Fatalf("remediation ran without a snapshot dir: purges=%d rescues=%d",
			g.purges, len(g.rescues))
	}
	if got := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckEtcd, "snapshot_error")); got != 1 {
		t.Fatalf("cycles{snapshot_error}=%v want 1", got)
	}
	if !strings.Contains(e.LogLines(), "snapshot dir") {
		t.Fatalf("dir failure not logged:\n%s", e.LogLines())
	}
}

// A failing statfs on the backup fs must abort the snapshot the same
// way — unknown headroom, no write.
func TestEtcdGuardSnapshotStatfsFailAborts(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.EtcdBackupDir = t.TempDir()
	g := &etcdGuardFake{
		status: etcdStatusJSON(cdeps.DefaultEtcdDBSizeLimit+1, 1<<30),
	}
	e.H.Cfg.K0sDir = e.MkEtcdHost(t)
	e.H.Cfg.EtcdctlFn = g.ctl
	e.H.Cfg.StatFSFn = func(string) (int64, int64, error) {
		return 0, 0, errors.New("statfs boom")
	}
	e.H.Cycle(context.Background())
	for _, c := range g.ctlCalls {
		if strings.Contains(strings.Join(c, " "), "snapshot") {
			t.Fatalf("snapshot attempted on statfs failure: %v", g.ctlCalls)
		}
	}
	if got := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckEtcd, "snapshot_error")); got != 1 {
		t.Fatalf("cycles{snapshot_error}=%v want 1", got)
	}
	if !strings.Contains(e.LogLines(), "statfs") {
		t.Fatalf("statfs failure not logged:\n%s", e.LogLines())
	}
}

// The `snapshot save` call itself failing aborts before evpurge and
// the rescue — the budget already spent (retry no sooner than the
// next guard window).
func TestEtcdGuardSnapshotSaveFailAborts(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.EtcdBackupDir = t.TempDir()
	g := &etcdGuardFake{
		status: etcdStatusJSON(cdeps.DefaultEtcdDBSizeLimit+1, 1<<30),
	}
	e.H.Cfg.K0sDir = e.MkEtcdHost(t)
	e.H.Cfg.EtcdctlFn = func(_ context.Context, args ...string) ([]byte, error) {
		j := strings.Join(args, " ")
		switch {
		case strings.Contains(j, "endpoint status"):
			return []byte(g.status), nil
		case strings.Contains(j, "snapshot save"):
			return nil, errors.New("save boom")
		}
		return nil, fmt.Errorf("fake: unexpected etcdctl args %q", j)
	}
	e.H.Cycle(context.Background())
	if g.purges != 0 || len(g.rescues) != 0 {
		t.Fatalf("remediation ran on a failed snapshot save: purges=%d rescues=%d",
			g.purges, len(g.rescues))
	}
	if got := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckEtcd, "snapshot_error")); got != 1 {
		t.Fatalf("cycles{snapshot_error}=%v want 1", got)
	}
	if !strings.Contains(e.LogLines(), "snapshot save failed") {
		t.Fatalf("save failure not logged:\n%s", e.LogLines())
	}
}

// A save that exits 0 but leaves an artifact `snapshot status`
// cannot parse aborts the destructive half (truncated-stream parity).
func TestEtcdGuardSnapshotVerifyAfterSaveFailAborts(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.EtcdBackupDir = t.TempDir()
	g := &etcdGuardFake{
		status: etcdStatusJSON(cdeps.DefaultEtcdDBSizeLimit+1, 1<<30),
	}
	e.H.Cfg.K0sDir = e.MkEtcdHost(t)
	e.H.Cfg.EtcdctlFn = func(_ context.Context, args ...string) ([]byte, error) {
		j := strings.Join(args, " ")
		switch {
		case strings.Contains(j, "endpoint status"):
			return []byte(g.status), nil
		case strings.Contains(j, "snapshot save"):
			// Non-empty this time — the size check must pass so the
			// snapshot-status verify is what fails.
			if err := os.WriteFile(args[len(args)-1], []byte("truncated"), 0o600); err != nil {
				return nil, err
			}
			return []byte("{}"), nil
		case strings.Contains(j, "snapshot status"):
			return nil, errors.New("corrupt snapshot")
		}
		return nil, fmt.Errorf("fake: unexpected etcdctl args %q", j)
	}
	e.H.Cycle(context.Background())
	if g.purges != 0 || len(g.rescues) != 0 {
		t.Fatalf("remediation ran on an unverifiable snapshot: purges=%d rescues=%d",
			g.purges, len(g.rescues))
	}
	if got := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckEtcd, "snapshot_error")); got != 1 {
		t.Fatalf("cycles{snapshot_error}=%v want 1", got)
	}
	if !strings.Contains(e.LogLines(), "failed verification") {
		t.Fatalf("verify failure not logged:\n%s", e.LogLines())
	}
}

// Inside the hourly snapshot budget a zero-byte newest premaint
// snapshot is no rollback point — the destructive half must abort.
func TestEtcdGuardSnapshotFallbackEmptyNewestAborts(t *testing.T) {
	e := fixture(t)
	dir := t.TempDir()
	e.H.Cfg.EtcdBackupDir = dir
	if err := os.WriteFile(filepath.Join(dir, "premaint-100.db"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	e.H.State.RateSpend(cdeps.FileRateEtcdPreMaintSnap)
	g := &etcdGuardFake{
		status: etcdStatusJSON(cdeps.DefaultEtcdDBSizeLimit+1, 1<<30),
	}
	e.H.Cfg.K0sDir = e.MkEtcdHost(t)
	e.H.Cfg.EtcdctlFn = g.ctl
	e.H.Cfg.StatFSFn = func(string) (int64, int64, error) { return 1 << 30, 2 << 30, nil }
	e.H.Cycle(context.Background())
	for _, c := range g.ctlCalls {
		if strings.Contains(strings.Join(c, " "), "snapshot status") {
			t.Fatalf("snapshot status ran against an empty file: %v", g.ctlCalls)
		}
	}
	if g.purges != 0 || len(g.rescues) != 0 {
		t.Fatalf("remediation ran on an empty fallback: purges=%d rescues=%d",
			g.purges, len(g.rescues))
	}
	if got := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckEtcd, "snapshot_error")); got != 1 {
		t.Fatalf("cycles{snapshot_error}=%v want 1", got)
	}
}

// Inside the hourly budget a non-empty premaint snapshot that no
// longer parses aborts too — a truncated artifact proves nothing.
func TestEtcdGuardSnapshotFallbackVerifyFailAborts(t *testing.T) {
	e := fixture(t)
	dir := t.TempDir()
	e.H.Cfg.EtcdBackupDir = dir
	if err := os.WriteFile(filepath.Join(dir, "premaint-100.db"),
		[]byte("snap"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.H.State.RateSpend(cdeps.FileRateEtcdPreMaintSnap)
	g := &etcdGuardFake{
		status: etcdStatusJSON(cdeps.DefaultEtcdDBSizeLimit+1, 1<<30),
	}
	e.H.Cfg.K0sDir = e.MkEtcdHost(t)
	e.H.Cfg.EtcdctlFn = func(_ context.Context, args ...string) ([]byte, error) {
		j := strings.Join(args, " ")
		switch {
		case strings.Contains(j, "endpoint status"):
			return []byte(g.status), nil
		case strings.Contains(j, "snapshot status"):
			return nil, errors.New("corrupt snapshot")
		}
		return nil, fmt.Errorf("fake: unexpected etcdctl args %q", j)
	}
	e.H.Cfg.StatFSFn = func(string) (int64, int64, error) { return 1 << 30, 2 << 30, nil }
	e.H.Cycle(context.Background())
	if g.purges != 0 || len(g.rescues) != 0 {
		t.Fatalf("remediation ran on a corrupt fallback: purges=%d rescues=%d",
			g.purges, len(g.rescues))
	}
	if got := promtest.ToFloat64(e.H.Cycles.WithLabelValues(cdeps.CheckEtcd, "snapshot_error")); got != 1 {
		t.Fatalf("cycles{snapshot_error}=%v want 1", got)
	}
	if !strings.Contains(e.LogLines(), "failed verification") {
		t.Fatalf("fallback verify failure not logged:\n%s", e.LogLines())
	}
}
