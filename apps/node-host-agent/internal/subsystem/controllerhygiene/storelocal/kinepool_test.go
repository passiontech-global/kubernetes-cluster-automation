// kinepool_test.go — kine postgres connection-pool runaway guard.

package storelocal_test

import (
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/cdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/controllerhygiene/storelocal"

	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// --- Guard b: kine pool ---

func TestKinePoolSpiral(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 1001, "kine",
		[]string{"kine", "--endpoint=postgres://10.0.0.9:6432/kine"}, 1000)
	for i := range 80 {
		e.MkSock(t, 1001, 100+i, strconv.Itoa(50000+i), 6432)
	}
	for range 3 { // KinePoolCycles=3
		e.H.Cycle(context.Background())
	}
	if !e.HasState(cdeps.StateKinePoolRunaway) {
		t.Fatal("kine-pool-runaway state missing")
	}
	if len(e.Kills) != 1 || e.Kills[0].PID != 1001 || e.Kills[0].Sig != syscall.SIGTERM {
		t.Fatalf("expected SIGTERM on kine pid 1001, got %v", e.Kills)
	}
	// Cooldown: still spiralling but no second kill.
	e.H.Cycle(context.Background())
	if len(e.Kills) != 1 {
		t.Fatal("cooldown did not suppress the second kill")
	}
}

func TestKinePoolHealthy(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 1001, "kine",
		[]string{"kine", "--endpoint=postgres://10.0.0.9:6432/kine"}, 1000)
	for i := 0; i < 10; i++ {
		e.MkSock(t, 1001, 100+i, strconv.Itoa(60000+i), 6432)
	}
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatal("healthy conn count killed kine")
	}
	if e.HasState(cdeps.StateKinePoolRunaway) {
		t.Fatal("runaway latched on healthy pool")
	}
}

// TestKinePoolCancelledCtxDoesNotSignal: a cycle whose ctx died
// (shutdown) must return WITHOUT the SIGTERM — killing kine on a
// cancelled context races the supervisor's own stop — and without
// spending the kill budget. The persisted spiral evidence re-arms,
// so the next live context still delivers the withheld remedy.
func TestKinePoolCancelledCtxDoesNotSignal(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 1001, "kine",
		[]string{"kine", "--endpoint=postgres://10.0.0.9:6432/kine"}, 1000)
	for i := range 80 {
		e.MkSock(t, 1001, 100+i, strconv.Itoa(50000+i), 6432)
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.H.Cycle(ctx) // streak 1/3
	e.H.Cycle(ctx) // streak 2/3
	cancel()
	e.H.Cycle(ctx) // confirmed streak, dead ctx — must abort, not kill
	if len(e.Kills) != 0 {
		t.Fatalf("cancelled cycle signalled kine: %v", e.Kills)
	}
	live, stop := context.WithCancel(context.Background())
	defer stop()
	e.H.Cycle(live)
	if len(e.Kills) != 1 || e.Kills[0].PID != 1001 ||
		e.Kills[0].Sig != syscall.SIGTERM {
		t.Fatalf("live cycle must deliver the withheld SIGTERM, kills=%v",
			e.Kills)
	}
}

// appendTCPRow appends one raw /proc/net/tcp data row — MkSock only
// writes ESTABLISHED rows, the stuck/orphan signatures need custom st.
func appendTCPRow(t *testing.T, path, row string) {
	t.Helper()
	fh, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	if _, err := fh.WriteString(row); err != nil {
		t.Fatal(err)
	}
}

// A FIN_WAIT2 row on a watched inode is the kine-orphaned-conn-watch orphan
// signature: counted as a conn AND surfaced as stuck on its own
// suspect line, while the pool stays healthy (2 conns << threshold).
func TestKinePoolStuckConnSuspect(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 1001, "kine",
		[]string{"kine", "--endpoint=postgres://10.0.0.9:6432/kine"}, 1000)
	e.MkSock(t, 1001, 100, "900", 6432)
	appendTCPRow(t, filepath.Join(e.Proc, "1001", "net", "tcp"),
		"   2: 0100007F:1234 0A0000FF:1920 05 00000000:00000000 00:00000000 00000000 0 0 900 1 0000000000000000\n")
	e.H.Cycle(context.Background())
	if n := e.CountLogLines("suspect: kine db conns stuck"); n != 1 {
		t.Fatalf("stuck-conn suspect lines=%d want 1", n)
	}
	if e.HasState(cdeps.StateKinePoolRunaway) {
		t.Fatal("runaway latched on a healthy pool with one orphan")
	}
	if len(e.Kills) != 0 {
		t.Fatalf("orphan row killed kine: %v", e.Kills)
	}
}

// A vanished (or non-socket) fd entry must not break the inode scan:
// Readlink errors are skipped, the remaining real sockets still count.
func TestKinePoolFdReadlinkErrorSkipped(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 1001, "kine",
		[]string{"kine", "--endpoint=postgres://10.0.0.9:6432/kine"}, 1000)
	e.MkSock(t, 1001, 100, "900", 6432)
	// fd entry that is a regular file (the entry-changed-under-us
	// race): os.Readlink fails with EINVAL → skipped.
	if err := os.WriteFile(filepath.Join(e.Proc, "1001", "fd", "9999"),
		[]byte("gone"), 0o644); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 || e.HasState(cdeps.StateKinePoolRunaway) {
		t.Fatal("unreadable fd entry broke the healthy pool")
	}
}

// A pid with sockets but no readable net/tcp table reports zero
// conns (the table read degrades, the fd scan alone proves nothing).
func TestKinePoolNetTCPUnreadable(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 1001, "kine",
		[]string{"kine", "--endpoint=postgres://10.0.0.9:6432/kine"}, 1000)
	e.MkSock(t, 1001, 100, "900", 6432)
	if err := os.Remove(filepath.Join(e.Proc, "1001", "net", "tcp")); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 || e.HasState(cdeps.StateKinePoolRunaway) {
		t.Fatal("unreadable net/tcp broke the healthy pool")
	}
}

// Spiral confirmed again while the kill budget is spent → the
// cooldown suspect line, no second kill.
func TestKinePoolKillCooldownSuspect(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.KinePool.Cycles = 1
	e.MkProc(t, 1001, "kine",
		[]string{"kine", "--endpoint=postgres://10.0.0.9:6432/kine"}, 1000)
	for i := range 80 {
		e.MkSock(t, 1001, 100+i, strconv.Itoa(50000+i), 6432)
	}
	e.H.Cycle(context.Background()) // latch + kill, budget spent
	if len(e.Kills) != 1 {
		t.Fatalf("first spiral not killed: %v", e.Kills)
	}
	e.H.Cycle(context.Background()) // still spiralling → cooldown skip
	if len(e.Kills) != 1 {
		t.Fatalf("cooldown did not suppress the kill: %v", e.Kills)
	}
	if n := e.CountLogLines("but in kill cooldown"); n != 1 {
		t.Fatalf("cooldown suspect lines=%d want 1", n)
	}
}

// A failed SIGTERM still latches and warns.
func TestKinePoolKillFailureWarns(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.KinePool.Cycles = 1
	e.MkProc(t, 1001, "kine",
		[]string{"kine", "--endpoint=postgres://10.0.0.9:6432/kine"}, 1000)
	for i := range 80 {
		e.MkSock(t, 1001, 100+i, strconv.Itoa(50000+i), 6432)
	}
	oldKill := e.H.Cfg.KillFn
	e.H.Cfg.KillFn = func(int, syscall.Signal) error { return errors.New("EPERM") }
	t.Cleanup(func() { e.H.Cfg.KillFn = oldKill })
	e.H.Cycle(context.Background())
	if !e.HasState(cdeps.StateKinePoolRunaway) {
		t.Fatal("runaway not latched on failed kill")
	}
	if n := e.CountLogLines("suspect: kill kine pid="); n != 1 {
		t.Fatalf("kill-failure warn lines=%d want 1", n)
	}
}

// Dry-run mode latches and logs the intent but never signals.
func TestKinePoolDryRunSparesKine(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.KinePool.Cycles = 1
	e.H.Cfg.KinePool.Mode = cdeps.ModeDryRun
	e.MkProc(t, 1001, "kine",
		[]string{"kine", "--endpoint=postgres://10.0.0.9:6432/kine"}, 1000)
	for i := range 80 {
		e.MkSock(t, 1001, 100+i, strconv.Itoa(50000+i), 6432)
	}
	e.H.Cycle(context.Background())
	if !e.HasState(cdeps.StateKinePoolRunaway) {
		t.Fatal("runaway not latched in dry-run")
	}
	if n := e.CountLogLines("DRY-RUN: would kill kine pid="); n != 1 {
		t.Fatalf("dry-run lines=%d want 1", n)
	}
	if len(e.Kills) != 0 {
		t.Fatalf("dry-run killed kine: %v", e.Kills)
	}
}

// gateCtx turns cancelled on its second Err() call — the
// deterministic stand-in for a cycle deadline expiring between the
// fd/net-table scan and the kill gate.
type gateCtx struct {
	context.Context
	errCalls int
}

func (c *gateCtx) Err() error {
	c.errCalls++
	if c.errCalls >= 2 {
		return context.Canceled
	}
	return nil
}

// Cancellation after the evidence is persisted but before the signal:
// the latch still enters, no SIGTERM flies and the kill budget stays
// unspent, so the next live cycle still remediates.
func TestKinePoolAbortBeforeKillKeepsBudget(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.KinePool.Cycles = 1
	e.MkProc(t, 1001, "kine",
		[]string{"kine", "--endpoint=postgres://10.0.0.9:6432/kine"}, 1000)
	for i := range 80 {
		e.MkSock(t, 1001, 100+i, strconv.Itoa(50000+i), 6432)
	}
	cdepstest.Check[*storelocal.PoolCheck](e.H, cdeps.CheckKinePool).
		Run(&gateCtx{Context: context.Background()})
	if !e.HasState(cdeps.StateKinePoolRunaway) {
		t.Fatal("aborted cycle lost the spiral evidence (latch)")
	}
	if len(e.Kills) != 0 {
		t.Fatalf("aborted cycle signalled kine: %v", e.Kills)
	}
	// The kill budget was not spent by the aborted cycle.
	cdepstest.Check[*storelocal.PoolCheck](e.H, cdeps.CheckKinePool).
		Run(context.Background())
	if len(e.Kills) != 1 || e.Kills[0].PID != 1001 {
		t.Fatalf("expected the follow-up live cycle to kill, got %v", e.Kills)
	}
}
