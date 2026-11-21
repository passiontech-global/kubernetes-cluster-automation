// network_mount_hung_test.go — external -race tests for Wave-4 #10-L1
// Network/FUSE mount hung guard.
package runtime_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	whruntime "github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/runtime"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func setupMountinfo(t *testing.T, e *env, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "mountinfo")
	wdepstest.WriteFile(t, p, content)
	e.H.Cfg.MountinfoFile = p
	return p
}

func runMountHung(e *env, ctx context.Context) {
	e.H.Check(wdeps.CheckNetworkMountHung).Run(ctx, &wdeps.CycleEnv{WorkerActive: true})
}

func mountHungCycles(e *env, result string) float64 {
	return testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckNetworkMountHung, result))
}

func TestNetworkMountHungMountinfoParsingFilteringAndStackedDedupe(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()

	mi := strings.Join([]string{
		// Ignored local/pseudo filesystems.
		"20 1 0:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw",
		"21 20 0:2 / /run rw,nosuid - tmpfs tmpfs rw",
		"22 20 0:3 / /var/lib/overlay rw - overlay overlay rw",
		"23 20 0:4 / /sys/fs/fuse/connections rw - fusectl fusectl rw",
		"24 20 0:5 / /var/lib/lxcfs rw,nosuid - fuse.lxcfs lxcfs rw",
		// Probed network/FUSE filesystems (with variable optional fields and \040 space).
		"30 20 0:30 / /mnt/nfs3 rw shared:10 master:2 - nfs 10.0.0.1:/export rw",
		"31 20 0:31 / /mnt/nfs4 rw - nfs4 10.0.0.2:/export rw",
		"32 20 0:32 / /mnt/cifs rw - cifs //10.0.0.3/share rw",
		"33 20 0:33 / /mnt/smb3 rw - smb3 //10.0.0.4/share rw",
		"34 20 0:34 / /mnt/ceph rw - ceph 10.0.0.5:/vol rw",
		`35 20 0:35 / /mnt/ssh\040dir rw - fuse.sshfs user@host:/dir rw`,
		"36 20 0:36 / /mnt/s3 rw - fuse.s3fs bucket rw",
		// Stacked duplicate nfs4 mount -> probed only once.
		"37 31 0:37 / /mnt/nfs4 rw - nfs4 10.0.0.2:/export2 rw",
		// Network mount shadowed by topmost ext4 -> 0 probes!
		"38 20 0:38 / /mnt/shadowed rw - nfs4 10.0.0.6:/old rw",
		"39 38 0:39 / /mnt/shadowed rw - ext4 /dev/vdb1 rw",
	}, "\n") + "\n"
	setupMountinfo(t, e, mi)

	var probed []string
	e.HostExec = func(_ context.Context, _ time.Duration, name string, args ...string) (string, error) {
		if name != "stat" || len(args) != 3 || args[0] != "-f" || args[1] != "--" {
			t.Fatalf("unexpected HostExec call: %s %v", name, args)
		}
		probed = append(probed, args[2])
		return "ok", nil
	}

	runMountHung(e, ctx)

	want := []string{
		"/mnt/ceph",
		"/mnt/cifs",
		"/mnt/nfs3",
		"/mnt/nfs4",
		"/mnt/s3",
		"/mnt/smb3",
		"/mnt/ssh dir",
	}
	if !reflect.DeepEqual(probed, want) {
		t.Fatalf("probed mounts = %v, want %v", probed, want)
	}
	if e.H.State.Exists(latchdefs.LatchNetworkMountHung) {
		t.Fatal("healthy mounts must not raise LatchNetworkMountHung")
	}
}

func TestNetworkMountHungSingleCycleHysteresis(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	chk := e.H.Check(wdeps.CheckNetworkMountHung).(*whruntime.NetworkMountHungCheck)
	chk.ProbeTimeout = 20 * time.Millisecond
	e.H.Cfg.TextfileDir = t.TempDir()

	setupMountinfo(t, e, "31 20 0:31 / /mnt/nfs4 rw - nfs4 10.0.0.2:/export rw\n")

	// Cycle 1: timeout -> streak 1/2, NO latch, NO textfile sample.
	e.MountStatErrs["/mnt/nfs4"] = context.DeadlineExceeded
	runMountHung(e, ctx)
	e.H.WriteNodeAgentPromTextfile()

	if e.H.State.Exists(latchdefs.LatchNetworkMountHung) {
		t.Fatal("single-cycle hang must NOT raise LatchNetworkMountHung")
	}
	if len(e.H.Series.NetworkMountHung) != 0 {
		t.Fatalf("single-cycle hang must NOT populate Series.NetworkMountHung: %+v", e.H.Series.NetworkMountHung)
	}
	if !strings.Contains(e.LogLines(t), "(check 1/2)") {
		t.Fatalf("expected (check 1/2) suspect line in log:\n%s", e.LogLines(t))
	}

	// Cycle 2: healthy -> resets streak to 0.
	delete(e.MountStatErrs, "/mnt/nfs4")
	runMountHung(e, ctx)

	// Cycle 3: single hang again -> still 1/2, must NOT raise latch.
	e.MountStatErrs["/mnt/nfs4"] = context.DeadlineExceeded
	runMountHung(e, ctx)
	if e.H.State.Exists(latchdefs.LatchNetworkMountHung) {
		t.Fatal("reset streak + single hang must NOT raise LatchNetworkMountHung")
	}
}

func TestNetworkMountHungIndefiniteHangBoundedGoroutinesAndRecovery(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	chk := e.H.Check(wdeps.CheckNetworkMountHung).(*whruntime.NetworkMountHungCheck)
	chk.ProbeTimeout = 20 * time.Millisecond
	textDir := t.TempDir()
	e.H.Cfg.TextfileDir = textDir

	setupMountinfo(t, e, "31 20 0:31 / /mnt/hung-nfs rw - nfs4 10.0.0.2:/export rw\n")

	release := make(chan struct{})
	var releasedOnce sync.Once
	unblock := func() { releasedOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)

	var calls atomic.Int64
	var probeMode atomic.Int32 // 0 = block on release, 1 = healthy immediate
	e.HostExec = func(context.Context, time.Duration, string, ...string) (string, error) {
		calls.Add(1)
		if probeMode.Load() == 0 {
			// Simulate uninterruptible D-state hang ignoring pctx.
			<-release
		}
		return "ok", nil
	}

	initialGoroutines := runtime.NumGoroutine()

	// Cycle 1: spawns 1 goroutine that blocks; returns after ProbeTimeout (~20ms).
	runMountHung(e, ctx)
	if got := calls.Load(); got != 1 {
		t.Fatalf("after cycle 1 calls = %d, want 1", got)
	}
	if e.H.State.Exists(latchdefs.LatchNetworkMountHung) {
		t.Fatal("cycle 1 must not latch yet")
	}

	// Cycles 2..6: must immediately treat mount as hung WITHOUT spawning duplicate goroutines.
	for i := 2; i <= 6; i++ {
		start := time.Now()
		runMountHung(e, ctx)
		elapsed := time.Since(start)
		if elapsed > 100*time.Millisecond {
			t.Fatalf("cycle %d took %v; expected immediate hung verdict while probe in-flight", i, elapsed)
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("cycle %d spawned duplicate probe goroutine: calls=%d want 1", i, got)
		}
	}
	if goroutines := runtime.NumGoroutine(); goroutines > initialGoroutines+2 {
		t.Fatalf("goroutines grew during repeated hung cycles: initial=%d now=%d", initialGoroutines, goroutines)
	}

	if !e.H.State.Exists(latchdefs.LatchNetworkMountHung) {
		t.Fatal("expected LatchNetworkMountHung after >= 2 cycles")
	}
	if !slices.Equal(e.H.Series.NetworkMountHung, []wdeps.NetworkMountHungEntry{
		{Mountpoint: "/mnt/hung-nfs", FSType: "nfs4"},
	}) {
		t.Fatalf("Series.NetworkMountHung = %+v", e.H.Series.NetworkMountHung)
	}
	e.H.WriteNodeAgentPromTextfile()
	promPath := filepath.Join(textDir, "node-agent-hygiene.prom")
	promBytes, err := os.ReadFile(promPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(promBytes), `node_agent_network_mount_hung{mountpoint="/mnt/hung-nfs",fstype="nfs4"} 1`) {
		t.Fatalf("missing hung mount metric in prom file:\n%s", string(promBytes))
	}

	// Unblock the wedged goroutine and verify clean recovery + zero goroutine leak.
	probeMode.Store(1)
	unblock()

	// Wait briefly for the background probe goroutine to exit and clear inflight.
	deadline := time.Now().Add(time.Second)
	for calls.Load() == 1 && time.Now().Before(deadline) {
		runMountHung(e, ctx)
		if calls.Load() >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := calls.Load(); got < 2 {
		t.Fatalf("expected fresh probe after wedged goroutine unblocked, calls=%d", got)
	}

	e.H.WriteNodeAgentPromTextfile()
	if e.H.State.Exists(latchdefs.LatchNetworkMountHung) {
		t.Fatal("expected LatchNetworkMountHung to clear after recovery")
	}
	if len(e.H.Series.NetworkMountHung) != 0 {
		t.Fatalf("expected empty Series.NetworkMountHung after recovery, got %+v", e.H.Series.NetworkMountHung)
	}
	promBytes, err = os.ReadFile(promPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(promBytes), "node_agent_network_mount_hung{") {
		t.Fatalf("stale node_agent_network_mount_hung sample leaked after recovery:\n%s", string(promBytes))
	}
	if !strings.Contains(e.LogLines(t), "STATE-EXIT: network-mount-hung") {
		t.Fatalf("expected STATE-EXIT: network-mount-hung in log:\n%s", e.LogLines(t))
	}

	// Allow runtime scheduler to reap exited goroutine and verify <= initialGoroutines.
	leakDeadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > initialGoroutines && time.Now().Before(leakDeadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if goroutines := runtime.NumGoroutine(); goroutines > initialGoroutines {
		t.Fatalf("possible goroutine leak: initial=%d after unblock=%d", initialGoroutines, goroutines)
	}
}

func TestNetworkMountHungUnmountAndMultiMountpointIndependence(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	chk := e.H.Check(wdeps.CheckNetworkMountHung).(*whruntime.NetworkMountHungCheck)
	chk.ProbeTimeout = 20 * time.Millisecond
	textDir := t.TempDir()
	e.H.Cfg.TextfileDir = textDir

	miPath := setupMountinfo(t, e,
		"31 20 0:31 / /mnt/a rw - nfs4 10.0.0.2:/a rw\n"+
			"32 20 0:32 / /mnt/b rw - cifs //10.0.0.3/b rw\n")

	// Cycle 1: only B hangs (B=1, A=0).
	e.MountStatErrs["/mnt/b"] = context.DeadlineExceeded
	runMountHung(e, ctx)
	if e.H.State.Exists(latchdefs.LatchNetworkMountHung) {
		t.Fatal("cycle 1 B=1 must not latch")
	}

	// Cycle 2: A hangs too, B hangs again (A=1, B=2 -> B confirmed!).
	e.MountStatErrs["/mnt/a"] = context.DeadlineExceeded
	runMountHung(e, ctx)
	if !e.H.State.Exists(latchdefs.LatchNetworkMountHung) {
		t.Fatal("cycle 2 B=2 must latch")
	}
	if !slices.Equal(e.H.Series.NetworkMountHung, []wdeps.NetworkMountHungEntry{
		{Mountpoint: "/mnt/b", FSType: "cifs"},
	}) {
		t.Fatalf("expected only /mnt/b confirmed, got %+v", e.H.Series.NetworkMountHung)
	}

	// Cycle 3: B recovers while A is healthy for a moment? No — keep A at streak 1
	// by simulating B recovering and A failing on cycle 3? Wait: if A hangs on cycle 3
	// A hits streak 2. To test A staying at streak 1 independently while B recovers,
	// test B=2, A=0 -> Cycle 3: A=1, B=0 (B recovers -> latch clears, A at 1) ->
	// Cycle 4: A=2 (A reaches 2 -> latch re-enters for A).
	delete(e.MountStatErrs, "/mnt/a")
	delete(e.MountStatErrs, "/mnt/b")
	runMountHung(e, ctx) // reset both
	if e.H.State.Exists(latchdefs.LatchNetworkMountHung) {
		t.Fatal("expected latch clear after both recover")
	}

	e.MountStatErrs["/mnt/b"] = context.DeadlineExceeded
	runMountHung(e, ctx) // B=1
	runMountHung(e, ctx) // B=2 -> latched
	if !e.H.State.Exists(latchdefs.LatchNetworkMountHung) {
		t.Fatal("expected latch for B=2")
	}

	// Cycle: B recovers, A starts hanging (A=1, B=0 -> latch clears!).
	delete(e.MountStatErrs, "/mnt/b")
	e.MountStatErrs["/mnt/a"] = context.DeadlineExceeded
	runMountHung(e, ctx)
	if e.H.State.Exists(latchdefs.LatchNetworkMountHung) {
		t.Fatal("expected latch to exit when B recovered and A is only at 1/2")
	}

	// Next cycle: A hangs again -> A=2 -> latch re-enters for A only!
	runMountHung(e, ctx)
	if !e.H.State.Exists(latchdefs.LatchNetworkMountHung) {
		t.Fatal("expected latch to re-enter when A reaches 2/2")
	}
	if !slices.Equal(e.H.Series.NetworkMountHung, []wdeps.NetworkMountHungEntry{
		{Mountpoint: "/mnt/a", FSType: "nfs4"},
	}) {
		t.Fatalf("expected only /mnt/a confirmed, got %+v", e.H.Series.NetworkMountHung)
	}

	// Unmount /mnt/a completely (no network mounts remain) -> clears latch, metrics, and streak!
	wdepstest.WriteFile(t, miPath, "20 1 0:1 / / rw - ext4 /dev/vda1 rw\n")
	runMountHung(e, ctx)
	e.H.WriteNodeAgentPromTextfile()
	if e.H.State.Exists(latchdefs.LatchNetworkMountHung) {
		t.Fatal("expected unmount to clear LatchNetworkMountHung")
	}
	if len(e.H.Series.NetworkMountHung) != 0 {
		t.Fatalf("expected unmount to clear Series.NetworkMountHung, got %+v", e.H.Series.NetworkMountHung)
	}
	promBytes, err := os.ReadFile(filepath.Join(textDir, "node-agent-hygiene.prom"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(promBytes), "node_agent_network_mount_hung{") {
		t.Fatalf("stale metric leaked after unmount:\n%s", string(promBytes))
	}

	// Remount /mnt/a while still failing -> must start at streak 1/2 (previous streak pruned on unmount).
	wdepstest.WriteFile(t, miPath, "31 20 0:31 / /mnt/a rw - nfs4 10.0.0.2:/a rw\n")
	runMountHung(e, ctx)
	if e.H.State.Exists(latchdefs.LatchNetworkMountHung) {
		t.Fatal("expected pruned streak after unmount so first hang after remount is 1/2")
	}
}

func TestNetworkMountHungFailClosedAborts(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	chk := e.H.Check(wdeps.CheckNetworkMountHung).(*whruntime.NetworkMountHungCheck)
	chk.ProbeTimeout = 20 * time.Millisecond

	miPath := setupMountinfo(t, e, "31 20 0:31 / /mnt/nfs4 rw - nfs4 10.0.0.2:/export rw\n")
	e.MountStatErrs["/mnt/nfs4"] = context.DeadlineExceeded
	runMountHung(e, ctx)
	runMountHung(e, ctx)
	if !e.H.State.Exists(latchdefs.LatchNetworkMountHung) || len(e.H.Series.NetworkMountHung) != 1 {
		t.Fatal("precondition failed: expected armed latch and series")
	}

	// 1. Non-timeout HostExec error (e.g., ENOENT) -> abort preserving latch & series.
	e.MountStatErrs["/mnt/nfs4"] = errors.Join(syscall.ENOENT, errors.New("stat binary missing"))
	runMountHung(e, ctx)
	if got := mountHungCycles(e, "abort"); got != 1 {
		t.Fatalf("non-timeout abort cycles = %v, want 1", got)
	}
	if !e.H.State.Exists(latchdefs.LatchNetworkMountHung) || len(e.H.Series.NetworkMountHung) != 1 {
		t.Fatal("non-timeout probe error must preserve latch and series")
	}

	// 2. HostExecFn == nil -> abort preserving latch & series.
	savedExec := e.H.Cfg.Seams.Host.HostExecFn
	e.H.Cfg.Seams.Host.HostExecFn = nil
	runMountHung(e, ctx)
	e.H.Cfg.Seams.Host.HostExecFn = savedExec
	if got := mountHungCycles(e, "abort"); got != 2 {
		t.Fatalf("nil HostExecFn abort cycles = %v, want 2", got)
	}
	if !e.H.State.Exists(latchdefs.LatchNetworkMountHung) || len(e.H.Series.NetworkMountHung) != 1 {
		t.Fatal("nil HostExecFn must preserve latch and series")
	}

	// 3. Canceled ctx -> abort preserving latch & series.
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	runMountHung(e, cctx)
	if got := mountHungCycles(e, "abort"); got != 3 {
		t.Fatalf("canceled ctx abort cycles = %v, want 3", got)
	}
	if !e.H.State.Exists(latchdefs.LatchNetworkMountHung) || len(e.H.Series.NetworkMountHung) != 1 {
		t.Fatal("canceled ctx must preserve latch and series")
	}

	// 4. Unreadable mountinfo -> abort preserving latch & series.
	if err := os.Remove(miPath); err != nil {
		t.Fatal(err)
	}
	runMountHung(e, ctx)
	if got := mountHungCycles(e, "abort"); got != 4 {
		t.Fatalf("unreadable mountinfo abort cycles = %v, want 4", got)
	}
	if !e.H.State.Exists(latchdefs.LatchNetworkMountHung) || len(e.H.Series.NetworkMountHung) != 1 {
		t.Fatal("unreadable mountinfo must preserve latch and series")
	}
}
