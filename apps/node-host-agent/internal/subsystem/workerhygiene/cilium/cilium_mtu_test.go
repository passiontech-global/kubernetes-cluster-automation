// cilium_mtu_test.go — B4 cilium_net vs nebula MTU drift latch
// + runtime-config MTU max-resolution.
package cilium_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// --- B4: MTU drift ---

func TestCiliumMTUDriftLatchesAndLogs(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "neb1", "mtu"), "1300\n")
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "cilium_net", "mtu"), "1500\n")
	e.H.Cycle(context.Background())
	if !e.H.State.Exists("cilium-mtu-drift") {
		t.Fatal("state-cilium-mtu-drift should latch when cilium_mtu > neb1")
	}
	data, err := os.ReadFile(e.H.Cfg.WatchdogLogFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "ACTION cilium-mtu-drift: cilium_net=1500 nebula=1300") {
		t.Fatalf("log missing drift ACTION line:\n%s", data)
	}
	// Drift fixed → latch clears.
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "cilium_net", "mtu"), "1300\n")
	e.H.Cycle(context.Background())
	if e.H.State.Exists("cilium-mtu-drift") {
		t.Fatal("latch should clear once MTUs align")
	}
}

func TestCiliumMTURuntimeConfigFallback(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "neb1", "mtu"), "1300\n")
	wdepstest.WriteFile(t, e.CiliumRt, `{"mtu":1500,"other":1}`)
	e.H.Cycle(context.Background())
	if !e.H.State.Exists("cilium-mtu-drift") {
		t.Fatal("runtime-config MTU 1500 > neb1 1300 should latch drift")
	}
}

// TestRuntimeConfigMTUMaxDeterministic pins the multi-mtu
// behaviour: several `mtu`-keyed values (nested maps AND arrays)
// must resolve to the MAX — a "first match" walk is unstable
// under Go's random map iteration order.
func TestRuntimeConfigMTUMaxDeterministic(t *testing.T) {
	e := fixture(t)
	wdepstest.WriteFile(t, e.CiliumRt,
		`{"a":{"mtu":1300},"list":[{"mtu":1400},{"mtu":1500}],"z":{"MTU":900}}`)
	got, ok := procfs.RuntimeConfigMTU(e.CiliumRt)
	if !ok || got != 1500 {
		t.Fatalf("RuntimeConfigMTU=%v,%v want 1500,true (max of all mtu keys)", got, ok)
	}
}

// TestCiliumMTUWG0DriftLatches: on the WireGuard datapath the
// double-encap interface must sit at least wgEncapOverheadBytes under
// the overlay — wg0 above nebula−60 blackholes pod traffic.
func TestCiliumMTUWG0DriftLatches(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "neb1", "mtu"), "1300\n")
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "cilium_net", "mtu"), "1300\n")
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "cilium_wg0", "mtu"), "1300\n")
	e.H.Cycle(context.Background())
	if !e.H.State.Exists("cilium-mtu-drift") {
		t.Fatal("wg0 MTU 1300 > nebula 1300-60 must latch drift")
	}
	if !strings.Contains(e.LogLines(t),
		"cilium_wg0=1300 nebula=1300 (wg overhead 60)") {
		t.Fatalf("missing wg0 drift reason:\n%s", e.LogLines(t))
	}
	// Aligning wg0 clears the latch.
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "cilium_wg0", "mtu"), "1240\n")
	e.H.Cycle(context.Background())
	if e.H.State.Exists("cilium-mtu-drift") {
		t.Fatal("drift latch must clear once wg0 fits the encap budget")
	}
}

// TestCiliumMTULxcDriftVotes: a stale pod veth (lxc<hex>) above the
// overlay MTU votes on the same latch; lxc_health must not.
func TestCiliumMTULxcDriftVotes(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "neb1", "mtu"), "1300\n")
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "lxc9aa1bb", "mtu"), "1400\n")
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "lxc_health", "mtu"), "9000\n")
	e.H.Cycle(context.Background())
	if !e.H.State.Exists("cilium-mtu-drift") {
		t.Fatal("pod lxc* MTU 1400 > nebula 1300 must latch drift")
	}
	if !strings.Contains(e.LogLines(t), "pod lxc*=1400 nebula=1300") {
		t.Fatalf("missing lxc drift reason (lxc_health must not win):\n%s", e.LogLines(t))
	}
}

// TestCiliumMTUNoOverlayClearsStaleLatch: without neb1 there is
// nothing to compare against — a pre-existing drift latch must not
// linger on a node that no longer runs the overlay.
func TestCiliumMTUNoOverlayClearsStaleLatch(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "cilium_net", "mtu"), "1500\n")
	e.H.State.Enter("cilium-mtu-drift", "stale evidence")
	e.H.Cycle(context.Background())
	if e.H.State.Exists("cilium-mtu-drift") {
		t.Fatal("drift latch kept without an overlay to compare against")
	}
}

// TestCiliumMTUDriftRefreshStaysQuiet: while the drift persists the
// latch file is refreshed (janitor-reap protection) but the NPD
// ACTION line stays one-shot per episode.
func TestCiliumMTUDriftRefreshStaysQuiet(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "neb1", "mtu"), "1300\n")
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "cilium_net", "mtu"), "1500\n")
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if n := strings.Count(e.LogLines(t), "ACTION cilium-mtu-drift:"); n != 1 {
		t.Fatalf("drift ACTION lines=%d want exactly 1 across a held latch", n)
	}
}

func TestCiliumMTUSysClassNetUnreadableAbortsPreservingLatch(t *testing.T) {
	t.Run("sysnet-not-dir", func(t *testing.T) {
		e := fixture(t)
		e.SDReply["is-active k0sworker.service"] = "active"
		wdepstest.WriteFile(t, filepath.Join(e.SysNet, "neb1", "mtu"), "1300\n")
		wdepstest.WriteFile(t, filepath.Join(e.SysNet, "cilium_net", "mtu"), "1500\n")
		e.H.Cycle(context.Background())
		if !e.H.State.Exists(latchdefs.LatchCiliumMTUDrift) {
			t.Fatal("setup: LatchCiliumMTUDrift not armed")
		}

		origSysNet := e.H.Cfg.SysClassNet
		notDir := filepath.Join(t.TempDir(), "not-a-dir")
		wdepstest.WriteFile(t, notDir, "x")
		e.H.Cfg.SysClassNet = notDir

		e.H.Cycle(context.Background())
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCiliumMTU, "abort")); got != 1 {
			t.Fatalf("abort cycles=%v want 1 on ENOTDIR", got)
		}
		if !e.H.State.Exists(latchdefs.LatchCiliumMTUDrift) {
			t.Fatal("LatchCiliumMTUDrift falsely exited on ENOTDIR")
		}
		if strings.Contains(e.LogLines(t), "STATE-EXIT: cilium-mtu-drift") {
			t.Fatalf("unexpected STATE-EXIT in log:\n%s", e.LogLines(t))
		}

		e.H.Cfg.SysClassNet = origSysNet
		if err := os.RemoveAll(filepath.Join(e.SysNet, "neb1")); err != nil {
			t.Fatal(err)
		}
		e.H.Cycle(context.Background())
		if e.H.State.Exists(latchdefs.LatchCiliumMTUDrift) {
			t.Fatal("ENOENT on neb1 should exit LatchCiliumMTUDrift")
		}
	})

	t.Run("sysnet-and-iface-chmod-0000", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0000 does not block root")
		}
		e := fixture(t)
		e.SDReply["is-active k0sworker.service"] = "active"
		wdepstest.WriteFile(t, filepath.Join(e.SysNet, "neb1", "mtu"), "1300\n")
		wdepstest.WriteFile(t, filepath.Join(e.SysNet, "cilium_net", "mtu"), "1500\n")
		e.H.Cycle(context.Background())
		if !e.H.State.Exists(latchdefs.LatchCiliumMTUDrift) {
			t.Fatal("setup: LatchCiliumMTUDrift not armed")
		}

		// 1) SysClassNet 0o000 -> abort, keep latch.
		if err := os.Chmod(e.SysNet, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(e.SysNet, 0o755) })
		e.H.Cycle(context.Background())
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCiliumMTU, "abort")); got != 1 {
			t.Fatalf("abort cycles=%v want 1 on SysClassNet 0o000", got)
		}
		if !e.H.State.Exists(latchdefs.LatchCiliumMTUDrift) {
			t.Fatal("LatchCiliumMTUDrift falsely exited on SysClassNet 0o000")
		}

		// 2) SysClassNet restored, cilium_net/mtu 0o000 -> abort, keep latch.
		if err := os.Chmod(e.SysNet, 0o755); err != nil {
			t.Fatal(err)
		}
		cilMTU := filepath.Join(e.SysNet, "cilium_net", "mtu")
		if err := os.Chmod(cilMTU, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(cilMTU, 0o644) })
		e.H.Cycle(context.Background())
		if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCiliumMTU, "abort")); got != 2 {
			t.Fatalf("abort cycles=%v want 2 on cilium_net/mtu 0o000", got)
		}
		if !e.H.State.Exists(latchdefs.LatchCiliumMTUDrift) {
			t.Fatal("LatchCiliumMTUDrift falsely exited on cilium_net/mtu 0o000")
		}
		if err := os.Chmod(cilMTU, 0o644); err != nil {
			t.Fatal(err)
		}

		// 3) ENOENT on neb1 -> clears latch cleanly.
		if err := os.RemoveAll(filepath.Join(e.SysNet, "neb1")); err != nil {
			t.Fatal(err)
		}
		e.H.Cycle(context.Background())
		if e.H.State.Exists(latchdefs.LatchCiliumMTUDrift) {
			t.Fatal("ENOENT on neb1 should exit LatchCiliumMTUDrift")
		}
	})
}

func TestCiliumMTULxcUnreadableAbortsPreservingLatch(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod 0000 does not block root")
	}
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "neb1", "mtu"), "1300\n")
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "cilium_net", "mtu"), "1300\n")
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "cilium_wg0", "mtu"), "1240\n")
	wdepstest.WriteFile(t, filepath.Join(e.SysNet, "lxc9aa1bb", "mtu"), "1500\n")

	// Cycle 1: drifted pod lxc9aa1bb arms LatchCiliumMTUDrift.
	e.H.Cycle(context.Background())
	if !e.H.State.Exists(latchdefs.LatchCiliumMTUDrift) {
		t.Fatal("setup: LatchCiliumMTUDrift not armed by lxc9aa1bb/mtu=1500")
	}
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCiliumMTU, "ok")); got != 1 {
		t.Fatalf("setup ok cycles=%v want 1", got)
	}

	// Cycle 2: lxc9aa1bb/mtu becomes unreadable (EACCES) -> must abort and preserve latch.
	lxcMTU := filepath.Join(e.SysNet, "lxc9aa1bb", "mtu")
	if err := os.Chmod(lxcMTU, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(lxcMTU, 0o644) })
	e.H.Cycle(context.Background())
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCiliumMTU, "abort")); got != 1 {
		t.Fatalf("abort cycles=%v want 1 on lxc9aa1bb/mtu 0o000", got)
	}
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCiliumMTU, "ok")); got != 1 {
		t.Fatalf("ok cycles=%v want 1 (unreadable lxc must not emit ok)", got)
	}
	if !e.H.State.Exists(latchdefs.LatchCiliumMTUDrift) {
		t.Fatal("LatchCiliumMTUDrift falsely exited on lxc9aa1bb/mtu 0o000")
	}
	if strings.Contains(e.LogLines(t), "STATE-EXIT: cilium-mtu-drift") {
		t.Fatalf("unexpected STATE-EXIT in log:\n%s", e.LogLines(t))
	}

	// Cycle 3: pod exits (ENOENT) -> clears latch cleanly and records ok.
	if err := os.Chmod(lxcMTU, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(e.SysNet, "lxc9aa1bb")); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCiliumMTU, "ok")); got != 2 {
		t.Fatalf("ok cycles=%v want 2 after lxc ENOENT recovery", got)
	}
	if e.H.State.Exists(latchdefs.LatchCiliumMTUDrift) {
		t.Fatal("ENOENT on exited lxc9aa1bb should exit LatchCiliumMTUDrift")
	}
}
