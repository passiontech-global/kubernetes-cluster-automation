// cilium_wg_test.go — W15-NM2 zombie-peer detection: the state
// machine driven over fake-clock cycles with synthetic
// `wg show cilium_wg0 dump` outputs, plus the allowed-ips
// backward-compatibility fallback.
package cilium_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/cilium"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// wgFixture wires a fixture with a live cilium-agent task, the
// cilium_wg0 sysfs node, a 2-node healthz (expected peers = 2) and
// mutable dump/clock seams. Returns the env, the CycleEnv to Run
// with, and the closures the test mutates per cycle.
func wgFixture(t *testing.T) (*env, *wdeps.CycleEnv, *string, *time.Time) {
	t.Helper()
	e := fixture(t)
	e.MkCiliumTask(t, 4242)
	if err := os.MkdirAll(filepath.Join(e.SysNet, "cilium_wg0"), 0o755); err != nil {
		t.Fatal(err)
	}
	// /v1/healthz answers 2 remote members → expected = 2.
	e.UnixBody = []byte(`{"cluster":{"nodes":[{},{}]}}`)
	dump := ""
	now := time.Unix(1_800_000_000, 0)
	e.H.Cfg.Seams.Cilium.WGDump = func(_ context.Context, _ *systemd.Client) (string, error) {
		return dump, nil
	}
	e.H.Cfg.Seams.Cilium.MonotonicNow = func() time.Time { return now }
	env := &wdeps.CycleEnv{APIOK: true, WorkerActive: true}
	return e, env, &dump, &now
}

// wgPeer renders one 8-column `wg dump` peer row.
func wgPeer(pub, allowedIPs string, handshake int64, rx, tx int64) string {
	return fmt.Sprintf("%s\tpsk\t12.0.0.9:51820\t%s\t%d\t%d\t%d\t25\n",
		pub, allowedIPs, handshake, rx, tx)
}

// runWGCycles advances the fake clock 1m per cycle and Run the
// check, returning the latch presence after the final cycle.
func runWGCycles(t *testing.T, e *env, env *wdeps.CycleEnv, now *time.Time, n int) bool {
	t.Helper()
	ctx := context.Background()
	for range n {
		*now = now.Add(time.Minute)
		wg := wdepstest.Check[*cilium.CiliumWGCheck](e.H, wdeps.CheckCiliumWG)
		wg.Run(ctx, env)
	}
	return e.H.State.Exists(hoststate.LatchCiliumWGPeerWipe)
}

// logContains reads the watchdog log for the evidence lines.
func wgLog(t *testing.T, e *env) string {
	t.Helper()
	b, err := os.ReadFile(e.H.Cfg.WatchdogLogFile)
	if err != nil {
		return ""
	}
	return string(b)
}

// TestWGZombieDetectedAtThreeStalledCycles — a peer whose tx grows
// while rx stays flat with an 11m-old handshake classifies exactly
// when its 3rd consecutive stalled cycle lands; exclusion drops the
// healthy count below expected and the restart path fires under
// the last-cilium-restart budget. The healthy peer never counts as
// a zombie.
func TestWGZombieDetectedAtThreeStalledCycles(t *testing.T) {
	e, env, dump, now := wgFixture(t)
	stale := now.Unix() - 11*60
	// Cycles 1-3: pubB accumulates stalled cycles 0,1,2 — no
	// classification, actual stays 2 (pubA healthy, rx advancing).
	for i := range 3 {
		*now = now.Add(time.Minute)
		*dump = wgPeer("pubA", "10.0.0.2/32", now.Unix()-30, 1000+int64(i)*100, 2000+int64(i)*100) +
			wgPeer("pubB", "10.0.0.3/32", stale, 5000, 1000+int64(i)*1000)
		wg := wdepstest.Check[*cilium.CiliumWGCheck](e.H, wdeps.CheckCiliumWG)
		wg.Run(context.Background(), env)
	}
	if latched := e.H.State.Exists(hoststate.LatchCiliumWGPeerWipe); latched {
		t.Fatal("zombie must not classify before the 3rd stalled cycle")
	}
	if strings.Contains(wgLog(t, e), "zombie peer") {
		t.Fatal("zombie log must not appear before the 3rd stalled cycle")
	}
	// Cycle 4: stalledCycles hits 3 → pubB excluded (actual 1 < 2),
	// Fails streak 1. Cycle 5: streak 2 → latch + agent restart.
	for i := range 2 {
		*now = now.Add(time.Minute)
		*dump = wgPeer("pubA", "10.0.0.2/32", now.Unix()-30, 1400+int64(i)*100, 2400) +
			wgPeer("pubB", "10.0.0.3/32", stale, 5000, 4000+int64(i)*1000)
		wg := wdepstest.Check[*cilium.CiliumWGCheck](e.H, wdeps.CheckCiliumWG)
		wg.Run(context.Background(), env)
	}
	if !e.H.State.Exists(hoststate.LatchCiliumWGPeerWipe) {
		t.Fatal("cilium-agent restart path must fire once the zombie is excluded for ConsecNeeded cycles")
	}
	if !strings.Contains(wgLog(t, e), "zombie peer") {
		t.Fatal("zombie exclusion should be logged")
	}
	if len(e.Kills) == 0 {
		t.Fatal("cilium-agent SIGKILL expected after zombie-triggered peer deficit")
	}
}

// TestWGNotZombieWhenRxAdvancesOrHandshakeFresh — tx growth with
// advancing rx is normal bidirectional flow; flat rx with a fresh
// handshake is also never a zombie.
func TestWGNotZombieWhenRxAdvancesOrHandshakeFresh(t *testing.T) {
	e, env, dump, now := wgFixture(t)
	for i := range 6 {
		*now = now.Add(time.Minute)
		// peerX: tx+rx both grow, handshake stale.
		// peerY: tx grows, rx flat, handshake always fresh.
		*dump = wgPeer("peerX", "10.0.0.2/32", now.Unix()-11*60, 1000+int64(i)*500, 2000+int64(i)*500) +
			wgPeer("peerY", "10.0.0.3/32", now.Unix()-30, 5000, 1000)
		wg := wdepstest.Check[*cilium.CiliumWGCheck](e.H, wdeps.CheckCiliumWG)
		wg.Run(context.Background(), env)
	}
	if e.H.State.Exists(hoststate.LatchCiliumWGPeerWipe) {
		t.Fatal("no latch expected — neither peer is a zombie")
	}
	if strings.Contains(wgLog(t, e), "zombie peer") {
		t.Fatal("no zombie classification expected")
	}
}

// TestWGZeroHandshakeFlowWindow — with handshake==0, tx must have
// been flowing >5m before the peer classifies (alongside the 3
// stalled cycles).
func TestWGZeroHandshakeFlowWindow(t *testing.T) {
	e, env, dump, now := wgFixture(t)
	// Cycle 1 sets firstZeroHandshakeAt (tx>0, handshake 0); stall
	// streak reaches 3 at cycle 4 (3m of flow — under the 5m gate).
	// The zero-handshake gate clears only after >5m of flow — cycle
	// 7 (6m). pubA stays healthy so actual only drops when pubZ
	// classifies.
	for i := range 7 {
		*now = now.Add(time.Minute)
		*dump = wgPeer("pubA", "10.0.0.2/32", now.Unix()-30, 1000+int64(i)*100, 2000) +
			wgPeer("pubZ", "10.0.0.9/32", 0, 5000, 1000+int64(i+1)*100)
		wg := wdepstest.Check[*cilium.CiliumWGCheck](e.H, wdeps.CheckCiliumWG)
		wg.Run(context.Background(), env)
		if i < 6 && strings.Contains(wgLog(t, e), "zombie peer") {
			t.Fatalf("zombie classified too early at cycle %d (flow <5m)", i+1)
		}
	}
	if !strings.Contains(wgLog(t, e), "zombie peer") {
		t.Fatal("zombie expected once zero-handshake flow passes 5m with 3 stalled cycles")
	}
}

// TestWGPeerGoneResetsState — a peer that disappears from the dump
// loses its stalled streak; reappearing it starts from zero.
func TestWGPeerGoneResetsState(t *testing.T) {
	e, env, dump, now := wgFixture(t)
	base := now.Unix() - 11*60
	// Two stalled cycles for pubB (tx up, rx flat, stale handshake).
	for i := range 2 {
		*now = now.Add(time.Minute)
		*dump = wgPeer("pubA", "10.0.0.2/32", base+int64(i)*60, 1000, 1000) +
			wgPeer("pubB", "10.0.0.3/32", base, 5000, 1000+int64(i+1)*100)
		wg := wdepstest.Check[*cilium.CiliumWGCheck](e.H, wdeps.CheckCiliumWG)
		wg.Run(context.Background(), env)
	}
	// pubB disappears for a cycle, then returns with the same
	// transfer pattern — its state was pruned, so the streak
	// restarts at 0 and it must NOT classify as a zombie.
	for i := range 4 {
		*now = now.Add(time.Minute)
		if i == 0 {
			*dump = wgPeer("pubA", "10.0.0.2/32", base, 2000, 2000)
		} else {
			*dump = wgPeer("pubA", "10.0.0.2/32", base, 2000+int64(i)*100, 2000) +
				wgPeer("pubB", "10.0.0.3/32", base, 5000, 1100+int64(i)*100)
		}
		wg := wdepstest.Check[*cilium.CiliumWGCheck](e.H, wdeps.CheckCiliumWG)
		wg.Run(context.Background(), env)
	}
	if strings.Contains(wgLog(t, e), "zombie peer") {
		t.Fatal("peer state must reset when the peer disappears from the dump")
	}
}

// TestWGAllowedIPsFallbackStillWorks — when the dump exec fails the
// check keeps the W5.6 allowed-ips counting path (wiped peers at
// "(none)" are not counted) and the restart path fires unchanged.
func TestWGAllowedIPsFallbackStillWorks(t *testing.T) {
	e := fixture(t)
	e.MkCiliumTask(t, 4242)
	if err := os.MkdirAll(filepath.Join(e.SysNet, "cilium_wg0"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.UnixBody = []byte(`{"cluster":{"nodes":[{},{}]}}`)
	e.H.Cfg.Seams.Cilium.WGDump = func(_ context.Context, _ *systemd.Client) (string, error) {
		return "", fmt.Errorf("wg exec unavailable")
	}
	e.SDReply["allowed-ips"] = "pubA\t10.0.0.2/32\npubB\t(none)\n"
	env := &wdeps.CycleEnv{APIOK: true, WorkerActive: true}
	if runWGCycles(t, e, env, &e.Now, 2) != true {
		t.Fatal("allowed-ips fallback must still drive the restart path")
	}
	if !strings.Contains(wgLog(t, e), "allowed_ips=1 expected=2") {
		t.Fatal("expected the W5.6 allowed-ips deficit evidence in the log")
	}
}
