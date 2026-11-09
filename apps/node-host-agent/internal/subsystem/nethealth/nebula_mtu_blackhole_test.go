package nethealth

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

// nebulaWD is a minimal nebula-active watchdog config for the MTU
// blackhole check.
func nebulaWD() *watchdogconf.Config {
	return &watchdogconf.Config{
		OverlayActive:       "nebula",
		NebulaNet:           "interdc",
		NebulaDev:           "neb1",
		OverlayProbeTargets: []string{"10.128.0.2"},
	}
}

func mtuEnv(t *testing.T) *env {
	t.Helper()
	e := fixture(t, nebulaWD())
	e.sd.On("is-enabled nebula@interdc", "enabled\n")
	e.sd.On("is-active nebula@interdc", "active\n")
	return e
}

func TestNebulaMTUBlackholeLatch(t *testing.T) {
	e := mtuEnv(t)
	n := e.n
	ctx := context.Background()
	st := n.mtuState()
	// Small ping OK, DF ping fails → 3 consecutive → latch + clamp.
	e.pingOK["10.128.0.2|false"] = true
	e.host.FailOn("-M do -s 1252", errCmdFail)
	for i := 0; i < mtuBlackholeNeeded; i++ {
		n.checkNebulaMTUBlackhole(ctx, st)
	}
	if _, err := os.Stat(filepath.Join(e.state,
		"state-nebula-mtu-blackhole")); err != nil {
		t.Fatal("nebula-mtu-blackhole latch missing after 3 DF fails")
	}
	// MSS clamp attempted on neb1 (iptables -C fails → -A runs).
	if !e.host.Ran("clamp-mss-to-pmtu") {
		t.Fatal("MSS clamp not attempted")
	}
	// DF ping succeeding clears the latch — and REMOVES the clamp
	// rule it installed (a left-behind TCPMSS keeps forcing PMTU MSS
	// on healthy overlay flows forever).
	e.host.On("-C POSTROUTING -o neb1", "ok\n") // rule present → -D runs
	e.host.Clear("-M do -s 1252")
	n.checkNebulaMTUBlackhole(ctx, st)
	if _, err := os.Stat(filepath.Join(e.state,
		"state-nebula-mtu-blackhole")); !os.IsNotExist(err) {
		t.Fatal("latch not cleared after DF ping recovers")
	}
	if !e.host.Ran("-D POSTROUTING -o neb1") {
		t.Fatal("MSS clamp rule not removed on recovery")
	}
	if strings.Contains(logLines(t, e), "MSS unclamp failed") {
		t.Fatalf("unclamp failed:\n%s", logLines(t, e))
	}
}

// TestNebulaMTUBlackholeRecoveryUnclampsCiliumWG: the blackhole
// remediation clamps cilium_wg0 alongside the overlay dev
// (maybeClampNebulaMSS) — recovery must remove BOTH rules, or the
// double-encapsulation path keeps forcing clamp-mss-to-pmtu forever
// after the fault cleared. The cilium_wg0 rule here came from the
// blackhole path (wgClampKnown false — the MTU invariant never fired
// in this fixture).
func TestNebulaMTUBlackholeRecoveryUnclampsCiliumWG(t *testing.T) {
	e := mtuEnv(t)
	n := e.n
	ctx := context.Background()
	st := n.mtuState()
	e.pingOK["10.128.0.2|false"] = true
	e.host.FailOn("-M do -s 1252", errCmdFail)
	// The fake answers "rule already present" by default — make the
	// -C probes fail so the latch phase actually INSTALLS (-A) on
	// both devs, like a host without the rules.
	e.host.FailOn("-C POSTROUTING", errCmdFail)
	for range mtuBlackholeNeeded {
		n.checkNebulaMTUBlackhole(ctx, st)
	}
	if _, err := os.Stat(filepath.Join(e.state,
		"state-nebula-mtu-blackhole")); err != nil {
		t.Fatal("latch missing after DF fails")
	}
	// The blackhole clamp covered BOTH devs.
	if !e.host.Ran("-A POSTROUTING -o neb1") ||
		!e.host.Ran("-A POSTROUTING -o cilium_wg0") {
		t.Fatal("blackhole clamp did not cover neb1 + cilium_wg0")
	}

	// Recovery with the invariant bit unset: both rules go.
	st.mu.Lock()
	st.wgClampKnown = false
	st.mu.Unlock()
	e.host.On("-C POSTROUTING -o neb1", "ok\n")       // rule present → -D
	e.host.On("-C POSTROUTING -o cilium_wg0", "ok\n") // rule present → -D
	e.host.Clear("-M do -s 1252")
	n.checkNebulaMTUBlackhole(ctx, st)
	if _, err := os.Stat(filepath.Join(e.state,
		"state-nebula-mtu-blackhole")); !os.IsNotExist(err) {
		t.Fatal("latch not cleared after DF ping recovers")
	}
	if !e.host.Ran("-D POSTROUTING -o neb1") {
		t.Fatal("neb1 clamp rule not removed on recovery")
	}
	if !e.host.Ran("-D POSTROUTING -o cilium_wg0") {
		t.Fatal("cilium_wg0 clamp rule not removed on blackhole recovery")
	}
}

// TestNebulaMTUBlackholeRecoveryKeepsInvariantClamp: when
// wgClampKnown is set the cilium_wg0 rule belongs to the MTU
// invariant (config drift that outlives the blackhole episode) —
// recovery unclamps the overlay dev ONLY and must not fork iptables
// against cilium_wg0 (the invariant re-installs the rule next probe
// cycle anyway).
func TestNebulaMTUBlackholeRecoveryKeepsInvariantClamp(t *testing.T) {
	e := mtuEnv(t)
	n := e.n
	ctx := context.Background()
	st := n.mtuState()
	e.pingOK["10.128.0.2|false"] = true
	e.host.FailOn("-M do -s 1252", errCmdFail)
	e.host.FailOn("-C POSTROUTING", errCmdFail)
	for range mtuBlackholeNeeded {
		n.checkNebulaMTUBlackhole(ctx, st)
	}
	if !e.host.Ran("-A POSTROUTING -o cilium_wg0") {
		t.Fatal("blackhole clamp did not cover cilium_wg0")
	}

	st.mu.Lock()
	st.wgClampKnown = true // the invariant owns the cilium_wg0 rule
	st.mu.Unlock()
	e.host.On("-C POSTROUTING -o neb1", "ok\n")
	e.host.ClearLog()
	e.host.Clear("-M do -s 1252")
	n.checkNebulaMTUBlackhole(ctx, st)
	if e.host.Ran("cilium_wg0") {
		t.Fatal("recovery touched the invariant-owned cilium_wg0 rule")
	}
	if !e.host.Ran("-D POSTROUTING -o neb1") {
		t.Fatal("neb1 clamp rule not removed on recovery")
	}
}

func TestNebulaMTUBlackholeNeedsSmallOK(t *testing.T) {
	e := mtuEnv(t)
	n := e.n
	ctx := context.Background()
	st := n.mtuState()
	// NO small ping → total overlay failure is NOT a PMTU latch.
	for i := 0; i < mtuBlackholeNeeded+1; i++ {
		n.checkNebulaMTUBlackhole(ctx, st)
	}
	if _, err := os.Stat(filepath.Join(e.state,
		"state-nebula-mtu-blackhole")); !os.IsNotExist(err) {
		t.Fatal("latch set with no alive peer — wrong verdict")
	}
	// Overlay not active → gated out entirely.
	n.cfg.Watchdog.OverlayActive = "tinc"
	n.checkNebulaMTUBlackhole(ctx, st)
	if e.host.Ran("-M do") {
		t.Fatal("DF probe ran while overlay=tinc")
	}
}

func TestNebulaMTUMetric(t *testing.T) {
	e := mtuEnv(t)
	n := e.n
	st := n.mtuState()
	dir := t.TempDir()
	textfileDirOverride = dir
	defer func() { textfileDirOverride = "" }()
	n.writeMTUBHMetric(st)
	b, err := os.ReadFile(filepath.Join(dir, "node-agent-nebula-mtu.prom"))
	if err != nil {
		t.Fatalf("metric file missing: %v", err)
	}
	if !strings.Contains(string(b),
		"node_agent_nebula_mtu_blackhole 0") {
		t.Fatalf("metric wrong:\n%s", b)
	}
	// Latch → gauge flips to 1.
	n.state.Enter("nebula-mtu-blackhole", "test")
	n.writeMTUBHMetric(st)
	b, _ = os.ReadFile(filepath.Join(dir, "node-agent-nebula-mtu.prom"))
	if !strings.Contains(string(b),
		"node_agent_nebula_mtu_blackhole 1") {
		t.Fatalf("metric not latched:\n%s", b)
	}
}

// ciliumSysfsMTU renders Host sysfs MTU files for the invariant check.
func ciliumSysfsMTU(t *testing.T, mtus map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for dev, mtu := range mtus {
		path := filepath.Join(root, "sys", "class", "net", dev, "mtu")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(mtu+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// The cilium_wg0 MTU invariant is config-drift enforcement,
// not a blackhole symptom — it must run EVERY probe cycle, including
// when neb1 is fully healthy (DF ping passes → no latch, no
// maybeClampNebulaMSS). A cilium_wg0 sized against the underlay
// (1420 > nebula 1300−80) must be caught + MSS-clamped here, not only
// after the blackhole latches.
func TestCiliumWGMTUInvariantOnHealthyOverlay(t *testing.T) {
	e := mtuEnv(t)
	n := e.n
	ctx := context.Background()
	st := n.mtuState()
	n.cfg.HostRoot = ciliumSysfsMTU(t, map[string]string{
		"neb1":       "1300",
		"cilium_wg0": "1420",
	})
	// Healthy overlay: small ping answers AND DF ping passes — no
	// blackhole, no clamp via maybeClampNebulaMSS.
	e.pingOK["10.128.0.2|false"] = true
	n.checkNebulaMTUBlackhole(ctx, st)
	if _, err := os.Stat(filepath.Join(e.state,
		"state-nebula-mtu-blackhole")); !os.IsNotExist(err) {
		t.Fatal("latch set on healthy DF ping")
	}
	if !e.host.Ran("-o cilium_wg0") {
		t.Fatal("cilium_wg0 invariant not enforced on a healthy overlay — MSS clamp missing")
	}
}

// Compliant control: cilium_wg0 within the invariant (1200 <= 1300−80)
// must NOT trigger a clamp on the healthy-overlay path.
func TestCiliumWGMTUInvariantCompliantNoClamp(t *testing.T) {
	e := mtuEnv(t)
	n := e.n
	ctx := context.Background()
	st := n.mtuState()
	n.cfg.HostRoot = ciliumSysfsMTU(t, map[string]string{
		"neb1":       "1300",
		"cilium_wg0": "1200",
	})
	e.pingOK["10.128.0.2|false"] = true
	n.checkNebulaMTUBlackhole(ctx, st)
	if e.host.Ran("-o cilium_wg0") {
		t.Fatal("clamp fired although cilium_wg0 satisfies the MTU invariant")
	}
}
