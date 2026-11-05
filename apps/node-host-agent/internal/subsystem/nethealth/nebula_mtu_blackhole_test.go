package nethealth

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/watchdogconf"
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
	e.sdReply["is-enabled nebula@interdc"] = "enabled\n"
	e.sdReply["is-active nebula@interdc"] = "active\n"
	return e
}

func TestNebulaMTUBlackholeLatch(t *testing.T) {
	e := mtuEnv(t)
	n := e.n
	ctx := context.Background()
	st := n.mtuState()
	// Small ping OK, DF ping fails → 3 consecutive → latch + clamp.
	e.pingOK["10.128.0.2|false"] = true
	e.cmdFail["-M do -s 1252"] = true
	for i := 0; i < mtuBlackholeNeeded; i++ {
		n.checkNebulaMTUBlackhole(ctx, st)
	}
	if _, err := os.Stat(filepath.Join(e.state,
		"state-nebula-mtu-blackhole")); err != nil {
		t.Fatal("nebula-mtu-blackhole latch missing after 3 DF fails")
	}
	// MSS clamp attempted on neb1 (iptables -C fails → -A runs).
	if !e.cmdRan("clamp-mss-to-pmtu") {
		t.Fatal("MSS clamp not attempted")
	}
	// DF ping succeeding clears the latch.
	delete(e.cmdFail, "-M do -s 1252")
	n.checkNebulaMTUBlackhole(ctx, st)
	if _, err := os.Stat(filepath.Join(e.state,
		"state-nebula-mtu-blackhole")); !os.IsNotExist(err) {
		t.Fatal("latch not cleared after DF ping recovers")
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
	if e.cmdRan("-M do") {
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
	n.stateEnter("nebula-mtu-blackhole", "test")
	n.writeMTUBHMetric(st)
	b, _ = os.ReadFile(filepath.Join(dir, "node-agent-nebula-mtu.prom"))
	if !strings.Contains(string(b),
		"node_agent_nebula_mtu_blackhole 1") {
		t.Fatalf("metric not latched:\n%s", b)
	}
}
