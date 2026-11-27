package nebula

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

type nebulaTestEnv struct {
	deps *Deps
	dir  string
	wd   *watchdogconf.Config
}

func newTestDeps(t *testing.T) *nebulaTestEnv {
	t.Helper()
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	clk := timex.NewCell(func() time.Time { return now })
	st := hoststate.New(stateDir, filepath.Join(dir, "watchdog.log"), clk.Now, nil)

	wd := &watchdogconf.Config{
		NebulaNet:              "mesh",
		NebulaPort:             4242,
		NebulaDev:              "neb1",
		NebulaStatsURL:         "http://127.0.0.1:9100/metrics",
		OverlayActive:          "nebula",
		OverlayProbeTargets:    []string{"1.1.1.1", "2.2.2.2"},
		OverlayProbeMarkers:    []string{"10.8.0.1", "10.8.0.2"},
		OverlaySlowpathMarkers: []string{"10.8.0.1"},
		OverlaySlowpathRTTms:   100,
		OverlaySiteMarkers:     []string{"10.8.0.9"},
		OverlaySiteedgeRTTms:   150,
		OverlayEgressRelays:    []string{"3.3.3.3"},
		NebulaDegradedConsec:   2,
		OverlayProbeCount:      1,
		OverlayProbeWait:       1,
	}

	udpFile := filepath.Join(dir, "udp")
	udp6File := filepath.Join(dir, "udp6")
	_ = os.WriteFile(udpFile, []byte("sl local_address\n0: 00000000:1092 00000000:0000 07\n"), 0o644) // 4242 = 0x1092
	_ = os.WriteFile(udp6File, []byte("sl local_address\n"), 0o644)

	d := &Deps{
		Cycles:  prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_cycles"}, []string{"check", "result"}),
		Actions: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_actions"}, []string{"check", "action"}),
		State:   st,
		Watchdog: func() *watchdogconf.Config {
			return wd
		},
		WatchdogConf: func() *watchdogconf.Config {
			return wd
		},
		Systemd: func() *systemd.Client { return nil },
		ConsecNeeded: func() int {
			return 2
		},
		MinRestart: func() time.Duration {
			return 5 * time.Minute
		},
		NebulaDirectTCPPorts: func() []int {
			return []int{443, 6443, 0, 70000}
		},
		ProcNetUDP:  func() string { return udpFile },
		ProcNetUDP6: func() string { return udp6File },
		HostRoot:    func() string { return dir },
		Interval:    func() time.Duration { return 5 * time.Millisecond },
		TextfileDir: func() string { return filepath.Join(dir, "textfile") },
		Clock:       func() *timex.Cell { return clk },
		RunHostCmd: func(_ context.Context, _ []string) (string, error) {
			return "", nil
		},
		RunMountCmd: func(_ context.Context, _ []string) (string, error) {
			return "", nil
		},
		Ping: func(_ context.Context, _ string, _, _ int, _ bool) (bool, float64) {
			return true, 5.0
		},
		ProbeHTTP: func(_ context.Context, _ string, _ time.Duration) error {
			return nil
		},
		IP: func(_ context.Context, _ ...string) (string, error) {
			return "", nil
		},
		LinkAddrs: func(_ int, _ string) ([]netlink.Addr, error) {
			return []netlink.Addr{{IPNet: &net.IPNet{IP: net.ParseIP("10.8.0.10"), Mask: net.CIDRMask(24, 32)}}}, nil
		},
		Rules: func(_ int) ([]netlink.Rule, error) {
			return nil, nil
		},
		StateExit: func(name string) {
			st.Exit(name, nil)
		},
		UnitEnabledActive: func(_ context.Context, _ string) bool {
			return true
		},
		NebulaUpExists: func(_ *watchdogconf.Config) bool {
			return true
		},
		FlushStaleUDPConntrack:   func(_ context.Context, _ string) {},
		FlushPeerNebulaConntrack: func(_ context.Context, _ string, _ ...string) {},
		TrimRunErr:               func(s string) string { return strings.TrimSpace(s) },
	}
	return &nebulaTestEnv{deps: d, dir: dir, wd: wd}
}

func TestDirectTCPAndHasRule(t *testing.T) {
	// Gated path.
	env := newTestDeps(t)
	env.deps.NebulaUpExists = func(*watchdogconf.Config) bool { return false }
	env.deps.CheckNebulaDirectTCP(context.Background())

	// Rules dump error path.
	env.deps.NebulaUpExists = func(*watchdogconf.Config) bool { return true }
	env.deps.Rules = func(int) ([]netlink.Rule, error) { return nil, errors.New("netlink err") }
	env.deps.CheckNebulaDirectTCP(context.Background())

	// Partial rule present + restore error + restore ok.
	env.deps.Rules = func(int) ([]netlink.Rule, error) {
		return []netlink.Rule{
			{Priority: 1499, Dport: &netlink.RulePortRange{Start: 443, End: 443}},
			{Priority: 1499, Sport: &netlink.RulePortRange{Start: 443, End: 443}},
		}, nil
	}
	ipCalls := 0
	env.deps.IP = func(_ context.Context, args ...string) (string, error) {
		ipCalls++
		if ipCalls == 1 {
			return "", errors.New("add failed")
		}
		return "", nil
	}
	env.deps.CheckNebulaDirectTCP(context.Background())
	if ipCalls != 2 {
		t.Fatalf("expected 2 IP add calls for port 6443 (dport+sport), got %d", ipCalls)
	}
	// Second run with IP succeeding.
	env.deps.CheckNebulaDirectTCP(context.Background())
	if ipCalls != 4 {
		t.Fatalf("expected 4 IP add calls total, got %d", ipCalls)
	}

	if hasDirectTCPRule([]netlink.Rule{{Priority: 1499, Dport: &netlink.RulePortRange{Start: 100, End: 200}}}, 100, directTCPDirections[0].getPort) {
		t.Fatal("range rule should not match single-port check")
	}
}

func TestHealthAndRemedyHelpers(t *testing.T) {
	ctx := context.Background()
	env := newTestDeps(t)

	if logger() == nil {
		t.Fatal("expected non-nil logger")
	}
	if env.deps.MTUState() != &env.deps.MTU {
		t.Fatal("MTUState returned unexpected pointer")
	}

	// Gated when unit inactive -> cleans state files.
	env.deps.State.Enter(latchdefs.LatchNebulaIsolated, "test")
	env.deps.UnitEnabledActive = func(context.Context, string) bool { return false }
	env.deps.CheckNebulaHealth(ctx)
	if env.deps.State.Exists(latchdefs.LatchNebulaIsolated) {
		t.Fatal("expected nebula latch to be cleaned up when unit inactive")
	}

	// Active & healthy path.
	env.deps.UnitEnabledActive = func(context.Context, string) bool { return true }
	env.deps.CheckNebulaHealth(ctx)
	if env.deps.NebulaFails != 0 || env.deps.NebulaDpFail != 0 {
		t.Fatalf("expected zero fails on healthy run, got %d/%d", env.deps.NebulaFails, env.deps.NebulaDpFail)
	}

	// Socket missing -> consecutive failures -> NebulaRestart (with nil systemd).
	env.deps.ProcNetUDP = func() string { return filepath.Join(env.dir, "missing-udp") }
	env.deps.CheckNebulaHealth(ctx) // fail 1 (pending)
	env.deps.CheckNebulaHealth(ctx) // fail 2 -> triggers NebulaRestart

	// Restore UDP, test missing tun addr, then stats dead, then RestartTimesyncdOnClockLatch.
	udpFile := filepath.Join(env.dir, "udp")
	env.deps.ProcNetUDP = func() string { return udpFile }
	env.deps.LinkAddrs = func(int, string) ([]netlink.Addr, error) { return nil, errors.New("no dev") }
	env.deps.CheckNebulaHealth(ctx)

	env.deps.LinkAddrs = func(int, string) ([]netlink.Addr, error) {
		return []netlink.Addr{{IPNet: &net.IPNet{IP: net.ParseIP("10.8.0.10"), Mask: net.CIDRMask(24, 32)}}}, nil
	}
	env.deps.ProbeHTTP = func(context.Context, string, time.Duration) error { return errors.New("stats down") }
	env.deps.State.Enter(latchdefs.LatchClockSkew, "skew")
	env.deps.CheckNebulaHealth(ctx)

	// Wired systemd client for NebulaRestart and RestartTimesyncdOnClockLatch.
	sd := systemd.New(systemd.Config{
		RunCmd: func(context.Context, []string) (string, error) { return "enabled\n", nil },
	})
	env.deps.Systemd = func() *systemd.Client { return sd }
	env.deps.NebulaRestart(ctx)
	env.deps.RestartTimesyncdOnClockLatch(ctx)
}

func TestOverlayPipelineAndUnderlayPeers(t *testing.T) {
	ctx := context.Background()
	env := newTestDeps(t)

	// Write static_host_map YAML for NebulaUnderlayPeers.
	nebDir := filepath.Join(env.dir, "etc", "nebula", "mesh")
	if err := os.MkdirAll(nebDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(nebDir, "hosts.yaml"), []byte("static_host_map:\n  \"10.8.0.2\": [\"9.9.9.9:4242\", \"[2001:db8::1]:4242\"]\n"), 0o644)
	_ = os.WriteFile(filepath.Join(nebDir, "bad.yaml"), []byte(":::bad-yaml"), 0o644)

	peers := env.deps.NebulaUnderlayPeers("mesh")
	if len(peers["10.8.0.2"]) != 2 || peers["10.8.0.2"][0] != "9.9.9.9" || peers["10.8.0.2"][1] != "2001:db8::1" {
		t.Fatalf("unexpected NebulaUnderlayPeers: %+v", peers)
	}
	if len(env.deps.NebulaUnderlayPeers("")) != 0 {
		t.Fatal("expected empty map for empty netName")
	}
	if UnderlayHost(" 1.2.3.4 ") != "1.2.3.4" || UnderlayHost("") != "" {
		t.Fatal("unexpected UnderlayHost result")
	}

	// AggregateNebulaOverlay: slowpath, degraded (3 targets, 1 alive -> dpTotal-dpAlive=2), siteedge.
	env.wd.OverlayProbeTargets = []string{"1.1.1.1", "2.2.2.2", "4.4.4.4"}
	results := map[string]PingResult{
		"1.1.1.1":  {Ok: true, Rtt: 10},
		"2.2.2.2":  {Ok: false},
		"4.4.4.4":  {Ok: false},
		"10.8.0.1": {Ok: true, Rtt: 200}, // slowpath
		"10.8.0.2": {Ok: false},          // dead overlay
		"10.8.0.9": {Ok: true, Rtt: 300}, // slow siteedge
	}
	// Trigger degraded (2 consecutive runs) + flushDeadNebulaPeers + checkNebulaPMTU failure.
	env.deps.RunHostCmd = func(context.Context, []string) (string, error) { return "frag needed", errors.New("df fail") }
	_, _ = env.deps.evalNebulaOverlay(ctx, env.wd, []string{"10.8.0.1"}, results)
	_, _ = env.deps.evalNebulaOverlay(ctx, env.wd, []string{"10.8.0.1"}, results)
	if !env.deps.State.Exists(latchdefs.LatchNebulaDegraded) || !env.deps.State.Exists(latchdefs.LatchNebulaSlowpath) || !env.deps.State.Exists(latchdefs.LatchNebulaSiteedge) {
		t.Fatal("expected degraded, slowpath, and siteedge latches to be armed")
	}

	// Isolated (all dead) -> FlushPeerNebulaConntrack & checkNebulaPMTU no-target reset.
	deadResults := map[string]PingResult{
		"1.1.1.1": {Ok: false},
		"2.2.2.2": {Ok: false},
	}
	flushed := false
	env.deps.FlushPeerNebulaConntrack = func(_ context.Context, _ string, _ ...string) { flushed = true }
	reason, dpFail := env.deps.evalNebulaOverlay(ctx, env.wd, []string{"1.1.1.1", "2.2.2.2"}, deadResults)
	if reason == "" || !dpFail || !flushed {
		t.Fatalf("expected isolated verdict + flush, got reason=%q dpFail=%v flushed=%v", reason, dpFail, flushed)
	}
}

func TestMTUBlackholeProberAndInvariants(t *testing.T) {
	ctx := context.Background()
	env := newTestDeps(t)

	// SysfsMTU & CheckCiliumWGMTUInvariant.
	sysNet := filepath.Join(env.dir, "sys", "class", "net")
	_ = os.MkdirAll(filepath.Join(sysNet, "neb1"), 0o755)
	_ = os.MkdirAll(filepath.Join(sysNet, "cilium_wg0"), 0o755)
	_ = os.WriteFile(filepath.Join(sysNet, "neb1", "mtu"), []byte("1300\n"), 0o644)
	_ = os.WriteFile(filepath.Join(sysNet, "cilium_wg0", "mtu"), []byte("1300\n"), 0o644) // > 1300-80

	if mtu, err := env.deps.SysfsMTU("neb1"); err != nil || mtu != 1300 {
		t.Fatalf("SysfsMTU(neb1) = (%d, %v)", mtu, err)
	}
	if _, err := env.deps.SysfsMTU("missing0"); err == nil {
		t.Fatal("expected error for missing sysfs iface")
	}

	// RunMountCmd: -C fails (rule absent), -A succeeds.
	env.deps.RunMountCmd = func(_ context.Context, argv []string) (string, error) {
		for _, a := range argv {
			if a == "-C" {
				return "", errors.New("not found")
			}
		}
		return "", nil
	}
	st := env.deps.MTUState()
	env.deps.CheckCiliumWGMTUInvariant(ctx, "neb1", st)
	if !st.WGClampKnown {
		t.Fatal("expected WGClampKnown=true after clamping cilium_wg0")
	}

	// CheckNebulaMTUBlackhole: DF fails mtuBlackholeNeeded times -> latches + clamps MSS.
	env.deps.RunHostCmd = func(context.Context, []string) (string, error) { return "mtu exceeded", errors.New("df fail") }
	for i := 0; i < mtuBlackholeNeeded; i++ {
		env.deps.CheckNebulaMTUBlackhole(ctx, st)
	}
	if !env.deps.State.Exists(latchdefs.LatchNebulaMTUBlackhole) {
		t.Fatal("expected LatchNebulaMTUBlackhole to be armed")
	}
	env.deps.WriteMTUBHMetric(st)
	env.deps.WriteMTUBHMetric(st) // cached no-op path

	// Recovery: DF succeeds -> unclamp MSS & clear latch.
	env.deps.RunHostCmd = func(context.Context, []string) (string, error) { return "ok", nil }
	env.deps.RunMountCmd = func(context.Context, []string) (string, error) { return "", nil } // -C succeeds, -D succeeds
	env.deps.CheckNebulaMTUBlackhole(ctx, st)
	if env.deps.State.Exists(latchdefs.LatchNebulaMTUBlackhole) {
		t.Fatal("expected LatchNebulaMTUBlackhole to clear on DF success")
	}

	// SpawnMTUProber + MTUProbeLoop short run.
	pctx, cancel := context.WithTimeout(ctx, 35*time.Millisecond)
	defer cancel()
	env.deps.SpawnMTUProber(pctx)
	env.deps.SpawnMTUProber(pctx) // second call while Running=true hits early return
	<-pctx.Done()
	// Wait briefly for goroutine defer to clear Running.
	time.Sleep(15 * time.Millisecond)
}

func TestMaybeClampNebulaMSSBackwardClock(t *testing.T) {
	env := newTestDeps(t)
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	env.deps.Clock = func() *timex.Cell {
		return timex.NewCell(func() time.Time { return now })
	}
	clamped := 0
	env.deps.RunMountCmd = func(_ context.Context, argv []string) (string, error) {
		for _, a := range argv {
			if a == "-C" {
				return "", errors.New("not found")
			}
			if a == "-A" {
				clamped++
			}
		}
		return "", nil
	}
	st := &MTUProbeState{LastClamp: now.Add(time.Hour)} // clock stepped backward relative to LastClamp
	env.deps.MaybeClampNebulaMSS(context.Background(), env.wd, st)
	if clamped == 0 {
		t.Fatal("MaybeClampNebulaMSS skipped clamping across backward clock jump")
	}
}
