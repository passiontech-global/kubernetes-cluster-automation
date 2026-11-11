// nebula_bridge.go — the parent nethealth side of the nebula
// subpackage boundary: wires the subsystem's Config seams, store and
// telemetry into nebula.Deps (live closures — post-New re-stubs stay
// visible), and keeps the NetHealth-method call surface the
// checks.Group table and the tests use, so check registration order
// is byte-identical to before the split.
package nethealth

import (
	"context"
	"regexp"
	"strconv"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/nethealth/nebula"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// newNebulaDeps builds the nebula checks' deps bundle off one
// NetHealth instance. Every closure reads the parent Config live —
// the Config fields stay the call indirection so tests can still
// re-stub n.cfg.ping/runHostCmd/... after New.
func newNebulaDeps(n *NetHealth) *nebula.Deps {
	return &nebula.Deps{
		Cycles:               n.cycles,
		Actions:              n.actions,
		State:                n.state,
		Watchdog:             func() *watchdogconf.Config { return n.cfg.Watchdog },
		WatchdogConf:         n.watchdogConf,
		Systemd:              func() *systemd.Client { return n.cfg.Systemd },
		ConsecNeeded:         func() int { return n.cfg.ConsecNeeded },
		MinRestart:           func() time.Duration { return n.cfg.MinRestart },
		NebulaDirectTCPPorts: func() []int { return n.cfg.NebulaDirectTCPPorts },
		ProcNetUDP:           func() string { return n.cfg.ProcNetUDP },
		ProcNetUDP6:          func() string { return n.cfg.ProcNetUDP6 },
		HostRoot:             func() string { return n.cfg.HostRoot },
		Interval: func() time.Duration {
			if n.cfg.Interval <= 0 {
				return defaultInterval
			}
			return n.cfg.Interval
		},
		TextfileDir:         func() string { return n.cfg.TextfileDir },
		TextfileDirOverride: func() string { return textfileDirOverride },
		Clock:               func() *timex.Cell { return n.cfg.Clock },
		RunHostCmd: func(ctx context.Context, argv []string) (string, error) {
			return n.cfg.runHostCmd(ctx, argv)
		},
		RunMountCmd: func(ctx context.Context, argv []string) (string, error) {
			return n.cfg.runMountCmd(ctx, argv)
		},
		Ping: func(ctx context.Context, ip string, count, waitSec int, marked bool) (bool, float64) {
			return n.cfg.ping(ctx, ip, count, waitSec, marked)
		},
		ProbeHTTP: func(ctx context.Context, url string, timeout time.Duration) error {
			return n.cfg.probeHTTP(ctx, url, timeout)
		},
		IP:                       n.ip,
		StateExit:                n.stateExit,
		UnitEnabledActive:        n.unitEnabledActive,
		NebulaUpExists:           n.nebulaUpExists,
		EgressFiles:              n.egressFiles,
		FlushStaleUDPConntrack:   n.flushStaleUDPConntrack,
		FlushPeerNebulaConntrack: n.flushPeerNebulaConntrack,
		TrimRunErr:               trimRunErr,
	}
}

// --- delegating wrappers — the registration/test call surface ---
//
// Each delegates 1:1 onto the nebula subpackage; the bodies live in
// internal/subsystem/nethealth/nebula now.

// checkNebulaDirectTCP enforces the pref-1499 Direct-Underlay TCP
// bypass rules — see nebula/direct_tcp.go.
func (n *NetHealth) checkNebulaDirectTCP(ctx context.Context) {
	n.neb.CheckNebulaDirectTCP(ctx)
}

// checkNebulaHealth — module 13 — see nebula/health.go.
func (n *NetHealth) checkNebulaHealth(ctx context.Context) {
	n.neb.CheckNebulaHealth(ctx)
}

// probeNebulaOverlay — see nebula/overlay.go.
func (n *NetHealth) probeNebulaOverlay(ctx context.Context,
	wd *watchdogconf.Config) ([]string, map[string]nebula.PingResult) {
	return n.neb.ProbeNebulaOverlay(ctx, wd)
}

// aggregateNebulaOverlay — see nebula/overlay.go.
func aggregateNebulaOverlay(wd *watchdogconf.Config,
	results map[string]nebula.PingResult) *nebula.NebulaOverlayStats {
	return nebula.AggregateNebulaOverlay(wd, results)
}

// latchNebulaOverlayPaths — see nebula/overlay.go.
func (n *NetHealth) latchNebulaOverlayPaths(wd *watchdogconf.Config,
	st *nebula.NebulaOverlayStats) {
	n.neb.LatchNebulaOverlayPaths(wd, st)
}

// nebulaOverlayVerdict — see nebula/overlay.go.
func (n *NetHealth) nebulaOverlayVerdict(ctx context.Context,
	wd *watchdogconf.Config, st *nebula.NebulaOverlayStats) (reason string,
	dpFail, isolated bool) {
	return n.neb.NebulaOverlayVerdict(ctx, wd, st)
}

// nebulaUnderlayPeers — see nebula/overlay.go.
func (n *NetHealth) nebulaUnderlayPeers(netName string) map[string][]string {
	return n.neb.NebulaUnderlayPeers(netName)
}

// restartTimesyncdOnClockLatch — see nebula/health.go.
func (n *NetHealth) restartTimesyncdOnClockLatch(ctx context.Context) {
	n.neb.RestartTimesyncdOnClockLatch(ctx)
}

// nebulaRestart — see nebula/health.go.
func (n *NetHealth) nebulaRestart(ctx context.Context) {
	n.neb.NebulaRestart(ctx)
}

// mtuState returns this instance's prober state — see
// nebula/mtu_blackhole.go.
func (n *NetHealth) mtuState() *nebula.MTUProbeState {
	return n.neb.MTUState()
}

// SpawnMTUProber — see nebula/mtu_blackhole.go (spawnRouteGuard's
// single-flight+respawn twin).
func (n *NetHealth) spawnMTUProber(ctx context.Context) {
	n.neb.SpawnMTUProber(ctx)
}

// mtuProbeLoop — see nebula/mtu_blackhole.go.
func (n *NetHealth) mtuProbeLoop(ctx context.Context, st *nebula.MTUProbeState) {
	n.neb.MTUProbeLoop(ctx, st)
}

// UnclampMSSOn — see nebula/mtu_blackhole.go.
func (n *NetHealth) UnclampMSSOn(ctx context.Context, dev string) {
	n.neb.UnclampMSSOn(ctx, dev)
}

// SysfsMTU — see nebula/mtu_blackhole.go.
func (n *NetHealth) SysfsMTU(dev string) (int, error) {
	return n.neb.SysfsMTU(dev)
}

// CheckCiliumWGMTUInvariant — see nebula/mtu_blackhole.go.
func (n *NetHealth) CheckCiliumWGMTUInvariant(ctx context.Context,
	nebDev string, st *nebula.MTUProbeState) {
	n.neb.CheckCiliumWGMTUInvariant(ctx, nebDev, st)
}

// checkNebulaMTUBlackhole — see nebula/mtu_blackhole.go.
func (n *NetHealth) checkNebulaMTUBlackhole(ctx context.Context,
	st *nebula.MTUProbeState) {
	n.neb.CheckNebulaMTUBlackhole(ctx, st)
}

// maybeClampNebulaMSS — see nebula/mtu_blackhole.go.
func (n *NetHealth) maybeClampNebulaMSS(ctx context.Context,
	wd *watchdogconf.Config, st *nebula.MTUProbeState) {
	n.neb.MaybeClampNebulaMSS(ctx, wd, st)
}

// writeMTUBHMetric — see nebula/mtu_blackhole.go.
func (n *NetHealth) writeMTUBHMetric(st *nebula.MTUProbeState) {
	n.neb.WriteMTUBHMetric(st)
}

// textfileDirOverride wins over the HostRoot-derived dir in
// tests (controllerhygiene's kineTextfileDirOverride parity).
var textfileDirOverride string

// minRTT parses the smallest "time=<ms>" from ping output — the
// shell's wd_probe_rtt (first sample is inflated by ARP/tunnel setup).
var rttRe = regexp.MustCompile(`time=([0-9.]+)`)

func minRTT(out string) float64 {
	best := -1.0
	for _, m := range rttRe.FindAllStringSubmatch(out, -1) {
		if v, err := strconv.ParseFloat(m[1], 64); err == nil && (best < 0 || v < best) {
			best = v
		}
	}
	return best
}
