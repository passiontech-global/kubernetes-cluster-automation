// nebula_mtu_blackhole.go — the Nebula overlay MTU blackhole prober:
// a dedicated goroutine (spawned alongside the route guard) that
// DF-pings a live overlay peer at a near-MTU payload every Nth tick,
// latches state-nebula-mtu-blackhole after consecutive failures, clamps
// TCP MSS on the overlay dev, and publishes the
// node_agent_nebula_mtu_blackhole gauge via the node-exporter
// textfile channel. Split out of routeguard.go.
package nethealth

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

// ===========================================================================
// W10-NM4 — Nebula overlay MTU blackhole prober
// ===========================================================================
//
// The W9-NM1 PMTU check (nethealth.go) probes ONE DF packet at 1200B
// bytes against the first alive overlay target every Cycle. NM4 is
// the deeper variant the plan assigns to this file: every 5th prober
// tick it DF-pings a peer NEBULA ip at 1252 payload bytes (neb1 MTU
// 1300 = 1252 + 28 IP/ICMP + 20 margin) and only calls it a blackhole
// when the SMALL ping still passes — total overlay failure stays the
// isolated/degraded verdict's job, never a PMTU latch.
//
// Three consecutive DF failures latch state-nebula-mtu-blackhole and
// clamp MSS on the overlay dev via iptables TCPMSS (rate-limited —
// the -C existence check keeps the rule idempotent). The
// node_agent_nebula_mtu_blackhole gauge rides the node-exporter
// textfile channel, the W10 metric convention.
//
// The prober is a separate goroutine from the netlink guard: the
// guard blocks inside routeGuardRead while the socket lives, so a
// periodic check can't share its loop. spawnRouteGuard (called by
// Run every tick) re-arms it after death via the n.mtuProbe field —
// the same single-flight+respawn shape routeGuardRunning gives the
// guard.

const (
	// mtuProbeEvery — the plan's "every 5th cycle": the prober
	// ticks on the nethealth Interval and probes every 5th tick.
	mtuProbeEvery = 5
	// mtuBlackholeNeeded — consecutive DF failures before the latch.
	mtuBlackholeNeeded = 3
	// mtuDFSize — 1252-byte ICMP payload (plan's DF=1 probe).
	mtuDFSize = "1252"
	// mtuDFCount/Wait — ping -c 2 -W 2 parity with the plan.
	mtuDFCount = "2"
	mtuDFWait  = "2"
	// mtuCiliumWGMTUInvariant — max MTU(cilium_wg0)
	// relative to MTU(neb1); WireGuard overhead is 60B, keep 80B
	// headroom per the plan's invariant.
	mtuCiliumWGOverhead = 80
	// mtuClampEvery rate-limits the iptables MSS clamp while
	// latched — the -C check makes repeats harmless but each exec
	// still costs a host fork.
	mtuClampEvery = 30 * time.Minute
	// mtuCheckName is the cycles metric label.
	mtuCheckName = "nebula-mtu-blackhole"
)

// mtuProbeState is NetHealth's nebula-mtu-blackhole prober state —
// a plain field on NetHealth (n.mtuProbe), so its lifetime is the
// instance's own.
type mtuProbeState struct {
	mu        sync.Mutex
	running   bool
	cycle     uint64
	mtuFails  int
	lastClamp time.Time
	lastGauge string // last written gauge value — skip identical writes
}

// mtuState returns this instance's prober state.
func (n *NetHealth) mtuState() *mtuProbeState {
	return &n.mtuProbe
}

// spawnMTUProber single-flights the MTU prober goroutine — the
// routeGuardRunning parity. cycle.Spawn owns the panic recovery
// (a dead prober clears running so the next spawnRouteGuard tick
// re-arms it); the returned stop is deliberately never called — the
// child exits when Run's ctx does.
func (n *NetHealth) spawnMTUProber(ctx context.Context) {
	st := n.mtuState()
	st.mu.Lock()
	if st.running {
		st.mu.Unlock()
		return
	}
	st.running = true
	st.mu.Unlock()
	cycle.Spawn(ctx, "nebula-mtu-prober", func(cctx context.Context) {
		defer func() {
			st.mu.Lock()
			st.running = false
			st.mu.Unlock()
		}()
		n.mtuProbeLoop(cctx, st)
	})
}

// mtuProbeLoop ticks on the nethealth Interval; every
// mtuProbeEvery-th invocation runs the DF blackhole probe.
// cycle.Every's up-front call counts as invocation #1, so the first
// probe lands ~4 intervals in (the old bare ticker waited 5 ticks) —
// harmless: the gauge is written every invocation so the series
// reflects the CURRENT latch even on off-invocations.
func (n *NetHealth) mtuProbeLoop(ctx context.Context, st *mtuProbeState) {
	interval := n.cfg.Interval
	if interval <= 0 {
		interval = defaultInterval
	}
	cycle.Every(mtuCheckName, interval, func(ctx context.Context) {
		st.mu.Lock()
		st.cycle++
		probe := st.cycle%mtuProbeEvery == 0
		st.mu.Unlock()
		if probe {
			n.checkNebulaMTUBlackhole(ctx, st)
		}
		n.writeMTUBHMetric(st)
	}).Run(ctx)
}

// checkNebulaMTUBlackhole runs one DF probe cycle (W10-NM4). Gating
// mirrors checkNebulaHealth's dataplane section: the nebula unit
// must be enabled+active AND nebula must own the overlay — probing
// a dormant mesh would latch on a dataplane that isn't carrying
// traffic. A peer is "small-ok" only when the unmarked ping answers;
// with NO alive peer the diagnosis is inconclusive (the
// isolated/degraded verdicts own that case) — fails reset but a
// held latch is released, same as checkNebulaPMTU's no-target path.
func (n *NetHealth) checkNebulaMTUBlackhole(ctx context.Context,
	st *mtuProbeState) {
	wd := n.watchdogConf()
	reset := func() {
		st.mu.Lock()
		st.mtuFails = 0
		st.mu.Unlock()
		n.stateExit(latchdefs.LatchNebulaMTUBlackhole)
	}
	if wd == nil || wd.NebulaNet == "" ||
		!n.unitEnabledActive(ctx, "nebula@"+wd.NebulaNet) ||
		wd.OverlayActive != "nebula" {
		reset()
		return
	}
	// The cilium_wg0 MTU invariant is a config-drift check,
	// not a blackhole symptom — enforce it every probe cycle,
	// independent of this cycle's DF ping verdict (a healthy neb1
	// must still catch cilium_wg0 sized against the underlay).
	dev := wd.NebulaDev
	if dev == "" {
		dev = "neb1"
	}
	n.checkCiliumWGMTUInvariant(ctx, dev)
	// Peer fanout: the overlay probe sets are the known nebula
	// endpoints — same source checkNebulaHealth pings. The first
	// peer answering the SMALL ping is this cycle's DF target, so
	// "small ok + DF fail" is measured on ONE path, not averaged.
	targets := append(append(append([]string{},
		wd.OverlayProbeTargets...),
		wd.OverlayProbeMarkers...),
		wd.OverlaySiteMarkers...)
	peer := ""
	for _, t := range targets {
		if ok, _ := n.cfg.ping(ctx, t, 2, 2, false); ok {
			peer = t
			break
		}
	}
	if peer == "" {
		// Total overlay failure — NOT a PMTU signature. Release a
		// held latch: the isolated/degraded verdict owns the node.
		reset()
		return
	}
	out, err := n.cfg.runHostCmd(ctx, []string{
		"ping", "-c", mtuDFCount, "-W", mtuDFWait,
		"-M", "do", "-s", mtuDFSize, peer})
	st.mu.Lock()
	if err != nil {
		st.mtuFails++
		fails := st.mtuFails
		st.mu.Unlock()
		n.state.SuspectLog(latchdefs.LatchNebulaMTUBlackhole, fmt.Sprintf(
			"suspect: nebula-mtu-blackhole df_probe_failed peer=%s size=%s (check %d/%d): %v (%s)",
			peer, mtuDFSize, fails, mtuBlackholeNeeded, err,
			trimRunErr(out)), suspectLogCadence)
		if fails >= mtuBlackholeNeeded {
			n.state.Enter(latchdefs.LatchNebulaMTUBlackhole,
				fmt.Sprintf("peer=%s df_size=%s", peer, mtuDFSize))
			n.maybeClampNebulaMSS(ctx, wd, st)
		}
		return
	}
	st.mtuFails = 0
	st.mu.Unlock()
	n.stateExit(latchdefs.LatchNebulaMTUBlackhole)
}

// maybeClampNebulaMSS installs the TCPMSS clamp on the overlay dev —
// the plan's remediation for a path MTU below the overlay's: clamp
// SYN MSS to PMTU so TCP flows stop blackholing while the route/MTU
// fault is investigated. Idempotent via the -C existence probe; the
// whole thing is rate-limited while the latch holds.
func (n *NetHealth) maybeClampNebulaMSS(ctx context.Context,
	wd *watchdogconf.Config, st *mtuProbeState) {
	st.mu.Lock()
	if n.cfg.Clock.Now().Sub(st.lastClamp) < mtuClampEvery {
		st.mu.Unlock()
		return
	}
	st.lastClamp = n.cfg.Clock.Now()
	st.mu.Unlock()
	dev := wd.NebulaDev
	if dev == "" {
		dev = "neb1"
	}
	n.clampMSSOn(ctx, dev)
	// The double-encapsulation path also blackholes on the
	// Cilium WireGuard dev — clamp it too whenever it exists.
	n.clampMSSOn(ctx, "cilium_wg0")
}

// clampMSSOn idempotently installs the TCPMSS --clamp-mss-to-pmtu
// rule on one interface (the -C existence probe keeps it idempotent).
func (n *NetHealth) clampMSSOn(ctx context.Context, dev string) {
	args := []string{"-t", "mangle", "-C", "POSTROUTING",
		"-o", dev, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--clamp-mss-to-pmtu"}
	if _, err := n.cfg.runMountCmd(ctx,
		append([]string{"iptables"}, args...)); err == nil {
		// Rule already present — nothing to do.
		return
	}
	out, err := n.cfg.runMountCmd(ctx,
		[]string{"iptables", "-t", "mangle", "-A",
			"POSTROUTING", "-o", dev, "-p", "tcp",
			"--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--clamp-mss-to-pmtu"})
	if err != nil {
		n.state.AppendLog(fmt.Sprintf(
			"suspect: nebula-mtu-blackhole MSS clamp failed on %s: %v (%s)",
			dev, err, trimRunErr(out)))
		return
	}
	n.actions.WithLabelValues(mtuCheckName, "mss_clamp").Inc()
	n.state.AppendLog("ACTION: nebula-mtu-blackhole clamped TCP MSS to PMTU on " + dev)
}

// sysfsMTU reads the MTU of one interface through the host sysfs
// (HostRoot-parity with the other proc/sys reads in this package).
func (n *NetHealth) sysfsMTU(dev string) (int, error) {
	b, err := os.ReadFile(filepath.Join(n.cfg.HostRoot,
		"sys", "class", "net", dev, "mtu"))
	if err != nil {
		return 0, err
	}
	var mtu int
	if _, err := fmt.Sscanf(string(b), "%d", &mtu); err != nil {
		return 0, err
	}
	return mtu, nil
}

// checkCiliumWGMTUInvariant enforces MTU(cilium_wg0) <= MTU(neb1)-80:
// the WireGuard header costs ~60B on top of nebula's ~80B, so a
// cilium_wg0 MTU sized against the underlay instead of the nebula
// overlay blackholes every large inner packet. On violation it
// clamps MSS on cilium_wg0 and warns (the plan's "warn + force the
// MTU/MSS correction").
func (n *NetHealth) checkCiliumWGMTUInvariant(ctx context.Context, nebDev string) {
	cilMTU, err := n.sysfsMTU("cilium_wg0")
	if err != nil {
		return // no cilium_wg0 — nothing to check.
	}
	nebMTU, err := n.sysfsMTU(nebDev)
	if err != nil {
		return
	}
	if cilMTU <= nebMTU-mtuCiliumWGOverhead {
		return
	}
	n.state.AppendLog(fmt.Sprintf(
		"warn: cilium_wg0 MTU %d exceeds nebula invariant (nebula %s MTU %d, max %d) — clamping TCP MSS on cilium_wg0",
		cilMTU, nebDev, nebMTU, nebMTU-mtuCiliumWGOverhead))
	n.clampMSSOn(ctx, "cilium_wg0")
}

// writeMTUBHMetric emits node_agent_nebula_mtu_blackhole (0/1) to
// the node-exporter textfile — the W10 metric channel
// (controllerhygiene's textfile-dir override parity). Identical values
// skip the rewrite so the file's mtime tracks real changes.
func (n *NetHealth) writeMTUBHMetric(st *mtuProbeState) {
	v := "0"
	if n.state.Exists(latchdefs.LatchNebulaMTUBlackhole) {
		v = "1"
	}
	st.mu.Lock()
	if st.lastGauge == v {
		st.mu.Unlock()
		return
	}
	st.lastGauge = v
	st.mu.Unlock()
	dir := filepath.Join(n.cfg.HostRoot,
		"var", "lib", "node-exporter", "textfile")
	if textfileDirOverride != "" {
		dir = textfileDirOverride
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		logger().Debug("mtu metric: textfile mkdir failed",
			"dir", dir, "error", err)
		return
	}
	var b promfile.Builder
	b.Header("node_agent_nebula_mtu_blackhole",
		"Nebula overlay MTU blackhole latched — small pings pass, "+
			"1252-byte DF probes fail (state-nebula-mtu-blackhole).")
	b.Line("node_agent_nebula_mtu_blackhole " + v)
	// promfile.Write stages through a hidden CreateTemp file, fsyncs
	// and renames — the textfile collector must never see a partial
	// .prom (and the staging name can't match its "*.prom" glob).
	if err := promfile.Write(dir, "node-agent-nebula-mtu.prom",
		[]byte(b.String())); err != nil {
		logger().Debug("mtu metric: write failed",
			"dir", dir, "error", err)
	}
}

// textfileDirOverride wins over the HostRoot-derived dir in
// tests (controllerhygiene's kineTextfileDirOverride parity).
var textfileDirOverride string
