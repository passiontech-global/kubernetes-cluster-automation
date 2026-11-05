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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
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
// Run every tick) re-arms it after death via mtuProbeStates — the
// same single-flight+respawn shape routeGuardRunning gives the
// guard, kept file-local because NetHealth's struct lives in
// nethealth.go.

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
	// mtuClampEvery rate-limits the iptables MSS clamp while
	// latched — the -C check makes repeats harmless but each exec
	// still costs a host fork.
	mtuClampEvery = 30 * time.Minute
	// mtuCheckName is the cycles metric label.
	mtuCheckName = "nebula-mtu-blackhole"
)

// mtuProbeState is the per-NetHealth prober state — NetHealth's
// struct is in nethealth.go so the prober keeps keyed state.
type mtuProbeState struct {
	mu        sync.Mutex
	running   bool
	cycle     uint64
	mtuFails  int
	lastClamp time.Time
	lastGauge string // last written gauge value — skip identical writes
}

var mtuProbeStates sync.Map // *NetHealth → *mtuProbeState

// mtuState returns (creating if needed) this instance's prober
// state.
func (n *NetHealth) mtuState() *mtuProbeState {
	if v, ok := mtuProbeStates.Load(n); ok {
		return v.(*mtuProbeState)
	}
	st := &mtuProbeState{}
	actual, _ := mtuProbeStates.LoadOrStore(n, st)
	return actual.(*mtuProbeState)
}

// spawnMTUProber single-flights the MTU prober goroutine — the
// routeGuardRunning parity. A dead prober (panic recovered inside)
// clears running so the next spawnRouteGuard tick re-arms it.
func (n *NetHealth) spawnMTUProber(ctx context.Context) {
	st := n.mtuState()
	st.mu.Lock()
	if st.running {
		st.mu.Unlock()
		return
	}
	st.running = true
	st.mu.Unlock()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger().Error("mtu prober panicked — exiting, "+
					"respawn allowed next tick",
					"panic", r)
			}
			st.mu.Lock()
			st.running = false
			st.mu.Unlock()
		}()
		n.mtuProbeLoop(ctx, st)
	}()
}

// mtuProbeLoop ticks on the nethealth Interval; every
// mtuProbeEvery-th tick runs the DF blackhole probe. The
// gauge is written every tick so the series reflects the CURRENT
// latch even on off-ticks.
func (n *NetHealth) mtuProbeLoop(ctx context.Context, st *mtuProbeState) {
	interval := n.cfg.Interval
	if interval <= 0 {
		interval = defaultInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			st.mu.Lock()
			st.cycle++
			probe := st.cycle%mtuProbeEvery == 0
			st.mu.Unlock()
			if probe {
				n.checkNebulaMTUBlackhole(ctx, st)
			}
			n.writeMTUBHMetric(st)
		}
	}
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
		n.stateExit(hoststate.LatchNebulaMTUBlackhole)
	}
	if wd == nil || wd.NebulaNet == "" ||
		!n.unitEnabledActive(ctx, "nebula@"+wd.NebulaNet) ||
		wd.OverlayActive != "nebula" {
		reset()
		return
	}
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
		n.state.SuspectLog(hoststate.LatchNebulaMTUBlackhole, fmt.Sprintf(
			"suspect: nebula-mtu-blackhole df_probe_failed peer=%s size=%s (check %d/%d): %v (%s)",
			peer, mtuDFSize, fails, mtuBlackholeNeeded, err,
			trimRunErr(out)), suspectLogCadence)
		if fails >= mtuBlackholeNeeded {
			n.state.Enter(hoststate.LatchNebulaMTUBlackhole,
				fmt.Sprintf("peer=%s df_size=%s", peer, mtuDFSize))
			n.maybeClampNebulaMSS(ctx, wd, st)
		}
		return
	}
	st.mtuFails = 0
	st.mu.Unlock()
	n.stateExit(hoststate.LatchNebulaMTUBlackhole)
}

// maybeClampNebulaMSS installs the TCPMSS clamp on the overlay dev —
// the plan's remediation for a path MTU below the overlay's: clamp
// SYN MSS to PMTU so TCP flows stop blackholing while the route/MTU
// fault is investigated. Idempotent via the -C existence probe; the
// whole thing is rate-limited while the latch holds.
func (n *NetHealth) maybeClampNebulaMSS(ctx context.Context,
	wd *watchdogconf.Config, st *mtuProbeState) {
	st.mu.Lock()
	if time.Since(st.lastClamp) < mtuClampEvery {
		st.mu.Unlock()
		return
	}
	st.lastClamp = n.cfg.nowFn()
	st.mu.Unlock()
	dev := wd.NebulaDev
	if dev == "" {
		dev = "neb1"
	}
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

// writeMTUBHMetric emits node_agent_nebula_mtu_blackhole (0/1) to
// the node-exporter textfile — the W10 metric channel
// (controllerhygiene's textfile-dir override parity). Identical values
// skip the rewrite so the file's mtime tracks real changes.
func (n *NetHealth) writeMTUBHMetric(st *mtuProbeState) {
	v := "0"
	if n.state.Exists(hoststate.LatchNebulaMTUBlackhole) {
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
	content := "# HELP node_agent_nebula_mtu_blackhole " +
		"Nebula overlay MTU blackhole latched — small pings pass, " +
		"1252-byte DF probes fail (state-nebula-mtu-blackhole).\n" +
		"# TYPE node_agent_nebula_mtu_blackhole gauge\n" +
		"node_agent_nebula_mtu_blackhole " + v + "\n"
	name := "node-agent-nebula-mtu.prom"
	tmp := filepath.Join(dir, "."+name+".tmp")
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		logger().Debug("mtu metric: write failed",
			"path", tmp, "error", err)
		return
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		logger().Debug("mtu metric: install failed",
			"dir", dir, "error", err)
	}
}

// textfileDirOverride wins over the HostRoot-derived dir in
// tests (controllerhygiene's kineTextfileDirOverride parity).
var textfileDirOverride string
