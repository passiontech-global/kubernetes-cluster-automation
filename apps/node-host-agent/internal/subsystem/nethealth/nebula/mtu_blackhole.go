// mtu_blackhole.go — the Nebula overlay MTU blackhole prober:
// a dedicated goroutine (spawned alongside the route guard) that
// DF-pings a live overlay peer at a near-MTU payload every Nth tick,
// latches state-nebula-mtu-blackhole after consecutive failures, clamps
// TCP MSS on the overlay dev, and publishes the
// node_agent_nebula_mtu_blackhole gauge via the node-exporter
// textfile channel. Moved verbatim out of the parent nethealth
// package's nebula_mtu_blackhole.go (which split it out of
// routeguard.go).
package nebula

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checkkit"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

// ===========================================================================
// nebula-mtu-blackhole — Nebula overlay MTU blackhole prober
// ===========================================================================
//
// The overlay-mtu-guard PMTU check (pmtu.go) probes ONE DF packet at 1200B
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
// textfile channel, the node-exporter textfile convention.
//
// The prober is a separate goroutine from the netlink guard: the
// guard blocks inside routeGuardRead while the socket lives, so a
// periodic check can't share its loop. spawnRouteGuard (called by
// Run every tick) re-arms it after death via the MTU field —
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

// MTUCheckName is the cycles metric label — exported for the parent
// tests.
const MTUCheckName = mtuCheckName

// MTUBlackholeNeeded — consecutive DF failures before the latch.
// Exported: the parent's tests drive the probe count directly.
const MTUBlackholeNeeded = mtuBlackholeNeeded

// MTUProbeState is the nebula-mtu-blackhole prober state —
// a plain field on Deps (n.MTU), so its lifetime is the
// parent NetHealth instance's own.
type MTUProbeState struct {
	Mu        sync.Mutex
	Running   bool
	Cycle     uint64
	MTUFails  int
	LastClamp time.Time
	LastGauge string // last written gauge value — skip identical writes
	// WGClampKnown records that the cilium_wg0 TCPMSS clamp was
	// confirmed installed (or already present). The MTU invariant
	// that installs it is CONFIG DRIFT — until the MTU is fixed the
	// condition stays true, so without this bit the invariant check
	// would warn + fork `iptables -C` every probe cycle for the
	// node's lifetime. The bit dies with the process, and an
	// operator-flushed rule is re-installed on agent restart.
	WGClampKnown bool
}

// SpawnMTUProber single-flights the MTU prober goroutine — the
// routeGuardRunning parity. cycle.Spawn owns the panic recovery
// (a dead prober clears running so the next spawnRouteGuard tick
// re-arms it); the returned stop is deliberately never called — the
// child exits when Run's ctx does.
func (n *Deps) SpawnMTUProber(ctx context.Context) {
	st := n.MTUState()
	st.Mu.Lock()
	if st.Running {
		st.Mu.Unlock()
		return
	}
	st.Running = true
	st.Mu.Unlock()
	cycle.Spawn(ctx, "nebula-mtu-prober", func(cctx context.Context) {
		defer func() {
			st.Mu.Lock()
			st.Running = false
			st.Mu.Unlock()
		}()
		n.MTUProbeLoop(cctx, st)
	})
}

// mtuProbeLoop ticks on the nethealth Interval; every
// mtuProbeEvery-th invocation runs the DF blackhole probe.
// cycle.Every's up-front call counts as invocation #1, so the first
// probe lands ~4 intervals in (the old bare ticker waited 5 ticks) —
// harmless: the gauge is written every invocation so the series
// reflects the CURRENT latch even on off-invocations.
func (n *Deps) MTUProbeLoop(ctx context.Context, st *MTUProbeState) {
	interval := n.Interval()
	cycle.Every(mtuCheckName, interval, func(ctx context.Context) {
		st.Mu.Lock()
		st.Cycle++
		probe := st.Cycle%mtuProbeEvery == 0
		st.Mu.Unlock()
		if probe {
			n.CheckNebulaMTUBlackhole(ctx, st)
		}
		n.WriteMTUBHMetric(st)
	}).Run(ctx)
}

// CheckNebulaMTUBlackhole runs one DF probe cycle (nebula-mtu-blackhole). Gating
// mirrors checkNebulaHealth's dataplane section: the nebula unit
// must be enabled+active AND nebula must own the overlay — probing
// a dormant mesh would latch on a dataplane that isn't carrying
// traffic. A peer is "small-ok" only when the unmarked ping answers;
// with NO alive peer the diagnosis is inconclusive (the
// isolated/degraded verdicts own that case) — fails reset but a
// held latch is released, same as checkNebulaPMTU's no-target path.
func (n *Deps) CheckNebulaMTUBlackhole(ctx context.Context,
	st *MTUProbeState) {
	wd := n.WatchdogConf()
	dev := "neb1"
	if wd != nil && wd.NebulaDev != "" {
		dev = wd.NebulaDev
	}
	reset := func() {
		st.Mu.Lock()
		st.MTUFails = 0
		st.Mu.Unlock()
		// Recovery: drop the latch AND its remediation — the TCPMSS
		// clamp exists only while the blackhole latch holds. A rule
		// left behind keeps forcing --clamp-mss-to-pmtu on every
		// overlay flow long after the fault cleared: a silent,
		// permanent performance regression. Gated on the latch
		// actually being held so the steady-state reset paths
		// (dormant mesh, no peer, small ping ok) don't fork
		// iptables every probe cycle.
		if !n.State.Exists(latchdefs.LatchNebulaMTUBlackhole) {
			return
		}
		n.StateExit(latchdefs.LatchNebulaMTUBlackhole)
		n.UnclampMSSOn(ctx, dev)
		// maybeClampNebulaMSS clamped cilium_wg0 alongside the
		// overlay dev — recovery must remove that rule too, or the
		// double-encapsulation path keeps its clamp forever. The
		// exception is WGClampKnown: the rule then belongs to the
		// cilium_wg0 MTU invariant (config drift — iptables can't
		// fix sysfs), which stays installed and is re-checked every
		// probe cycle; unclamping it would just re-clamp next tick.
		st.Mu.Lock()
		wgKnown := st.WGClampKnown
		st.Mu.Unlock()
		if !wgKnown {
			n.UnclampMSSOn(ctx, "cilium_wg0")
		}
		st.Mu.Lock()
		st.LastClamp = time.Time{} // a re-latch clamps immediately
		st.Mu.Unlock()
	}
	if wd == nil || wd.NebulaNet == "" ||
		!n.UnitEnabledActive(ctx, "nebula@"+wd.NebulaNet) ||
		wd.OverlayActive != "nebula" {
		reset()
		return
	}
	// The cilium_wg0 MTU invariant is a config-drift check,
	// not a blackhole symptom — enforce it every probe cycle,
	// independent of this cycle's DF ping verdict (a healthy neb1
	// must still catch cilium_wg0 sized against the underlay).
	n.CheckCiliumWGMTUInvariant(ctx, dev, st)
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
		if ok, _ := n.Ping(ctx, t, 2, 2, false); ok {
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
	out, err := n.RunHostCmd(ctx, []string{
		"ping", "-c", mtuDFCount, "-W", mtuDFWait,
		"-M", "do", "-s", mtuDFSize, peer})
	st.Mu.Lock()
	if err != nil {
		st.MTUFails++
		fails := st.MTUFails
		st.Mu.Unlock()
		n.State.SuspectLog(latchdefs.LatchNebulaMTUBlackhole, fmt.Sprintf(
			"suspect: nebula-mtu-blackhole df_probe_failed peer=%s size=%s%s: %v (%s)",
			peer, mtuDFSize, checkkit.Progress(fails, mtuBlackholeNeeded),
			err, n.TrimRunErr(out)), suspectLogCadence)
		if fails >= mtuBlackholeNeeded {
			// NPD contract: the ACTION entry line feeds
			// NebulaMTUBlackhole (events.go) — ActionEntryRe
			// parses it. Once per episode, gated on the latch
			// being absent (Enter is idempotent while held).
			fresh := !n.State.Exists(latchdefs.LatchNebulaMTUBlackhole)
			n.State.Enter(latchdefs.LatchNebulaMTUBlackhole,
				fmt.Sprintf("peer=%s df_size=%s", peer, mtuDFSize))
			if fresh {
				n.State.AppendLog(latchdefs.ActionEntryPrefix(
					latchdefs.LatchNebulaMTUBlackhole) +
					fmt.Sprintf("peer=%s df_size=%s", peer, mtuDFSize))
			}
			n.MaybeClampNebulaMSS(ctx, wd, st)
		}
		return
	}
	st.MTUFails = 0
	st.Mu.Unlock()
	reset()
}

// MaybeClampNebulaMSS installs the TCPMSS clamp on the overlay dev —
// the plan's remediation for a path MTU below the overlay's: clamp
// SYN MSS to PMTU so TCP flows stop blackholing while the route/MTU
// fault is investigated. Idempotent via the -C existence probe; the
// whole thing is rate-limited while the latch holds.
func (n *Deps) MaybeClampNebulaMSS(ctx context.Context,
	wd *watchdogconf.Config, st *MTUProbeState) {
	st.Mu.Lock()
	if n.Clock().Now().Sub(st.LastClamp) < mtuClampEvery {
		st.Mu.Unlock()
		return
	}
	st.Mu.Unlock()
	dev := wd.NebulaDev
	if dev == "" {
		dev = "neb1"
	}
	// The rate-limit budget is spent only on a DELIVERED clamp —
	// a failed iptables run keeps lastClamp untouched so the next
	// tick retries immediately instead of waiting out
	// mtuClampEvery while flows still blackhole.
	if err := n.clampMSSOn(ctx, dev); err != nil {
		return
	}
	// The double-encapsulation path also blackholes on the
	// Cilium WireGuard dev — clamp it too whenever it exists.
	// A cilium_wg0 failure must not re-open the (successful)
	// overlay clamp rate limit every tick — only the overlay
	// dev's outcome spends the budget.
	_ = n.clampMSSOn(ctx, "cilium_wg0")
	st.Mu.Lock()
	st.LastClamp = n.Clock().Now()
	st.Mu.Unlock()
}

// clampMSSOn idempotently installs the TCPMSS --clamp-mss-to-pmtu
// rule on one interface (the -C existence probe keeps it idempotent).
// The error is the rate-limit gate's success signal: the clamp budget
// (LastClamp) must only be spent once the rule actually landed —
// a failed iptables run would otherwise mute retries for a full
// mtuClampEvery while the blackhole persists.
func (n *Deps) clampMSSOn(ctx context.Context, dev string) error {
	args := []string{"-t", "mangle", "-C", "POSTROUTING",
		"-o", dev, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--clamp-mss-to-pmtu"}
	if _, err := n.RunMountCmd(ctx,
		append([]string{"iptables", "-w", "5"}, args...)); err == nil {
		// Rule already present — nothing to do.
		return nil
	}
	out, err := n.RunMountCmd(ctx,
		[]string{"iptables", "-w", "5", "-t", "mangle", "-A",
			"POSTROUTING", "-o", dev, "-p", "tcp",
			"--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--clamp-mss-to-pmtu"})
	if err != nil {
		n.State.AppendLog(fmt.Sprintf(
			"suspect: nebula-mtu-blackhole MSS clamp failed on %s: %v (%s)",
			dev, err, n.TrimRunErr(out)))
		return err
	}
	n.Actions.WithLabelValues(mtuCheckName, "mss_clamp").Inc()
	n.State.AppendLog("ACTION: nebula-mtu-blackhole clamped TCP MSS to PMTU on " + dev)
	return nil
}

// UnclampMSSOn removes the TCPMSS --clamp-mss-to-pmtu rule one
// interface carries — the blackhole-recovery half of clampMSSOn.
// The -C probe keeps it idempotent (a rule never installed, or
// already removed, is a silent no-op — cilium_wg0 legitimately
// carries no rule when the invariant is satisfied).
func (n *Deps) UnclampMSSOn(ctx context.Context, dev string) {
	args := []string{"-t", "mangle", "-C", "POSTROUTING",
		"-o", dev, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--clamp-mss-to-pmtu"}
	if _, err := n.RunMountCmd(ctx,
		append([]string{"iptables", "-w", "5"}, args...)); err != nil {
		return // rule absent (or uncheckable) — nothing to remove
	}
	if out, err := n.RunMountCmd(ctx,
		[]string{"iptables", "-w", "5", "-t", "mangle", "-D",
			"POSTROUTING", "-o", dev, "-p", "tcp",
			"--tcp-flags", "SYN,RST", "SYN",
			"-j", "TCPMSS", "--clamp-mss-to-pmtu"}); err != nil {
		n.State.AppendLog(fmt.Sprintf(
			"suspect: nebula-mtu-blackhole MSS unclamp failed on %s: %v (%s)",
			dev, err, n.TrimRunErr(out)))
		return
	}
	n.Actions.WithLabelValues(mtuCheckName, "mss_unclamp").Inc()
	n.State.AppendLog("ACTION: nebula-mtu-blackhole removed the TCP MSS clamp on " + dev)
}

// SysfsMTU reads the MTU of one interface through the host sysfs
// (HostRoot-parity with the other proc/sys reads in this package).
func (n *Deps) SysfsMTU(dev string) (int, error) {
	b, err := os.ReadFile(filepath.Join(n.HostRoot(),
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

// CheckCiliumWGMTUInvariant enforces MTU(cilium_wg0) <= MTU(neb1)-80:
// the WireGuard header costs ~60B on top of nebula's ~80B, so a
// cilium_wg0 MTU sized against the underlay instead of the nebula
// overlay blackholes every large inner packet. On violation it
// clamps MSS on cilium_wg0 and warns — ONCE per rule install: the
// violating MTU outlives the clamp (iptables can't fix sysfs), so
// re-checking the invariant every probe cycle would warn and fork
// `iptables -C` for the node's lifetime while the clamp rule sits
// there already doing its job (WGClampKnown, reset by process
// restart or a blackhole recovery's unclamp).
func (n *Deps) CheckCiliumWGMTUInvariant(ctx context.Context, nebDev string, st *MTUProbeState) {
	st.Mu.Lock()
	known := st.WGClampKnown
	st.Mu.Unlock()
	if known {
		return
	}
	cilMTU, err := n.SysfsMTU("cilium_wg0")
	if err != nil {
		return // no cilium_wg0 — nothing to check.
	}
	nebMTU, err := n.SysfsMTU(nebDev)
	if err != nil {
		return
	}
	if cilMTU <= nebMTU-mtuCiliumWGOverhead {
		return
	}
	n.State.AppendLog(fmt.Sprintf(
		"warn: cilium_wg0 MTU %d exceeds nebula invariant (nebula %s MTU %d, max %d) — clamping TCP MSS on cilium_wg0",
		cilMTU, nebDev, nebMTU, nebMTU-mtuCiliumWGOverhead))
	if err := n.clampMSSOn(ctx, "cilium_wg0"); err != nil {
		// Unclamped drift keeps blackholing WG traffic — the next
		// probe cycle retries (WGClampKnown stays false).
		n.State.AppendLog("warn: cilium_wg0 MSS clamp failed: " + err.Error())
		return
	}
	st.Mu.Lock()
	st.WGClampKnown = true
	st.Mu.Unlock()
}

// WriteMTUBHMetric emits node_agent_nebula_mtu_blackhole (0/1) to
// the node-exporter textfile — the node-exporter textfile channel
// (controllerhygiene's textfile-dir override parity). Identical values
// skip the rewrite so the file's mtime tracks real changes.
func (n *Deps) WriteMTUBHMetric(st *MTUProbeState) {
	v := "0"
	if n.State.Exists(latchdefs.LatchNebulaMTUBlackhole) {
		v = "1"
	}
	st.Mu.Lock()
	if st.LastGauge == v {
		st.Mu.Unlock()
		return
	}
	st.LastGauge = v
	st.Mu.Unlock()
	// NODE_HOST_AGENT_TEXTFILE_DIR (Config.TextfileDir) wins — the
	// HostRoot derivation only covers configs built without the
	// hostctx bundle (tests, hand-rolled Configs).
	dir := n.TextfileDir()
	if dir == "" {
		dir = filepath.Join(n.HostRoot(),
			"var", "lib", "node-exporter", "textfile")
	}
	if o := n.TextfileDirOverride(); o != "" {
		dir = o
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
