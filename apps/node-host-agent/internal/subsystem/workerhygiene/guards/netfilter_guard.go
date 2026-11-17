// netfilter_guard.go — the netfilter wedge guard
// (wdeps.CheckNetfilterGuard, P2.11): the classic cluster freeze is
// a process blocked forever on /run/xtables.lock — every iptables/
// nft/iptables-restore invocation on the node queues behind it, so
// CNI ADD/DEL, kube-proxy syncs and NetworkPolicy updates all hang
// while the API server reports green.
//
// Evidence per cycle:
//
//   - hung commands: every pid whose comm is a netfilter tool
//     (nft/iptables*/xtables-*, `nft monitor` excluded via
//     /proc/<pid>/cmdline — it is a legitimate long-running
//     process) in uninterruptible or long-blocked state past
//     NetfilterGuardHungCmdSec, confirmed across
//     NetfilterGuardStuckCycles consecutive cycles before the
//     kill pass touches it.
//   - lock wedge: a non-blocking unix.Flock(LOCK_EX|LOCK_NB)
//     probe on the host xtables.lock — EWOULDBLOCK means a process
//     holds it. netfilterLockStreakCycles (3) consecutive held
//     reads → state-netfilter-locked →
//     NodeCondition NetfilterLockWedged.
//
// Remedies (all gated):
//
//   - NetfilterGuardKillEnabled: SIGKILL the confirmed stuck
//     command pids, capped per cycle, emitting
//     "ACTION netfilter-hung-kill: pid=N comm=..." + a node event.
//   - NetfilterGuardLegacyProbe: iptables-legacy-save counts real
//     "-A " rules — only when /proc/1/net/ip_tables_names is
//     non-empty (an empty legacy table set must not false-positive
//     on the mangle table) — published as the
//     node_agent_iptables_legacy_leaked_rules gauge.
//
// ModeOff skips entirely; ModeAuto/On run the same sweep (there is
// no cheap "does this node use netfilter" probe that isn't itself
// a netfilter command).
package guards

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostexec"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// NetfilterGuardCheck is the P2.11 guard as a Check; it owns the
// per-pid stuck streaks and the xtables.lock held streak.
type NetfilterGuardCheck struct {
	d          *wdeps.Deps
	seen       map[netfilterPidKey]int // (pid,starttime) → consecutive qualifying cycles
	lockStreak int                     // consecutive cycles xtables.lock read held
	lastScan   time.Time               // last full scan — NetfilterGuardIntervalSec spacing
}

// netfilterPidKey is the streak identity — (pid, starttime jiffies)
// so a recycled pid cannot inherit a dead process's confirmation
// streak (the classic PID-reuse false-positive: kill a fresh,
// healthy iptables because the OLD one's streak carried over).
type netfilterPidKey struct {
	pid   int
	start int64
}

// NewNetfilterGuard builds the check.
func NewNetfilterGuard(d *wdeps.Deps) *NetfilterGuardCheck {
	return &NetfilterGuardCheck{d: d}
}

// Name returns the check label / WD_SIG key.
func (c *NetfilterGuardCheck) Name() string { return wdeps.CheckNetfilterGuard }

// netfilterLockStreakCycles is the consecutive-held-cycles bound
// for the xtables.lock wedge latch — the plan's ">= 3 cycles".
const netfilterLockStreakCycles = 3

// netfilterComm reports whether comm names a netfilter-mutating
// tool — iptables/ip6tables/iptables-restore/nft and the legacy
// xtables-multi variants. Read-only tools (iptables -L wrappers)
// share comms with mutating ones, so the age+state filter below
// does the discriminating: a -L finishes in ms, a wedged one sits
// for minutes. `nft monitor` shares the "nft" comm but is a
// legitimate long-running process — scanStuck excludes it via
// cmdline, not here (comm alone cannot tell them apart).
func netfilterComm(comm string) bool {
	switch comm {
	case "iptables", "ip6tables", "iptables-restore", "ip6tables-restore",
		"iptables-save", "ip6tables-save", "nft", "xtables-nft-multi",
		"iptables-legacy", "ip6tables-legacy", "iptables-legacy-restore",
		"ip6tables-legacy-restore", "iptables-legacy-save", "ip6tables-legacy-save":
		return true
	}
	return false
}

// nftMonitor reports whether the pid is `nft monitor` — the one
// netfilter comm that is SUPPOSED to live forever; killing it
// would be a false positive, not a wedge heal.
func (c *NetfilterGuardCheck) nftMonitor(pid int) bool {
	args := c.d.Proc.Cmdline(pid)
	return len(args) >= 2 && args[0] == "nft" && args[1] == "monitor"
}

// stuckNetfilterProc is one qualifying hung command.
type stuckNetfilterProc struct {
	pid   int
	start int64 // /proc stat field 22 — jiffies since boot
	comm  string
	state string
	age   time.Duration
}

// scanStuck returns the pids currently qualifying: netfilter comm
// + non-running state (D preferred — S counts too because a
// process parked on flock() shows S, not D) + age >= HungCmdSec.
func (c *NetfilterGuardCheck) scanStuck(now time.Time,
	pids []int) []stuckNetfilterProc {
	minAge := time.Duration(c.d.Cfg.Wave2.NetfilterGuardHungCmdSec) * time.Second
	if minAge <= 0 {
		minAge = 60 * time.Second
	}
	var out []stuckNetfilterProc
	for _, pid := range pids {
		st, ok := c.d.Proc.Stat(pid)
		if !ok || !st.HasComm || !netfilterComm(st.Comm) {
			continue
		}
		if st.Comm == "nft" && c.nftMonitor(pid) {
			continue // `nft monitor` is meant to live forever
		}
		if len(st.Fields) == 0 {
			continue
		}
		state := st.Fields[0]
		// R/S are normal for a command mid-run; only age makes
		// them suspect — but D is always suspect regardless of
		// the bound (a netfilter tool in D for ANY duration is a
		// kernel-side wedge, not a slow query).
		age := c.d.Proc.Age(pid, now)
		if state != "D" && age < minAge {
			continue
		}
		if state == "R" {
			continue // running — CPU-bound, not lock-blocked
		}
		// stat Fields[19] is field 22 (starttime, jiffies) — the
		// process-instance identity the streak keys on. A stat
		// too short to carry it gets the -1 sentinel: streaks
		// still work cycle-to-cycle, they just cannot distinguish
		// a pid reuse on a malformed stat (vanishingly rare).
		var start int64 = -1
		if len(st.Fields) > 19 {
			if v, err := strconv.ParseInt(st.Fields[19], 10, 64); err == nil {
				start = v
			}
		}
		out = append(out, stuckNetfilterProc{
			pid: pid, start: start, comm: st.Comm, state: state,
			age: age,
		})
	}
	return out
}

// lockPath resolves the host xtables.lock — the explicit knob
// wins; otherwise it derives from Disk.HostRunDir so the
// DaemonSet's /host/run mount (and standalone /run) both land on
// the HOST lock file, never the container's own /run.
func (c *NetfilterGuardCheck) lockPath() string {
	if p := c.d.Cfg.Wave2.NetfilterGuardLockPath; p != "" {
		return p
	}
	return filepath.Join(c.d.Cfg.Disk.HostRunDir, "xtables.lock")
}

// lockHeld probes the xtables.lock with a non-blocking exclusive
// flock — the plan's wedge test. EWOULDBLOCK/EAGAIN means another
// process holds it; a missing file or a successful acquire means
// no wedge (an acquired lock is released before returning). Other
// errors are inconclusive → false, never fabricated evidence.
func (c *NetfilterGuardCheck) lockHeld() bool {
	fd, err := unix.Open(c.lockPath(), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return err == unix.EWOULDBLOCK || err == unix.EAGAIN
	}
	_ = unix.Flock(fd, unix.LOCK_UN)
	return false
}

// Run executes one netfilter-guard round.
func (c *NetfilterGuardCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckNetfilterGuard) {
		return
	}
	if c.d.Cfg.Wave2.NetfilterGuardMode == envx.ModeOff {
		c.d.State.Exit(latchdefs.LatchNetfilterLocked, nil)
		c.lockStreak = 0
		c.d.CycleResult(wdeps.CheckNetfilterGuard, "ok")
		return
	}
	// NetfilterGuardIntervalSec spaces the full scan — the check
	// runs every subsystem cycle but the /proc walk + flock probe
	// + legacy-save exec only fire once per interval. Skipped
	// cycles bump no cycle counter (the four-value result
	// vocabulary stays intact) and hold every streak: the
	// "consecutive cycles" the plan counts are scan cycles.
	interval := time.Duration(c.d.Cfg.Wave2.NetfilterGuardIntervalSec) * time.Second
	if interval > 0 {
		now := c.d.Cfg.Seams.Host.Clock.Now()
		if !c.lastScan.IsZero() && now.Sub(c.lastScan) < interval {
			return
		}
		c.lastScan = now
	}
	if c.d.Cfg.Wave2.NetfilterGuardLegacyProbe {
		c.probeLegacyRules(ctx)
	}
	var pids []int
	var err error
	if e != nil && e.PidsOnce != nil {
		pids = e.PidsOnce()
	} else {
		pids, err = c.d.Proc.PIDs()
	}
	if err != nil {
		c.d.CycleResult(wdeps.CheckNetfilterGuard, "inconclusive")
		return
	}
	stuck := c.scanStuck(c.d.Cfg.Seams.Host.Clock.Now(), pids)

	// Per-pid consecutive-cycle confirmation — a pid must qualify
	// NetfilterGuardStuckCycles cycles running before the kill
	// pass may touch it (the plan's ">= 2 cycles" rail against
	// murdering a slow-but-legitimate command).
	need := c.d.Cfg.Wave2.NetfilterGuardStuckCycles
	if need <= 0 {
		need = 2
	}
	streak := map[netfilterPidKey]int{}
	var confirmed []stuckNetfilterProc
	for _, sp := range stuck {
		key := netfilterPidKey{pid: sp.pid, start: sp.start}
		n := c.seen[key] + 1
		streak[key] = n
		if n >= need {
			confirmed = append(confirmed, sp)
		}
	}
	c.seen = streak

	// Kill pass — bounded per cycle, detect-only when disabled.
	maxKills := c.d.Cfg.Wave2.NetfilterGuardMaxKillsCycle
	if maxKills <= 0 {
		maxKills = 1
	}
	killed := 0
	if c.d.Cfg.Wave2.NetfilterGuardKillEnabled {
		for _, sp := range confirmed {
			if killed >= maxKills {
				break
			}
			c.d.State.AppendLog(fmt.Sprintf(
				"ACTION netfilter-hung-kill: pid=%d comm=%s state=%s age=%s",
				sp.pid, sp.comm, sp.state, sp.age.Round(time.Second)))
			if err := c.d.Cfg.Seams.Host.KillFn(sp.pid, syscall.SIGKILL); err != nil {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: netfilter-guard kill pid=%d failed: %v", sp.pid, err))
				continue
			}
			killed++
			c.emitNetfilterEvent(ctx, sp)
		}
	}
	c.d.Actions.WithLabelValues(wdeps.CheckNetfilterGuard, "cmd_kill").Add(float64(killed))

	// Lock wedge — the flock probe's own >=3-cycle streak owns the
	// latch; stuck commands alone are remedied by the kill pass,
	// not latched (the condition means "the lock is held", per
	// P2.11).
	held := c.lockHeld()
	if held {
		c.lockStreak++
	} else {
		c.lockStreak = 0
	}
	switch {
	case c.lockStreak >= netfilterLockStreakCycles:
		c.d.State.Enter(latchdefs.LatchNetfilterLocked, fmt.Sprintf(
			"xtables.lock held %d consecutive cycles", c.lockStreak))
		c.d.CycleResult(wdeps.CheckNetfilterGuard, "firing")
	case len(confirmed) > 0 || len(stuck) > 0:
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: netfilter-guard %d stuck netfilter cmd(s) (%d confirmed), lock_held=%v streak=%d",
			len(stuck), len(confirmed), held, c.lockStreak))
		c.d.CycleResult(wdeps.CheckNetfilterGuard, "pending")
	default:
		c.d.State.Exit(latchdefs.LatchNetfilterLocked, nil)
		c.d.CycleResult(wdeps.CheckNetfilterGuard, "ok")
	}
}

// probeLegacyRules feeds node_agent_iptables_legacy_leaked_rules —
// the iptables-nft/iptables-legacy split-brain gauge. The probe
// only runs when /proc/1/net/ip_tables_names is non-empty: an
// iptables-nft host whose legacy table set is empty must not
// false-positive on the (always-present, usually empty) mangle
// table — exactly the lanit-04 trap the plan calls out. Only
// "-A " chain lines count as leaked rules. An inconclusive probe
// (names unreadable AND save failing) leaves the prior gauge —
// never a fabricated 0.
func (c *NetfilterGuardCheck) probeLegacyRules(ctx context.Context) {
	namesPath := filepath.Join(c.d.Cfg.ProcRoot, "1", "net", "ip_tables_names")
	names, err := os.ReadFile(namesPath)
	if err != nil || strings.TrimSpace(string(names)) == "" {
		// No legacy tables registered → definitively zero leaked.
		c.d.Series.IPTablesLegacyLeakedRules = 0
		return
	}
	// NetfilterGuardCmdTimeoutSec bounds the legacy-save exec — a
	// wedged iptables-legacy-save must not stall the check cycle.
	timeout := time.Duration(c.d.Cfg.Wave2.NetfilterGuardCmdTimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := hostexec.RunCombined(ctx, "iptables-legacy-save")
	if err != nil {
		return // inconclusive — keep the last good gauge
	}
	rules := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "-A ") {
			rules++
		}
	}
	c.d.Series.IPTablesLegacyLeakedRules = int64(rules)
}

// emitNetfilterEvent emits the node Warning event for one killed
// stuck netfilter command.
func (c *NetfilterGuardCheck) emitNetfilterEvent(ctx context.Context, sp stuckNetfilterProc) {
	now := c.d.Cfg.Seams.Host.Clock.Now()
	_ = c.d.EmitCheckEvent(ctx, wdeps.CheckEvent{
		Name: fmt.Sprintf("%s.%s.%x", c.d.Cfg.NodeName,
			latchdefs.ActionNetfilterHungKill, now.UnixNano()),
		Namespace: c.d.Cfg.Host.EventNamespace,
		Reason:    "NetfilterCommandKilled",
		Note: fmt.Sprintf(
			"node-host-agent killed stuck netfilter command pid=%d comm=%s state=%s age=%s",
			sp.pid, sp.comm, sp.state, sp.age.Round(time.Second)),
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Node",
			Name:       c.d.Cfg.NodeName,
		},
	})
}
