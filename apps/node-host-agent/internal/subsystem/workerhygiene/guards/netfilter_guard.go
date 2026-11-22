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
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
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

type nftMonitorResult uint8

const (
	nftCmdNonMonitor nftMonitorResult = iota
	nftCmdMonitor
	nftCmdStateD
	nftCmdSkip
	nftCmdReadErr
)

// nftMonitor classifies an `nft` pid without opening mm-backed cmdline
// on D/Z/X/x/R or non-ENOENT stat states, distinguishing `nft monitor`,
// mid-scan state transitions, and non-ENOENT read errors.
func (c *NetfilterGuardCheck) nftMonitor(pid int) nftMonitorResult {
	st, ok := c.d.Proc.Stat(pid)
	if !ok {
		if statNonENOENT(c.d, pid) {
			return nftCmdReadErr
		}
		return nftCmdSkip
	}
	if len(st.Fields) == 0 {
		return nftCmdSkip
	}
	switch st.Fields[0] {
	case "D":
		return nftCmdStateD
	case "Z", "X", "x", "R":
		return nftCmdSkip
	}
	args := c.d.Proc.Cmdline(pid)
	if len(args) == 0 {
		if st, ok := c.d.Proc.Stat(pid); !ok {
			if statNonENOENT(c.d, pid) {
				return nftCmdReadErr
			}
			return nftCmdSkip
		} else if len(st.Fields) == 0 {
			return nftCmdSkip
		} else {
			switch st.Fields[0] {
			case "D":
				return nftCmdStateD
			case "Z", "X", "x", "R":
				return nftCmdSkip
			}
		}
		if procFileNonENOENT(c.d, pid, "cmdline") {
			return nftCmdReadErr
		}
		return nftCmdNonMonitor
	}
	if len(args) >= 2 && filepath.Base(args[0]) == "nft" && args[1] == "monitor" {
		return nftCmdMonitor
	}
	return nftCmdNonMonitor
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
// unreadable marks PIDs whose stat or cmdline failed with !ENOENT so
// callers preserve their confirmation streaks and abort.
func (c *NetfilterGuardCheck) scanStuck(e *wdeps.CycleEnv, now time.Time,
	pids []int) (out []stuckNetfilterProc, unreadable map[int]bool, inconclusive bool) {
	minAge := time.Duration(c.d.Cfg.Wave2.NetfilterGuardHungCmdSec) * time.Second
	if minAge <= 0 {
		minAge = 60 * time.Second
	}
	var statsSnap map[int]procfs.Stat
	if e != nil && e.StatsOnce != nil {
		statsSnap = e.StatsOnce()
	}
	for _, pid := range pids {
		var st procfs.Stat
		var ok bool
		if statsSnap != nil {
			st, ok = statsSnap[pid]
		} else {
			st, ok = c.d.Proc.Stat(pid)
		}
		if !ok {
			if statNonENOENT(c.d, pid) {
				if unreadable == nil {
					unreadable = map[int]bool{}
				}
				unreadable[pid] = true
				inconclusive = true
			}
			continue
		}
		if !st.HasComm || !netfilterComm(st.Comm) || len(st.Fields) == 0 {
			continue
		}
		state := st.Fields[0]
		if state == "R" || state == "Z" || state == "X" || state == "x" {
			continue // running or dead/zombie — SIGKILL cannot clear Z/X or busy R
		}
		if st.Comm == "nft" && state != "D" {
			switch c.nftMonitor(pid) {
			case nftCmdReadErr:
				if unreadable == nil {
					unreadable = map[int]bool{}
				}
				unreadable[pid] = true
				inconclusive = true
				continue
			case nftCmdMonitor, nftCmdSkip:
				continue // `nft monitor` or exited/Z/X/R mid-scan
			case nftCmdStateD:
				state = "D"
			case nftCmdNonMonitor:
			}
		}
		// R/S are normal for a command mid-run; only age makes
		// them suspect — but D is always suspect regardless of
		// the bound (a netfilter tool in D for ANY duration is a
		// kernel-side wedge, not a slow query).
		age := c.d.Proc.Age(pid, now)
		if state != "D" && age < minAge {
			continue
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
	return out, unreadable, inconclusive
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

// lockHeld passively inspects <ProcRoot>/locks (falling back to /proc/locks
// if <ProcRoot>/locks does not exist) for any kernel lock referencing the
// xtables.lock (dev, ino), avoiding flock(LOCK_EX) lock-stealing races.
// ok=false when lockPath or locks cannot be read due to non-ENOENT errors
// (inconclusive — caller preserves lockStreak and LatchNetfilterLocked).
func (c *NetfilterGuardCheck) lockHeld() (held, ok bool) {
	var st unix.Stat_t
	if err := unix.Stat(c.lockPath(), &st); err != nil {
		if os.IsNotExist(err) {
			return false, true
		}
		return false, false
	}
	target := fmt.Sprintf("%02x:%02x:%d", unix.Major(st.Dev), unix.Minor(st.Dev), st.Ino)
	var data []byte
	var err error
	if c.d.Cfg.ProcRoot != "" {
		locksPath := filepath.Join(c.d.Cfg.ProcRoot, "locks")
		data, err = os.ReadFile(locksPath)
		if err != nil {
			if !os.IsNotExist(err) {
				return false, false
			}
			data, err = os.ReadFile("/proc/locks")
		}
	} else {
		data, err = os.ReadFile("/proc/locks")
	}
	if err != nil {
		return false, false
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		// Expected fields: N: FLOCK ADVISORY WRITE PID MAJ:MIN:INO START END
		if len(fields) >= 6 && fields[5] == target {
			return true, true
		}
	}
	return false, true
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
	var scanNow time.Time
	if interval > 0 {
		scanNow = c.d.Cfg.Seams.Host.Clock.Now()
		if !c.lastScan.IsZero() && scanNow.Sub(c.lastScan) < interval {
			return
		}
	}
	pids, pidsOK := c.d.CyclePIDs(e)
	if !pidsOK {
		c.d.CycleResult(wdeps.CheckNetfilterGuard, "inconclusive")
		return
	}
	if interval > 0 {
		c.lastScan = scanNow
	}
	stuck, unreadable, scanInconclusive := c.scanStuck(e, c.d.Cfg.Seams.Host.Clock.Now(), pids)
	held, lockOK := c.lockHeld()

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
	if scanInconclusive {
		for k, v := range c.seen {
			if unreadable[k.pid] {
				streak[k] = v
			}
		}
	}
	c.seen = streak

	// Kill pass — bounded per cycle, detect-only when disabled.
	maxKills := c.d.Cfg.Wave2.NetfilterGuardMaxKillsCycle
	if maxKills <= 0 {
		maxKills = 1
	}
	killed := 0
	healHoldChecked := false
	healHeld := false
	holdEmergency := func() bool {
		if !healHoldChecked {
			healHoldChecked = true
			healHeld = c.d.HoldEmergencyHeal(ctx)
		}
		return healHeld
	}
	if c.d.Cfg.Wave2.NetfilterGuardKillEnabled {
		for _, sp := range confirmed {
			if sp.state == "D" {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: netfilter-guard pid=%d comm=%s uninterruptible D-state (SIGKILL ineffective)",
					sp.pid, sp.comm))
				continue
			}
			if killed >= maxKills {
				break
			}
			if holdEmergency() {
				c.d.State.AppendLog(fmt.Sprintf(
					"cleanup: netfilter-guard kill pid=%d held by maintenance window, skip",
					sp.pid))
				continue
			}
			// Re-verify process identity and starttime immediately
			// before SIGKILL to close any PID-reuse window.
			st, ok := c.d.Proc.Stat(sp.pid)
			if !ok || !st.HasComm || !netfilterComm(st.Comm) || len(st.Fields) == 0 {
				continue
			}
			curState := st.Fields[0]
			if curState == "D" || curState == "Z" || curState == "R" || curState == "X" || curState == "x" {
				if curState == "D" {
					c.d.State.AppendLog(fmt.Sprintf(
						"suspect: netfilter-guard pid=%d comm=%s uninterruptible D-state (SIGKILL ineffective)",
						sp.pid, st.Comm))
				}
				continue
			}
			if sp.start >= 0 {
				var curStart int64 = -1
				if len(st.Fields) > 19 {
					if v, perr := strconv.ParseInt(st.Fields[19], 10, 64); perr == nil {
						curStart = v
					}
				}
				if curStart != sp.start {
					continue
				}
			}
			c.d.State.AppendLog(fmt.Sprintf(
				"ACTION netfilter-hung-kill: pid=%d comm=%s state=%s age=%s",
				sp.pid, sp.comm, curState, sp.age.Round(time.Second)))
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
	if c.d.Cfg.Wave2.NetfilterGuardLegacyProbe && lockOK && !held {
		c.probeLegacyRules(ctx)
	}

	// Lock wedge — the passive /proc/locks probe's >=3-cycle streak owns the latch.
	if lockOK {
		if held {
			c.lockStreak++
		} else {
			c.lockStreak = 0
			c.d.State.Exit(latchdefs.LatchNetfilterLocked, nil)
		}
	}
	switch {
	case lockOK && c.lockStreak >= netfilterLockStreakCycles:
		c.d.State.Enter(latchdefs.LatchNetfilterLocked, fmt.Sprintf(
			"xtables.lock held %d consecutive cycles", c.lockStreak))
	case len(confirmed) > 0 || len(stuck) > 0:
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: netfilter-guard %d stuck netfilter cmd(s) (%d confirmed), lock_held=%v lock_ok=%v streak=%d",
			len(stuck), len(confirmed), held, lockOK, c.lockStreak))
	}
	if !lockOK || scanInconclusive {
		c.d.CycleResult(wdeps.CheckNetfilterGuard, "abort")
		return
	}
	c.d.CycleResult(wdeps.CheckNetfilterGuard, "ok")
}

// probeLegacyRules feeds node_agent_iptables_legacy_leaked_rules —
// the iptables-nft/iptables-legacy split-brain gauge.
func (c *NetfilterGuardCheck) probeLegacyRules(ctx context.Context) {
	namesPath := filepath.Join(c.d.Cfg.ProcRoot, "1", "net", "ip_tables_names")
	names, err := os.ReadFile(namesPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No legacy tables registered → definitively zero leaked.
			c.d.Series.IPTablesLegacyLeakedRules = 0
		}
		return
	}
	if strings.TrimSpace(string(names)) == "" {
		// No legacy tables registered → definitively zero leaked.
		c.d.Series.IPTablesLegacyLeakedRules = 0
		return
	}
	if c.d.Cfg.Systemd == nil {
		return
	}
	timeout := time.Duration(c.d.Cfg.Wave2.NetfilterGuardCmdTimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	out, err := c.d.Cfg.Systemd.ExecBounded(ctx, timeout, "iptables-legacy-save")
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
