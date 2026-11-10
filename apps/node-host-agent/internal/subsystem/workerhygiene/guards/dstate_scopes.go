package guards

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checkkit"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// Guard defaults (d-state-storm..H7): the D-state storm thresholds
// (total procs OR runtime-critical procs), the 30m
// systemd-scope reaper cadence, and the A2 zombie-storm
// threshold.
const (
	dStateRuntimeMin         = 2 // runtime-critical D-state procs → storm
	systemdScopeScanInterval = 30 * time.Minute
)

var (
	// Pod UID inside a /proc/<pid>/cgroup path — kubepods slices
	// embed it with underscores
	// (kubepods-burstable-pod<8_4_4_4_12>.slice), some runtimes keep
	// dashes; both normalize to the dashed form.
	podUIDCgroupRe = regexp.MustCompile(`pod([0-9a-fA-F_-]{36})`)
)

// podUIDForPID extracts the pod UID owning a pid via
// /proc/<pid>/cgroup — kubepods slices embed the uid with
// underscores; normalized to the dashed form. The parse assumes
// the cgroup-v2 unified hierarchy (the `0::/kubepods...` line and
// kubepods*.slice naming — k0s hosts are v2; on v1 the per-
// hierarchy lines differ and pod_uid resolves "unknown").
func podUIDForPID(d *wdeps.Deps, pid int) string {
	data, err := os.ReadFile(d.Proc.File(pid, "cgroup"))
	if err != nil {
		return "unknown"
	}
	if m := podUIDCgroupRe.FindSubmatch(data); m != nil {
		return strings.ReplaceAll(string(m[1]), "_", "-")
	}
	return "unknown"
}

// ZombieParent keys one storm streak: pid alone lies after PID
// reuse — the /proc/<pid>/stat starttime (field 22, jiffies since
// boot) tags the process generation so a recycled ppid restarts at
// streak 0 instead of inheriting a dead parent's count and holding
// the latch open for a storm that ended with it. An unreadable
// starttime leaves the zero value — streaks then merge on pid
// alone (same as the pre-key behaviour: the pid still has to stay
// over threshold to accumulate).
type ZombieParent struct {
	pid   int
	start string // /proc/<pid>/stat field 22
}

// procStartTime reads /proc/<pid>/stat field 22 (starttime) — the
// generation tag inside ZombieParent. "" when the stat is
// unreadable or truncated (the parent exited mid-sweep).
func procStartTime(d *wdeps.Deps, pid int) string {
	st, ok := d.Proc.Stat(pid)
	// Fields after ')' start at field 3: Fields[0]=state,
	// Fields[1]=ppid, … Fields[19]=starttime (field 22).
	if !ok || len(st.Fields) <= 19 {
		return ""
	}
	return st.Fields[19]
}

// ZombieStormCheck is the A2 storm detector as a Check. streaks
// counts consecutive cycles each parent has produced >
// ZombieStormThreshold defunct children (ex-Hygiene.zombieStreaks).
// Keyed by ZombieParent (pid + stat starttime), NOT raw pid — a
// pid recycled between cycles must not inherit a dead process's
// streak and hold the latch open for a storm that is over.
type ZombieStormCheck struct {
	d       *wdeps.Deps
	streaks map[ZombieParent]int
}

// Name returns the check label / WD_SIG key.
func (c *ZombieStormCheck) Name() string { return wdeps.CheckZombieStorm }

// Run executes one zombie-storm round.
func (c *ZombieStormCheck) Run(_ context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckZombieStorm) {
		return
	}
	byPPID := map[int]int{}
	for _, pid := range e.PidsOnce() {
		state, ppid, ok := c.d.ProcStatStatePPID(pid)
		if !ok || state != "Z" {
			continue
		}
		byPPID[ppid]++
	}
	// Resolve each parent once — one extra stat read per parent,
	// not per zombie.
	parents := map[int]ZombieParent{}
	keyOf := func(ppid int) ZombieParent {
		k, ok := parents[ppid]
		if !ok {
			k = ZombieParent{pid: ppid, start: procStartTime(c.d, ppid)}
			parents[ppid] = k
		}
		return k
	}
	// Loop 1 only PRUNES dead streaks — a stored streak must not set
	// storm here: this cycle's zombie count isn't re-validated yet,
	// so a parent that dropped below threshold would hold the latch
	// one extra cycle. Loop 2 re-validates against the current count
	// before any streak contributes to storm.
	storm := false
	for parent := range c.streaks {
		if _, ok := byPPID[parent.pid]; !ok || keyOf(parent.pid) != parent {
			delete(c.streaks, parent) // parent gone or pid recycled — streak dead
		}
	}
	for ppid, n := range byPPID {
		key := keyOf(ppid)
		if n <= c.d.Cfg.Pressure.ZombieStormThreshold {
			delete(c.streaks, key)
			continue
		}
		c.streaks[key]++
		switch streak := c.streaks[key]; {
		case streak == c.d.Cfg.ConsecNeeded:
			storm = true
			uid := podUIDForPID(c.d, ppid)
			// NPD contract: nodereporter maps this line to the
			// ZombieProcessStorm Event + problem_counter. Logged
			// on streak ENTRY only — repeating it every cycle while
			// the storm persists would spawn a fresh K8s Event per
			// interval (the !stateExists gating wdeps.CheckCiliumMTU
			// uses).
			c.d.State.AppendLog(fmt.Sprintf(
				latchdefs.ActionEntryPrefix(latchdefs.LatchZombieStorm)+
					"pod_uid=%s zombies=%d ppid=%d", uid, n, ppid))
		case streak > c.d.Cfg.ConsecNeeded:
			storm = true // latched storm continues — no repeated ACTION line
		default:
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: zombie-storm ppid=%d zombies=%d%s",
				ppid, n, checkkit.Progress(streak, c.d.Cfg.ConsecNeeded)))
		}
	}
	if storm {
		c.d.State.Enter(latchdefs.LatchZombieStorm, "")
	} else {
		c.d.State.Exit(latchdefs.LatchZombieStorm, nil)
	}
	c.d.CycleResult(wdeps.CheckZombieStorm, "ok")
}

// procStatCommState parses /proc/<pid>/stat for comm + state — comm
// sits between the FIRST '(' and the LAST ')' (it can hold spaces
// and parens), state is the first field after that ')' (same trick
// as procStatStatePPID).
func procStatCommState(d *wdeps.Deps, pid int) (comm, state string, ok bool) {
	st, ok := d.Proc.Stat(pid)
	if !ok || !st.HasComm {
		return "", "", false
	}
	return st.Comm, st.Fields[0], true
}

// procWchan returns the kernel function a task is sleeping inside —
// /proc/<pid>/wchan names it; "0" (running/not-sleeping) and
// unreadable files report "".
func procWchan(d *wdeps.Deps, pid int) string {
	data, err := os.ReadFile(d.Proc.File(pid, "wchan"))
	if err != nil {
		return ""
	}
	w := strings.TrimSpace(string(data))
	if w == "0" {
		return ""
	}
	return w
}

// DstateRuntimeComm reports whether a /proc/<pid>/stat comm belongs
// to the runtime-critical set — D-state here wedges the pod
// lifecycle (runc, containerd + containerd-shim, k0s workers,
// kubelet) or signals a hung fs journal (btrfs-*/jbd2/* kernel
// threads). Prefixes, not exact names: comm is truncated at 15
// bytes ("containerd-shim" is the shim's real comm) and jbd2
// threads embed the device (jbd2/vda1-8).
func DstateRuntimeComm(comm string) bool {
	for _, p := range []string{
		"runc", "containerd", "k0s", "kubelet", "btrfs-", "jbd2/",
	} {
		if strings.HasPrefix(comm, p) {
			return true
		}
	}
	return false
}

// DstateCheck is the d-state-storm storm detector as a Check; it owns the
// over-threshold streak (ex-Hygiene.dstateFails).
type DstateCheck struct {
	d     *wdeps.Deps
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *DstateCheck) Name() string { return wdeps.CheckDState }

// Run executes one d-state-storm round.
func (c *DstateCheck) Run(_ context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckDState) {
		return
	}
	total, runtime := 0, 0
	// A small comm=wchan sample for the ACTION line — the kernel
	// function holding the tasks is the triage hint (umount_tree /
	// wait_transaction_locked / blk_mq_get_tag).
	wchans := make([]string, 0, 4)
	for _, pid := range e.PidsOnce() {
		comm, state, ok := procStatCommState(c.d, pid)
		if !ok || state != "D" {
			continue
		}
		total++
		if DstateRuntimeComm(comm) {
			runtime++
		}
		if len(wchans) < 4 {
			if w := procWchan(c.d, pid); w != "" {
				wchans = append(wchans, comm+"="+w)
			}
		}
	}
	if total < c.d.Cfg.Pressure.DStateStormThreshold && runtime < dStateRuntimeMin {
		c.fails = 0
		c.d.State.Exit(latchdefs.LatchDStateStorm, nil)
		c.d.CycleResult(wdeps.CheckDState, "ok")
		return
	}
	if c.d.StreakPending(&c.fails, fmt.Sprintf(
		"suspect: d-state-storm count=%d runtime=%d",
		total, runtime)) {
		c.d.CycleResult(wdeps.CheckDState, "ok")
		return
	}
	if !c.d.State.Exists(latchdefs.LatchDStateStorm) {
		// NPD contract: nodereporter maps this line to the
		// KernelHungTasks Event + problem_counter — logged once per
		// latch entry (the !stateExists gate, wdeps.CheckCiliumMTU parity).
		c.d.State.AppendLog(fmt.Sprintf(
			latchdefs.ActionEntryPrefix(latchdefs.LatchDStateStorm)+
				"count=%d runtime=%d wchan=%s",
			total, runtime, strings.Join(wchans, ",")))
	}
	c.d.State.Enter(latchdefs.LatchDStateStorm,
		fmt.Sprintf("count=%d runtime=%d", total, runtime))
	c.d.CycleResult(wdeps.CheckDState, "ok")
}

// --- Check: systemd-scopes (systemd-scopes) ---
// On high-churn nodes (cicd's Concourse/Tekton/Shipwright build
// pods, crashloop storms) PID 1 leaks transient
// cri-containerd-*.scope units in the failed state — they pile into
// systemd's unit hash table and every D-Bus call kubelet/containerd
// makes (sandbox create) slows from ms to seconds (kubernetes
// #104029). A 30m sweep lists the failed scopes and resets them —
// reset-failed is safe on live scopes (it only clears the failed
// bookkeeping of already-dead units).

// ScopesCheck is the systemd-scopes failed-scope reaper as a Check; it owns
// the 30m sweep stamp (ex-Hygiene.lastScopeScan) and the consecutive-sweep
// streak for units wedged in `deactivating` (W20-KR1).
type ScopesCheck struct {
	d           *wdeps.Deps
	lastScan    time.Time
	deactStreak int
	// prevDeact is the W21-G3 per-unit deactivating ledger — unit
	// name → was deactivating at the previous sweep. A unit wedged
	// across ≥2 sweeps whose container id is absent from every
	// Running pod's container set is an orphaned teardown the
	// reaper force-stops.
	prevDeact map[string]bool
}

// Name returns the check label / WD_SIG key.
func (c *ScopesCheck) Name() string { return wdeps.CheckSysScopes }

// Run executes one systemd-scopes round.
func (c *ScopesCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckSysScopes) {
		return
	}
	if c.d.Cfg.Systemd == nil {
		c.d.CycleResult(wdeps.CheckSysScopes, "gated")
		return
	}
	if c.d.Cfg.Seams.Host.Clock.Now().Sub(c.lastScan) < systemdScopeScanInterval {
		c.d.CycleResult(wdeps.CheckSysScopes, "ok")
		return
	}
	out, err := c.d.Cfg.Systemd.Exec(ctx, "systemctl", "list-units",
		"--type=scope", "--state=failed", "--no-legend", "--plain",
		"cri-containerd-*.scope")
	if err != nil {
		// A transient systemctl/D-Bus failure is inconclusive — the
		// scan must NOT stamp (a stamped failure defers the retry a
		// full interval) and zero evidence was gathered.
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: systemd-scopes list-units failed: %v (%s) — scan skipped",
			err, strings.TrimSpace(out)))
		c.d.CycleResult(wdeps.CheckSysScopes, "abort")
		return
	}
	c.lastScan = c.d.Cfg.Seams.Host.Clock.Now()
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) > 0 &&
			strings.HasSuffix(f[0], ".scope") {
			n++
		}
	}
	c.checkDeactivating(ctx, e)
	if n == 0 {
		c.d.CycleResult(wdeps.CheckSysScopes, "ok")
		return
	}
	// NPD contract line (reset-failed evidence in the watchdog log).
	c.d.State.AppendLog(fmt.Sprintf("ACTION: systemd-scopes reset-failed count=%d", n))
	if rout, rerr := c.d.Cfg.Systemd.Exec(ctx,
		"systemctl", "reset-failed", "cri-containerd-*.scope"); rerr != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: systemd-scopes reset-failed failed: %v (%s)",
			rerr, strings.TrimSpace(rout)))
	} else {
		c.d.Actions.WithLabelValues(wdeps.CheckSysScopes, "reset_failed").Inc()
	}
	c.d.CycleResult(wdeps.CheckSysScopes, "ok")
}

// checkDeactivating is the W20-KR1 deactivating wedge detector:
// cri-containerd-*.scope units stuck in `deactivating` across
// consecutive sweeps mean container teardown is wedged inside
// systemd PID 1 (stop-sigterm/sigkill never completing) —
// reset-failed cannot clear these. Units still owned by a Running
// pod stay diagnose-only; orphaned ones (W21-G3) are force-stopped
// by reapDeactivating once the streak proves the wedge is real.
// The streak must survive ≥2 sweeps (~1h) before alerting so a
// normal stop-in-progress transient never pages. Runs even when no
// failed scopes exist — a node can wedge on deactivating alone.
func (c *ScopesCheck) checkDeactivating(ctx context.Context, e *wdeps.CycleEnv) {
	dout, derr := c.d.Cfg.Systemd.Exec(ctx, "systemctl", "list-units",
		"--type=scope", "--state=deactivating", "--no-legend", "--plain",
		"cri-containerd-*.scope")
	if derr != nil {
		// Inconclusive — leave the streak AND the per-unit ledger
		// untouched rather than resetting on a transient D-Bus
		// failure.
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: systemd-scopes deactivating list-units failed: %v (%s) — streak kept",
			derr, strings.TrimSpace(dout)))
	} else {
		var units []string
		for _, line := range strings.Split(dout, "\n") {
			if f := strings.Fields(line); len(f) > 0 &&
				strings.HasSuffix(f[0], ".scope") {
				units = append(units, f[0])
			}
		}
		if len(units) == 0 {
			c.deactStreak = 0
		} else {
			c.deactStreak++
			if c.deactStreak >= 2 {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: systemd-scopes deactivating count=%d streak=%d",
					len(units), c.deactStreak))
			}
		}
		c.reapDeactivating(ctx, e, units)
		// Rebuild the per-unit ledger AFTER the reap read it —
		// prevDeact must hold LAST sweep's set when judging this
		// sweep's candidates.
		next := make(map[string]bool, len(units))
		for _, u := range units {
			next[u] = true
		}
		c.prevDeact = next
	}
	// No CycleResult here — Run owns the per-sweep cycle accounting;
	// a second "ok" from this helper would double-count every scan.
}

// reapDeactivating is the W21-G3 orphaned-teardown reaper: a
// cri-containerd-*.scope wedged in `deactivating` across ≥2
// consecutive sweeps (prevDeact[unit] && deactStreak ≥ 2) whose
// container id is absent from every Running pod's container set is
// a dead teardown systemd will never finish — SIGKILL + stop
// forces the scope closed, capped at 5 units per sweep. A scope
// still owned by a live pod is diagnose-only: killing it would be
// a pod kill, which is not this check's remit.
func (c *ScopesCheck) reapDeactivating(ctx context.Context,
	e *wdeps.CycleEnv, units []string) {

	if c.deactStreak < 2 || len(c.prevDeact) == 0 {
		return
	}
	live := runningContainerIDs(e)
	killed := 0
	for _, unit := range units {
		if killed >= 5 {
			break
		}
		if !c.prevDeact[unit] || containerIDLive(scopeContainerID(unit), live) {
			continue
		}
		if out, err := c.d.Cfg.Systemd.Exec(ctx, "systemctl",
			"kill", "--signal=SIGKILL", unit); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: systemd-scopes deactivating kill %s failed: %v (%s)",
				unit, err, strings.TrimSpace(out)))
			continue
		}
		if out, err := c.d.Cfg.Systemd.Exec(ctx, "systemctl",
			"stop", unit); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: systemd-scopes deactivating stop %s failed: %v (%s)",
				unit, err, strings.TrimSpace(out)))
			continue // the SIGKILL landed; stop retries next sweep
		}
		killed++
		c.d.Actions.WithLabelValues(wdeps.CheckSysScopes, "kill_deactivating").Inc()
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: systemd-scopes deactivating reap unit=%s — orphaned cri-containerd scope force-stopped after %d sweeps",
			unit, c.deactStreak))
	}
}

// scopeContainerID extracts the containerd id out of a
// cri-containerd-<id>.scope unit name.
func scopeContainerID(unit string) string {
	return strings.TrimSuffix(
		strings.TrimPrefix(unit, "cri-containerd-"), ".scope")
}

// runningContainerIDs collects the containerd ids of every
// container status on this node's Running pods — init, ephemeral
// and regular. The deactivating reaper treats a scope whose id is
// absent here as orphaned teardown.
func runningContainerIDs(e *wdeps.CycleEnv) []string {
	var ids []string
	for i := range e.Pods {
		p := &e.Pods[i]
		if p.Status.Phase != corev1.PodRunning {
			continue
		}
		for _, cs := range p.Status.ContainerStatuses {
			ids = append(ids, containerStatusID(cs.ContainerID))
		}
		for _, cs := range p.Status.InitContainerStatuses {
			ids = append(ids, containerStatusID(cs.ContainerID))
		}
		for _, cs := range p.Status.EphemeralContainerStatuses {
			ids = append(ids, containerStatusID(cs.ContainerID))
		}
	}
	return ids
}

// containerStatusID strips the "<runtime>://" prefix off a pod
// status containerID — "" when the status carries no id yet
// (excluded by the caller's empty check via containerIDLive).
func containerStatusID(id string) string {
	if i := strings.Index(id, "://"); i >= 0 {
		return id[i+3:]
	}
	return id
}

// containerIDLive reports whether a scope's container id belongs to
// a Running pod — exact match or a truncated/prefixed variant
// (systemd unit-name limits can shorten the id either way).
func containerIDLive(scopeID string, live []string) bool {
	if scopeID == "" {
		return true // unparseable unit — never reap on a guess
	}
	for _, lid := range live {
		if lid == "" {
			continue
		}
		if lid == scopeID || strings.HasPrefix(lid, scopeID) ||
			strings.HasPrefix(scopeID, lid) {
			return true
		}
	}
	return false
}

// --- Check: cilium-envoy xDS NACK + node-local-dns LRP (envoy-xds-lrp) ---
// Two datapath wedges that leave every healthz green:
//   - envoy rejects xDS pushes (cds/lds/rds update_rejected
//     counters climbing) — the listener accepts connections but
//     never programs new routes; Gateway API objects report
//     Accepted:True while replies 404/503.
//   - the LocalRedirectPolicy sends cluster :53 to the local
//     node-local-dns pod whose UDP/TCP :53 listener is hung while
//     its :8080 healthz still answers — every pod on the node loses
//     DNS (the 8-day LRP outage shape). The API still reports the
//     pod Ready=True, so the pod itself is the remedy target.
