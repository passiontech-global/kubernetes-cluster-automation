package workerhygiene

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
)

// Wave-7 defaults (W7-H1..H7): the D-state storm thresholds
// (total procs OR runtime-critical procs), the 30m
// systemd-scope reaper cadence, and the A2 zombie-storm
// threshold.
const (
	defaultDStateStormThreshold = 5
	dStateRuntimeMin            = 2 // runtime-critical D-state procs → storm
	systemdScopeScanInterval    = 30 * time.Minute
	zombieStormThreshold        = 500 // <defunct> children of one parent = storm
)

var (
	// Pod UID inside a /proc/<pid>/cgroup path — kubepods slices
	// embed it with underscores
	// (kubepods-burstable-pod<8_4_4_4_12>.slice), some runtimes keep
	// dashes; both normalize to the dashed form.
	podUIDCgroupRe = regexp.MustCompile(`pod([0-9a-fA-F_-]{36})`)
)

// procStatStatePPID parses /proc/<pid>/stat for state + ppid — the
// fields right after the LAST ')' (comm can hold spaces/parens).
func (d *deps) procStatStatePPID(pid int) (state string, ppid int, ok bool) {
	st, ok := d.proc.Stat(pid)
	if !ok || len(st.Fields) < 2 { // Fields[0]=state, Fields[1]=ppid
		return "", 0, false
	}
	p, err := strconv.Atoi(st.Fields[1])
	if err != nil || p < 0 {
		return "", 0, false
	}
	return st.Fields[0], p, true
}

// podUIDForPID extracts the pod UID owning a pid via
// /proc/<pid>/cgroup — kubepods slices embed the uid with
// underscores; normalized to the dashed form. The parse assumes
// the cgroup-v2 unified hierarchy (the `0::/kubepods...` line and
// kubepods*.slice naming — k0s hosts are v2; on v1 the per-
// hierarchy lines differ and pod_uid resolves "unknown").
func (d *deps) podUIDForPID(pid int) string {
	data, err := os.ReadFile(d.proc.File(pid, "cgroup"))
	if err != nil {
		return "unknown"
	}
	if m := podUIDCgroupRe.FindSubmatch(data); m != nil {
		return strings.ReplaceAll(string(m[1]), "_", "-")
	}
	return "unknown"
}

// zombieParent keys one storm streak: pid alone lies after PID
// reuse — the /proc/<pid>/stat starttime (field 22, jiffies since
// boot) tags the process generation so a recycled ppid restarts at
// streak 0 instead of inheriting a dead parent's count and holding
// the latch open for a storm that ended with it. An unreadable
// starttime leaves the zero value — streaks then merge on pid
// alone (same as the pre-key behaviour: the pid still has to stay
// over threshold to accumulate).
type zombieParent struct {
	pid   int
	start string // /proc/<pid>/stat field 22
}

// procStartTime reads /proc/<pid>/stat field 22 (starttime) — the
// generation tag inside zombieParent. "" when the stat is
// unreadable or truncated (the parent exited mid-sweep).
func (d *deps) procStartTime(pid int) string {
	st, ok := d.proc.Stat(pid)
	// Fields after ')' start at field 3: Fields[0]=state,
	// Fields[1]=ppid, … Fields[19]=starttime (field 22).
	if !ok || len(st.Fields) <= 19 {
		return ""
	}
	return st.Fields[19]
}

// zombieStormCheck is the A2 storm detector as a Check. streaks
// counts consecutive cycles each parent has produced >
// ZombieStormThreshold defunct children (ex-Hygiene.zombieStreaks).
// Keyed by zombieParent (pid + stat starttime), NOT raw pid — a
// pid recycled between cycles must not inherit a dead process's
// streak and hold the latch open for a storm that is over.
type zombieStormCheck struct {
	d       *deps
	streaks map[zombieParent]int
}

// Name returns the check label / WD_SIG key.
func (c *zombieStormCheck) Name() string { return checkZombieStorm }

// Run executes one zombie-storm round.
func (c *zombieStormCheck) Run(_ context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.d.cycles.WithLabelValues(checkZombieStorm, "gated").Inc()
		return
	}
	byPPID := map[int]int{}
	for _, pid := range e.pidsOnce() {
		state, ppid, ok := c.d.procStatStatePPID(pid)
		if !ok || state != "Z" {
			continue
		}
		byPPID[ppid]++
	}
	// Resolve each parent once — one extra stat read per parent,
	// not per zombie.
	parents := map[int]zombieParent{}
	keyOf := func(ppid int) zombieParent {
		k, ok := parents[ppid]
		if !ok {
			k = zombieParent{pid: ppid, start: c.d.procStartTime(ppid)}
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
		if n <= c.d.cfg.Pressure.ZombieStormThreshold {
			delete(c.streaks, key)
			continue
		}
		c.streaks[key]++
		switch streak := c.streaks[key]; {
		case streak == c.d.cfg.ConsecNeeded:
			storm = true
			uid := c.d.podUIDForPID(ppid)
			// NPD contract: nodereporter maps this line to the
			// ZombieProcessStorm Event + problem_counter. Logged
			// on streak ENTRY only — repeating it every cycle while
			// the storm persists would spawn a fresh K8s Event per
			// interval (the !stateExists gating checkCiliumMTU
			// uses).
			c.d.state.AppendLog(fmt.Sprintf(
				"ACTION zombie-storm: pod_uid=%s zombies=%d ppid=%d", uid, n, ppid))
		case streak > c.d.cfg.ConsecNeeded:
			storm = true // latched storm continues — no repeated ACTION line
		default:
			c.d.state.AppendLog(fmt.Sprintf(
				"suspect: zombie-storm ppid=%d zombies=%d (check %d/%d)",
				ppid, n, streak, c.d.cfg.ConsecNeeded))
		}
	}
	if storm {
		c.d.state.Enter(hoststate.LatchZombieStorm, "")
	} else {
		c.d.state.Exit(hoststate.LatchZombieStorm, nil)
	}
	c.d.cycles.WithLabelValues(checkZombieStorm, "ok").Inc()
}

// procStatCommState parses /proc/<pid>/stat for comm + state — comm
// sits between the FIRST '(' and the LAST ')' (it can hold spaces
// and parens), state is the first field after that ')' (same trick
// as procStatStatePPID).
func (d *deps) procStatCommState(pid int) (comm, state string, ok bool) {
	st, ok := d.proc.Stat(pid)
	if !ok || !st.HasComm {
		return "", "", false
	}
	return st.Comm, st.Fields[0], true
}

// procWchan returns the kernel function a task is sleeping inside —
// /proc/<pid>/wchan names it; "0" (running/not-sleeping) and
// unreadable files report "".
func (d *deps) procWchan(pid int) string {
	data, err := os.ReadFile(d.proc.File(pid, "wchan"))
	if err != nil {
		return ""
	}
	w := strings.TrimSpace(string(data))
	if w == "0" {
		return ""
	}
	return w
}

// dstateRuntimeComm reports whether a /proc/<pid>/stat comm belongs
// to the runtime-critical set — D-state here wedges the pod
// lifecycle (runc, containerd + containerd-shim, k0s workers,
// kubelet) or signals a hung fs journal (btrfs-*/jbd2/* kernel
// threads). Prefixes, not exact names: comm is truncated at 15
// bytes ("containerd-shim" is the shim's real comm) and jbd2
// threads embed the device (jbd2/vda1-8).
func dstateRuntimeComm(comm string) bool {
	for _, p := range []string{
		"runc", "containerd", "k0s", "kubelet", "btrfs-", "jbd2/",
	} {
		if strings.HasPrefix(comm, p) {
			return true
		}
	}
	return false
}

// dstateCheck is the W7-H1 storm detector as a Check; it owns the
// over-threshold streak (ex-Hygiene.dstateFails).
type dstateCheck struct {
	d     *deps
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *dstateCheck) Name() string { return checkDState }

// Run executes one d-state-storm round.
func (c *dstateCheck) Run(_ context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.d.cycles.WithLabelValues(checkDState, "gated").Inc()
		return
	}
	total, runtime := 0, 0
	// A small comm=wchan sample for the ACTION line — the kernel
	// function holding the tasks is the triage hint (umount_tree /
	// wait_transaction_locked / blk_mq_get_tag).
	wchans := make([]string, 0, 4)
	for _, pid := range e.pidsOnce() {
		comm, state, ok := c.d.procStatCommState(pid)
		if !ok || state != "D" {
			continue
		}
		total++
		if dstateRuntimeComm(comm) {
			runtime++
		}
		if len(wchans) < 4 {
			if w := c.d.procWchan(pid); w != "" {
				wchans = append(wchans, comm+"="+w)
			}
		}
	}
	if total < c.d.cfg.Pressure.DStateStormThreshold && runtime < dStateRuntimeMin {
		c.fails = 0
		c.d.state.Exit(hoststate.LatchDStateStorm, nil)
		c.d.cycles.WithLabelValues(checkDState, "ok").Inc()
		return
	}
	c.fails++
	if c.fails < c.d.cfg.ConsecNeeded {
		c.d.state.AppendLog(fmt.Sprintf(
			"suspect: d-state-storm count=%d runtime=%d (check %d/%d)",
			total, runtime, c.fails, c.d.cfg.ConsecNeeded))
		c.d.cycles.WithLabelValues(checkDState, "ok").Inc()
		return
	}
	if !c.d.state.Exists(hoststate.LatchDStateStorm) {
		// NPD contract: nodereporter maps this line to the
		// KernelHungTasks Event + problem_counter — logged once per
		// latch entry (the !stateExists gate, checkCiliumMTU parity).
		c.d.state.AppendLog(fmt.Sprintf(
			"ACTION d-state-storm: count=%d runtime=%d wchan=%s",
			total, runtime, strings.Join(wchans, ",")))
	}
	c.d.state.Enter(hoststate.LatchDStateStorm,
		fmt.Sprintf("count=%d runtime=%d", total, runtime))
	c.d.cycles.WithLabelValues(checkDState, "ok").Inc()
}

// checkDStateTasks forwards to the migrated Check — tests written
// before the interface still call the old method shape.
func (h *Hygiene) checkDStateTasks(pidsOnce func() []int, workerActive bool) {
	h.dstate.Run(context.Background(), &cycleEnv{
		pidsOnce: pidsOnce, workerActive: workerActive})
}

// --- Check: systemd-scopes (W7-H2) ---
// On high-churn nodes (cicd's Concourse/Tekton/Shipwright build
// pods, crashloop storms) PID 1 leaks transient
// cri-containerd-*.scope units in the failed state — they pile into
// systemd's unit hash table and every D-Bus call kubelet/containerd
// makes (sandbox create) slows from ms to seconds (kubernetes
// #104029). A 30m sweep lists the failed scopes and resets them —
// reset-failed is safe on live scopes (it only clears the failed
// bookkeeping of already-dead units).

// scopesCheck is the W7-H2 failed-scope reaper as a Check; it owns
// the 30m sweep stamp (ex-Hygiene.lastScopeScan).
type scopesCheck struct {
	d        *deps
	lastScan time.Time
}

// Name returns the check label / WD_SIG key.
func (c *scopesCheck) Name() string { return checkSysScopes }

// Run executes one systemd-scopes round.
func (c *scopesCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.d.cycles.WithLabelValues(checkSysScopes, "gated").Inc()
		return
	}
	if c.d.cfg.Systemd == nil {
		c.d.cycles.WithLabelValues(checkSysScopes, "gated").Inc()
		return
	}
	if c.d.cfg.Seams.nowFn().Sub(c.lastScan) < systemdScopeScanInterval {
		c.d.cycles.WithLabelValues(checkSysScopes, "ok").Inc()
		return
	}
	out, err := c.d.cfg.Systemd.Exec(ctx, "systemctl", "list-units",
		"--type=scope", "--state=failed", "--no-legend", "--plain",
		"cri-containerd-*.scope")
	if err != nil {
		// A transient systemctl/D-Bus failure is inconclusive — the
		// scan must NOT stamp (a stamped failure defers the retry a
		// full interval) and zero evidence was gathered.
		c.d.state.AppendLog(fmt.Sprintf(
			"suspect: systemd-scopes list-units failed: %v (%s) — scan skipped",
			err, strings.TrimSpace(out)))
		c.d.cycles.WithLabelValues(checkSysScopes, "abort").Inc()
		return
	}
	c.lastScan = c.d.cfg.Seams.nowFn()
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) > 0 &&
			strings.HasSuffix(f[0], ".scope") {
			n++
		}
	}
	if n == 0 {
		c.d.cycles.WithLabelValues(checkSysScopes, "ok").Inc()
		return
	}
	// NPD contract line (reset-failed evidence in the watchdog log).
	c.d.state.AppendLog(fmt.Sprintf("ACTION: systemd-scopes reset-failed count=%d", n))
	if rout, rerr := c.d.cfg.Systemd.Exec(ctx,
		"systemctl", "reset-failed", "cri-containerd-*.scope"); rerr != nil {
		c.d.state.AppendLog(fmt.Sprintf(
			"suspect: systemd-scopes reset-failed failed: %v (%s)",
			rerr, strings.TrimSpace(rout)))
	} else {
		c.d.actions.WithLabelValues(checkSysScopes, "reset_failed").Inc()
	}
	c.d.cycles.WithLabelValues(checkSysScopes, "ok").Inc()
}

// checkSystemdScopes forwards to the migrated Check — tests
// written before the interface still call the old method shape.
func (h *Hygiene) checkSystemdScopes(ctx context.Context, workerActive bool) {
	h.scopes.Run(ctx, &cycleEnv{workerActive: workerActive})
}

// --- Check: cilium-envoy xDS NACK + node-local-dns LRP (W7-H3) ---
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
