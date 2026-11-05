package workerhygiene

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// procStatStatePPID parses /proc/<pid>/stat for state + ppid — the
// fields right after the LAST ')' (comm can hold spaces/parens).
func (h *Hygiene) procStatStatePPID(pid int) (state string, ppid int, ok bool) {
	st, ok := h.proc.Stat(pid)
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
func (h *Hygiene) podUIDForPID(pid int) string {
	data, err := os.ReadFile(h.proc.File(pid, "cgroup"))
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
func (h *Hygiene) procStartTime(pid int) string {
	st, ok := h.proc.Stat(pid)
	// Fields after ')' start at field 3: Fields[0]=state,
	// Fields[1]=ppid, … Fields[19]=starttime (field 22).
	if !ok || len(st.Fields) <= 19 {
		return ""
	}
	return st.Fields[19]
}

func (h *Hygiene) checkZombieStorm(pidsOnce func() []int, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkZombieStorm, "gated").Inc()
		return
	}
	byPPID := map[int]int{}
	for _, pid := range pidsOnce() {
		state, ppid, ok := h.procStatStatePPID(pid)
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
			k = zombieParent{pid: ppid, start: h.procStartTime(ppid)}
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
	for parent := range h.zombieStreaks {
		if _, ok := byPPID[parent.pid]; !ok || keyOf(parent.pid) != parent {
			delete(h.zombieStreaks, parent) // parent gone or pid recycled — streak dead
		}
	}
	for ppid, n := range byPPID {
		key := keyOf(ppid)
		if n <= h.cfg.ZombieStormThreshold {
			delete(h.zombieStreaks, key)
			continue
		}
		h.zombieStreaks[key]++
		switch streak := h.zombieStreaks[key]; {
		case streak == h.cfg.ConsecNeeded:
			storm = true
			uid := h.podUIDForPID(ppid)
			// NPD contract: nodereporter maps this line to the
			// ZombieProcessStorm Event + problem_counter. Logged
			// on streak ENTRY only — repeating it every cycle while
			// the storm persists would spawn a fresh K8s Event per
			// interval (the !stateExists gating checkCiliumMTU
			// uses).
			h.state.AppendLog(fmt.Sprintf(
				"ACTION zombie-storm: pod_uid=%s zombies=%d ppid=%d", uid, n, ppid))
		case streak > h.cfg.ConsecNeeded:
			storm = true // latched storm continues — no repeated ACTION line
		default:
			h.state.AppendLog(fmt.Sprintf(
				"suspect: zombie-storm ppid=%d zombies=%d (check %d/%d)",
				ppid, n, streak, h.cfg.ConsecNeeded))
		}
	}
	if storm {
		h.state.Enter("zombie-storm", "")
	} else {
		h.state.Exit("zombie-storm", nil)
	}
	h.cycles.WithLabelValues(checkZombieStorm, "ok").Inc()
}

// procStatCommState parses /proc/<pid>/stat for comm + state — comm
// sits between the FIRST '(' and the LAST ')' (it can hold spaces
// and parens), state is the first field after that ')' (same trick
// as procStatStatePPID).
func (h *Hygiene) procStatCommState(pid int) (comm, state string, ok bool) {
	st, ok := h.proc.Stat(pid)
	if !ok || !st.HasComm {
		return "", "", false
	}
	return st.Comm, st.Fields[0], true
}

// procWchan returns the kernel function a task is sleeping inside —
// /proc/<pid>/wchan names it; "0" (running/not-sleeping) and
// unreadable files report "".
func (h *Hygiene) procWchan(pid int) string {
	data, err := os.ReadFile(h.proc.File(pid, "wchan"))
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

func (h *Hygiene) checkDStateTasks(pidsOnce func() []int, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkDState, "gated").Inc()
		return
	}
	total, runtime := 0, 0
	// A small comm=wchan sample for the ACTION line — the kernel
	// function holding the tasks is the triage hint (umount_tree /
	// wait_transaction_locked / blk_mq_get_tag).
	wchans := make([]string, 0, 4)
	for _, pid := range pidsOnce() {
		comm, state, ok := h.procStatCommState(pid)
		if !ok || state != "D" {
			continue
		}
		total++
		if dstateRuntimeComm(comm) {
			runtime++
		}
		if len(wchans) < 4 {
			if w := h.procWchan(pid); w != "" {
				wchans = append(wchans, comm+"="+w)
			}
		}
	}
	if total < h.cfg.DStateStormThreshold && runtime < dStateRuntimeMin {
		h.dstateFails = 0
		h.state.Exit("d-state-storm", nil)
		h.cycles.WithLabelValues(checkDState, "ok").Inc()
		return
	}
	h.dstateFails++
	if h.dstateFails < h.cfg.ConsecNeeded {
		h.state.AppendLog(fmt.Sprintf(
			"suspect: d-state-storm count=%d runtime=%d (check %d/%d)",
			total, runtime, h.dstateFails, h.cfg.ConsecNeeded))
		h.cycles.WithLabelValues(checkDState, "ok").Inc()
		return
	}
	if !h.state.Exists("d-state-storm") {
		// NPD contract: nodereporter maps this line to the
		// KernelHungTasks Event + problem_counter — logged once per
		// latch entry (the !stateExists gate, checkCiliumMTU parity).
		h.state.AppendLog(fmt.Sprintf(
			"ACTION d-state-storm: count=%d runtime=%d wchan=%s",
			total, runtime, strings.Join(wchans, ",")))
	}
	h.state.Enter("d-state-storm",
		fmt.Sprintf("count=%d runtime=%d", total, runtime))
	h.cycles.WithLabelValues(checkDState, "ok").Inc()
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

func (h *Hygiene) checkSystemdScopes(ctx context.Context, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkSysScopes, "gated").Inc()
		return
	}
	if h.cfg.Systemd == nil {
		h.cycles.WithLabelValues(checkSysScopes, "gated").Inc()
		return
	}
	if h.cfg.nowFn().Sub(h.lastScopeScan) < systemdScopeScanInterval {
		h.cycles.WithLabelValues(checkSysScopes, "ok").Inc()
		return
	}
	out, err := h.cfg.Systemd.Exec(ctx, "systemctl", "list-units",
		"--type=scope", "--state=failed", "--no-legend", "--plain",
		"cri-containerd-*.scope")
	if err != nil {
		// A transient systemctl/D-Bus failure is inconclusive — the
		// scan must NOT stamp (a stamped failure defers the retry a
		// full interval) and zero evidence was gathered.
		h.state.AppendLog(fmt.Sprintf(
			"suspect: systemd-scopes list-units failed: %v (%s) — scan skipped",
			err, strings.TrimSpace(out)))
		h.cycles.WithLabelValues(checkSysScopes, "abort").Inc()
		return
	}
	h.lastScopeScan = h.cfg.nowFn()
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) > 0 &&
			strings.HasSuffix(f[0], ".scope") {
			n++
		}
	}
	if n == 0 {
		h.cycles.WithLabelValues(checkSysScopes, "ok").Inc()
		return
	}
	// NPD contract line (reset-failed evidence in the watchdog log).
	h.state.AppendLog(fmt.Sprintf("ACTION: systemd-scopes reset-failed count=%d", n))
	if rout, rerr := h.cfg.Systemd.Exec(ctx,
		"systemctl", "reset-failed", "cri-containerd-*.scope"); rerr != nil {
		h.state.AppendLog(fmt.Sprintf(
			"suspect: systemd-scopes reset-failed failed: %v (%s)",
			rerr, strings.TrimSpace(rout)))
	} else {
		h.actions.WithLabelValues(checkSysScopes, "reset_failed").Inc()
	}
	h.cycles.WithLabelValues(checkSysScopes, "ok").Inc()
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
