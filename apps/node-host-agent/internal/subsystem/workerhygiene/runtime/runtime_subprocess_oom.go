// runtime_subprocess_oom.go — the container-subproc-oom guard
// (wdeps.CheckSubprocOOM, subproc-oom). The kernel's memcg OOM killer
// picks the LARGEST RSS task in the cgroup — not necessarily the
// container's PID 1. When a subprocess (a worker thread, a forked
// helper) eats the kill while PID 1 survives, kubelet sees the
// container as Running forever: no restart, no backoff, a
// "living dead" container that lost part of its process tree. The
// check watches memory.events:oom_kill per container scope under
// kubepods.slice: when oom_kill advances but the SAME init pid is
// still there after a 60s confirm window, the kill hit a
// subprocess → ContainerSubprocessOOMKilled Warning event on the
// Pod + the node_agent_container_subprocess_oom_total counter.
package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// subprocOOMConfirm is the living-dead confirm window — a
// legitimate PID-1 kill takes the container down inside seconds;
// an init pid still alive 60s after oom_kill advanced proves the
// victim was a subprocess.
const subprocOOMConfirm = 60 * time.Second

// oomScope is the per-container-cgroup observation state: the last
// oom_kill count read, the init pid seen when it last advanced and
// when, plus the oom_kill generation already reported (one event
// per kill burst, not per cycle).
type oomScope struct {
	oomKill   int64
	pid1      int
	pendingAt time.Time // zero = no pending living-dead verdict
	reported  int64     // oom_kill value the event already covers
}

// SubprocOOMCheck is the subproc-oom living-dead OOM detector as a
// Check. scopes is its delta ledger — per scope-dir last state;
// vanished cgroups are pruned each cycle.
type SubprocOOMCheck struct {
	d      *wdeps.Deps
	scopes map[string]*oomScope
}

// Name returns the check label / WD_SIG key.
func (c *SubprocOOMCheck) Name() string { return wdeps.CheckSubprocOOM }

// containerScopeDirs lists the cri-containerd-*.scope dirs under a
// pod slice — one per container (the pod-sandbox scope is named
// the same way; its pid1 is pause, which the same logic covers).
func containerScopeDirs(podDir string) []string {
	m, err := filepath.Glob(filepath.Join(podDir, "cri-containerd-*.scope"))
	if err != nil {
		return nil
	}
	return m
}

// cgroupInitPID returns the first pid in cgroup.procs — the
// container's PID 1 (kernel lists the oldest task first for
// populated cgroups; any member works as the liveness token since
// a real PID-1 kill empties the file within the confirm window —
// but PID 1 specifically is the verdict the event describes).
func cgroupInitPID(scopeDir string) (int, bool) {
	data, err := os.ReadFile(filepath.Join(scopeDir, "cgroup.procs"))
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if pid, err := strconv.Atoi(line); err == nil {
			return pid, true
		}
	}
	return 0, false
}

// oomMemStatMiB reads memory.stat of the container cgroup at OOM
// confirmation time and formats the subproc-oom-breakdown tmpfs breakdown
// "anon=XMiB shmem=YMiB file=ZMiB" (bytes / 1024 / 1024, rounded
// to nearest). A big `shmem` is the tmpfs/emptyDir{medium:Memory}
// fingerprint — the page cache `file` is reclaimable, anon+shmem
// is what the kill actually had to shoot. "" on any read/parse
// failure — the event keeps working without the breakdown.
func oomMemStatMiB(scopeDir string) string {
	data, err := os.ReadFile(filepath.Join(scopeDir, "memory.stat"))
	if err != nil {
		return ""
	}
	vals := map[string]uint64{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		if v, err := strconv.ParseUint(f[1], 10, 64); err == nil {
			vals[f[0]] = v
		}
	}
	if len(vals) == 0 {
		return ""
	}
	const miB = 1024 * 1024
	mib := func(key string) string {
		return strconv.FormatUint((vals[key]+miB/2)/miB, 10)
	}
	return fmt.Sprintf("anon=%sMiB shmem=%sMiB file=%sMiB",
		mib("anon"), mib("shmem"), mib("file"))
}

// Run executes one subproc-oom round.
func (c *SubprocOOMCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckSubprocOOM) {
		return
	}
	kubepods := filepath.Join(c.d.Cfg.Runtime.CgroupRoot, "kubepods.slice")
	if _, err := os.Stat(kubepods); err != nil {
		// cgroup v1 host or no kubepods — dormant (abort parity
		// with cgroup-pod-throttle).
		c.d.CycleResult(wdeps.CheckSubprocOOM, "abort")
		return
	}
	if c.scopes == nil {
		c.scopes = map[string]*oomScope{}
	}
	now := c.d.Cfg.Seams.Host.Clock.Now()
	podByUID := map[string]*corev1.Pod{}
	for i := range e.Pods {
		podByUID[string(e.Pods[i].UID)] = &e.Pods[i]
	}
	seen := map[string]bool{}
	for _, podDir := range podSliceDirs(kubepods) {
		uid := podUIDFromSlice(podDir)
		for _, scope := range containerScopeDirs(podDir) {
			seen[scope] = true
			kill, ok := cgroupEventsValue(
				filepath.Join(scope, "memory.events"), "oom_kill")
			if !ok {
				continue
			}
			pid1, pidOK := cgroupInitPID(scope)
			st := c.scopes[scope]
			if st == nil {
				st = &oomScope{oomKill: kill, pid1: pid1}
				c.scopes[scope] = st
				continue // first sighting — no delta to judge
			}
			switch {
			case kill > st.oomKill:
				st.oomKill = kill
				if pid1 != st.pid1 {
					// The init pid already changed (or the
					// cgroup went empty — !pidOK reads pid1=0)
					// — the container restarted; the kill was
					// legitimate, not a living-dead. Clear
					// any pending verdict instead of arming a
					// confirm window against the NEW init pid
					// (it would false-positive 60s later).
					st.pid1 = pid1
					st.pendingAt = time.Time{}
					continue
				}
				// Same init pid survived the kill — arm the
				// confirm window once. Repeated kills must
				// not push pendingAt forward forever and
				// postpone the verdict past ConfirmWindow.
				if st.pendingAt.IsZero() {
					st.pendingAt = now
				}
			case st.pendingAt.IsZero():
				// No pending verdict; keep pid1 current for the
				// NEXT delta's restart-vs-survived compare.
				st.pid1 = pid1
			}
			// Confirm: kill observed >=60s ago, init pid alive and
			// UNCHANGED → the victim was a subprocess.
			if !st.pendingAt.IsZero() && pidOK && pid1 == st.pid1 &&
				now.Sub(st.pendingAt) >= subprocOOMConfirm &&
				kill > st.reported {
				st.reported = kill
				st.pendingAt = time.Time{}
				c.report(ctx, uid, podByUID[uid], scope, kill, pid1,
					oomMemStatMiB(scope))
			} else if pidOK && pid1 != st.pid1 {
				// init pid changed while pending — the container
				// DID restart; the kill was legitimate.
				st.pendingAt = time.Time{}
				st.pid1 = pid1
			}
		}
	}
	for dir := range c.scopes {
		if !seen[dir] {
			delete(c.scopes, dir)
		}
	}
	c.d.CycleResult(wdeps.CheckSubprocOOM, "ok")
}

// report emits the ContainerSubprocessOOMKilled Warning event on
// the owning Pod and bumps the counter — events.v1 shape like the
// SystemOOMVictim emitter. memStat carries the subproc-oom-breakdown memory.stat
// breakdown ("anon=XMiB shmem=YMiB file=ZMiB"), appended to both
// the event note and the log lines when non-empty.
func (c *SubprocOOMCheck) report(ctx context.Context, uid string,
	pod *corev1.Pod, scope string, kill int64, pid1 int, memStat string) {
	c.d.ContainerSubprocessOOM++
	base := filepath.Base(scope)
	if memStat != "" {
		memStat = " mem_stat=" + memStat
	}
	if pod == nil || c.d.Cfg.Client == nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: container-subproc-oom scope=%s pod uid=%s oom_kill=%d pid1=%d%s — pod unresolvable, event skipped",
			base, uid, kill, pid1, memStat))
		return
	}
	now := c.d.Cfg.Seams.Host.Clock.Now()
	if err := c.d.EmitCheckEvent(ctx, wdeps.CheckEvent{
		Name:      fmt.Sprintf("%s.%x", pod.Name, now.UnixNano()),
		Namespace: pod.Namespace,
		Reason:    "ContainerSubprocessOOMKilled",
		Note: fmt.Sprintf(
			"container %s hit memcg oom_kill (total %d) but PID 1 (%d) survived %s — subprocess kill, container left running (living dead)%s",
			base, kill, pid1, subprocOOMConfirm, memStat),
		When: now,
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Pod",
			Namespace:  pod.Namespace,
			Name:       pod.Name,
			UID:        pod.UID,
		},
		Owner: pod.Namespace + "/" + pod.Name,
	}); err != nil {
		return
	}
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: ContainerSubprocessOOMKilled — pod %s/%s scope=%s oom_kill=%d pid1=%d%s unchanged after %s",
		pod.Namespace, pod.Name, base, kill, pid1, memStat, subprocOOMConfirm))
	c.d.Actions.WithLabelValues(wdeps.CheckSubprocOOM, "event").Inc()
}
