// guards_pipe_write.go — the pipe-write-freeze check (roadmap A1,
// Datadog/Chronosphere/Uber stdout pipe class): containerd shims a
// container's stdout/stderr through a 64KB kernel pipe. When the
// shim or a log consumer stalls (log rotation under I/O pressure),
// the pipe fills and the app's synchronous write(1, ...) blocks in
// the kernel FOREVER — and because the kernel answers the
// tcpSocket readiness probe (RabbitMQ :5672 class) at the TCP
// layer, the pod stays "Running, probes green" while its process
// is fully frozen: the Ghost Pod.
//
// DstateCheck (guards_dstate_storm.go) cannot see this: a full
// pipe puts the writer in TASK_INTERRUPTIBLE (state "S"), not
// "D". This check scans the pod-cgroup processes for state "S"
// with wchan == "pipe_write" and requires the roadmap's persist
// window — stuck for pipeWriteMinCycles consecutive cycles —
// before a process counts, so one blocked log line never pages.
//
// Remediation note: the RabbitMQ tcpSocket probe swap lives in the
// fluxcd repo; here the detection surface is the suspect line +
// ContainerPipeWriteBlocked Warning Event on the owning Pod (the
// throttle/oom emitters' convention — the stall is invisible in
// pod status, so the event is the operator-facing surface) plus
// the node_agent_container_pipe_blocked textfile gauge.
package guards

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// pipeWriteMinCycles is the persist window (roadmap: "≥ 2 chu
// kỳ"): a process must sit in state-S pipe_write on two
// consecutive cycles before it counts as frozen. A one-cycle hit
// is a momentary full pipe; a real deadlock never drains because
// the consumer is wedged, so consecutive hits only accumulate.
const pipeWriteMinCycles = 2

// pipeWriteKey is one streak slot — pid alone lies after PID reuse,
// so the /proc/<pid>/stat starttime generation tag (ZombieParent
// parity) and the owning pod's UID join the key: a recycled pid
// restarts at streak 0 and never inherits a dead process's window.
type pipeWriteKey struct {
	uid   string
	pid   int
	start string
}

// PipeWriteCheck is the pipe-write-freeze stdout pipe deadlock
// detector as a Check. It owns the per-process streak ledger and
// the per-pod event dedup marker.
type PipeWriteCheck struct {
	d *wdeps.Deps
	// streak counts consecutive blocked cycles per process slot.
	streak map[pipeWriteKey]int
	// evented dedupes the Warning per pod UID — re-armed when the
	// pod clears the persist window (a later freeze emits a fresh
	// event; a pod recovered-and-refrozen must re-page).
	evented map[string]bool
}

// Name returns the check label / WD_SIG key.
func (c *PipeWriteCheck) Name() string { return wdeps.CheckPipeWrite }

// Run executes one pipe-write-freeze round.
func (c *PipeWriteCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckPipeWrite) {
		return
	}
	podByUID := e.PodByUID()
	blocked := map[pipeWriteKey]bool{}
	for _, pid := range e.PidsOnce() {
		uid := podUIDForPID(c.d, pid)
		if uid == "unknown" {
			continue // host process, shim, kubelet — outside pod cgroups
		}
		// TASK_INTERRUPTIBLE is the frozen writer's state — a
		// full pipe parks write(2) on an interruptible wait, so
		// state "D" (the DstateCheck signal) never appears.
		if _, state, ok := procStatCommState(e, c.d, pid); !ok || state != "S" {
			continue
		}
		if procWchan(c.d, pid) != "pipe_write" {
			continue
		}
		st, ok := statFor(e, c.d, pid)
		key := pipeWriteKey{uid: uid, pid: pid, start: procStartTime(st, ok)}
		blocked[key] = true
		c.streak[key]++
	}
	// Clear streaks for processes that left the pipe — a freed
	// writer must not carry a half-built window into its next
	// freeze, and the ledger must not pin exited pids forever.
	for key := range c.streak {
		if !blocked[key] {
			delete(c.streak, key)
		}
	}
	count := 0
	stuckPods := map[string]bool{}
	for key := range blocked {
		if c.streak[key] < pipeWriteMinCycles {
			continue
		}
		count++
		stuckPods[key.uid] = true
		if !c.evented[key.uid] && c.pipeBlockedEvent(ctx, key, podByUID[key.uid]) {
			c.evented[key.uid] = true
		}
	}
	// Re-arm the event markers of pods with nothing past the
	// persist window — the throttle check's conclusive-cycle rule:
	// a recovered pod must page again on its NEXT freeze.
	for uid := range c.evented {
		if !stuckPods[uid] {
			delete(c.evented, uid)
		}
	}
	c.d.PipeBlockedProcs = int64(count)
	c.d.CycleResult(wdeps.CheckPipeWrite, "ok")
}

// pipeBlockedEvent emits the suspect line + the
// ContainerPipeWriteBlocked Warning Event on the owning Pod.
// Returns true when the episode counts as handled — event created,
// pod unresolvable, or no events client (standalone/test posture,
// cgroup-pod-throttle parity). A create failure returns false so
// the dedup marker does not advance and the next cycle retries.
func (c *PipeWriteCheck) pipeBlockedEvent(ctx context.Context,
	key pipeWriteKey, pod *corev1.Pod) bool {
	c.d.State.AppendLog(fmt.Sprintf(
		"suspect: pipe-write-freeze pod uid=%s pid=%d stuck in state-S pipe_write %d cycles — stdout/stderr pipe freeze (containerd 64KB pipe deadlock)",
		key.uid, key.pid, c.streak[key]))
	if pod == nil || c.d.Cfg.Client == nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: pipe-write-freeze pod uid=%s — pod unresolvable, event skipped",
			key.uid))
		return true
	}
	if err := c.d.EmitPodEvent(ctx, pod, "", "ContainerPipeWriteBlocked",
		fmt.Sprintf(
			"container process pid=%d has been blocked in pipe_write (TASK_INTERRUPTIBLE) for %d consecutive cycles — the stdout/stderr 64KB pipe is full and write(1, ...) can never drain (shim/log consumer stalled, typically during log rotation). The pod answers tcpSocket probes at the kernel TCP layer while the app is frozen (Ghost Pod); inspect the shim/log tail, then restart the pod",
			key.pid, c.streak[key])); err != nil {
		return false
	}
	c.d.Actions.WithLabelValues(wdeps.CheckPipeWrite, "event").Inc()
	return true
}
