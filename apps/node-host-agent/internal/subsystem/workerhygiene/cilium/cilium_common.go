// cilium_common.go — containerd task helpers shared by the cilium
// check family: cilium-agent/cilium-envoy task discovery off the
// ctr task roots (config.json container-name annotation) and the
// SIGKILL helpers behind "kubelet restarts it" remediation.
package cilium

import (
	"fmt"
	"syscall"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	// The DaemonSet mounts host /run at /host/run — /host/var/run is
	// never mounted (host /var/run is a symlink to /run on modern
	// distros but the pod bind-mount does not follow it).
	ciliumProbeTime = 5 * time.Second // task spec: 3x timeout 5s
)

// taskSnapshot returns the cycle's shared containerd task map —
// e.TasksOnce when the orchestrator wired it (built at most once
// per workerhygiene cycle, shared with the teardown/dns checks),
// or a direct BuildTaskMap for bare CycleEnvs (unit tests calling
// Run without a full Cycle). Either way the task roots' config.json
// + init.pid sweep happens once — the old per-check rescan cost
// every one of the ~5 cilium checks a full directory walk.
func taskSnapshot(d *wdeps.Deps, e *wdeps.CycleEnv) (map[string][]wdeps.CtrTask, bool) {
	if e != nil && e.TasksOnce != nil {
		return e.TasksOnce()
	}
	return d.BuildTaskMap()
}

// ciliumNamedTasks finds containerd tasks of one cilium container
// (cilium-agent / cilium-envoy) by container-name annotation — the
// Go port of `ctr containers ls 'labels."io.kubernetes.container.name"=="<name>"'`,
// filtered out of the shared task snapshot. reachable=false means a
// task root could not be listed (the map's `complete` flag — ctr
// unreachable parity: inconclusive, keep counters/latches). Note the
// map only carries tasks WITH a pod-uid annotation — real CRI
// containers always have one; it also fails closed on a sandbox-root
// read error where the old scan silently skipped it.
func ciliumNamedTasks(d *wdeps.Deps, e *wdeps.CycleEnv, name string) (tasks []wdeps.CtrTask, reachable bool) {
	m, complete := taskSnapshot(d, e)
	if !complete {
		d.State.AppendLog(fmt.Sprintf(
			"suspect: ctr task root %s unreadable — cilium checks inconclusive",
			d.Cfg.CtrTaskRoot))
		return nil, false
	}
	for _, list := range m {
		for _, t := range list {
			if t.Name == name {
				tasks = append(tasks, t)
			}
		}
	}
	return tasks, true
}

// ciliumAgentTasks is the cilium-agent specialization kept for the
// 32/35 call sites.
func ciliumAgentTasks(d *wdeps.Deps, e *wdeps.CycleEnv) (tasks []wdeps.CtrTask, reachable bool) {
	return ciliumNamedTasks(d, e, "cilium-agent")
}

// killNamedTasks SIGKILLs every live init pid of the named
// container — `ctr tasks kill -s SIGKILL` parity. true = at least
// one task killed (a dead task can't be signalled; kubelet retries
// on its own).
func killNamedTasks(d *wdeps.Deps, tasks []wdeps.CtrTask, name string) bool {
	killed := false
	for _, t := range tasks {
		if t.Live && t.PID > 0 {
			if err := d.Cfg.Seams.Host.KillFn(t.PID, syscall.SIGKILL); err != nil {
				d.State.AppendLog(fmt.Sprintf(
					"suspect: kill %s pid=%d failed: %v", name, t.PID, err))
			} else {
				killed = true
			}
		}
	}
	return killed
}

// killCiliumAgent SIGKILLs the cilium-agent tasks and flags the
// kill so the B1 check restarts cilium-envoy the same cycle.
func killCiliumAgent(d *wdeps.Deps, tasks []wdeps.CtrTask) bool {
	if killNamedTasks(d, tasks, "cilium-agent") {
		d.CiliumAgentKilled = true
		return true
	}
	return false
}

// restartEnvoyAfterAgentKill covers the envoy side of an agent
// restart when the killing check runs AFTER CiliumEnvoyCheck in the
// dispatch order (cilium-wg, cilium-lrp): the shared
// CiliumAgentKilled flag is consumed only by the envoy check, which
// already ran this cycle — without this the envoy keeps a stale xDS
// socket across the agent restart until its own probe fails. The
// dedicated last-cilium-envoy-restart budget bounds it identically
// to CiliumEnvoyCheck.killCiliumEnvoy.
func restartEnvoyAfterAgentKill(d *wdeps.Deps, e *wdeps.CycleEnv, check, why string) {
	tasks, reachable := ciliumNamedTasks(d, e, "cilium-envoy")
	if !reachable || len(tasks) == 0 {
		return // no L7 proxy deployed — nothing to bounce
	}
	if !d.State.RateTrySpend("last-cilium-envoy-restart", d.Cfg.MinRestartInterval) {
		d.State.AppendLog(fmt.Sprintf(
			"suspect: cilium-envoy kill skipped (%s) — restart cooldown (<30m)", why))
		return
	}
	if killNamedTasks(d, tasks, "cilium-envoy") {
		d.State.AppendLog(fmt.Sprintf(
			"ACTION: killed cilium-envoy container - %s (kubelet will restart -> xDS resync)", why))
		d.Actions.WithLabelValues(check, "sigkill").Inc()
	}
}
