// cilium_common.go — containerd task helpers shared by the cilium
// check family: cilium-agent/cilium-envoy task discovery off the
// ctr task roots (config.json container-name annotation) and the
// SIGKILL helpers behind "kubelet restarts it" remediation.
package workerhygiene

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// ciliumNamedTasks finds containerd tasks of one cilium container
// (cilium-agent / cilium-envoy) by container-name annotation — the
// Go port of `ctr containers ls 'labels."io.kubernetes.container.name"=="<name>"'`.
// reachable=false means the task root itself is unreadable (ctr
// unreachable parity: inconclusive, keep counters/latches).
func (h *Hygiene) ciliumNamedTasks(name string) (tasks []ctrTask, reachable bool) {
	if _, err := os.ReadDir(h.cfg.CtrTaskRoot); err != nil {
		h.state.AppendLog(fmt.Sprintf(
			"suspect: ctr task root %s unreadable: %v — cilium checks inconclusive",
			h.cfg.CtrTaskRoot, err))
		return nil, false
	}
	for _, root := range []string{h.cfg.CtrTaskRoot, h.cfg.SandboxCtlRoot} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			d := filepath.Join(root, e.Name())
			cfgData, err := os.ReadFile(filepath.Join(d, "config.json"))
			if err != nil {
				continue
			}
			nm := containerNameRe.FindSubmatch(cfgData)
			if nm == nil || string(nm[1]) != name {
				continue
			}
			t := ctrTask{}
			if pidData, err := os.ReadFile(filepath.Join(d, "init.pid")); err == nil {
				if pid, err := strconv.Atoi(strings.TrimSpace(string(pidData))); err == nil {
					t.pid = pid
					t.live = h.pidLive(pid)
				}
			}
			tasks = append(tasks, t)
		}
	}
	return tasks, true
}

// ciliumAgentTasks is the cilium-agent specialization kept for the
// 32/35 call sites.
func (h *Hygiene) ciliumAgentTasks() (tasks []ctrTask, reachable bool) {
	return h.ciliumNamedTasks("cilium-agent")
}

// killNamedTasks SIGKILLs every live init pid of the named
// container — `ctr tasks kill -s SIGKILL` parity. true = at least
// one task killed (a dead task can't be signalled; kubelet retries
// on its own).
func (h *Hygiene) killNamedTasks(tasks []ctrTask, name string) bool {
	killed := false
	for _, t := range tasks {
		if t.live && t.pid > 0 {
			if err := h.cfg.Seams.killFn(t.pid, syscall.SIGKILL); err != nil {
				h.state.AppendLog(fmt.Sprintf(
					"suspect: kill %s pid=%d failed: %v", name, t.pid, err))
			} else {
				killed = true
			}
		}
	}
	return killed
}

// killCiliumAgent SIGKILLs the cilium-agent tasks and flags the
// kill so the B1 check restarts cilium-envoy the same cycle.
func (h *Hygiene) killCiliumAgent(tasks []ctrTask) bool {
	if h.killNamedTasks(tasks, "cilium-agent") {
		h.ciliumAgentKilled = true
		return true
	}
	return false
}
