package workerhygiene

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func (h *Hygiene) checkPodTeardown(ctx context.Context, pods []corev1.Pod,
	apiOK bool, tasksOnce func() (map[string][]ctrTask, bool), workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkTeardown, "gated").Inc()
		return
	}
	if !apiOK {
		// Inconclusive — shell "exit 0" semantics: abort silently,
		// keep counters and latches (no state_exit flap on API blip).
		h.cycles.WithLabelValues(checkTeardown, "abort").Inc()
		return
	}
	// The task map is only worth building once a Terminating pod
	// exists — with none, the whole loop below is a no-op.
	var tasks map[string][]ctrTask
	now := h.cfg.nowFn()
	wedged := 0
	ndel := 0
	for i := range pods {
		p := &pods[i]
		if p.DeletionTimestamp == nil {
			continue
		}
		if tasks == nil {
			var complete bool
			tasks, complete = tasksOnce()
			if !complete {
				// A task root was unreadable — "zero live tasks"
				// is unverifiable, so a force-delete could reap a
				// pod whose tasks the map never saw. Inconclusive
				// cycle: keep counters/latch, act on nothing
				// (checkCtrTasks unreadable-root parity).
				h.state.AppendLog(
					"suspect: pod-teardown aborted — ctr task map incomplete, force-deletes unverifiable")
				h.cycles.WithLabelValues(checkTeardown, "abort").Inc()
				return
			}
		}
		uid := string(p.UID)
		age := now.Sub(p.DeletionTimestamp.Time)
		// Wedge evidence is measured on pod level: Terminating long
		// past StuckWedgeAge AND containerd still holds a task dir
		// (live or not) — sig7/force-delete had their chance; only a
		// reboot clears a shim/kernel-level wedge.
		if age >= h.cfg.StuckWedgeAge && len(tasks[uid]) >= 1 {
			wedged++
		}
		if age < h.cfg.StuckDeleteAge {
			continue
		}
		// Rule C: external resources or kubelet mirrors → never
		// force-delete (finalizer = another controller owns cleanup;
		// PVC = dual-mount risk; mirror = pointless).
		if len(p.Finalizers) > 0 || podHasPVC(p) || isMirrorPod(p) {
			continue
		}
		if countLive(tasks[uid]) > 0 {
			continue // a live task exists — kubelet may still be tearing down
		}
		if ndel >= h.cfg.MaxForceDelete {
			continue // per-cycle cap bounds the blast radius
		}
		if err := h.forceDeletePod(ctx, p); err != nil {
			h.state.AppendLog(fmt.Sprintf("suspect: force-delete %s/%s failed: %v",
				p.Namespace, p.Name, err))
			continue
		}
		ndel++
		h.actions.WithLabelValues(checkTeardown, "force_delete").Inc()
	}

	switch {
	case wedged >= 1:
		h.wedgeFails++
		if h.wedgeFails >= h.cfg.ConsecNeeded {
			if h.state.Exists("node-overloaded") {
				// Suppression parity: a wedge under overload is a
				// symptom — rebooting would dump 100% of its load
				// onto the remaining nodes (amplifier). Log-only,
				// once per suppression episode.
				if !h.state.Exists("pod-teardown-wedged") {
					h.state.AppendLog(fmt.Sprintf(
						"pod-teardown-wedged suppressed-overloaded stuck=%d", wedged))
				}
			} else {
				h.state.Enter("pod-teardown-wedged", fmt.Sprintf("stuck=%d", wedged))
			}
		} else {
			h.state.AppendLog(fmt.Sprintf("suspect: pod-teardown-wedged stuck=%d (check %d/%d)",
				wedged, h.wedgeFails, h.cfg.ConsecNeeded))
		}
	default:
		h.wedgeFails = 0
		h.state.Exit("pod-teardown-wedged", nil)
	}
	h.cycles.WithLabelValues(checkTeardown, "ok").Inc()
}

// --- Check 2: konnectivity IP drift (30-konnectivity.sh) ---

// k0sWorkerNodeIP reads --node-ip=<ip> out of the k0sworker unit —
// the node's InternalIP konnectivity-agent should have baked in.
func (h *Hygiene) k0sWorkerNodeIP() string {
	data, err := os.ReadFile(h.cfg.K0sWorkerUnitFile)
	if err != nil {
		return ""
	}
	if m := nodeIPRe.FindSubmatch(data); m != nil {
		return string(m[1])
	}
	return ""
}

// isProxyAgent matches `pgrep -f 'proxy-agent --'` on the joined
// cmdline (the bare "/proxy-agent" prefix covers argv[0]-only forms).
func isProxyAgent(argv []string) bool {
	// Shell parity: `pgrep -f 'proxy-agent --'` — the trailing
	// space/dash keeps /proxy-agent-foo lookalikes out.
	joined := strings.Join(argv, " ")
	return strings.HasPrefix(joined, "/proxy-agent ") ||
		strings.Contains(joined, "proxy-agent --")
}

// proxyAgentHost returns the host identifier baked into the agent:
// NODE_IP from environ (downward status.hostIP, set at pod create),
// falling back to --agent-identifiers=host=<ip> on the cmdline.
func (h *Hygiene) proxyAgentHost(pid int, argv []string) string {
	if v := h.procEnvValue(pid, "NODE_IP"); v != "" {
		return v
	}
	if m := agentHostRe.FindStringSubmatch(strings.Join(argv, " ")); m != nil {
		return m[1]
	}
	return ""
}

// deleteKonnectivityPod deletes this node's konnectivity-agent pod in
// kube-system (grace 0) — the Go equivalent of SIGKILL on its pause
// task: the DaemonSet recreates the pod with freshly baked env.
// Anchored name match + namespace pin (see konnPodRe comment).
func (h *Hygiene) deleteKonnectivityPod(ctx context.Context, pods []corev1.Pod) bool {
	for i := range pods {
		p := &pods[i]
		if p.Namespace != "kube-system" || !konnPodRe.MatchString(p.Name) ||
			p.DeletionTimestamp != nil {
			continue
		}
		if err := h.cfg.Client.CoreV1().Pods(p.Namespace).Delete(ctx, p.Name,
			metav1.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)}); err != nil {
			h.state.AppendLog(fmt.Sprintf(
				"suspect: konnectivity pod delete %s/%s failed: %v",
				p.Namespace, p.Name, err))
			continue // a stale entry must not block the next candidate
		}
		return true
	}
	return false
}

func (h *Hygiene) checkKonnectivity(ctx context.Context, pods []corev1.Pod,
	pidsOnce func() []int, workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkKonn, "gated").Inc()
		return
	}
	nodeIP := h.k0sWorkerNodeIP()
	// Healthy = ANY proxy-agent process baked with the current node
	// IP. Scan ALL processes, never take the first match: an orphaned
	// agent (task dir gone, process alive under a dead shim) keeps its
	// old NODE_IP and usually has the lower pid — first-match would
	// read the orphan's environ and report "stale" forever
	// (incident 2026-09-19..23: 163 pause kills). Only when NO
	// process matches do we suspect.
	healthy := false
	agentHost := ""
	stalePID := 0
	for _, pid := range pidsOnce() {
		argv := h.procCmdline(pid)
		if !isProxyAgent(argv) {
			continue
		}
		phost := h.proxyAgentHost(pid, argv)
		if nodeIP != "" && phost == nodeIP {
			healthy = true
			break
		}
		if phost != "" && agentHost == "" {
			agentHost = phost
			stalePID = pid
		}
	}

	if healthy || nodeIP == "" || agentHost == "" {
		// Healthy or inconclusive (no node-ip parsed / no proxy-agent
		// found — e.g. konnectivity not deployed): reset, drop latch.
		h.konnFails = 0
		h.state.Exit("konnectivity-ip-mismatch", nil)
		h.cycles.WithLabelValues(checkKonn, "ok").Inc()
		return
	}

	h.konnFails++
	h.state.Enter("konnectivity-ip-mismatch",
		fmt.Sprintf("host=%s node-ip=%s", agentHost, nodeIP))
	if h.konnFails >= h.cfg.ConsecNeeded &&
		h.state.RateTrySpend("last-konn-restart", h.cfg.MinRestartInterval) {
		// Budget spent atomically BEFORE acting — a failed action
		// still consumed it (conservative, rate_spend parity).
		h.konnFails = 0
		// NPD contract: "recreating konnectivity-agent ..." fires the
		// KonnectivityStaleId filelog pattern.
		h.state.AppendLog(fmt.Sprintf(
			"KONNECTIVITY-IP-RESTART: recreating konnectivity-agent sandbox - stale identifier host=%s != node-ip=%s",
			agentHost, nodeIP))
		if h.deleteKonnectivityPod(ctx, pods) {
			h.actions.WithLabelValues(checkKonn, "pod_delete").Inc()
		} else if stalePID > 0 {
			// No API pod found (list failed or pod renamed) — kill
			// the stale proxy-agent directly. Least-bad: a container
			// restart alone can't fix env baked at pod create, but
			// it still clears a hung agent while humans look.
			if err := h.cfg.killFn(stalePID, syscall.SIGKILL); err != nil {
				h.state.AppendLog(fmt.Sprintf(
					"suspect: kill stale proxy-agent pid=%d failed: %v", stalePID, err))
			} else {
				h.state.AppendLog(fmt.Sprintf(
					"ACTION: killed stale proxy-agent pid=%d — no API pod found",
					stalePID))
			}
			h.actions.WithLabelValues(checkKonn, "sigkill").Inc()
		}
	} else {
		// NPD contract: "konnectivity stale identifier ..." fires the
		// same KonnectivityStaleId pattern while accumulating.
		h.state.AppendLog(fmt.Sprintf(
			"suspect: konnectivity stale identifier host=%s != node-ip=%s (check %d/%d)",
			agentHost, nodeIP, h.konnFails, h.cfg.ConsecNeeded))
	}
	h.cycles.WithLabelValues(checkKonn, "ok").Inc()
}

// --- Check 3: DNS resolv.conf drift (33-dns-resolv-drift.sh) ---

// nameserverSet returns the sorted-unique nameserver IPs of a
// resolv.conf file. ok=false when the file contains
// "svc.cluster.local" — a ClusterFirst resolv.conf is NOT a host
// snapshot and must be skipped (killing those pauses killed innocent
// job pods — incident 2026-09-26).
func nameserverSet(path string) (ns []string, clusterLocal bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	if strings.Contains(string(data), "svc.cluster.local") {
		return nil, true
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" && !seen[f[1]] {
			seen[f[1]] = true
			ns = append(ns, f[1])
		}
	}
	sort.Strings(ns)
	return ns, false
}

func equalNS(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// dnsStale is one drifted DNS pod: the pause pid to SIGKILL and the
// pod name for logging.
type dnsStale struct {
	pod string
	pid int
}

// pausePIDOf finds the live pause (sandbox infra) task pid for a pod
// UID — container name "pause" (CRI) or "POD" (containerd internal
// name) in the task config.json annotations.
func pausePIDOf(tasks []ctrTask) int {
	for _, t := range tasks {
		if t.live && (t.name == "pause" || t.name == "POD") {
			return t.pid
		}
	}
	return 0
}

func (h *Hygiene) checkDNSResolvDrift(pods []corev1.Pod, apiOK bool,
	tasksOnce func() (map[string][]ctrTask, bool), workerActive bool) {
	if !workerActive {
		h.cycles.WithLabelValues(checkDNS, "gated").Inc()
		return
	}
	if !apiOK {
		// Same inconclusive rule as teardown: a failed LIST keeps
		// counters and the latch (no flap on API blip).
		h.cycles.WithLabelValues(checkDNS, "abort").Inc()
		return
	}
	hostNS, _ := nameserverSet(h.cfg.HostResolvConf)

	var stale []dnsStale
	if len(hostNS) > 0 { // empty host set → nothing to compare (shell parity)
		// Task map is built only when a Running dns-pod actually
		// needs its pause pid looked up.
		var tasks map[string][]ctrTask
		for i := range pods {
			p := &pods[i]
			// Namespace pin like deleteKonnectivityPod: the name
			// regex alone would match a user pod named coredns-*/
			// node-local-dns-* in ANY namespace — the pause SIGKILL
			// is only for the kube-system DaemonSets.
			if p.Status.Phase != corev1.PodRunning ||
				p.Namespace != "kube-system" ||
				!dnsPodRe.MatchString(p.Name) {
				continue
			}
			if tasks == nil {
				tasks, _ = tasksOnce()
				// An incomplete map is fail-closed here already:
				// an unseen pause pid reads as pid==0 → the pod
				// is skipped, never killed.
			}
			pid := pausePIDOf(tasks[string(p.UID)])
			if pid == 0 {
				continue // no live pause task — can't see the pod's resolv.conf
			}
			// Read the POD's resolv.conf through the pause mount ns —
			// ProcRoot/<pid>/root is the task's filesystem view.
			podNS, clusterLocal := nameserverSet(
				h.procFile(pid, "root/etc/resolv.conf"))
			if clusterLocal || len(podNS) == 0 {
				continue
			}
			if !equalNS(podNS, hostNS) {
				stale = append(stale, dnsStale{pod: p.Name, pid: pid})
			}
		}
	}

	if len(stale) == 0 {
		h.dnsFails = 0
		h.state.Exit("dns-resolv-stale", nil)
		h.cycles.WithLabelValues(checkDNS, "ok").Inc()
		return
	}

	specs := make([]string, 0, len(stale))
	for _, s := range stale {
		specs = append(specs, fmt.Sprintf("%s:pid=%d", s.pod, s.pid))
	}
	staleStr := strings.Join(specs, " ")
	// Latch first — the state file is what NPD's permanent
	// DnsResolvStale condition checks; the counter gates the action.
	h.state.Enter("dns-resolv-stale", staleStr)
	h.dnsFails++
	switch {
	case h.dnsFails >= h.cfg.ConsecNeeded &&
		h.state.RateTrySpend("last-dnsresolv-restart", h.cfg.MinRestartInterval):
		// budget already spent atomically — spend BEFORE action (lib.sh)
		for _, s := range stale {
			// SIGKILL on the PAUSE pid — NOT the app container
			// (restarting the app keeps the old sandbox +
			// resolv.conf; the pod object itself is fine).
			h.state.AppendLog(fmt.Sprintf(
				"DNS-RESOLV-RESTART: killing pause %d (%s) - dns-resolv-stale, resolv.conf pod stale vs host",
				s.pid, s.pod))
			if err := h.cfg.killFn(s.pid, syscall.SIGKILL); err != nil {
				h.state.AppendLog(fmt.Sprintf(
					"suspect: kill pause %d (%s) failed: %v", s.pid, s.pod, err))
			}
			h.actions.WithLabelValues(checkDNS, "pause_kill").Inc()
		}
		h.dnsFails = 0
	default:
		h.state.AppendLog(fmt.Sprintf("suspect: dns-resolv-stale %s (check %d/%d)",
			staleStr, h.dnsFails, h.cfg.ConsecNeeded))
	}
	h.cycles.WithLabelValues(checkDNS, "ok").Inc()
}

// --- shared helpers for the ported kubelet/cilium/ctr checks ---
