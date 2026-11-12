package pods

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"syscall"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checkkit"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// Regexes — anchored where the shell learned to anchor (the konn pod
// name and the DNS pod names MUST be anchored: unanchored ~= filters
// previously matched konnectivity-agent-patcher-* and coredns-* job
// pods → wrong pause killed, incident 2026-09-26).
var (
	// --node-ip=<ip> inside the k0sworker unit's ExecStart.
	nodeIPRe = regexp.MustCompile(`--node-ip=([0-9.]+)`)
	// --agent-identifiers=host=<ip> inside proxy-agent cmdline —
	// fallback when environ is unreadable. NEVER grep bare 'host='
	// (matches --proxy-server-host first — the false positive that
	// caused the 163x pause-kill loop of 2026-09-19..23).
	agentHostRe = regexp.MustCompile(`--agent-identifiers=host=([0-9.]+)`)
	// DaemonSet pod names only (anchored — see comment block above).
	KonnPodRe = regexp.MustCompile(`^konnectivity-agent-[a-z0-9]+$`)
	dnsPodRe  = regexp.MustCompile(`^(node-local-dns-[a-z0-9]+|coredns-[a-z0-9]+-[a-z0-9]+)$`)
)

// PodTeardownCheck is the 36-pod-teardown check as a Check; it owns
// the wedged-pod streak (ex-Hygiene.wedgeFails).
type PodTeardownCheck struct {
	d     *wdeps.Deps
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *PodTeardownCheck) Name() string { return wdeps.CheckTeardown }

// Run executes one pod-teardown round.
func (c *PodTeardownCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckTeardown) {
		return
	}
	if !e.APIOK {
		// Inconclusive — shell "exit 0" semantics: abort silently,
		// keep counters and latches (no state_exit flap on API blip).
		c.d.CycleResult(wdeps.CheckTeardown, "abort")
		return
	}
	// The task map is only worth building once a Terminating pod
	// exists — with none, the whole loop below is a no-op.
	var tasks map[string][]wdeps.CtrTask
	now := c.d.Cfg.Seams.Host.Clock.Now()
	wedged := 0
	ndel := 0
	for i := range e.Pods {
		p := &e.Pods[i]
		if p.DeletionTimestamp == nil {
			continue
		}
		if tasks == nil {
			var complete bool
			tasks, complete = e.TasksOnce()
			if !complete {
				// A task root was unreadable — "zero live tasks"
				// is unverifiable, so a force-delete could reap a
				// pod whose tasks the map never saw. Inconclusive
				// cycle: keep counters/latch, act on nothing
				// (wdeps.CheckCtrTasks unreadable-root parity).
				c.d.State.AppendLog(
					"suspect: pod-teardown aborted — ctr task map incomplete, force-deletes unverifiable")
				c.d.CycleResult(wdeps.CheckTeardown, "abort")
				return
			}
		}
		uid := string(p.UID)
		age := now.Sub(p.DeletionTimestamp.Time)
		// Wedge evidence is measured on pod level: Terminating long
		// past StuckWedgeAge AND containerd still holds a task dir
		// (live or not) — sig7/force-delete had their chance; only a
		// reboot clears a shim/kernel-level wedge.
		if age >= c.d.Cfg.Teardown.StuckWedgeAge && len(tasks[uid]) >= 1 {
			wedged++
		}
		if age < c.d.Cfg.Teardown.StuckDeleteAge {
			continue
		}
		// Rule C: external resources or kubelet mirrors → never
		// force-delete (finalizer = another controller owns cleanup;
		// PVC = dual-mount risk; mirror = pointless).
		if len(p.Finalizers) > 0 || wdeps.PodHasPVC(p) || wdeps.IsMirrorPod(p) {
			continue
		}
		if wdeps.CountLive(tasks[uid]) > 0 {
			continue // a live task exists — kubelet may still be tearing down
		}
		if ndel >= c.d.Cfg.Teardown.MaxForceDelete {
			continue // per-cycle cap bounds the blast radius
		}
		// L1↔L3 hold: force-deleting pods mid cluster-maintenance is
		// churn the drain then has to un-wedge — stop this cycle.
		if c.d.HoldLocalAction(ctx) {
			c.d.State.AppendLog("cleanup: pod-teardown force-delete held — " +
				"cluster maintenance in progress")
			break
		}
		// The heal stamp rides BEFORE the delete so the cluster side
		// sees the attribution even if this process dies mid-call.
		c.d.StampPodHealed(ctx, p.Namespace, p.Name)
		if err := c.d.ForceDeletePod(ctx, p); err != nil {
			c.d.State.AppendLog(fmt.Sprintf("suspect: force-delete %s/%s failed: %v",
				p.Namespace, p.Name, err))
			continue
		}
		ndel++
		c.d.Actions.WithLabelValues(wdeps.CheckTeardown, "force_delete").Inc()
	}

	switch {
	case wedged >= 1:
		if !c.d.StreakPending(&c.fails,
			fmt.Sprintf("suspect: pod-teardown-wedged stuck=%d", wedged)) {
			if c.d.State.Exists(latchdefs.LatchNodeOverloaded) {
				// Suppression parity: a wedge under overload is a
				// symptom — rebooting would dump 100% of its load
				// onto the remaining nodes (amplifier). Log-only,
				// once per suppression episode.
				if !c.d.State.Exists(latchdefs.LatchPodTeardownWedged) {
					c.d.State.AppendLog(fmt.Sprintf(
						"pod-teardown-wedged suppressed-overloaded stuck=%d", wedged))
				}
			} else {
				// EnterFrom: ctr-tasks shares this latch for
				// unkillable orphan shims — our exit below must
				// release only OUR hold, never theirs.
				c.d.State.EnterFrom(latchdefs.LatchPodTeardownWedged,
					wdeps.CheckTeardown, fmt.Sprintf("stuck=%d", wedged))
			}
		}
	default:
		c.fails = 0
		c.d.State.ExitFrom(latchdefs.LatchPodTeardownWedged,
			wdeps.CheckTeardown, nil)
	}
	c.d.CycleResult(wdeps.CheckTeardown, "ok")
}

// --- Check 2: konnectivity IP drift (30-konnectivity.sh) ---

// k0sWorkerNodeIP reads --node-ip=<ip> out of the k0sworker unit —
// the node's InternalIP konnectivity-agent should have baked in.
func k0sWorkerNodeIP(d *wdeps.Deps) string {
	data, err := os.ReadFile(d.Cfg.K0sWorkerUnitFile)
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
func proxyAgentHost(d *wdeps.Deps, pid int, argv []string) string {
	if v := d.Proc.EnvValue(pid, "NODE_IP"); v != "" {
		return v
	}
	if m := agentHostRe.FindStringSubmatch(strings.Join(argv, " ")); m != nil {
		return m[1]
	}
	return ""
}

// deleteKonnectivityPod deletes this node's konnectivity-agent pod in
// kube-system (grace 5 — the Running DaemonSet pod gets a bounded
// shutdown window instead of an instant SIGKILL) — the DaemonSet
// recreates the pod with freshly baked env.
// Anchored name match + namespace pin (see KonnPodRe comment).
func DeleteKonnectivityPod(d *wdeps.Deps, ctx context.Context, pods []corev1.Pod) bool {
	// L1↔L3 hold: deleting the konnectivity agent mid cluster-
	// maintenance severs the very control path a drain needs.
	if d.HoldLocalAction(ctx) {
		d.State.AppendLog("suspect: konnectivity pod delete held — " +
			"cluster maintenance in progress")
		return false
	}
	for i := range pods {
		p := &pods[i]
		if p.Namespace != "kube-system" || !KonnPodRe.MatchString(p.Name) ||
			p.DeletionTimestamp != nil {
			continue
		}
		// The heal stamp rides BEFORE the delete so the cluster side
		// sees the attribution even if this process dies mid-call.
		d.StampPodHealed(ctx, p.Namespace, p.Name)
		if err := d.Cfg.Client.CoreV1().Pods(p.Namespace).Delete(ctx, p.Name,
			metav1.DeleteOptions{
				GracePeriodSeconds: ptr.To[int64](5),
				// UID precondition: the listing→delete window can
				// outlive this pod — a same-named recycle (DS churn)
				// is not ours to kill.
				Preconditions: &metav1.Preconditions{UID: &p.UID},
			}); err != nil {
			d.State.AppendLog(fmt.Sprintf(
				"suspect: konnectivity pod delete %s/%s failed: %v",
				p.Namespace, p.Name, err))
			continue // a stale entry must not block the next candidate
		}
		return true
	}
	return false
}

// KonnCheck is the 30-konnectivity stale-identifier guard as a
// Check; it owns the mismatch streak (ex-Hygiene.konnFails).
type KonnCheck struct {
	d     *wdeps.Deps
	Fails int
}

// Name returns the check label / WD_SIG key.
func (c *KonnCheck) Name() string { return wdeps.CheckKonn }

// Run executes one konnectivity round.
func (c *KonnCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckKonn) {
		return
	}
	nodeIP := k0sWorkerNodeIP(c.d)
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
	for _, pid := range e.PidsOnce() {
		argv := c.d.Proc.Cmdline(pid)
		if !isProxyAgent(argv) {
			continue
		}
		phost := proxyAgentHost(c.d, pid, argv)
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
		c.Fails = 0
		c.d.State.Exit(latchdefs.LatchKonnectivityIPMismatch, nil)
		c.d.CycleResult(wdeps.CheckKonn, "ok")
		return
	}

	c.Fails++
	c.d.State.Enter(latchdefs.LatchKonnectivityIPMismatch,
		fmt.Sprintf("host=%s node-ip=%s", agentHost, nodeIP))
	if c.Fails >= c.d.Cfg.ConsecNeeded &&
		c.d.State.RateTrySpend("last-konn-restart", c.d.Cfg.MinRestartInterval) {
		// Budget spent atomically BEFORE acting — a failed action
		// still consumed it (conservative, rate_spend parity).
		c.Fails = 0
		// NPD contract: "recreating konnectivity-agent ..." fires the
		// KonnectivityStaleId filelog pattern.
		c.d.State.AppendLog("KONNECTIVITY-IP-RESTART: " +
			latchdefs.ReasonKonnectivityAgentRecreate +
			fmt.Sprintf(" sandbox - stale identifier host=%s != node-ip=%s",
				agentHost, nodeIP))
		if DeleteKonnectivityPod(c.d, ctx, e.Pods) {
			c.d.Actions.WithLabelValues(wdeps.CheckKonn, "pod_delete").Inc()
		} else if stalePID > 0 {
			// No API pod found (list failed or pod renamed) — kill
			// the stale proxy-agent directly. Least-bad: a container
			// restart alone can't fix env baked at pod create, but
			// it still clears a hung agent while humans look.
			if err := c.d.Cfg.Seams.Host.KillFn(stalePID, syscall.SIGKILL); err != nil {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: kill stale proxy-agent pid=%d failed: %v", stalePID, err))
			} else {
				c.d.State.AppendLog(fmt.Sprintf(
					"ACTION: killed stale proxy-agent pid=%d — no API pod found",
					stalePID))
			}
			c.d.Actions.WithLabelValues(wdeps.CheckKonn, "sigkill").Inc()
		}
	} else {
		// NPD contract: "konnectivity stale identifier ..." fires the
		// same KonnectivityStaleId pattern while accumulating.
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: "+latchdefs.ReasonKonnectivityStaleID+
				" host=%s != node-ip=%s%s",
			agentHost, nodeIP,
			checkkit.Progress(c.Fails, c.d.Cfg.ConsecNeeded)))
	}
	c.d.CycleResult(wdeps.CheckKonn, "ok")
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
func pausePIDOf(tasks []wdeps.CtrTask) int {
	for _, t := range tasks {
		if t.Live && (t.Name == "pause" || t.Name == "POD") {
			return t.PID
		}
	}
	return 0
}

// DNSResolvCheck is the 33-dns-resolv-drift guard as a Check; it
// owns the stale-pause streak (ex-Hygiene.dnsFails).
type DNSResolvCheck struct {
	d     *wdeps.Deps
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *DNSResolvCheck) Name() string { return wdeps.CheckDNS }

// Run executes one dns-resolv round.
func (c *DNSResolvCheck) Run(_ context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckDNS) {
		return
	}
	if !e.APIOK {
		// Same inconclusive rule as teardown: a failed LIST keeps
		// counters and the latch (no flap on API blip).
		c.d.CycleResult(wdeps.CheckDNS, "abort")
		return
	}
	hostNS, _ := nameserverSet(c.d.Cfg.HostResolvConf)

	var stale []dnsStale
	if len(hostNS) > 0 { // empty host set → nothing to compare (shell parity)
		// Task map is built only when a Running dns-pod actually
		// needs its pause pid looked up.
		var tasks map[string][]wdeps.CtrTask
		for i := range e.Pods {
			p := &e.Pods[i]
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
				tasks, _ = e.TasksOnce()
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
				c.d.Proc.File(pid, "root/etc/resolv.conf"))
			if clusterLocal || len(podNS) == 0 {
				continue
			}
			if !equalNS(podNS, hostNS) {
				stale = append(stale, dnsStale{pod: p.Name, pid: pid})
			}
		}
	}

	if len(stale) == 0 {
		c.fails = 0
		c.d.State.Exit(latchdefs.LatchDNSResolvStale, nil)
		c.d.CycleResult(wdeps.CheckDNS, "ok")
		return
	}

	specs := make([]string, 0, len(stale))
	for _, s := range stale {
		specs = append(specs, fmt.Sprintf("%s:pid=%d", s.pod, s.pid))
	}
	staleStr := strings.Join(specs, " ")
	// Latch first — the state file is what NPD's permanent
	// DnsResolvStale condition checks; the counter gates the action.
	c.d.State.Enter(latchdefs.LatchDNSResolvStale, staleStr)
	c.fails++
	switch {
	case c.fails >= c.d.Cfg.ConsecNeeded &&
		c.d.State.RateTrySpend("last-dnsresolv-restart", c.d.Cfg.MinRestartInterval):
		// budget already spent atomically — spend BEFORE action (lib.sh)
		for _, s := range stale {
			// SIGKILL on the PAUSE pid — NOT the app container
			// (restarting the app keeps the old sandbox +
			// resolv.conf; the pod object itself is fine).
			c.d.State.AppendLog(fmt.Sprintf(
				"DNS-RESOLV-RESTART: killing pause %d (%s) - dns-resolv-stale, resolv.conf pod stale vs host",
				s.pid, s.pod))
			if err := c.d.Cfg.Seams.Host.KillFn(s.pid, syscall.SIGKILL); err != nil {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: kill pause %d (%s) failed: %v", s.pid, s.pod, err))
			}
			c.d.Actions.WithLabelValues(wdeps.CheckDNS, "pause_kill").Inc()
		}
		c.fails = 0
	default:
		c.d.State.AppendLog(fmt.Sprintf("suspect: dns-resolv-stale %s%s",
			staleStr, checkkit.Progress(c.fails, c.d.Cfg.ConsecNeeded)))
	}
	c.d.CycleResult(wdeps.CheckDNS, "ok")
}

// --- shared helpers for the ported kubelet/cilium/ctr checks ---
