// dns_resolv.go — the 33-dns-resolv-drift guard (33-dns-resolv-
// drift.sh port): Running kube-system dns pods whose pause task sees
// a resolv.conf that drifted from the host's get their pause pid
// SIGKILLed (the sandbox — not the app container — owns the stale
// resolv.conf). ClusterFirst resolv.confs are skipped outright —
// see nameserverSet.
package pods

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"syscall"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checkkit"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// DaemonSet pod names only (anchored — unanchored ~= filters
// previously matched konnectivity-agent-patcher-* and coredns-* job
// pods → wrong pause killed, incident 2026-09-26).
var dnsPodRe = regexp.MustCompile(`^(node-local-dns-[a-z0-9]+|coredns-[a-z0-9]+-[a-z0-9]+)$`)

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
	for line := range strings.SplitSeq(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" && !seen[f[1]] {
			seen[f[1]] = true
			ns = append(ns, f[1])
		}
	}
	slices.Sort(ns)
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
// owns the stale-pause streak (ex-Hygiene.dnsFails), per-UID resolv.conf
// overflow cache (Wave-3 #12a), and loopback DNS event dedup.
type DNSResolvCheck struct {
	d               *wdeps.Deps
	fails           int
	resolvCache     map[string]resolvInspect
	loopbackEvented map[string]bool
}

type resolvInspect struct {
	overflow bool
	detail   string
	evented  bool
}

func isLoopbackNS(ip string) bool {
	return ip == "127.0.0.53" || ip == "127.0.0.1" || ip == "::1"
}

func checkResolvOverflow(path string) (overflow bool, detail string, ok bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, "", false
	}
	var nsCount, searchDomains, maxSearchLine int
	for rawLine := range strings.SplitSeq(string(data), "\n") {
		line := strings.TrimRight(rawLine, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		f := strings.Fields(trimmed)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "nameserver":
			if len(f) >= 2 {
				nsCount++
			}
		case "search":
			if len(line) > maxSearchLine {
				maxSearchLine = len(line)
			}
			searchDomains += len(f) - 1
		}
	}
	var reasons []string
	if nsCount > 3 {
		reasons = append(reasons, fmt.Sprintf("nameservers=%d>3", nsCount))
	}
	if searchDomains > 6 {
		reasons = append(reasons, fmt.Sprintf("search_domains=%d>6", searchDomains))
	}
	if maxSearchLine > 256 {
		reasons = append(reasons, fmt.Sprintf("search_line_bytes=%d>256", maxSearchLine))
	}
	if len(reasons) > 0 {
		return true, strings.Join(reasons, ", "), true
	}
	return false, "", true
}

// Name returns the check label / WD_SIG key.
func (c *DNSResolvCheck) Name() string { return wdeps.CheckDNS }

// Run executes one dns-resolv round.
func (c *DNSResolvCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckDNS) {
		return
	}
	if !e.APIOK {
		// Same inconclusive rule as teardown: a failed LIST keeps
		// counters and the latch (no flap on API blip).
		c.d.CycleResult(wdeps.CheckDNS, "abort")
		return
	}
	if c.resolvCache == nil {
		c.resolvCache = map[string]resolvInspect{}
	}
	if c.loopbackEvented == nil {
		c.loopbackEvented = map[string]bool{}
	}

	hostNS, _ := nameserverSet(c.d.Cfg.HostResolvConf)
	hostHasLoopback := slices.ContainsFunc(hostNS, isLoopbackNS)
	hostHasExternal := false
	for _, ns := range hostNS {
		if !isLoopbackNS(ns) {
			hostHasExternal = true
			break
		}
	}

	var tasks map[string][]wdeps.CtrTask
	tasksLoaded := false
	loadTasks := func() map[string][]wdeps.CtrTask {
		if !tasksLoaded {
			tasksLoaded = true
			if e.TasksOnce != nil {
				tasks, _ = e.TasksOnce()
			}
		}
		return tasks
	}

	liveUIDs := make(map[string]bool, len(e.Pods))
	var overflowCount int64
	var stale []dnsStale

	for i := range e.Pods {
		p := &e.Pods[i]
		uid := string(p.UID)
		liveUIDs[uid] = true

		// 1. Wave-3 #12a: inspect resolv.conf limits for every Running pod (cached by UID).
		if p.Status.Phase == corev1.PodRunning {
			entry, cached := c.resolvCache[uid]
			if !cached {
				pid := pausePIDOf(loadTasks()[uid])
				if pid != 0 {
					if ov, det, ok := checkResolvOverflow(c.d.Proc.File(pid, "root/etc/resolv.conf")); ok {
						entry = resolvInspect{overflow: ov, detail: det}
						c.resolvCache[uid] = entry
						cached = true
					}
				}
			}
			if cached && entry.overflow {
				overflowCount++
				if !entry.evented {
					if c.d.Cfg.Client == nil {
						entry.evented = true
						c.resolvCache[uid] = entry
					} else if err := c.d.EmitPodEvent(ctx, p, "resolv-overflow", "PodDNSResolvOverflow",
						fmt.Sprintf("pod /etc/resolv.conf exceeds glibc limits (%s)", entry.detail)); err == nil {
						entry.evented = true
						c.resolvCache[uid] = entry
						c.d.Actions.WithLabelValues(wdeps.CheckDNS, "resolv_overflow_event").Inc()
					}
				}
			}
		}

		// 2. DNS DaemonSet pod drift + loopback guard (covers Running & CrashLoopBackOff).
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed ||
			p.Namespace != "kube-system" || !dnsPodRe.MatchString(p.Name) {
			continue
		}
		pid := pausePIDOf(loadTasks()[uid])
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
		podHasLoopback := slices.ContainsFunc(podNS, isLoopbackNS)
		switch {
		case podHasLoopback && hostHasLoopback:
			// Both host and DNS pod point to 127.0.0.53 (systemd-resolved stub not converged):
			// surface suspect + deduped Warning Event rather than looping on equalNS.
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: dns-resolv loopback nameserver on both host and DNS pod %s (pod_ns=%v host_ns=%v)",
				p.Name, podNS, hostNS))
			if !c.loopbackEvented[uid] {
				if c.d.Cfg.Client == nil {
					c.loopbackEvented[uid] = true
				} else if err := c.d.EmitPodEvent(ctx, p, "dns-loopback", "DNSLoopbackNameserver",
					fmt.Sprintf("DNS pod %s and host /etc/resolv.conf both contain loopback nameserver (%v) — systemd-resolved stub may cause CoreDNS plugin/loop",
						p.Name, podNS)); err == nil {
					c.loopbackEvented[uid] = true
					c.d.Actions.WithLabelValues(wdeps.CheckDNS, "loopback_event").Inc()
				}
			}
		case podHasLoopback && hostHasExternal && !hostHasLoopback:
			// Host resolv.conf is clean with external upstreams while DNS pod sandbox still
			// carries loopback (even in CrashLoopBackOff): kill pause so kubelet rebuilds sandbox.
			stale = append(stale, dnsStale{pod: p.Name, pid: pid})
		case p.Status.Phase == corev1.PodRunning && len(hostNS) > 0 && !equalNS(podNS, hostNS):
			stale = append(stale, dnsStale{pod: p.Name, pid: pid})
		default:
			delete(c.loopbackEvented, uid)
		}
	}

	c.d.Series.PodDNSResolvOverflow = overflowCount
	for uid := range c.resolvCache {
		if !liveUIDs[uid] {
			delete(c.resolvCache, uid)
		}
	}
	for uid := range c.loopbackEvented {
		if !liveUIDs[uid] {
			delete(c.loopbackEvented, uid)
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
	case c.fails >= c.d.Cfg.ConsecNeeded && c.d.HoldEmergencyHeal(ctx):
		c.d.State.AppendLog(fmt.Sprintf("suspect: dns-resolv-stale %s — emergency heal held by maintenance window",
			staleStr))
	case c.fails >= c.d.Cfg.ConsecNeeded &&
		c.d.State.RateTrySpend("last-dnsresolv-restart", c.d.Cfg.MinRestartInterval):
		c.d.StampLocalRemediation(ctx)
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
