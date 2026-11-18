// dns_resolv.go — the 33-dns-resolv-drift guard (33-dns-resolv-
// drift.sh port): Running kube-system dns pods whose pause task sees
// a resolv.conf that drifted from the host's get their pause pid
// SIGKILLed (the sandbox — not the app container — owns the stale
// resolv.conf). ClusterFirst resolv.confs are skipped outright —
// see nameserverSet.
//
// Wave-5 P0: hostconfig T9 deliberately writes "nameserver 127.0.0.1"
// (plus real external upstreams) on EVERY node. Treating 127.0.0.1 as
// the same thing as the systemd-resolved stub 127.0.0.53 made the
// "both loopback" branch fire every 60s on every node, spamming a
// warning and hiding real upstream drift; worse, a loopback-only host
// could push the !equalNS branch into killing a healthy CoreDNS.
// The loopback verdict now compares ONLY the non-loopback upstream
// set, never kills when the host has no valid external upstream, and
// ignores hostNetwork / deleting pods.
package pods

import (
	"context"
	"fmt"
	"io"
	"net/netip"
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

const (
	// systemdStubNS is the systemd-resolved stub — a DIFFERENT thing
	// from T9's intentional 127.0.0.1 local-CoreDNS stub. Only the
	// former means "resolved did not converge".
	systemdStubNS = "127.0.0.53"
	// resolvReadLimit caps a single resolv.conf read. A path under a
	// pause mount namespace is normally tiny; a pathological/bind-
	// mounted file must never let the 60s check hold an unbounded
	// read (O_NONBLOCK + LimitReader — Wave-5 P0).
	resolvReadLimit = 64 << 10
)

// readResolvLimited opens a resolv.conf non-blocking and caps the
// bytes consumed. A file that cannot be opened/read is inconclusive
// (ok=false), never a drift verdict. The regular-file check is
// essential: Go registers an O_NONBLOCK fd with the epoll netpoller,
// so io.ReadAll on a FIFO (an untrusted container can bind-mount one
// over resolv.conf) parks until CycleTimeout instead of returning.
func readResolvLimited(path string) ([]byte, bool) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(f, resolvReadLimit))
	if err != nil {
		return nil, false
	}
	return data, true
}

// nameserverSet returns the sorted-unique nameserver IPs of a
// resolv.conf file. ok=false when the file contains
// "svc.cluster.local" — a ClusterFirst resolv.conf is NOT a host
// snapshot and must be skipped (killing those pauses killed innocent
// job pods — incident 2026-09-26).
func nameserverSet(path string) (ns []string, clusterLocal bool) {
	data, ok := readResolvLimited(path)
	if !ok {
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

// resolvCacheKey includes the pause pid: a recreated sandbox with the
// same pod UID gets a NEW resolv.conf and must be re-inspected rather
// than inheriting the dead pause's overflow verdict.
type resolvCacheKey struct {
	uid string
	pid int
}

// DNSResolvCheck is the 33-dns-resolv-drift guard as a Check; it
// owns the stale-pause streak (ex-Hygiene.dnsFails), per-(UID,pausePID)
// resolv.conf overflow cache (Wave-3 #12a / Wave-5 P0), and loopback
// DNS event dedup.
type DNSResolvCheck struct {
	d               *wdeps.Deps
	fails           int
	resolvCache     map[resolvCacheKey]resolvInspect
	loopbackEvented map[string]bool
}

type resolvInspect struct {
	overflow bool
	detail   string
	evented  bool
}

// isLoopbackNS uses the IP's semantic loopback flag, not a hardcoded
// list — a stub on 127.0.0.54 (or any other 127/8 address) is just
// as loopback as 127.0.0.1, 127.0.0.53 or ::1.
func isLoopbackNS(ip string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	return err == nil && addr.IsLoopback()
}

// nonLoopbackNS keeps only the real upstreams. T9's 127.0.0.1 stub is
// expected in both host and pod; comparing it says nothing about
// drift. This is the set Wave-5 compares when CRI filters loopback.
func nonLoopbackNS(ns []string) []string {
	out := make([]string, 0, len(ns))
	for _, ip := range ns {
		if !isLoopbackNS(ip) {
			out = append(out, ip)
		}
	}
	return out
}

func checkResolvOverflow(path string) (overflow bool, detail string, ok bool) {
	data, ok := readResolvLimited(path)
	if !ok {
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

// emitLoopbackSuspectEvent is the single per-pod emitter for loopback
// findings. The event name/reason and action label are the SAME as
// the original both-stub path — only the note text is situation-aware.
func (c *DNSResolvCheck) emitLoopbackSuspectEvent(ctx context.Context, p *corev1.Pod,
	uid, note string) {
	if c.loopbackEvented[uid] {
		return
	}
	if c.d.Cfg.Client == nil {
		c.loopbackEvented[uid] = true
		return
	}
	if err := c.d.EmitPodEvent(ctx, p, "dns-loopback", "DNSLoopbackNameserver", note); err == nil {
		c.loopbackEvented[uid] = true
		c.d.Actions.WithLabelValues(wdeps.CheckDNS, "loopback_event").Inc()
	}
}

// suspectLoopback surfaces the one genuine loopback case — both sides
// on the systemd-resolved stub — once per pod. It never kills: a stub
// without an external upstream is not usable drift evidence.
func (c *DNSResolvCheck) suspectLoopback(ctx context.Context, p *corev1.Pod,
	uid string, podNS, hostNS []string) {
	c.d.State.AppendLog(fmt.Sprintf(
		"suspect: dns-resolv loopback nameserver on both host and DNS pod %s (pod_ns=%v host_ns=%v)",
		p.Name, podNS, hostNS))
	c.emitLoopbackSuspectEvent(ctx, p, uid, fmt.Sprintf(
		"DNS pod %s and host /etc/resolv.conf both contain the systemd-resolved stub (%s) — plugin/loop risk",
		p.Name, systemdStubNS))
}

// suspectPodStubOnly covers node T9: the host uses its OWN 127.0.0.1
// local stub plus external upstreams (hostStub == false, but
// hostHasLoopback == true), while the DNS pod sandbox is still pinned
// to the systemd-resolved stub. Every old case missed that shape.
// It is a plugin/loop SUSPECT (log + one event), never a kill — the
// host has a usable external upstream, so the upstream set remains a
// trustworthy drift signal and a loopback-only host is already
// stopped by the !hostHasExternal rail above.
func (c *DNSResolvCheck) suspectPodStubOnly(ctx context.Context, p *corev1.Pod,
	uid string, podNS, hostNS []string) {
	c.d.State.AppendLog(fmt.Sprintf(
		"suspect: dns-resolv systemd stub in DNS pod %s but not on host (pod_ns=%v host_ns=%v)",
		p.Name, podNS, hostNS))
	c.emitLoopbackSuspectEvent(ctx, p, uid, fmt.Sprintf(
		"DNS pod %s still contains the systemd-resolved stub (%s) while host /etc/resolv.conf uses a local stub with external upstreams — plugin/loop risk",
		p.Name, systemdStubNS))
}

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
		c.resolvCache = map[resolvCacheKey]resolvInspect{}
	}
	if c.loopbackEvented == nil {
		c.loopbackEvented = map[string]bool{}
	}

	hostNS, _ := nameserverSet(c.d.Cfg.HostResolvConf)
	hostStub := slices.Contains(hostNS, systemdStubNS)
	hostExt := nonLoopbackNS(hostNS)
	hostHasExternal := len(hostExt) > 0

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
	liveCacheKeys := make(map[resolvCacheKey]bool, len(e.Pods))
	var overflowCount int64
	var stale []dnsStale

	for i := range e.Pods {
		p := &e.Pods[i]
		uid := string(p.UID)
		liveUIDs[uid] = true
		pid := pausePIDOf(loadTasks()[uid])

		// 1. Wave-3 #12a: inspect resolv.conf limits for every Running
		// pod (cached by UID + pausePID so a recreated sandbox is
		// re-inspected).
		if p.Status.Phase == corev1.PodRunning && pid != 0 {
			key := resolvCacheKey{uid: uid, pid: pid}
			liveCacheKeys[key] = true
			entry, cached := c.resolvCache[key]
			if !cached {
				if ov, det, ok := checkResolvOverflow(c.d.Proc.File(pid, "root/etc/resolv.conf")); ok {
					entry = resolvInspect{overflow: ov, detail: det}
					c.resolvCache[key] = entry
					cached = true
				}
			}
			if cached && entry.overflow {
				overflowCount++
				if !entry.evented {
					if c.d.Cfg.Client == nil {
						entry.evented = true
						c.resolvCache[key] = entry
					} else if err := c.d.EmitPodEvent(ctx, p, "resolv-overflow", "PodDNSResolvOverflow",
						fmt.Sprintf("pod /etc/resolv.conf exceeds glibc limits (%s)", entry.detail)); err == nil {
						entry.evented = true
						c.resolvCache[key] = entry
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
		// A pod being deleted is already on its way out — do not
		// pile a pause SIGKILL on top of the termination.
		if p.DeletionTimestamp != nil {
			continue
		}
		// hostNetwork DNS pods share the host's resolv.conf by
		// definition — a pod-vs-host diff is meaningless there.
		if p.Spec.HostNetwork {
			continue
		}
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
		podStub := slices.Contains(podNS, systemdStubNS)
		podExt := nonLoopbackNS(podNS)
		podHasLoopback := slices.ContainsFunc(podNS, isLoopbackNS)
		hostHasLoopback := slices.ContainsFunc(hostNS, isLoopbackNS)

		switch {
		case !hostHasExternal:
			// ABSOLUTE RAIL (Wave-5 P0): the host has no usable
			// upstream (bare stub / empty resolv.conf). Never
			// SIGKILL a healthy DNS pod on this evidence — the
			// drift verdict is not trustworthy. The genuine
			// "both systemd stubs" case is a one-shot suspect.
			if podStub && hostStub {
				c.suspectLoopback(ctx, p, uid, podNS, hostNS)
			} else {
				delete(c.loopbackEvented, uid)
			}
		case podStub && hostStub:
			// Both still carry the systemd-resolved stub, but T9's
			// external upstreams exist on the host. The stub is
			// expected here — do NOT spam the loopback warning;
			// only a real upstream drift or a loopback-only
			// sandbox justifies rebuilding the pause.
			if len(podExt) == 0 || (p.Status.Phase == corev1.PodRunning && !equalNS(podExt, hostExt)) {
				stale = append(stale, dnsStale{pod: p.Name, pid: pid})
			} else {
				delete(c.loopbackEvented, uid)
			}
		case podHasLoopback && !hostHasLoopback:
			// Host is clean (no loopback at all) while the DNS
			// pod sandbox still carries one — the stub never got
			// installed into the pod. Rebuild it.
			stale = append(stale, dnsStale{pod: p.Name, pid: pid})
		case podHasLoopback && len(podExt) == 0:
			// Pod carries only a loopback nameserver while the
			// host has usable upstreams: CRI may have filtered
			// the stub or the sandbox never converged. Rebuild.
			stale = append(stale, dnsStale{pod: p.Name, pid: pid})
		case p.Status.Phase == corev1.PodRunning && !equalNS(podExt, hostExt):
			// Real drift on the upstream set — the branch the
			// old 127.0.0.1/127.0.0.53 loopback spam used to hide.
			// This MUST precede the podStub-only suspect below: a
			// T9 pod can carry BOTH the systemd stub and a drifted
			// external upstream, and a suspect is not a rebuild —
			// the stale upstream would keep serving wrong answers.
			stale = append(stale, dnsStale{pod: p.Name, pid: pid})
		case podStub && !hostStub:
			// T9 (host 127.0.0.1 + external upstreams) with a DNS
			// pod still on 127.0.0.53 AND matching upstreams: only
			// now is it a pure plugin/loop suspect. Do NOT kill —
			// the host upstreams are still usable. A pod whose
			// upstreams also drifted was already caught above.
			c.suspectPodStubOnly(ctx, p, uid, podNS, hostNS)
		default:
			delete(c.loopbackEvented, uid)
		}
	}

	c.d.Series.PodDNSResolvOverflow = overflowCount
	for key := range c.resolvCache {
		if !liveUIDs[key.uid] || !liveCacheKeys[key] {
			delete(c.resolvCache, key)
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
