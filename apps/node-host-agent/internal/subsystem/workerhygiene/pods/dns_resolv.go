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
