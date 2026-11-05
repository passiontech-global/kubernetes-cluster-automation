package workerhygiene

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// spegelCheck is the W7-H4 mirror-peer guard as a Check; it owns
// the Ready=False streak (ex-Hygiene.spegelFails).
type spegelCheck struct {
	h     *Hygiene
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *spegelCheck) Name() string { return checkSpegel }

// Run executes one spegel-mirror round.
func (c *spegelCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.h.cycles.WithLabelValues(checkSpegel, "gated").Inc()
		return
	}
	if !e.apiOK {
		// Inconclusive — keep streak/latch exactly like teardown.
		c.h.cycles.WithLabelValues(checkSpegel, "abort").Inc()
		return
	}
	var sp *corev1.Pod
	for i := range e.pods {
		p := &e.pods[i]
		if (p.Namespace != "spegel" && p.Namespace != "kube-system") ||
			!spegelPodRe.MatchString(p.Name) ||
			p.DeletionTimestamp != nil ||
			p.Status.Phase != corev1.PodRunning ||
			c.h.cfg.Seams.nowFn().Sub(p.CreationTimestamp.Time) < spegelMinPodAge {
			continue
		}
		sp = p
		break
	}
	if sp == nil || podReady(sp) {
		// No spegel DS on this node, or the pod is healthy — either
		// way the mirror datapath isn't our problem; clear stale
		// evidence like checkCilium's no-agent path.
		c.fails = 0
		c.h.state.Exit("spegel-mirror-degraded", nil)
		c.h.cycles.WithLabelValues(checkSpegel, "ok").Inc()
		return
	}
	c.fails++
	if c.fails < c.h.cfg.ConsecNeeded {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: spegel-mirror pod %s/%s Ready=False (check %d/%d)",
			sp.Namespace, sp.Name, c.fails, c.h.cfg.ConsecNeeded))
		c.h.cycles.WithLabelValues(checkSpegel, "ok").Inc()
		return
	}
	c.h.state.Enter("spegel-mirror-degraded",
		fmt.Sprintf("pod=%s/%s ready_fails=%d", sp.Namespace, sp.Name, c.fails))
	if !c.h.state.RateTrySpend("last-spegel-restart", c.h.cfg.MinRestartInterval) {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: spegel-mirror %s/%s Ready=False %dx but restart in cooldown (<30m), skip",
			sp.Namespace, sp.Name, c.fails))
		c.h.cycles.WithLabelValues(checkSpegel, "ok").Inc()
		return
	}
	// Budget spent atomically BEFORE the delete (rate_spend parity).
	c.h.state.AppendLog(fmt.Sprintf(
		"ACTION: spegel-mirror deleted pod %s/%s - Ready=False %dx (containerd mirror points at a wedged peer)",
		sp.Namespace, sp.Name, c.fails))
	if err := c.h.cfg.Client.CoreV1().Pods(sp.Namespace).Delete(ctx, sp.Name,
		metav1.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)}); err != nil {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: spegel-mirror delete %s/%s failed: %v",
			sp.Namespace, sp.Name, err))
	} else {
		c.fails = 0
		c.h.actions.WithLabelValues(checkSpegel, "pod_delete").Inc()
	}
	c.h.cycles.WithLabelValues(checkSpegel, "ok").Inc()
}

// checkSpegelMirror forwards to the migrated Check — tests written
// before the interface still call the old method shape.
func (h *Hygiene) checkSpegelMirror(ctx context.Context, pods []corev1.Pod,
	apiOK, workerActive bool) {
	h.spegel.Run(ctx, &cycleEnv{
		pods: pods, apiOK: apiOK, workerActive: workerActive})
}

// --- Check: calico-hygiene (W7-H7) ---
// The cicd cluster runs Calico, not Cilium — the cilium guard
// family above is all dormant there, while calico has its own leak
// modes: orphan cali* veth pairs left by failed CNI DELs (classic
// on high-churn CI nodes) and a wedged felix datapath whose
// :9099/readiness goes dark while the pod looks Running.
//   - Check 1 (veth leak): cali* iface count > node pod count +
//     CalicoOrphanVethThreshold for ConsecNeeded cycles →
//     state-calico-veth-leak (log-only — mass veth deletion is not
//     an unattended remedy).
//   - Check 2 (felix readiness): a Running calico-node pod whose
//     :9099/readiness fails ConsecNeeded cycles →
//     state-calico-felix-down for the NHC escalation path.
// The check is dormant everywhere cilium_host exists (cilium nodes)
// and on hosts with no cali* ifaces at all (non-calico, hub nodes).

// calicoIfaceCount counts cali* interfaces under SysClassNet; -1
// when the sysfs root is unreadable (inconclusive).
func (h *Hygiene) calicoIfaceCount() int {
	entries, err := os.ReadDir(h.cfg.Net.SysClassNet)
	if err != nil {
		return -1
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "cali") {
			n++
		}
	}
	return n
}

// calicoCheck is the W7-H7 calico guard as a Check; it owns the
// veth-leak and felix readiness streaks (ex-Hygiene.calicoVethFails/
// .calicoFelixFails).
type calicoCheck struct {
	h          *Hygiene
	vethFails  int
	felixFails int
}

// Name returns the check label / WD_SIG key.
func (c *calicoCheck) Name() string { return checkCalico }

// Run executes one calico-hygiene round.
func (c *calicoCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.h.cycles.WithLabelValues(checkCalico, "gated").Inc()
		return
	}
	if _, err := os.Stat(filepath.Join(c.h.cfg.Net.SysClassNet, "cilium_host")); err == nil {
		// Cilium node — every calico verdict belongs to the cilium
		// guard family; drop stale evidence like checkCiliumWGPeers.
		c.vethFails = 0
		c.felixFails = 0
		c.h.state.Exit("calico-veth-leak", nil)
		c.h.state.Exit("calico-felix-down", nil)
		c.h.cycles.WithLabelValues(checkCalico, "ok").Inc()
		return
	}
	cali := c.h.calicoIfaceCount()
	if cali <= 0 {
		// No cali* veth at all — not a calico node (unreadable
		// sysfs reports -1 the same way: nothing to verify).
		c.vethFails = 0
		c.felixFails = 0
		c.h.state.Exit("calico-veth-leak", nil)
		c.h.state.Exit("calico-felix-down", nil)
		c.h.cycles.WithLabelValues(checkCalico, "ok").Inc()
		return
	}
	if !e.apiOK {
		// Pod count is the leak baseline — an API flake makes the
		// comparison invalid. Keep streaks/latches (inconclusive).
		c.h.cycles.WithLabelValues(checkCalico, "abort").Inc()
		return
	}
	// Check 1 — orphan veth leak.
	if cali > len(e.pods)+c.h.cfg.Calico.OrphanVethThreshold {
		c.vethFails++
		if c.vethFails >= c.h.cfg.ConsecNeeded {
			if !c.h.state.Exists("calico-veth-leak") {
				c.h.state.AppendLog(fmt.Sprintf(
					"suspect: calico-hygiene orphan veth leak cali=%d pods=%d threshold=%d — CNI DEL cleanup is leaking veth pairs",
					cali, len(e.pods), c.h.cfg.Calico.OrphanVethThreshold))
			}
			c.h.state.Enter("calico-veth-leak",
				fmt.Sprintf("cali=%d pods=%d", cali, len(e.pods)))
		} else {
			c.h.state.AppendLog(fmt.Sprintf(
				"suspect: calico-hygiene veth leak candidate cali=%d pods=%d (check %d/%d)",
				cali, len(e.pods), c.vethFails, c.h.cfg.ConsecNeeded))
		}
	} else {
		c.vethFails = 0
		c.h.state.Exit("calico-veth-leak", nil)
	}
	// Check 1b — orphan-veth GC (W8-NM3): while the leak latch is
	// set, reap cali* host veths that stayed DOWN (carrier 0) for
	// calicoVethGCMinAge. Live veths always answer carrier=1; a
	// leaked one from a failed CNI DEL is DOWN forever. The
	// veth-seen-<name> marker provides the 15m age — same
	// confirm-marker shape as wedged-seen-* (a veth must not be
	// deleted on a single read: an interface mid-creation can read
	// carrier 0 for a moment).
	if c.h.state.Exists("calico-veth-leak") {
		c.h.gcCalicoOrphanVeths(ctx)
	}
	// Check 2 — felix readiness, gated on a Running calico-node pod
	// on this node (no pod → nothing to probe).
	var felix *corev1.Pod
	for i := range e.pods {
		p := &e.pods[i]
		if (p.Namespace == "kube-system" || p.Namespace == "calico-system") &&
			calicoNodePodRe.MatchString(p.Name) &&
			p.DeletionTimestamp == nil && p.Status.Phase == corev1.PodRunning {
			felix = p
			break
		}
	}
	switch {
	case felix == nil || c.h.cfg.Calico.FelixReadyURL == "":
		c.felixFails = 0
		c.h.state.Exit("calico-felix-down", nil)
	default:
		code, err := c.h.cfg.Seams.probeHTTPStatus(ctx,
			c.h.cfg.Calico.FelixReadyURL, "", ciliumProbeTime)
		if err == nil && code == http.StatusOK {
			c.felixFails = 0
			c.h.state.Exit("calico-felix-down", nil)
			break
		}
		c.felixFails++
		if c.felixFails < c.h.cfg.ConsecNeeded {
			c.h.state.AppendLog(fmt.Sprintf(
				"suspect: calico-felix-down readiness probe code=%d err=%v (check %d/%d)",
				code, err, c.felixFails, c.h.cfg.ConsecNeeded))
			break
		}
		c.h.state.Enter("calico-felix-down",
			fmt.Sprintf("readiness_probe_fails=%d", c.felixFails))
		// W8-NM3: a felix datapath whose readiness stayed dark
		// across calicoFelixRestartFails consecutive cycles is a
		// real wedge, not a flap — delete the calico-node pod so
		// the DaemonSet rebuilds it (last-calico-restart budget).
		if c.felixFails >= calicoFelixRestartFails {
			switch {
			case c.h.state.Exists("node-overloaded"):
				c.h.state.AppendLog(fmt.Sprintf(
					"suspect: calico-felix-down %dx but node overloaded — skip pod restart", c.felixFails))
			case !c.h.state.RateTrySpend("last-calico-restart", c.h.cfg.MinRestartInterval):
				c.h.state.AppendLog(fmt.Sprintf(
					"suspect: calico-felix-down %dx but pod restart in cooldown (<30m), skip", c.felixFails))
			default:
				// Budget spent atomically BEFORE the delete.
				c.h.state.AppendLog(fmt.Sprintf(
					"ACTION: calico-hygiene deleted pod %s/%s - felix readiness down %dx",
					felix.Namespace, felix.Name, c.felixFails))
				if derr := c.h.cfg.Client.CoreV1().Pods(felix.Namespace).Delete(
					ctx, felix.Name, metav1.DeleteOptions{
						GracePeriodSeconds: ptr.To[int64](0)}); derr != nil {
					c.h.state.AppendLog(fmt.Sprintf(
						"suspect: calico-hygiene delete %s/%s failed: %v",
						felix.Namespace, felix.Name, derr))
				} else {
					c.h.actions.WithLabelValues(checkCalico, "pod_delete").Inc()
				}
			}
		}
	}
	c.h.cycles.WithLabelValues(checkCalico, "ok").Inc()
}

// checkCalicoHygiene forwards to the migrated Check — tests written
// before the interface still call the old method shape.
func (h *Hygiene) checkCalicoHygiene(ctx context.Context, pods []corev1.Pod,
	apiOK, workerActive bool) {
	h.calico.Run(ctx, &cycleEnv{
		pods: pods, apiOK: apiOK, workerActive: workerActive})
}

// gcCalicoOrphanVeths reaps cali* host veths that have been DOWN
// (carrier 0) for calicoVethGCMinAge — the orphans a failed CNI
// DEL leaks: they still carry iptables routes and keep the leak
// count climbing even after the latch fired. Confirmation goes
// through a veth-seen-<name> marker in the state dir (the
// wedged-seen-* pattern — a single down read is not enough: an
// iface mid-creation reads carrier 0 briefly). Markers for ifaces
// that vanished or came back up are pruned.
func (h *Hygiene) gcCalicoOrphanVeths(ctx context.Context) {
	entries, err := os.ReadDir(h.cfg.Net.SysClassNet)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "cali") {
			continue
		}
		marker := filepath.Join(h.cfg.WatchdogStateDir, "veth-seen-"+name)
		carrier, err := os.ReadFile(filepath.Join(h.cfg.Net.SysClassNet, name, "carrier"))
		if err != nil {
			continue // racing an iface add/remove — neither up nor down
		}
		if strings.TrimSpace(string(carrier)) != "0" {
			// Live veth — a stale marker from an earlier leak
			// episode must not carry into this one.
			_ = os.Remove(marker)
			continue
		}
		if !h.stateFileExists("veth-seen-" + name) {
			h.state.RateSpend("veth-seen-" + name)
			h.state.AppendLog(fmt.Sprintf(
				"calico-hygiene: orphan veth candidate %s - carrier down, confirm in %dm",
				name, int(calicoVethGCMinAge.Minutes())))
			continue
		}
		if !h.state.RateOK("veth-seen-"+name, calicoVethGCMinAge) {
			continue
		}
		if h.cfg.Systemd == nil {
			h.state.AppendLog(fmt.Sprintf(
				"suspect: calico-hygiene orphan veth %s down >%dm but no systemd client — skip delete",
				name, int(calicoVethGCMinAge.Minutes())))
			continue
		}
		out, derr := h.cfg.Systemd.Exec(ctx, "ip", "link", "delete", name)
		if derr != nil {
			h.state.AppendLog(fmt.Sprintf(
				"suspect: calico-hygiene ip link delete %s failed: %v (%s)",
				name, derr, strings.TrimSpace(out)))
			continue
		}
		_ = os.Remove(marker)
		h.state.AppendLog(fmt.Sprintf(
			"ACTION: calico-hygiene deleted orphan veth %s - carrier down >%dm (CNI DEL leak)",
			name, int(calicoVethGCMinAge.Minutes())))
		h.actions.WithLabelValues(checkCalico, "veth_delete").Inc()
	}
	// Prune markers for ifaces that no longer exist.
	if ms, err := filepath.Glob(
		filepath.Join(h.cfg.WatchdogStateDir, "veth-seen-*")); err == nil {
		for _, m := range ms {
			name := strings.TrimPrefix(filepath.Base(m), "veth-seen-")
			if _, err := os.Stat(filepath.Join(h.cfg.Net.SysClassNet, name)); err != nil {
				_ = os.Remove(m)
			}
		}
	}
}

// --- Check: orphan CNI netns reaper (W9) ---
// CNI plugins pin each pod sandbox's network namespace by
// bind-mounting its nsfs file at /run/netns/cni-<id>. A pod teardown
// that dies mid-DEL (crash, OOM kill, kubelet restart) leaks the
// mount: the file outlives the namespace, and `ip netns` listings
// accumulate dead entries that confuse operators and slow CNI
// scans. The reaper stats every cni-* file — the nsfs inode is the
// namespace's identity, shared with /proc/<pid>/ns/net for every
// process still inside it — and only a file whose inode NO live
// process references is an orphan. Confirmation is the
// cni-netns-seen-<name> two-pass marker (veth-seen-* parity): first
// sighting records the epoch, and only a file still unreferenced
// >= cniNetnsMinAge later is lazily unmounted + removed. The umount
// runs through the systemd nsenter wrapper so the HOST mount
// namespace is the one modified; the file removal uses the /host
// view (NetnsDir).

// netnsInode stats a netns file and returns the nsfs inode — the
// identity /proc/<pid>/ns/net entries share for the same network
// namespace (bind-mounted copies keep the inode).
func netnsInode(path string) (uint64, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Ino, true
}

// liveNetnsInodes collects the nsfs inode of every live process's
// network namespace. Unreadable entries are skipped — a pid that
// vanished mid-scan is not a reference.
func (h *Hygiene) liveNetnsInodes(pids []int) map[uint64]bool {
	out := map[uint64]bool{}
	for _, pid := range pids {
		if ino, ok := netnsInode(h.proc.File(pid, "ns", "net")); ok {
			out[ino] = true
		}
	}
	return out
}

// cniNetnsCheck is the W9 orphan /run/netns/cni-* reaper as a Check.
type cniNetnsCheck struct{ h *Hygiene }

// Name returns the check label / WD_SIG key.
func (c *cniNetnsCheck) Name() string { return checkCNINetns }

// Run executes one cni-netns-gc round.
func (c *cniNetnsCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.h.cycles.WithLabelValues(checkCNINetns, "gated").Inc()
		return
	}
	entries, err := os.ReadDir(c.h.cfg.Net.NetnsDir)
	if err != nil {
		if os.IsNotExist(err) {
			// No netns dir at all (non-CNI node, unmounted /run) —
			// prune stale markers and go quiet.
			c.h.pruneCNINetnsMarkers(nil)
			c.h.cycles.WithLabelValues(checkCNINetns, "ok").Inc()
			return
		}
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: cni-netns-gc read %s failed: %v — scan skipped",
			c.h.cfg.Net.NetnsDir, err))
		c.h.cycles.WithLabelValues(checkCNINetns, "abort").Inc()
		return
	}
	// Collect cni-* candidates first — the /proc ns/net stat sweep
	// only runs when there is something to check.
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "cni-") {
			continue
		}
		names = append(names, e.Name())
	}
	if len(names) == 0 {
		c.h.pruneCNINetnsMarkers(nil)
		c.h.cycles.WithLabelValues(checkCNINetns, "ok").Inc()
		return
	}
	live := c.h.liveNetnsInodes(e.pidsOnce())
	seen := map[string]bool{}
	for _, name := range names {
		seen[name] = true
		path := filepath.Join(c.h.cfg.Net.NetnsDir, name)
		ino, ok := netnsInode(path)
		if !ok {
			continue // vanished or unreadable — next cycle re-reads
		}
		if live[ino] {
			// A live process still sits in this netns — the mount
			// is real. Drop any stale marker so a later orphan
			// episode re-arms the full confirmation window.
			_ = os.Remove(filepath.Join(
				c.h.cfg.WatchdogStateDir, "cni-netns-seen-"+name))
			continue
		}
		marker := "cni-netns-seen-" + name
		if !c.h.stateFileExists(marker) {
			c.h.state.RateSpend(marker)
			c.h.state.AppendLog(fmt.Sprintf(
				"cni-netns-gc: orphan netns candidate %s - no live process, confirm in %dm",
				name, int(cniNetnsMinAge.Minutes())))
			continue
		}
		if !c.h.state.RateOK(marker, cniNetnsMinAge) {
			continue
		}
		// Re-stat before acting: the inode must STILL be
		// unreferenced (a process may have joined the netns since
		// the snapshot; `live` is a per-cycle map).
		ino2, ok2 := netnsInode(path)
		if !ok2 || live[ino2] {
			continue
		}
		c.h.reapCNINetns(ctx, name)
	}
	c.h.pruneCNINetnsMarkers(seen)
	c.h.cycles.WithLabelValues(checkCNINetns, "ok").Inc()
}

// checkOrphanCNINetns forwards to the migrated Check — tests written
// before the interface still call the old method shape.
func (h *Hygiene) checkOrphanCNINetns(ctx context.Context,
	pidsOnce func() []int, workerActive bool) {
	h.cniNetns.Run(ctx, &cycleEnv{
		pidsOnce: pidsOnce, workerActive: workerActive})
}

// reapCNINetns lazily unmounts the orphan netns bind-mount inside
// the HOST mount namespace, then removes the file under the /host
// view. The marker is dropped only after the umount succeeds — a
// failed umount keeps the confirmation so the next cycle retries.
func (h *Hygiene) reapCNINetns(ctx context.Context, name string) {
	if h.cfg.Systemd == nil {
		h.state.AppendLog(fmt.Sprintf(
			"suspect: cni-netns-gc orphan netns %s confirmed but no systemd client — skip umount",
			name))
		return
	}
	// The umount path is the HOST's /run/netns — NOT NetnsDir,
	// which is the /host-prefixed filesystem view used for scans.
	out, err := h.cfg.Systemd.Exec(ctx, "umount", "-l",
		"/run/netns/"+name)
	if err != nil {
		h.state.AppendLog(fmt.Sprintf(
			"suspect: cni-netns-gc umount /run/netns/%s failed: %v (%s) — keeping marker",
			name, err, strings.TrimSpace(out)))
		return
	}
	if rerr := os.Remove(filepath.Join(h.cfg.Net.NetnsDir, name)); rerr != nil &&
		!os.IsNotExist(rerr) {
		// The mount IS detached — the dangerous half is done; a
		// leftover plain file re-arms as a fresh candidate next
		// cycle rather than looping a doomed umount.
		h.state.AppendLog(fmt.Sprintf(
			"suspect: cni-netns-gc rm %s failed: %v — mount detached, file remains",
			filepath.Join(h.cfg.Net.NetnsDir, name), rerr))
	}
	_ = os.Remove(filepath.Join(
		h.cfg.WatchdogStateDir, "cni-netns-seen-"+name))
	h.state.AppendLog(fmt.Sprintf(
		"ACTION: cni-netns-gc reaped orphan netns %s - unmounted + removed (no live process >%dm)",
		name, int(cniNetnsMinAge.Minutes())))
	h.actions.WithLabelValues(checkCNINetns, "umount_rm").Inc()
}

// pruneCNINetnsMarkers drops cni-netns-seen-* markers whose netns
// file vanished — a file that reappeared referenced or was cleaned
// up by other means must not keep a stale confirmation armed.
func (h *Hygiene) pruneCNINetnsMarkers(seen map[string]bool) {
	ms, err := filepath.Glob(filepath.Join(
		h.cfg.WatchdogStateDir, "cni-netns-seen-*"))
	if err != nil {
		return
	}
	for _, m := range ms {
		name := strings.TrimPrefix(filepath.Base(m), "cni-netns-seen-")
		if seen != nil && seen[name] {
			continue
		}
		if _, err := os.Stat(filepath.Join(h.cfg.Net.NetnsDir, name)); err != nil {
			_ = os.Remove(m)
		}
	}
}

// --- Check: PSI memory thrash guard (W2) ---
// When the kernel is genuinely out of memory the LAST thing that
// should die is a system daemon — but the OOM killer scores by
// oom_score, not by "this box still needs a kubelet". A sustained
// memory-full stall (PSI `full avg60` > PSIFullAvg60) together with
// real free memory under MemFreeMinRatio means the node IS
// thrashing; for ConsecNeeded consecutive cycles the
// state-psi-memory-thrash latch fires and the highest-RSS eligible
// pod is evicted through the policy/v1 Eviction API (PDB-enforced,
// last-psi-evict 15m budget) — buying back headroom before the
// kernel picks a victim of its own (k0sworker, containerd, the
// agent itself). W9 hardening: a kernel-slab-leak latch suppresses
// the eviction entirely (a kernel leak is not a pod-size problem),
// and victim selection excludes system namespaces, critical
// priority classes, terminating pods, StatefulSet database/quorum
// members, and anything under the 512 MiB RSS floor.
