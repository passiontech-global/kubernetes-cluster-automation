package guards

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	// defaultNetnsDir is the host /run/netns mount — the CNI
	// netns-file leak reaper scans cni-* entries here.
	spegelMinPodAge = 3 * time.Minute
	// Wave-8 knobs: felix restart after the latch persisted this
	// many consecutive failed cycles, and the orphan-veth down-age
	// for the cali* GC.
	CalicoFelixRestartFails = 3
	calicoVethGCMinAge      = 15 * time.Minute
	// calicoProbeTimeout is the felix readiness probe deadline (5s,
	// curl --max-time 5 parity with the other admin probes).
	calicoProbeTimeout = 5 * time.Second
	// cniNetnsMinAge is the orphan CNI netns confirmation age
	// (Wave-9).
	cniNetnsMinAge = 30 * time.Minute
	// cniNetnsMaxReapPerCycle bounds the per-cycle umount blast
	// radius (W12-KR2) — a mass CNI DEL failure can leak dozens of
	// netns mounts at once; the reaper drains them at a fixed rate
	// rather than stalling the check budget on one cycle.
	cniNetnsMaxReapPerCycle = 10
)

var (
	// W7 pod matchers — anchored like konnPodRe/dnsPodRe.
	spegelPodRe     = regexp.MustCompile(`^spegel-[a-z0-9]+$`)      // H4 P2P mirror
	calicoNodePodRe = regexp.MustCompile(`^calico-node-[a-z0-9]+$`) // H7 felix
)

// SpegelCheck is the W7-H4 mirror-peer guard as a Check; it owns
// the Ready=False streak (ex-Hygiene.spegelFails).
type SpegelCheck struct {
	d     *wdeps.Deps
	Fails int
}

// Name returns the check label / WD_SIG key.
func (c *SpegelCheck) Name() string { return wdeps.CheckSpegel }

// Run executes one spegel-mirror round.
func (c *SpegelCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckSpegel, "gated").Inc()
		return
	}
	if !e.APIOK {
		// Inconclusive — keep streak/latch exactly like teardown.
		c.d.Cycles.WithLabelValues(wdeps.CheckSpegel, "abort").Inc()
		return
	}
	var sp *corev1.Pod
	for i := range e.Pods {
		p := &e.Pods[i]
		if (p.Namespace != "spegel" && p.Namespace != "kube-system") ||
			!spegelPodRe.MatchString(p.Name) ||
			p.DeletionTimestamp != nil ||
			p.Status.Phase != corev1.PodRunning ||
			c.d.Cfg.Seams.Host.NowFn().Sub(p.CreationTimestamp.Time) < spegelMinPodAge {
			continue
		}
		sp = p
		break
	}
	if sp == nil || wdeps.PodReady(sp) {
		// No spegel DS on this node, or the pod is healthy — either
		// way the mirror datapath isn't our problem; clear stale
		// evidence like wdeps.CheckCilium's no-agent path.
		c.Fails = 0
		c.d.State.Exit(hoststate.LatchSpegelMirrorDegraded, nil)
		c.d.Cycles.WithLabelValues(wdeps.CheckSpegel, "ok").Inc()
		return
	}
	c.Fails++
	if c.Fails < c.d.Cfg.ConsecNeeded {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: spegel-mirror pod %s/%s Ready=False (check %d/%d)",
			sp.Namespace, sp.Name, c.Fails, c.d.Cfg.ConsecNeeded))
		c.d.Cycles.WithLabelValues(wdeps.CheckSpegel, "ok").Inc()
		return
	}
	c.d.State.Enter(hoststate.LatchSpegelMirrorDegraded,
		fmt.Sprintf("pod=%s/%s ready_fails=%d", sp.Namespace, sp.Name, c.Fails))
	if !c.d.State.RateTrySpend("last-spegel-restart", c.d.Cfg.MinRestartInterval) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: spegel-mirror %s/%s Ready=False %dx but restart in cooldown (<30m), skip",
			sp.Namespace, sp.Name, c.Fails))
		c.d.Cycles.WithLabelValues(wdeps.CheckSpegel, "ok").Inc()
		return
	}
	// Budget spent atomically BEFORE the delete (rate_spend parity).
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: spegel-mirror deleted pod %s/%s - Ready=False %dx (containerd mirror points at a wedged peer)",
		sp.Namespace, sp.Name, c.Fails))
	if err := c.d.Cfg.Client.CoreV1().Pods(sp.Namespace).Delete(ctx, sp.Name,
		metav1.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)}); err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: spegel-mirror delete %s/%s failed: %v",
			sp.Namespace, sp.Name, err))
	} else {
		c.Fails = 0
		c.d.Actions.WithLabelValues(wdeps.CheckSpegel, "pod_delete").Inc()
	}
	c.d.Cycles.WithLabelValues(wdeps.CheckSpegel, "ok").Inc()
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
func calicoIfaceCount(d *wdeps.Deps) int {
	entries, err := os.ReadDir(d.Cfg.SysClassNet)
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

// CalicoCheck is the W7-H7 calico guard as a Check; it owns the
// veth-leak and felix readiness streaks (ex-Hygiene.calicoVethFails/
// .calicoFelixFails).
type CalicoCheck struct {
	d          *wdeps.Deps
	VethFails  int
	felixFails int
}

// Name returns the check label / WD_SIG key.
func (c *CalicoCheck) Name() string { return wdeps.CheckCalico }

// Run executes one calico-hygiene round.
func (c *CalicoCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckCalico, "gated").Inc()
		return
	}
	if _, err := os.Stat(filepath.Join(c.d.Cfg.SysClassNet, "cilium_host")); err == nil {
		// Cilium node — every calico verdict belongs to the cilium
		// guard family; drop stale evidence like checkCiliumWGPeers.
		c.VethFails = 0
		c.felixFails = 0
		c.d.State.Exit(hoststate.LatchCalicoVethLeak, nil)
		c.d.State.Exit(hoststate.LatchCalicoFelixDown, nil)
		c.d.Cycles.WithLabelValues(wdeps.CheckCalico, "ok").Inc()
		return
	}
	cali := calicoIfaceCount(c.d)
	if cali <= 0 {
		// No cali* veth at all — not a calico node (unreadable
		// sysfs reports -1 the same way: nothing to verify).
		c.VethFails = 0
		c.felixFails = 0
		c.d.State.Exit(hoststate.LatchCalicoVethLeak, nil)
		c.d.State.Exit(hoststate.LatchCalicoFelixDown, nil)
		c.d.Cycles.WithLabelValues(wdeps.CheckCalico, "ok").Inc()
		return
	}
	if !e.APIOK {
		// Pod count is the leak baseline — an API flake makes the
		// comparison invalid. Keep streaks/latches (inconclusive).
		c.d.Cycles.WithLabelValues(wdeps.CheckCalico, "abort").Inc()
		return
	}
	// Check 1 — orphan veth leak.
	if cali > len(e.Pods)+c.d.Cfg.Calico.OrphanVethThreshold {
		c.VethFails++
		if c.VethFails >= c.d.Cfg.ConsecNeeded {
			if !c.d.State.Exists(hoststate.LatchCalicoVethLeak) {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: calico-hygiene orphan veth leak cali=%d pods=%d threshold=%d — CNI DEL cleanup is leaking veth pairs",
					cali, len(e.Pods), c.d.Cfg.Calico.OrphanVethThreshold))
			}
			c.d.State.Enter(hoststate.LatchCalicoVethLeak,
				fmt.Sprintf("cali=%d pods=%d", cali, len(e.Pods)))
		} else {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: calico-hygiene veth leak candidate cali=%d pods=%d (check %d/%d)",
				cali, len(e.Pods), c.VethFails, c.d.Cfg.ConsecNeeded))
		}
	} else {
		c.VethFails = 0
		c.d.State.Exit(hoststate.LatchCalicoVethLeak, nil)
	}
	// Check 1b — orphan-veth GC (W8-NM3): while the leak latch is
	// set, reap cali* host veths that stayed DOWN (carrier 0) for
	// calicoVethGCMinAge. Live veths always answer carrier=1; a
	// leaked one from a failed CNI DEL is DOWN forever. The
	// veth-seen-<name> marker provides the 15m age — same
	// confirm-marker shape as wedged-seen-* (a veth must not be
	// deleted on a single read: an interface mid-creation can read
	// carrier 0 for a moment).
	if c.d.State.Exists(hoststate.LatchCalicoVethLeak) {
		gcCalicoOrphanVeths(c.d, ctx)
	}
	// Check 2 — felix readiness, gated on a Running calico-node pod
	// on this node (no pod → nothing to probe).
	var felix *corev1.Pod
	for i := range e.Pods {
		p := &e.Pods[i]
		if (p.Namespace == "kube-system" || p.Namespace == "calico-system") &&
			calicoNodePodRe.MatchString(p.Name) &&
			p.DeletionTimestamp == nil && p.Status.Phase == corev1.PodRunning {
			felix = p
			break
		}
	}
	switch {
	case felix == nil || c.d.Cfg.Calico.FelixReadyURL == "":
		c.felixFails = 0
		c.d.State.Exit(hoststate.LatchCalicoFelixDown, nil)
	default:
		code, err := c.d.Cfg.Seams.Probe.ProbeHTTPStatus(ctx,
			c.d.Cfg.Calico.FelixReadyURL, "", calicoProbeTimeout)
		if err == nil && code == http.StatusOK {
			c.felixFails = 0
			c.d.State.Exit(hoststate.LatchCalicoFelixDown, nil)
			break
		}
		c.felixFails++
		if c.felixFails < c.d.Cfg.ConsecNeeded {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: calico-felix-down readiness probe code=%d err=%v (check %d/%d)",
				code, err, c.felixFails, c.d.Cfg.ConsecNeeded))
			break
		}
		c.d.State.Enter(hoststate.LatchCalicoFelixDown,
			fmt.Sprintf("readiness_probe_fails=%d", c.felixFails))
		// W8-NM3: a felix datapath whose readiness stayed dark
		// across CalicoFelixRestartFails consecutive cycles is a
		// real wedge, not a flap — delete the calico-node pod so
		// the DaemonSet rebuilds it (last-calico-restart budget).
		if c.felixFails >= CalicoFelixRestartFails {
			switch {
			case c.d.State.Exists(hoststate.LatchNodeOverloaded):
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: calico-felix-down %dx but node overloaded — skip pod restart", c.felixFails))
			case !c.d.State.RateTrySpend("last-calico-restart", c.d.Cfg.MinRestartInterval):
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: calico-felix-down %dx but pod restart in cooldown (<30m), skip", c.felixFails))
			default:
				// Budget spent atomically BEFORE the delete.
				c.d.State.AppendLog(fmt.Sprintf(
					"ACTION: calico-hygiene deleted pod %s/%s - felix readiness down %dx",
					felix.Namespace, felix.Name, c.felixFails))
				if derr := c.d.Cfg.Client.CoreV1().Pods(felix.Namespace).Delete(
					ctx, felix.Name, metav1.DeleteOptions{
						GracePeriodSeconds: ptr.To[int64](0)}); derr != nil {
					c.d.State.AppendLog(fmt.Sprintf(
						"suspect: calico-hygiene delete %s/%s failed: %v",
						felix.Namespace, felix.Name, derr))
				} else {
					c.d.Actions.WithLabelValues(wdeps.CheckCalico, "pod_delete").Inc()
				}
			}
		}
	}
	c.d.Cycles.WithLabelValues(wdeps.CheckCalico, "ok").Inc()
}

// gcCalicoOrphanVeths reaps cali* host veths that have been DOWN
// (carrier 0) for calicoVethGCMinAge — the orphans a failed CNI
// DEL leaks: they still carry iptables routes and keep the leak
// count climbing even after the latch fired. Confirmation goes
// through a veth-seen-<name> marker in the state dir (the
// wedged-seen-* pattern — a single down read is not enough: an
// iface mid-creation reads carrier 0 briefly). Markers for ifaces
// that vanished or came back up are pruned.
func gcCalicoOrphanVeths(d *wdeps.Deps, ctx context.Context) {
	entries, err := os.ReadDir(d.Cfg.SysClassNet)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "cali") {
			continue
		}
		marker := filepath.Join(d.Cfg.WatchdogStateDir, "veth-seen-"+name)
		carrier, err := os.ReadFile(filepath.Join(d.Cfg.SysClassNet, name, "carrier"))
		if err != nil {
			continue // racing an iface add/remove — neither up nor down
		}
		if strings.TrimSpace(string(carrier)) != "0" {
			// Live veth — a stale marker from an earlier leak
			// episode must not carry into this one.
			_ = os.Remove(marker)
			continue
		}
		if !d.StateFileExists("veth-seen-" + name) {
			d.State.RateSpend("veth-seen-" + name)
			d.State.AppendLog(fmt.Sprintf(
				"calico-hygiene: orphan veth candidate %s - carrier down, confirm in %dm",
				name, int(calicoVethGCMinAge.Minutes())))
			continue
		}
		if !d.State.RateOK("veth-seen-"+name, calicoVethGCMinAge) {
			continue
		}
		if d.Cfg.Systemd == nil {
			d.State.AppendLog(fmt.Sprintf(
				"suspect: calico-hygiene orphan veth %s down >%dm but no systemd client — skip delete",
				name, int(calicoVethGCMinAge.Minutes())))
			continue
		}
		out, derr := d.Cfg.Systemd.Exec(ctx, "ip", "link", "delete", name)
		if derr != nil {
			d.State.AppendLog(fmt.Sprintf(
				"suspect: calico-hygiene ip link delete %s failed: %v (%s)",
				name, derr, strings.TrimSpace(out)))
			continue
		}
		_ = os.Remove(marker)
		d.State.AppendLog(fmt.Sprintf(
			"ACTION: calico-hygiene deleted orphan veth %s - carrier down >%dm (CNI DEL leak)",
			name, int(calicoVethGCMinAge.Minutes())))
		d.Actions.WithLabelValues(wdeps.CheckCalico, "veth_delete").Inc()
	}
	// Prune markers for ifaces that no longer exist.
	if ms, err := filepath.Glob(
		filepath.Join(d.Cfg.WatchdogStateDir, "veth-seen-*")); err == nil {
		for _, m := range ms {
			name := strings.TrimPrefix(filepath.Base(m), "veth-seen-")
			if _, err := os.Stat(filepath.Join(d.Cfg.SysClassNet, name)); err != nil {
				_ = os.Remove(m)
			}
		}
	}
}

// --- Check: orphan CNI netns reaper (W9, hardened W12-KR2) ---
// CNI plugins pin each pod sandbox's network namespace by
// bind-mounting its nsfs file at /run/netns/cni-<id>. A pod teardown
// that dies mid-DEL (crash, OOM kill, kubelet restart) leaks the
// mount: the file outlives the namespace, and `ip netns` listings
// accumulate dead entries that confuse operators and slow CNI
// scans — worse, a leaked net_namespace slab keeps Cilium IPAM from
// reclaiming the pod IP and pins any hostPort it held. The reaper
// stats every cni-* file — the nsfs inode is the namespace's
// identity, shared with /proc/<pid>/ns/net for every process still
// inside it — and only a file whose inode NO live process
// references is an orphan. Confirmation is the
// cni-netns-seen-<name> two-pass marker (veth-seen-* parity): first
// sighting records the epoch, and only a file still unreferenced
// >= cniNetnsMinAge later is lazily unmounted + removed. The umount
// runs through the systemd nsenter wrapper so the HOST mount
// namespace is the one modified; the file removal uses the /host
// view (NetnsDir). W12-KR2 adds three qualifiers to the reap
// itself: the file mtime must be older than the confirm window
// (a just-created mount point the sweep raced is never an
// orphan), the containerd task map must not show a live task
// still inside the netns, and reaps cap at
// cniNetnsMaxReapPerCycle per cycle. The scan runs on every
// worker — Cilium AND Calico pin netns the same way.

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
func liveNetnsInodes(d *wdeps.Deps, pids []int) map[uint64]bool {
	out := map[uint64]bool{}
	for _, pid := range pids {
		if ino, ok := netnsInode(d.Proc.File(pid, "ns", "net")); ok {
			out[ino] = true
		}
	}
	return out
}

// netnsHeldByLiveTask reports whether any containerd task with a
// live init pid still sits inside the netns inode — the
// containerd-side half of the W12-KR2 orphan verdict (a live task
// pins the sandbox netns even when the /proc sweep raced it).
func netnsHeldByLiveTask(d *wdeps.Deps, tasks map[string][]wdeps.CtrTask,
	ino uint64) bool {

	for _, ts := range tasks {
		for _, t := range ts {
			if !t.Live || t.PID <= 0 {
				continue
			}
			if tino, ok := netnsInode(d.Proc.File(t.PID, "ns", "net")); ok &&
				tino == ino {
				return true
			}
		}
	}
	return false
}

// CNINetnsCheck is the W9 orphan /run/netns/cni-* reaper as a Check.
type CNINetnsCheck struct{ d *wdeps.Deps }

// Name returns the check label / WD_SIG key.
func (c *CNINetnsCheck) Name() string { return wdeps.CheckCNINetns }

// Run executes one cni-netns-gc round.
func (c *CNINetnsCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckCNINetns, "gated").Inc()
		return
	}
	entries, err := os.ReadDir(c.d.Cfg.Net.NetnsDir)
	if err != nil {
		if os.IsNotExist(err) {
			// No netns dir at all (non-CNI node, unmounted /run) —
			// prune stale markers and go quiet.
			pruneCNINetnsMarkers(c.d, nil)
			c.d.Cycles.WithLabelValues(wdeps.CheckCNINetns, "ok").Inc()
			return
		}
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: cni-netns-gc read %s failed: %v — scan skipped",
			c.d.Cfg.Net.NetnsDir, err))
		c.d.Cycles.WithLabelValues(wdeps.CheckCNINetns, "abort").Inc()
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
		pruneCNINetnsMarkers(c.d, nil)
		c.d.Cycles.WithLabelValues(wdeps.CheckCNINetns, "ok").Inc()
		return
	}
	live := liveNetnsInodes(c.d, e.PidsOnce())
	seen := map[string]bool{}
	reaped := 0
	for _, name := range names {
		seen[name] = true
		path := filepath.Join(c.d.Cfg.Net.NetnsDir, name)
		ino, ok := netnsInode(path)
		if !ok {
			continue // vanished or unreadable — next cycle re-reads
		}
		if live[ino] {
			// A live process still sits in this netns — the mount
			// is real. Drop any stale marker so a later orphan
			// episode re-arms the full confirmation window.
			_ = os.Remove(filepath.Join(
				c.d.Cfg.WatchdogStateDir, "cni-netns-seen-"+name))
			continue
		}
		marker := "cni-netns-seen-" + name
		if !c.d.StateFileExists(marker) {
			c.d.State.RateSpend(marker)
			c.d.State.AppendLog(fmt.Sprintf(
				"cni-netns-gc: orphan netns candidate %s - no live process, confirm in %dm",
				name, int(cniNetnsMinAge.Minutes())))
			continue
		}
		if !c.d.State.RateOK(marker, cniNetnsMinAge) {
			continue
		}
		// Re-stat before acting: the inode must STILL be
		// unreferenced (a process may have joined the netns since
		// the snapshot; `live` is a per-cycle map).
		ino2, ok2 := netnsInode(path)
		if !ok2 || live[ino2] {
			continue
		}
		// W12-KR2: the netns file itself must be older than the
		// confirm window — a just-created mount point whose sweep
		// raced the CNI ADD is not an orphan no matter what the
		// inode check says.
		if fi, err := os.Stat(path); err != nil ||
			c.d.Cfg.Seams.Host.NowFn().Sub(fi.ModTime()) < cniNetnsMinAge {
			continue
		}
		// W12-KR2: the containerd task map is the stronger liveness
		// verdict — a live task pins its sandbox netns even when
		// the pid sweep raced it. An unreadable map makes "no
		// live task" unverifiable → fail closed, retry next cycle.
		if e.TasksOnce != nil {
			tasks, complete := e.TasksOnce()
			if !complete || netnsHeldByLiveTask(c.d, tasks, ino2) {
				continue
			}
		}
		if reaped >= cniNetnsMaxReapPerCycle {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: cni-netns-gc reap cap %d reached — remaining orphans drain next cycle",
				cniNetnsMaxReapPerCycle))
			break
		}
		reapCNINetns(c.d, ctx, name)
		reaped++
	}
	pruneCNINetnsMarkers(c.d, seen)
	c.d.Cycles.WithLabelValues(wdeps.CheckCNINetns, "ok").Inc()
}

// reapCNINetns lazily unmounts the orphan netns bind-mount inside
// the HOST mount namespace, then removes the file under the /host
// view. The marker is dropped only after the umount succeeds — a
// failed umount keeps the confirmation so the next cycle retries.
func reapCNINetns(d *wdeps.Deps, ctx context.Context, name string) {
	if d.Cfg.Systemd == nil {
		d.State.AppendLog(fmt.Sprintf(
			"suspect: cni-netns-gc orphan netns %s confirmed but no systemd client — skip umount",
			name))
		return
	}
	// The umount path is the HOST's /run/netns — NOT NetnsDir,
	// which is the /host-prefixed filesystem view used for scans.
	out, err := d.Cfg.Systemd.Exec(ctx, "umount", "-l",
		"/run/netns/"+name)
	if err != nil {
		d.State.AppendLog(fmt.Sprintf(
			"suspect: cni-netns-gc umount /run/netns/%s failed: %v (%s) — keeping marker",
			name, err, strings.TrimSpace(out)))
		return
	}
	if rerr := os.Remove(filepath.Join(d.Cfg.Net.NetnsDir, name)); rerr != nil &&
		!os.IsNotExist(rerr) {
		// The mount IS detached — the dangerous half is done; a
		// leftover plain file re-arms as a fresh candidate next
		// cycle rather than looping a doomed umount.
		d.State.AppendLog(fmt.Sprintf(
			"suspect: cni-netns-gc rm %s failed: %v — mount detached, file remains",
			filepath.Join(d.Cfg.Net.NetnsDir, name), rerr))
	}
	_ = os.Remove(filepath.Join(
		d.Cfg.WatchdogStateDir, "cni-netns-seen-"+name))
	d.State.AppendLog(fmt.Sprintf(
		"ACTION: cni-netns-gc reaped orphan netns %s - unmounted + removed (no live process >%dm)",
		name, int(cniNetnsMinAge.Minutes())))
	d.Actions.WithLabelValues(wdeps.CheckCNINetns, "umount_rm").Inc()
}

// pruneCNINetnsMarkers drops cni-netns-seen-* markers whose netns
// file vanished — a file that reappeared referenced or was cleaned
// up by other means must not keep a stale confirmation armed.
func pruneCNINetnsMarkers(d *wdeps.Deps, seen map[string]bool) {
	ms, err := filepath.Glob(filepath.Join(
		d.Cfg.WatchdogStateDir, "cni-netns-seen-*"))
	if err != nil {
		return
	}
	for _, m := range ms {
		name := strings.TrimPrefix(filepath.Base(m), "cni-netns-seen-")
		if seen != nil && seen[name] {
			continue
		}
		if _, err := os.Stat(filepath.Join(d.Cfg.Net.NetnsDir, name)); err != nil {
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
