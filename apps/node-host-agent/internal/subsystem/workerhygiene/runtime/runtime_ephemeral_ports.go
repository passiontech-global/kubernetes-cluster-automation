// runtime_ephemeral_ports.go — the ephemeral-port-pressure check
// (wdeps.CheckEphemeralPorts, P0.3): per-destination ephemeral port
// exhaustion and CLOSE_WAIT socket leaks on a churn-heavy node.
//
// Evidence comes from ONE netlink sock-diag census per cycle
// (netlinkx.TCPTables on pid 1 — the host netns): the per-state
// histogram gives CLOSE_WAIT and SYN_SENT counts without forking
// ss/conntrack, and the socket total bounds ephemeral-port usage
// against /proc/sys/net/ipv4/ip_local_port_range. Two remedies ride
// the same verdict:
//
//   - SYN_SENT reaper (Wave2.SynSentKillEnabled): sockets wedged in
//     SYN_SENT hold an ephemeral local port until the kernel's
//     retransmit timeout gives up (minutes); past the floor the
//     check SOCK_DESTROYs them via netlinkx.DestroyStuckSynSent —
//     the in-process `ss -K` equivalent, no fork.
//   - CLOSE_WAIT pod evictor (Wave2.PortEvictRunawayPod): CLOSE_WAIT
//     inodes are mapped back to pods through /proc/<pid>/fd →
//     cgroup → pod UID; a pod holding >= PortLeakMinPct of the
//     node's leaking sockets for >= PortLeakWindowSec (the
//     Store.ConfirmMarker two-phase window) is evicted through the
//     shared rails — protection maps, maintenance hold, per-pod
//     cooldown — with a UID-preconditioned delete.
//
// Pressure (tuple ratio >= PortTupleRatioThreshold OR CLOSE_WAIT >=
// PortCloseWaitMax) latches state-ephemeral-port-pressure →
// NodeCondition EphemeralPortPressure after ConsecNeeded cycles and
// releases only on the clear path (<= 0.65 AND <= 2048 — the
// hysteresis band between warn and clear keeps the latch stable).
package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/netlinkx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	// tcpStateCloseWait / tcpStateSynSent are the idiag_state ids
	// (include/net/tcp_states.h) the census histogram keys on.
	tcpStateSynSent   = 2
	tcpStateCloseWait = 8
	tcpStateListen    = 10
	// synSentKillFloor is the minimum SYN_SENT census before the
	// reaper fires — below it the kernel's own retransmit timeout
	// drains the table faster than a destroy storm would help.
	synSentKillFloor = 32
	// portRangePath is the proc sysctl bounding ephemeral ports.
	portRangeRel = "sys/net/ipv4/ip_local_port_range"
	// P0.3 clear hysteresis: the pressure latch arms at
	// PortTupleRatioThreshold/PortCloseWaitMax but only releases
	// once BOTH signals fall to the clear bounds — the band
	// between the two keeps the latch state so a borderline node
	// cannot flap the condition every cycle.
	portClearRatio     = 0.65
	portClearCloseWait = 2048
	// minCloseWaitFloor prevents evicting a pod over 1-10 CLOSE_WAIT sockets
	// when a node is healthy or portRangeCeiling is small in tests.
	minCloseWaitFloor = 1000
)

// EphemeralPortsCheck is the P0.3 guard as a Check; it owns the
// pressure pending streak and the per-pod leak-window markers.
type EphemeralPortsCheck struct {
	d     *wdeps.Deps
	fails int
}

// NewEphemeralPorts builds the check.
func NewEphemeralPorts(d *wdeps.Deps) *EphemeralPortsCheck {
	return &EphemeralPortsCheck{d: d}
}

// Name returns the check label / WD_SIG key.
func (c *EphemeralPortsCheck) Name() string { return wdeps.CheckEphemeralPorts }

// portRangeCeiling reads ip_local_port_range ("32768 60999") and
// returns the usable ephemeral span. ok=false when unreadable —
// the ratio evidence is then inconclusive (CLOSE_WAIT absolute
// count still applies).
func (c *EphemeralPortsCheck) portRangeCeiling() (int, bool) {
	data, err := os.ReadFile(filepath.Join(c.d.Cfg.ProcRoot, portRangeRel))
	if err != nil {
		return 0, false
	}
	f := strings.Fields(string(data))
	if len(f) < 2 {
		return 0, false
	}
	lo, err1 := strconv.Atoi(f[0])
	hi, err2 := strconv.Atoi(f[1])
	if err1 != nil || err2 != nil || hi <= lo {
		return 0, false
	}
	return hi - lo + 1, true
}

// netnsReps returns one representative pid per distinct network
// namespace visible in the pid sweep, pid 1 first (the host netns —
// the pre-P0.3 census target). A pod with hostNetwork:false lives
// in its own /proc/<pid>/ns/net, so a pid-1-only sock_diag dump is
// blind to every workload socket — the census MUST fan out across
// netns or CLOSE_WAIT/SYN_SENT evidence silently reads zero on a
// healthy-looking node. Dedup by the net:[inode] link keeps
// hostNetwork pods and processes sharing a netns to one dump.
func (c *EphemeralPortsCheck) netnsReps(pids []int) []int {
	reps, _ := c.netnsRepsChecked(pids)
	return reps
}

func (c *EphemeralPortsCheck) netnsRepsChecked(pids []int) ([]int, bool) {
	seen := map[string]bool{}
	reps := []int{}
	nonENOENT := false
	add := func(pid int) {
		link, err := os.Readlink(c.d.Proc.File(pid, "ns", "net"))
		if err != nil {
			if !os.IsNotExist(err) {
				nonENOENT = true
			}
			return
		}
		if seen[link] {
			return
		}
		seen[link] = true
		reps = append(reps, pid)
	}
	// pid 1 anchors the host netns even when its ns link is
	// unreadable — TCPTables(1) was the original census target.
	reps = append(reps, 1)
	if link, err := os.Readlink(c.d.Proc.File(1, "ns", "net")); err == nil {
		seen[link] = true
	} else if !os.IsNotExist(err) {
		nonENOENT = true
	}
	for _, pid := range pids {
		if pid == 1 {
			continue
		}
		add(pid)
	}
	return reps, nonENOENT
}

// Run executes one ephemeral-port-pressure round.
func (c *EphemeralPortsCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckEphemeralPorts) {
		return
	}
	pids, pidsOK := c.d.CyclePIDs(e)
	if !pidsOK {
		c.d.CycleResult(wdeps.CheckEphemeralPorts, "inconclusive")
		return
	}
	reps, netnsErr := c.netnsRepsChecked(pids)
	if netnsErr {
		c.d.CycleResult(wdeps.CheckEphemeralPorts, "abort")
		return
	}

	ceiling, ceilingOK := c.portRangeCeiling()
	if !ceilingOK || ceiling <= 0 {
		ceiling = c.d.Cfg.Wave2.MaxConcurrent
	}

	// Evaluate per network namespace (never sum sockets across 50+
	// independent pod netns against one host ephemeral port range).
	tcpTables := c.d.Cfg.Seams.Host.TCPTablesFn
	if tcpTables == nil {
		tcpTables = netlinkx.TCPTables
	}
	synSentByRep := map[int]int{}
	ok := 0
	maxUsed := 0
	maxCloseWait := 0
	totalSynSent := 0
	maxRatio := 0.0
	for _, rep := range reps {
		cen, err := tcpTables(rep)
		if err != nil {
			continue // per-netns inconclusive — the rest still count
		}
		ok++
		nsCloseWait := cen.States[tcpStateCloseWait]
		nsSynSent := cen.States[tcpStateSynSent]
		synSentByRep[rep] = nsSynSent
		totalSynSent += nsSynSent
		nsUsed := 0
		for st, n := range cen.States {
			if st != tcpStateListen {
				nsUsed += n
			}
		}
		if nsUsed > maxUsed {
			maxUsed = nsUsed
		}
		if nsCloseWait > maxCloseWait {
			maxCloseWait = nsCloseWait
		}
		if ceiling > 0 {
			if r := float64(nsUsed) / float64(ceiling); r > maxRatio {
				maxRatio = r
			}
		}
	}
	if ok == 0 {
		c.d.CycleResult(wdeps.CheckEphemeralPorts, "inconclusive")
		return
	}
	pressured := maxRatio >= c.d.Cfg.Wave2.PortTupleRatioThreshold ||
		maxCloseWait >= c.d.Cfg.Wave2.PortCloseWaitMax
	cleared := maxRatio <= portClearRatio && maxCloseWait <= portClearCloseWait

	// Remedies run on evidence, not on the latch — a SYN_SENT pile
	// or a leaking pod is actionable even below the warn ratio.
	c.reapSynSent(ctx, synSentByRep)
	evictOK := c.evictPortLeakers(ctx, e, maxCloseWait, ceiling, reps, pids)

	if cleared {
		if !evictOK {
			c.d.CycleResult(wdeps.CheckEphemeralPorts, "abort")
			return
		}
		c.fails = 0
		c.d.State.Exit(latchdefs.LatchEphemeralPortPressure, nil)
		c.d.CycleResult(wdeps.CheckEphemeralPorts, "ok")
		return
	}
	if !pressured {
		// Hysteresis band: pressure eased below the warn bounds but
		// not to the clear bounds — keep the latch state and the
		// pending streak untouched so the boundary cannot flap.
		if !evictOK {
			c.d.CycleResult(wdeps.CheckEphemeralPorts, "abort")
			return
		}
		c.d.CycleResult(wdeps.CheckEphemeralPorts, "ok")
		return
	}
	if c.d.StreakPending(&c.fails, fmt.Sprintf(
		"suspect: ephemeral-port-pressure used=%d/%d (%.0f%%) close_wait=%d syn_sent=%d",
		maxUsed, ceiling, maxRatio*100, maxCloseWait, totalSynSent)) {
		if !evictOK {
			c.d.CycleResult(wdeps.CheckEphemeralPorts, "abort")
			return
		}
		c.d.CycleResult(wdeps.CheckEphemeralPorts, "ok")
		return
	}
	c.d.State.Enter(latchdefs.LatchEphemeralPortPressure,
		fmt.Sprintf("used=%d/%d close_wait=%d syn_sent=%d",
			maxUsed, ceiling, maxCloseWait, totalSynSent))
	if !evictOK {
		c.d.CycleResult(wdeps.CheckEphemeralPorts, "abort")
		return
	}
	c.d.CycleResult(wdeps.CheckEphemeralPorts, "ok")
}

// reapSynSent destroys wedged SYN_SENT sockets per netns — each
// rep pid's census count gates its own destroy pass inside that
// netns, bounded by the floor and the kill knob.
func (c *EphemeralPortsCheck) reapSynSent(ctx context.Context, synSentByRep map[int]int) {
	if !c.d.Cfg.Wave2.SynSentKillEnabled {
		return
	}
	minRetrans := c.d.Cfg.Wave2.SynSentMinRetrans
	if minRetrans < 1 {
		minRetrans = 1
	} else if minRetrans > 255 {
		minRetrans = 255
	}
	holdChecked := false
	held := false
	for rep, synSent := range synSentByRep {
		if synSent < synSentKillFloor {
			continue
		}
		if !holdChecked {
			holdChecked = true
			held = c.d.HoldLocalAction(ctx)
		}
		if held {
			c.d.State.AppendLog(
				"cleanup: ephemeral-port-pressure syn_sent destroy held - cluster maintenance in progress")
			return
		}
		killed, err := netlinkx.DestroyStuckSynSent(rep,
			uint8(minRetrans), c.d.Cfg.Wave2.SynSentMaxKills)
		if err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: ephemeral-port-pressure netns(pid=%d) syn_sent destroy failed: %v",
				rep, err))
			continue
		}
		if killed > 0 {
			c.d.State.AppendLog(fmt.Sprintf(
				"ACTION: ephemeral-port-pressure destroyed %d stuck SYN_SENT sockets in netns(pid=%d) (census=%d)",
				killed, rep, synSent))
			c.d.Actions.WithLabelValues(wdeps.CheckEphemeralPorts, "syn_sent_destroy").Inc()
		}
	}
}

// closeWaitInodes returns the set of socket inodes sitting in
// CLOSE_WAIT across /proc/<rep>/net/tcp + tcp6 for every netns rep
// — the per-pid net view is what makes pod-netns sockets visible
// (plain /proc/net/tcp only shows the agent's own netns). Socket
// inode numbers are kernel-global, so the fd-scan attribution in
// podCloseWait matches regardless of which netns the socket lives
// in. ok=false when a non-ENOENT error occurred and either no netns
// tcp/tcp6 file was readable or no CLOSE_WAIT inodes were observed.
func (c *EphemeralPortsCheck) closeWaitInodes(reps []int) (map[string]bool, bool) {
	out := map[string]bool{}
	nonENOENT := false
	for _, rep := range reps {
		for _, name := range []string{"tcp", "tcp6"} {
			data, err := os.ReadFile(filepath.Join(
				c.d.Proc.File(rep, "net"), name))
			if err != nil {
				if !os.IsNotExist(err) {
					nonENOENT = true
				}
				continue
			}
			for _, line := range strings.Split(string(data), "\n")[1:] {
				f := strings.Fields(line)
				// sl local rem st ... inode is field 9 (0-based):
				// sl(0) local(1) rem(2) st(3) ... inode(9).
				if len(f) < 10 || f[3] != "08" {
					continue
				}
				out[f[9]] = true
			}
		}
	}
	if nonENOENT {
		return out, false
	}
	return out, true
}

// podCloseWait counts CLOSE_WAIT sockets per pod UID by walking
// /proc/<pid>/fd socket links — only pids whose cgroup resolves to
// a pod are scanned (host processes leak too but are never evict
// candidates). ok=false when any /proc/<pid>/fd read failed with
// non-ENOENT so callers preserve port-leak markers.
func (c *EphemeralPortsCheck) podCloseWait(inodes map[string]bool,
	pids []int) (map[string]int, bool) {
	out := map[string]int{}
	if len(inodes) == 0 {
		return out, true
	}
	nonENOENT := false
	for _, pid := range pids {
		uid, ok := wdeps.PodUIDForPID(c.d, pid)
		if !ok {
			continue
		}
		fds, err := os.ReadDir(c.d.Proc.File(pid, "fd"))
		if err != nil {
			if !os.IsNotExist(err) {
				nonENOENT = true
			}
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(
				c.d.Proc.File(pid, "fd"), fd.Name()))
			if err != nil {
				if !os.IsNotExist(err) {
					nonENOENT = true
				}
				continue
			}
			if !strings.HasPrefix(target, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
			if inodes[inode] {
				out[uid]++
			}
		}
	}
	if nonENOENT {
		return out, false
	}
	return out, true
}

// evictPortLeakers deletes the pod dominating the CLOSE_WAIT leak —
// gated on the evict knob, a conclusive pod LIST, the shared
// eviction rails, the maintenance hold and a per-pod confirm window
// (PortLeakWindowSec via Store.ConfirmMarker) plus the
// last-port-leak-evict cooldown. Returns false when /proc reads
// were inconclusive so callers can record "abort" and keep markers.
func (c *EphemeralPortsCheck) evictPortLeakers(ctx context.Context,
	e *wdeps.CycleEnv, closeWait, ceiling int, reps, pids []int) bool {
	// An inconclusive pod LIST must never reach the pruning tail: an
	// empty active set there would erase every leak-window first-seen
	// marker and restart ConfirmMarker's window on every API blip.
	if e == nil || !e.APIOK {
		c.d.State.AppendLog(
			"suspect: ephemeral-port-pressure leak evict skipped - pod LIST inconclusive")
		return true
	}
	activeMarkers := map[string]bool{}
	pruneOK := true
	defer func() {
		if !pruneOK {
			return
		}
		c.d.State.PruneMarkers("port-leak-", func(id string) bool {
			return activeMarkers["port-leak-"+id]
		})
	}()
	floor := max(minCloseWaitFloor, int(0.25*float64(ceiling)))
	if !c.d.Cfg.Wave2.PortEvictRunawayPod || closeWait < floor {
		return true
	}
	inodes, inodesOK := c.closeWaitInodes(reps)
	if !inodesOK {
		pruneOK = false
		return false
	}
	if len(inodes) == 0 {
		return true
	}
	byUID, podCWOK := c.podCloseWait(inodes, pids)
	if !podCWOK {
		pruneOK = false
		return false
	}
	if len(byUID) == 0 {
		return true
	}
	total := 0
	for _, n := range byUID {
		total += n
	}
	if total == 0 {
		return true
	}
	// Top pod by CLOSE_WAIT share — must clear PortLeakMinPct AND a
	// substantial CLOSE_WAIT floor so 1-10 sockets can never delete a healthy pod.
	var topUID string
	var topN int
	for uid, n := range byUID {
		if n > topN || (n == topN && uid < topUID) {
			topUID, topN = uid, n
		}
	}
	if topN < floor {
		return true
	}
	share := float64(topN) / float64(total)
	if share*100 < float64(c.d.Cfg.Wave2.PortLeakMinPct) {
		c.d.State.SuspectLog(wdeps.CheckEphemeralPorts+"-diffuse", fmt.Sprintf(
			"suspect: ephemeral-port-pressure no pod holds >=%d%% of %d leaking sockets - diffuse leak, no evict",
			c.d.Cfg.Wave2.PortLeakMinPct, total), time.Hour)
		return true
	}
	pod := e.PodByUID()[topUID]
	if pod == nil {
		return true // attributed uid has no live pod object
	}
	if pod.DeletionTimestamp != nil ||
		wdeps.IsEvictProtectedPod(pod) ||
		wdeps.PodHasPVC(pod) ||
		wdeps.IsMirrorPod(pod) ||
		metav1.GetControllerOf(pod) == nil ||
		wdeps.EvictProtectedNamespaces[pod.Namespace] ||
		wdeps.EvictCriticalPriorityClasses[pod.Spec.PriorityClassName] ||
		wdeps.CarriesDBQuorumLabel(pod) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: ephemeral-port-pressure pod %s/%s uid=%s protected by eviction rails - skip",
			pod.Namespace, pod.Name, topUID))
		return true
	}
	// Mark active BEFORE confirming window so PruneMarkers keeps live leakers
	// and cleans resolved ones.
	marker := "port-leak-" + topUID
	activeMarkers[marker] = true
	// Two-phase window: the leak must persist PortLeakWindowSec —
	// ConfirmMarker stamps first-seen and confirms after minAge.
	window := time.Duration(c.d.Cfg.Wave2.PortLeakWindowSec) * time.Second
	if window <= 0 {
		window = 120 * time.Second
	}
	_, confirmed := c.d.State.ConfirmMarker(marker, window)
	if !confirmed {
		return true
	}
	if c.d.HoldLocalAction(ctx) {
		c.d.State.AppendLog(
			"cleanup: ephemeral-port-pressure evict held - cluster maintenance in progress")
		return true
	}
	cooldown := time.Duration(c.d.Cfg.Wave2.PortLeakEvictCooldownMin) * time.Minute
	if !c.d.State.RateTrySpend("last-port-leak-evict", cooldown) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: ephemeral-port-pressure victim %s/%s holds %d/%d CLOSE_WAIT - in evict cooldown, skip",
			pod.Namespace, pod.Name, topN, total))
		return true
	}
	c.d.StampLocalRemediation(ctx)
	// PodSocketLeakDetected — the plan's named event for the
	// confirmed leak verdict, emitted before the delete so the
	// postmortem survives even if the eviction itself fails.
	now := c.d.Cfg.Seams.Host.Clock.Now()
	_ = c.d.EmitCheckEvent(ctx, wdeps.CheckEvent{
		Name:      fmt.Sprintf("%s.pod-socket-leak.%x", pod.Name, now.UnixNano()),
		Namespace: pod.Namespace,
		Reason:    "PodSocketLeakDetected",
		Note: fmt.Sprintf(
			"node-host-agent: pod holds %d/%d CLOSE_WAIT sockets (%.0f%%) on %s past the %.0fs leak window — evicting",
			topN, total, share*100, c.d.Cfg.NodeName, window.Seconds()),
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Pod",
			Namespace:  pod.Namespace,
			Name:       pod.Name,
			UID:        pod.UID,
		},
	})
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION %s: pod=%s/%s uid=%s close_wait=%d/%d (%.0f%%)",
		latchdefs.ActionPortLeakEvict, pod.Namespace, pod.Name,
		topUID, topN, total, share*100))
	if err := c.d.DeletePodGraceful(ctx, pod); err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: ephemeral-port-pressure evict %s/%s failed: %v",
			pod.Namespace, pod.Name, err))
		return true
	}
	c.d.Actions.WithLabelValues(wdeps.CheckEphemeralPorts, "pod_delete").Inc()
	return true
}
