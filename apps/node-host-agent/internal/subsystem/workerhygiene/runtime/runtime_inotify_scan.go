// runtime_inotify_scan.go — /proc/<pid>/fd inotify census, kcmp OFD
// deduplication, and runaway-pod eviction for InotifyPressureCheck.
// Split out of runtime_inotify_pressure.go.
package runtime

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// scanInotify walks <ProcRoot>/<pid>/fd once per cycle counting
// anon_inode:inotify descriptors and their fdinfo watch lines —
// there is no global inotify usage counter, so the per-pid fd walk
// is the only evidence source (the unlinked-open-files guard's
// sweep shape). pids come from the cycle's shared PidsOnce when
// wired.
type inotifyRUIDEntry struct {
	pid     int
	fdNum   int
	podUID  string
	watches int64
}

func (c *InotifyPressureCheck) scanInotify(e *wdeps.CycleEnv, instLimit, watchLimit int64, forceDirect bool) (inotifyScan, bool, bool) {
	pids, pidsOK := c.d.CyclePIDs(e)
	if !pidsOK {
		return inotifyScan{}, false, false
	}

	var snap *procfs.FDSnapshot
	usedCache := false
	if !forceDirect {
		var nowFn func() time.Time
		if c.d.Cfg.Seams.Host.Clock != nil {
			nowFn = c.d.Cfg.Seams.Host.Clock.Now
		}
		snap = procfs.SharedFDCache(c.d.Cfg.ProcRoot, nowFn).Snapshot(inotifyFDTTL)
		if snap != nil && snap.ProcOK && !snap.Partial {
			usedCache = true
		}
	}
	if snap == nil || !snap.ProcOK || snap.Partial {
		// SharedFDCache never caches !ProcOK or Partial snapshots across
		// inotifyFDTTL; fall back to a direct ScanFDs(pids) walk when
		// forceDirect was requested, when the shared walk failed or was
		// partial (e.g. an unrelated PID outside e.PidsOnce caused Partial),
		// or when /proc was unreadable.
		usedCache = false
		snap = c.d.Proc.ScanFDs(pids)
		if snap == nil || !snap.ProcOK || snap.Partial {
			return inotifyScan{}, false, false
		}
	}

	var allowed map[int]bool
	if e != nil && e.PidsOnce != nil {
		allowed = make(map[int]bool, len(pids))
		for _, pid := range pids {
			allowed[pid] = true
		}
	}

	scan := inotifyScan{
		byRUID:       map[int64]inotifyTotals{},
		byUID:        map[string]inotifyTotals{},
		byRUIDAndUID: map[int64]map[string]inotifyTotals{},
	}
	// When an explicit InotifyFDIno test seam is wired, dedup on its returned
	// OFD key; otherwise keep each (pid, fd) distinct and run kcmp(KCMP_FILE)
	// only inside pressured RUIDs so Linux's shared anon_inode_inode never
	// collapses distinct instances to 1.
	seenExplicitOFD := map[string]bool{}
	rawEntriesByRUID := map[int64][]inotifyRUIDEntry{}

	type pidMeta struct {
		ruid      int64
		podUID    string
		hasPodUID bool
	}
	metaByPID := map[int]pidMeta{}

	for _, entry := range snap.Inotify {
		if allowed != nil && !allowed[entry.PID] {
			continue
		}
		watches := entry.Watches
		meta, seenMeta := metaByPID[entry.PID]
		if !seenMeta {
			ruid, _ := procRealUID(c.d, entry.PID) // -1 bucket on unreadable
			podUID, hasPodUID := wdeps.PodUIDForPID(c.d, entry.PID)
			meta = pidMeta{ruid: ruid, podUID: podUID, hasPodUID: hasPodUID}
			metaByPID[entry.PID] = meta
		}
		if c.d.Cfg.Seams.Host.InotifyFDIno != nil {
			if ino, ok := c.d.Cfg.Seams.Host.InotifyFDIno(entry.PID, strconv.Itoa(entry.FD)); ok {
				key := "ino:" + strconv.FormatUint(ino, 10)
				if seenExplicitOFD[key] {
					continue
				}
				seenExplicitOFD[key] = true
			}
		} else {
			rawEntriesByRUID[meta.ruid] = append(rawEntriesByRUID[meta.ruid], inotifyRUIDEntry{
				pid:     entry.PID,
				fdNum:   entry.FD,
				podUID:  meta.podUID,
				watches: watches,
			})
		}

		scan.total.instances++
		scan.total.watches += watches
		a := scan.byRUID[meta.ruid]
		a.instances++
		a.watches += watches
		scan.byRUID[meta.ruid] = a
		if meta.hasPodUID && meta.podUID != "" {
			p := scan.byUID[meta.podUID]
			p.instances++
			p.watches += watches
			scan.byUID[meta.podUID] = p
			if scan.byRUIDAndUID[meta.ruid] == nil {
				scan.byRUIDAndUID[meta.ruid] = map[string]inotifyTotals{}
			}
			rp := scan.byRUIDAndUID[meta.ruid][meta.podUID]
			rp.instances++
			rp.watches += watches
			scan.byRUIDAndUID[meta.ruid][meta.podUID] = rp
		}
	}

	sameOFD := c.d.Cfg.Seams.Host.InotifySameOFDFn
	if sameOFD == nil || c.d.Cfg.Seams.Host.InotifyFDIno != nil {
		return scan, usedCache, true
	}
	// Refine only RUIDs near or past the clear threshold using unix.Kcmp(KCMP_FILE).
	for ruid, entries := range rawEntriesByRUID {
		tot := scan.byRUID[ruid]
		if !ruidNeedsKCMP(tot, instLimit, watchLimit) || len(entries) <= 1 {
			continue
		}
		deduped := dedupRUIDEntriesKCMP(entries, sameOFD)
		if len(deduped) == len(entries) {
			continue
		}
		scan.total.instances -= tot.instances
		scan.total.watches -= tot.watches
		var newTot inotifyTotals
		newPodTotals := map[string]inotifyTotals{}
		for _, ent := range deduped {
			newTot.instances++
			newTot.watches += ent.watches
			if ent.podUID != "" {
				pt := newPodTotals[ent.podUID]
				pt.instances++
				pt.watches += ent.watches
				newPodTotals[ent.podUID] = pt
			}
		}
		scan.total.instances += newTot.instances
		scan.total.watches += newTot.watches
		scan.byRUID[ruid] = newTot
		for uid, oldPT := range scan.byRUIDAndUID[ruid] {
			cur := scan.byUID[uid]
			cur.instances -= oldPT.instances
			cur.watches -= oldPT.watches
			if cur.instances <= 0 && cur.watches <= 0 {
				delete(scan.byUID, uid)
			} else {
				scan.byUID[uid] = cur
			}
		}
		scan.byRUIDAndUID[ruid] = newPodTotals
		for uid, pt := range newPodTotals {
			cur := scan.byUID[uid]
			cur.instances += pt.instances
			cur.watches += pt.watches
			scan.byUID[uid] = cur
		}
	}
	return scan, usedCache, true
}

func ruidNeedsKCMP(tot inotifyTotals, instLimit, watchLimit int64) bool {
	if instLimit > 0 && float64(tot.instances)/float64(instLimit) > inotifyClearRatio {
		return true
	}
	if watchLimit > 0 && float64(tot.watches)/float64(watchLimit) > inotifyClearRatio {
		return true
	}
	return false
}

// dedupRUIDEntriesKCMP collapses entries sharing one open file
// description (proved by kcmp/KCMP_FILE) into a single census entry.
// A shared OFD is one struct file, so its fdinfo always reports the
// SAME watch count: bucket candidates by watches before paying for the
// kcmp syscall. Every keeper in the matching bucket is compared — the
// old flat maxKCMPCompareKeepers=512 cut silently stopped dedup once a
// RUID held >512 OFDs (a forked RUID past that point leaked dupes and
// overstated pressure). Bucketing keeps the comparison set small
// without ever dropping a genuine duplicate behind a hard cap.
func dedupRUIDEntriesKCMP(entries []inotifyRUIDEntry, sameOFD func(int, int, int, int) bool) []inotifyRUIDEntry {
	kept := make([]inotifyRUIDEntry, 0, len(entries))
	buckets := map[int64][]int{} // watch count → indices into kept
	for _, ent := range entries {
		dup := false
		for _, i := range buckets[ent.watches] {
			k := kept[i]
			if (k.pid == ent.pid && k.fdNum == ent.fdNum) ||
				sameOFD(k.pid, k.fdNum, ent.pid, ent.fdNum) {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		buckets[ent.watches] = append(buckets[ent.watches], len(kept))
		kept = append(kept, ent)
	}
	return kept
}

// procRealUID reads the real uid from /proc/<pid>/status — the
// ucounts charging identity for inotify instances/watches.
// ok=false on unreadable/malformed status; callers bucket those
// pids under -1 rather than dropping their usage.
func procRealUID(d *wdeps.Deps, pid int) (int64, bool) {
	data, err := os.ReadFile(d.Proc.File(pid, "status"))
	if err != nil {
		return -1, false
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			return -1, false
		}
		uid, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			return -1, false
		}
		return uid, true
	}
	return -1, false
}

// instCeilAxis/watchAxis pick the pressured field out of one
// per-uid total for worstUIDRatio.
func instCeilAxis(u inotifyTotals) int64 { return u.instances }
func watchAxis(u inotifyTotals) int64    { return u.watches }

// worstUIDRatio returns the maximum usage/limit across every real
// uid — the ucounts-correct pressure signal. A uid with zero
// usage on the axis is skipped; an empty map (no inotify pids at
// all) reads 0.
func worstUIDRatio(byRUID map[int64]inotifyTotals,
	pick func(inotifyTotals) int64, limit int64) float64 {

	var worst float64
	for _, u := range byRUID {
		v := pick(u)
		if v <= 0 || limit <= 0 {
			continue
		}
		if r := float64(v) / float64(limit); r > worst {
			worst = r
		}
	}
	return worst
}

// maybeEvictRunaway deletes the pod dominating the axis that is
// actually exhausted — gated on the evict knob, a conclusive pod
// LIST, the shared eviction rails, the maintenance hold and the
// 15m cooldown. The budget is spent BEFORE the delete (rate_spend
// parity); the delete itself carries the UID precondition so a
// same-name recycle can't be killed by mistake.
//
// Share math is PER-AXIS, never summed: instances (ceiling ~8k) and
// watches (ceiling ~512k) are different units 64x apart, so a pod's
// instances+watches aggregate is meaningless — a pod leaking 8k
// instances would lose the "top pod" race to a healthy pod holding
// 16k watches while the instance ceiling stays pinned. Each
// pressured axis (instPressured/watchPressured — the ones that
// armed the latch) is scored independently: the victim must hold
// >= 50% of the node's usage ON THAT AXIS. When both axes are
// pressured the higher-share candidate wins.
func (c *InotifyPressureCheck) maybeEvictRunaway(ctx context.Context,
	e *wdeps.CycleEnv, scan inotifyScan, instLimit, watchLimit int64,
	instPressured, watchPressured bool) {
	if !c.d.Cfg.Pressure.InotifyEvictRunawayPod {
		return
	}
	if e == nil || !e.APIOK {
		c.d.State.AppendLog(
			"suspect: inotify-pressure-hygiene runaway-pod evict skipped - pod LIST inconclusive")
		return
	}
	if !instPressured && !watchPressured {
		return // latch evidence went stale between arm and evict
	}

	type axisPick struct {
		uid   string
		u     inotifyTotals
		axis  string
		share float64
	}
	var best *axisPick
	consider := func(axis string, pressured bool, limit int64,
		val func(inotifyTotals) int64) {
		if !pressured || limit <= 0 {
			return
		}
		// Pick the pressured RUID with highest usage on this axis, then score
		// only pods belonging to THAT RUID against that RUID's total.
		var worstRUID int64
		var worstRUIDTotal int64
		hasWorst := false
		for ruid, rt := range scan.byRUID {
			v := val(rt)
			if float64(v)/float64(limit) < inotifyLatchRatio {
				continue
			}
			if !hasWorst || v > worstRUIDTotal || (v == worstRUIDTotal && ruid < worstRUID) {
				worstRUID, worstRUIDTotal, hasWorst = ruid, v, true
			}
		}
		if !hasWorst || worstRUIDTotal <= 0 {
			return
		}
		podTotals := scan.byRUIDAndUID[worstRUID]
		uids := make([]string, 0, len(podTotals))
		for uid := range podTotals {
			uids = append(uids, uid)
		}
		slices.Sort(uids)
		var topUID string
		var topVal int64
		for _, uid := range uids {
			if v := val(podTotals[uid]); v > topVal {
				topVal, topUID = v, uid
			}
		}
		if topUID == "" {
			return
		}
		share := float64(topVal) / float64(worstRUIDTotal)
		if share < inotifyEvictShare {
			return
		}
		if best == nil || share > best.share {
			best = &axisPick{uid: topUID, u: podTotals[topUID],
				axis: axis, share: share}
		}
	}
	consider("instances", instPressured, instLimit,
		func(u inotifyTotals) int64 { return u.instances })
	consider("watches", watchPressured, watchLimit,
		func(u inotifyTotals) int64 { return u.watches })
	if best == nil {
		c.d.State.AppendLog(
			"suspect: inotify-pressure-hygiene no pod holds >=50% of a pressured axis - diffuse pressure, no evict")
		return
	}
	pod := e.PodByUID()[best.uid]
	if pod == nil {
		// The cgroup-attributed uid has no live pod object — a
		// terminating/gone pod's stragglers; nothing safe to delete.
		return
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
			"suspect: inotify-pressure-hygiene pod %s/%s uid=%s protected by eviction rails - skip",
			pod.Namespace, pod.Name, best.uid))
		return
	}
	// L1↔L3 hold BEFORE the cooldown spend so a drain doesn't burn
	// last-inotify-evict.
	if c.d.HoldLocalAction(ctx) {
		c.d.State.AppendLog(
			"cleanup: inotify-pressure-hygiene evict held - cluster maintenance in progress")
		return
	}
	if !c.d.State.RateTrySpend("last-inotify-evict", inotifyEvictInterval) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: inotify-pressure-hygiene victim %s/%s holds %.0f%% of %s - in evict cooldown (<15m), skip",
			pod.Namespace, pod.Name, best.share*100, best.axis))
		return
	}
	c.d.StampLocalRemediation(ctx)
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: inotify-pressure-hygiene evicted pod %s/%s - holds %d instances + %d watches (%.0f%% of node %s)",
		pod.Namespace, pod.Name, best.u.instances, best.u.watches,
		best.share*100, best.axis))
	if err := c.d.DeletePodGraceful(ctx, pod); err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: inotify-pressure-hygiene evict %s/%s failed: %v",
			pod.Namespace, pod.Name, err))
		return
	}
	c.d.Actions.WithLabelValues(wdeps.CheckInotifyHygiene, "pod_delete").Inc()
}
