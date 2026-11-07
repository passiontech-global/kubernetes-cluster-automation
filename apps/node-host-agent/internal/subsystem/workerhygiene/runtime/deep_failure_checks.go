// deep_failure_checks.go — the W10 host-side deep-failure guards
// (W10-KR1 SystemOOMVictim consumer + W10-ST2 orphaned hostPath
// volumes); the W10-KR3 containerd meta.db half lives in the ctr
// package, the shared textfile writer + watermark/walk helpers in
// wdeps.
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
	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// orphanHostPathMinAge is the ST2 grace period — a pvc-* dir younger
// than this may belong to a PV the apiserver hasn't finished
// deleting (or one about to be created).
const orphanHostPathMinAge = 24 * time.Hour

const lastHostOOMEventFile = "last-host-oom-event"

// The kernel-pressure producer latch this check consumes lives in the
// hoststate registry: hostmetrics' kmsg scanner enters
// hoststate.LatchPageAllocFailure (state-page-alloc-failure) when
// the kernel logs "page allocation failure: order:N".

// memoryCompactEvery is the kernel-pressure compaction cooldown — one
// vm.compact_memory write per 30 minutes: direct compaction is a
// non-invasive buddy-allocator defrag pass but it still stalls
// page allocation while it runs.
const memoryCompactEvery = 30 * time.Minute

// HostOOMCheck is the W10-KR1 hostmetrics kmsg-marker consumer as
// a Check (no streak — the dedup marker file is the state). It also
// owns the kernel-pressure memory-compaction remedy, consuming the
// state-page-alloc-failure latch produced by the hostmetrics kmsg
// scanner.
type HostOOMCheck struct{ d *wdeps.Deps }

// Name returns the check label / WD_SIG key.
func (c *HostOOMCheck) Name() string { return wdeps.CheckHostOOM }

// Run consumes the hostmetrics kmsg scanner's markers: a NEW
// host-level OOM kill (count advanced since the last emitted
// event) produces a Warning Event on this Node plus the
// node_agent_host_oom_kills_total delta. Pod-cgroup kills never
// reach the markers — hostmetrics already classified them out.
func (c *HostOOMCheck) Run(ctx context.Context, _ *wdeps.CycleEnv) {
	c.compactMemory()
	victim := strings.TrimSpace(wdeps.ReadSmallFile(c.d.Cfg.Host.OOMVictimFile))
	fv := strings.Fields(victim)
	if len(fv) < 2 {
		c.d.Cycles.WithLabelValues(wdeps.CheckHostOOM, "ok").Inc()
		return
	}
	epoch, _ := strconv.ParseInt(fv[0], 10, 64)
	comm := fv[1]
	var count int64 = -1
	if b, err := os.ReadFile(c.d.Cfg.Host.OOMCountFile); err == nil {
		count, _ = strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	}
	// Dedup on the cumulative count — the marker's epoch only moves
	// forward anyway, but count is the authoritative "kills seen".
	lastCount := int64(-1)
	if b, err := os.ReadFile(filepath.Join(
		c.d.Cfg.WatchdogStateDir, lastHostOOMEventFile)); err == nil {
		lf := strings.Fields(string(b))
		if len(lf) > 0 {
			lastCount, _ = strconv.ParseInt(lf[0], 10, 64)
		}
	}
	if count >= 0 && count <= lastCount {
		c.d.Cycles.WithLabelValues(wdeps.CheckHostOOM, "ok").Inc()
		return
	}
	delta := int64(1)
	if count >= 0 && lastCount >= 0 {
		delta = count - lastCount
	}
	if delta < 1 {
		delta = 1
	}
	// Record the emission only AFTER the event create succeeded —
	// a failed create leaves the count unseen so next cycle retries
	// instead of the kill being swallowed by an early marker.
	if emitOOMEvent(c.d, ctx, comm, epoch, delta, count) && count >= 0 {
		p := filepath.Join(c.d.Cfg.WatchdogStateDir, lastHostOOMEventFile)
		content := strconv.FormatInt(count, 10) + " " +
			strconv.FormatInt(epoch, 10) + "\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: host-oom dedup marker write failed: %v", err))
		}
	}
	c.d.Cycles.WithLabelValues(wdeps.CheckHostOOM, "ok").Inc()
}

// compactMemory is the kernel-pressure remedy half: while the hostmetrics
// kmsg scanner's state-page-alloc-failure latch is held (kernel
// "page allocation failure: order:N" — the buddy allocator can't
// serve a contiguous block, fragmentation is winning), write 1 to
// <ProcRoot>/sys/vm/compact_memory on the last-memory-compact 30m
// budget and count node_agent_memory_compaction_runs_total. Per the
// hoststate registry contract the consumer Exits the latch after a
// successful compaction — without it the latch would re-fire the
// 30m compact forever off a single past episode; the next kmsg
// sighting re-Enters it (Enter is idempotent).
func (c *HostOOMCheck) compactMemory() {
	if !c.d.State.Exists(hoststate.LatchPageAllocFailure) {
		return
	}
	target := filepath.Join(c.d.Cfg.ProcRoot, "sys", "vm", "compact_memory")
	if _, err := os.Stat(target); err != nil {
		return // non-v2 sysctl or unmounted proc — nothing to poke
	}
	if !c.d.State.RateTrySpend("last-memory-compact", memoryCompactEvery) {
		return
	}
	if err := os.WriteFile(target, []byte("1"), 0o644); err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: page-alloc-failure compact_memory write failed: %v", err))
		return
	}
	c.d.State.Exit(hoststate.LatchPageAllocFailure, nil)
	c.d.MemoryCompactionRuns++
	c.d.State.AppendLog(
		"ACTION: page-alloc-failure latch held — triggered vm.compact_memory (kernel-pressure defrag)")
	c.d.Actions.WithLabelValues(wdeps.CheckHostOOM, "compact_memory").Inc()
}

// emitOOMEvent creates the SystemOOMVictim Warning Event on this
// Node — the events.k8s.io/v1 shape nodereporter's emitter uses
// (Action required, deprecated* fields unset). It reports whether
// the event was actually created: the caller's dedup marker may
// only advance on true.
func emitOOMEvent(d *wdeps.Deps, ctx context.Context, comm string,
	epoch, delta, total int64) bool {
	if d.Cfg.Client == nil {
		return false
	}
	now := d.Cfg.Seams.Host.Clock.Now()
	when := now
	if epoch > 0 {
		when = time.Unix(epoch, 0)
	}
	ev := &eventsv1.Event{
		ObjectMeta: metav1.ObjectMeta{
			// events.v1 names are <regarding>.<hex> — count+epoch
			// keep repeat kills distinct even when the clock is frozen
			// (tests) or two kills land in the same nanosecond.
			Name: fmt.Sprintf("%s.%x.%x", d.Cfg.NodeName, total,
				now.UnixNano()),
			Namespace: d.Cfg.Host.EventNamespace,
		},
		EventTime: metav1.NewMicroTime(when),
		Reason:    "SystemOOMVictim",
		Note: fmt.Sprintf(
			"host-level OOM kill: victim %s (+%d kills, %d total observed)",
			comm, delta, total),
		Type:                corev1.EventTypeWarning,
		ReportingController: "node-host-agent",
		ReportingInstance:   d.Cfg.NodeName,
		Action:              "SystemOOMVictim",
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Node",
			Name:       d.Cfg.NodeName,
		},
	}
	if _, err := d.Cfg.Client.EventsV1().Events(d.Cfg.Host.EventNamespace).
		Create(ctx, ev, metav1.CreateOptions{}); err != nil {
		d.State.AppendLog(fmt.Sprintf(
			"suspect: SystemOOMVictim event create failed: %v", err))
		return false
	}
	d.State.AppendLog(fmt.Sprintf(
		"ACTION: SystemOOMVictim event — host-level OOM kill victim=%s delta=%d total=%d",
		comm, delta, total))
	return true
}

// --- W10-ST2: orphaned hostPath volume dirs ---

// OrphanHPCheck finds pvc-* dirs under the local-provisioner roots
// whose PersistentVolume is gone from the apiserver — the disk leak
// a deleted PV leaves behind (the provisioner removes the PV
// object; the hostPath dir is its problem). Metrics always report
// confirmed orphans; removal is deliberately narrow: dir mtime
// >24h (deletion grace), backing filesystem >80% used, and the dir
// EMPTY or holding only a ".deleted" marker — anything with real
// data is reported, never touched. An apiserver LIST failure makes
// "PV not found" unverifiable → the whole removal half stands down
// (metrics keep their last values). The gauge values live on
// deps (orphanHostPathBytes/Dirs) — writeNodeAgentPromTextfile
// reads them at end of Cycle.
type OrphanHPCheck struct{ d *wdeps.Deps }

// Name returns the check label / WD_SIG key.
func (c *OrphanHPCheck) Name() string { return wdeps.CheckOrphanHP }

// Run executes one orphan-hostpath round.
func (c *OrphanHPCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckOrphanHP, "gated").Inc()
		return
	}
	type cand struct {
		path, name string
	}
	var cands []cand
	for _, root := range c.d.Cfg.Disk.OrphanHostPathDirs {
		ents, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if !e.IsDir() || !strings.HasPrefix(e.Name(), "pvc-") {
				continue
			}
			cands = append(cands, cand{
				path: filepath.Join(root, e.Name()), name: e.Name()})
		}
	}
	if len(cands) == 0 || c.d.Cfg.Client == nil {
		// Nothing to verify — a cluster-scope PV LIST on every
		// worker every cycle for zero candidates is wasted
		// apiserver traffic (and a nil client, defensive only —
		// New rejects it — would nil-pointer panic). Zero the
		// gauges too so a dir set deleted since the last real
		// scan can't leave stale counts behind.
		c.d.OrphanHostPathDirs = 0
		c.d.OrphanHostPathBytes = 0
		c.d.Cycles.WithLabelValues(wdeps.CheckOrphanHP, "ok").Inc()
		return
	}
	pvNames := map[string]bool{}
	apiOK := true
	if pvs, err := c.d.Cfg.Client.CoreV1().PersistentVolumes().
		List(ctx, metav1.ListOptions{}); err != nil {
		apiOK = false
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: orphan-hostpath PV list failed: %v — removal half inconclusive",
			err))
	} else {
		for _, pv := range pvs.Items {
			pvNames[pv.Name] = true
		}
	}
	var totalBytes int64
	orphans := 0
	for _, cd := range cands {
		if orphanHPKnownPV(pvNames, cd.name) {
			continue
		}
		if !apiOK {
			continue // can't confirm "PV gone" — not an orphan yet
		}
		orphans++
		size, _ := c.d.WalkBytes(cd.path)
		totalBytes += size
		fi, err := os.Stat(cd.path)
		if err != nil {
			continue
		}
		if c.d.Cfg.Seams.Host.Clock.Now().Sub(fi.ModTime()) < orphanHostPathMinAge {
			continue // inside the deletion grace window
		}
		if !c.d.DiskUsageAboveWatermark(filepath.Dir(cd.path)) {
			continue // disk pressure gate — keep the evidence
		}
		if ok, why := orphanHPRemovable(cd.path); ok {
			if rerr := os.RemoveAll(cd.path); rerr != nil {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: orphan-hostpath remove %s failed: %v", cd.path, rerr))
			} else {
				c.d.State.AppendLog(fmt.Sprintf(
					"ACTION: removed orphaned hostpath volume dir %s (%s, %d bytes)",
					cd.path, why, size))
				c.d.Actions.WithLabelValues(wdeps.CheckOrphanHP, "rm_dir").Inc()
			}
		} else {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: orphan hostpath %s holds data (%s, %d bytes) — left in place",
				cd.path, why, size))
		}
	}
	if apiOK {
		c.d.OrphanHostPathBytes = totalBytes
		c.d.OrphanHostPathDirs = orphans
	}
	c.d.Cycles.WithLabelValues(wdeps.CheckOrphanHP, "ok").Inc()
}

// checkOrphanedHostPathVolumes forwards to the migrated Check —
// tests written before the interface still call the old method
// shape.

// orphanHPKnownPV reports whether a pvc-* dir name still maps to a
// live PV — exact match plus the trimmed-uuid variants provisioners
// use (dir "pvc-<uuid>" ↔ PV "pvc-<uuid>"; some name the PV without
// the pvc- prefix).
func orphanHPKnownPV(pvNames map[string]bool, dirName string) bool {
	if pvNames[dirName] {
		return true
	}
	trimmed := strings.TrimPrefix(dirName, "pvc-")
	return pvNames[trimmed] || pvNames["pvc-"+trimmed]
}

// orphanHPRemovable reports whether an orphan dir is safe to delete:
// completely empty, or containing ONLY a ".deleted" marker file
// (the local-path provisioner's tombstone). Anything else holds
// potential data and is reported, never removed.
func orphanHPRemovable(dir string) (bool, string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false, "unreadable: " + err.Error()
	}
	if len(ents) == 0 {
		return true, "empty"
	}
	if len(ents) == 1 && ents[0].Name() == ".deleted" && ents[0].Type().IsRegular() {
		return true, "deleted-marker"
	}
	return false, fmt.Sprintf("%d entries", len(ents))
}
