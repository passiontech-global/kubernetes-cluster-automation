package workerhygiene

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
)

// ===========================================================================
// Wave-10 — kernel/runtime/storage deep failure modes
// (W10-KR1 consumer, W10-KR3, W10-ST2)
// ===========================================================================

// ctrMetaOrphanMinAge is the "dead for >15m" evidence bar for KR3
// orphan shims — a shim whose init died seconds ago is a normal
// teardown in flight, not corruption.
const ctrMetaOrphanMinAge = 15 * time.Minute

// ctrMetaJournalWindow is the KR3 journal lookback — corruption
// signatures only need the recent window; a stale hit from days ago
// must not latch.
const ctrMetaJournalWindow = "3 minutes ago"

// orphanHostPathMinAge is the ST2 grace period — a pvc-* dir younger
// than this may belong to a PV the apiserver hasn't finished
// deleting (or one about to be created).
const orphanHostPathMinAge = 24 * time.Hour

// orphanHostPathDiskHigh is the ST2 removal gate — empty/.deleted
// remnants are only reclaimed when the backing filesystem is above
// 80% used (the plan's disk-pressure qualifier).
const orphanHostPathDiskHigh = 0.80

// ctrMetaCorruptRe is the KR3 journal signature set — bbolt/meta.db
// corruption phrases containerd logs when its bolt store won't open.
var ctrMetaCorruptRe = regexp.MustCompile(
	`failed to loadmeta|invalid freelist page|bbolt|meta\.db: Somethings wrong`)

// ctrMetaCheck is the W10-KR3 containerd meta.db corruption
// guard as a Check; it owns the evidence streak
// (ex-Hygiene.ctrMetaFails). Two evidence channels, either
// sufficient for state-containerd-corrupt (KubeletRuntimeStall
// altStateKey — a corrupt store survives k0sworker restarts, so the
// NHC→SNR path needs the latch, not just a restart):
//
//   - journalctl -u k0sworker -u containerd --since "3 minutes ago"
//     matching the bbolt/meta.db corruption signatures, and
//   - containerd-shim-runc-v2 processes reparented to PID 1 whose
//     k8s.io task dir still exists but whose init has been dead
//     >15m — the shape containerd leaves when it loses track of a
//     task (its bookkeeping DB is the usual suspect).
//
// ConsecNeeded consecutive evidence cycles latch; a clean cycle
// clears. An unreadable journal is inconclusive for that half —
// the shim half still evaluates.
type ctrMetaCheck struct {
	d     *deps
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *ctrMetaCheck) Name() string { return checkCtrMeta }

// Run executes one containerd-meta round.
func (c *ctrMetaCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.d.cycles.WithLabelValues(checkCtrMeta, "gated").Inc()
		return
	}
	evidence := ""
	journalFn := c.d.cfg.Ctr.MetaJournalFn
	if journalFn == nil && c.d.cfg.Systemd != nil {
		journalFn = func(ctx context.Context) (string, error) {
			return c.d.cfg.Systemd.ExecCombined(ctx, "journalctl",
				"-u", "k0sworker.service", "-u", "containerd.service",
				"--since", ctrMetaJournalWindow, "--no-pager")
		}
	}
	if journalFn != nil {
		out, err := journalFn(ctx)
		if err != nil {
			c.d.state.AppendLog(fmt.Sprintf(
				"suspect: containerd-meta journal probe failed: %v — journal half inconclusive",
				err))
		} else if m := ctrMetaCorruptRe.FindString(out); m != "" {
			evidence = "journal: " + m
		}
	}
	if orphans := c.d.countMetaOrphanShims(e.pidsOnce()); orphans > 0 {
		if evidence != "" {
			evidence += "; "
		}
		evidence += fmt.Sprintf("%d orphan shim(s) ppid=1", orphans)
	}
	if evidence != "" {
		c.fails++
		c.d.state.AppendLog(fmt.Sprintf(
			"suspect: containerd meta.db corruption evidence (%s) — run %d/%d",
			evidence, c.fails, c.d.cfg.ConsecNeeded))
		if c.fails >= c.d.cfg.ConsecNeeded {
			c.d.state.Enter(hoststate.LatchContainerdCorrupt, evidence)
		}
	} else {
		c.fails = 0
		c.d.state.Exit(hoststate.LatchContainerdCorrupt, nil)
	}
	c.d.cycles.WithLabelValues(checkCtrMeta, "ok").Inc()
}

// checkContainerdHealth forwards to the migrated Check — tests
// written before the interface still call the old method shape.
func (h *Hygiene) checkContainerdHealth(ctx context.Context,
	pidsOnce func() []int, workerActive bool) {
	h.ctrMeta.Run(ctx, &cycleEnv{
		pidsOnce: pidsOnce, workerActive: workerActive})
}

// countMetaOrphanShims counts containerd-shim-runc-v2 processes that
// look like meta.db-loss orphans: in-scope for THIS containerd
// (ctrShimScope — never a foreign daemon's shim), reparented to PID
// 1 (containerd forgot them), older than ctrMetaOrphanMinAge, and
// whose k8s.io task dir still exists with a dead/missing init —
// checkCtrTasks owns the missing-dir orphan case and live-init dirs
// are normal tasks, so both are excluded here.
func (d *deps) countMetaOrphanShims(pids []int) int {
	n := 0
	for _, pid := range pids {
		argv := d.proc.Cmdline(pid)
		if len(argv) == 0 ||
			!strings.Contains(strings.Join(argv, " "), "containerd-shim-runc-v2") {
			continue
		}
		ns, sid, inScope := d.ctrShimScope(argv)
		if !inScope || ns != "k8s.io" || sid == "" {
			continue
		}
		_, ppid, ok := d.procStatStatePPID(pid)
		if !ok || ppid != 1 {
			continue
		}
		if d.procAge(pid) < ctrMetaOrphanMinAge {
			continue
		}
		dir := d.shimTaskDir(ns, sid)
		fi, err := os.Stat(dir)
		if err != nil || !fi.IsDir() {
			continue // dir gone → checkCtrTasks' orphan-shim path
		}
		if d.cfg.Seams.nowFn().Sub(fi.ModTime()) < ctrMetaOrphanMinAge {
			continue
		}
		if d.ctrTaskInitLive(dir) {
			continue
		}
		n++
	}
	return n
}

// ctrTaskInitLive reports whether the task dir's init.pid names a
// live process — the same liveness rule checkCtrTasks applies.
func (d *deps) ctrTaskInitLive(dir string) bool {
	data, err := os.ReadFile(filepath.Join(dir, "init.pid"))
	if err != nil {
		return false
	}
	ipid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || ipid <= 0 {
		return false
	}
	return d.pidLive(ipid)
}

// --- W10-KR1 consumer: host-level OOM → event + metric ---

// lastHostOOMEventFile dedups SystemOOMVictim events — the marker
// files are cumulative, so "already emitted" is a count/epoch pair.
const lastHostOOMEventFile = "last-host-oom-event"

// hostOOMCheck is the W10-KR1 hostmetrics kmsg-marker consumer as
// a Check (no streak — the dedup marker file is the state).
type hostOOMCheck struct{ d *deps }

// Name returns the check label / WD_SIG key.
func (c *hostOOMCheck) Name() string { return checkHostOOM }

// Run consumes the hostmetrics kmsg scanner's markers: a NEW
// host-level OOM kill (count advanced since the last emitted
// event) produces a Warning Event on this Node plus the
// node_agent_host_oom_kills_total delta. Pod-cgroup kills never
// reach the markers — hostmetrics already classified them out.
func (c *hostOOMCheck) Run(ctx context.Context, _ *cycleEnv) {
	victim := strings.TrimSpace(readSmallFile(c.d.cfg.Host.OOMVictimFile))
	fv := strings.Fields(victim)
	if len(fv) < 2 {
		c.d.cycles.WithLabelValues(checkHostOOM, "ok").Inc()
		return
	}
	epoch, _ := strconv.ParseInt(fv[0], 10, 64)
	comm := fv[1]
	var count int64 = -1
	if b, err := os.ReadFile(c.d.cfg.Host.OOMCountFile); err == nil {
		count, _ = strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	}
	// Dedup on the cumulative count — the marker's epoch only moves
	// forward anyway, but count is the authoritative "kills seen".
	lastCount := int64(-1)
	if b, err := os.ReadFile(filepath.Join(
		c.d.cfg.WatchdogStateDir, lastHostOOMEventFile)); err == nil {
		lf := strings.Fields(string(b))
		if len(lf) > 0 {
			lastCount, _ = strconv.ParseInt(lf[0], 10, 64)
		}
	}
	if count >= 0 && count <= lastCount {
		c.d.cycles.WithLabelValues(checkHostOOM, "ok").Inc()
		return
	}
	delta := int64(1)
	if count >= 0 && lastCount >= 0 {
		delta = count - lastCount
	}
	if delta < 1 {
		delta = 1
	}
	c.d.emitOOMEvent(ctx, comm, epoch, delta, count)
	// Record the emission — count first so a failed event create
	// retries next cycle instead of being swallowed.
	if count >= 0 {
		p := filepath.Join(c.d.cfg.WatchdogStateDir, lastHostOOMEventFile)
		content := strconv.FormatInt(count, 10) + " " +
			strconv.FormatInt(epoch, 10) + "\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			c.d.state.AppendLog(fmt.Sprintf(
				"suspect: host-oom dedup marker write failed: %v", err))
		}
	}
	c.d.cycles.WithLabelValues(checkHostOOM, "ok").Inc()
}

// checkHostOOMVictims forwards to the migrated Check — tests
// written before the interface still call the old method shape.
func (h *Hygiene) checkHostOOMVictims(ctx context.Context) {
	h.hostOOM.Run(ctx, &cycleEnv{})
}

// emitOOMEvent creates the SystemOOMVictim Warning Event on this
// Node — the events.k8s.io/v1 shape nodereporter's emitter uses
// (Action required, deprecated* fields unset).
func (d *deps) emitOOMEvent(ctx context.Context, comm string,
	epoch, delta, total int64) {
	if d.cfg.Client == nil {
		return
	}
	now := d.cfg.Seams.nowFn()
	when := now
	if epoch > 0 {
		when = time.Unix(epoch, 0)
	}
	ev := &eventsv1.Event{
		ObjectMeta: metav1.ObjectMeta{
			// events.v1 names are <regarding>.<hex> — count+epoch
			// keep repeat kills distinct even when nowFn is frozen
			// (tests) or two kills land in the same nanosecond.
			Name: fmt.Sprintf("%s.%x.%x", d.cfg.NodeName, total,
				now.UnixNano()),
			Namespace: d.cfg.Host.EventNamespace,
		},
		EventTime: metav1.NewMicroTime(when),
		Reason:    "SystemOOMVictim",
		Note: fmt.Sprintf(
			"host-level OOM kill: victim %s (+%d kills, %d total observed)",
			comm, delta, total),
		Type:                corev1.EventTypeWarning,
		ReportingController: "node-host-agent",
		ReportingInstance:   d.cfg.NodeName,
		Action:              "SystemOOMVictim",
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Node",
			Name:       d.cfg.NodeName,
		},
	}
	if _, err := d.cfg.Client.EventsV1().Events(d.cfg.Host.EventNamespace).
		Create(ctx, ev, metav1.CreateOptions{}); err != nil {
		d.state.AppendLog(fmt.Sprintf(
			"suspect: SystemOOMVictim event create failed: %v", err))
		return
	}
	d.state.AppendLog(fmt.Sprintf(
		"ACTION: SystemOOMVictim event — host-level OOM kill victim=%s delta=%d total=%d",
		comm, delta, total))
}

// --- W10-ST2: orphaned hostPath volume dirs ---

// orphanHPCheck finds pvc-* dirs under the local-provisioner roots
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
type orphanHPCheck struct{ d *deps }

// Name returns the check label / WD_SIG key.
func (c *orphanHPCheck) Name() string { return checkOrphanHP }

// Run executes one orphan-hostpath round.
func (c *orphanHPCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.d.cycles.WithLabelValues(checkOrphanHP, "gated").Inc()
		return
	}
	type cand struct {
		path, name string
	}
	var cands []cand
	for _, root := range c.d.cfg.Disk.OrphanHostPathDirs {
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
	pvNames := map[string]bool{}
	apiOK := true
	if pvs, err := c.d.cfg.Client.CoreV1().PersistentVolumes().
		List(ctx, metav1.ListOptions{}); err != nil {
		apiOK = false
		c.d.state.AppendLog(fmt.Sprintf(
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
		size, _ := c.d.walkBytes(cd.path)
		totalBytes += size
		fi, err := os.Stat(cd.path)
		if err != nil {
			continue
		}
		if c.d.cfg.Seams.nowFn().Sub(fi.ModTime()) < orphanHostPathMinAge {
			continue // inside the deletion grace window
		}
		if !c.d.diskUsageAboveWatermark(filepath.Dir(cd.path)) {
			continue // disk pressure gate — keep the evidence
		}
		if ok, why := orphanHPRemovable(cd.path); ok {
			if rerr := os.RemoveAll(cd.path); rerr != nil {
				c.d.state.AppendLog(fmt.Sprintf(
					"suspect: orphan-hostpath remove %s failed: %v", cd.path, rerr))
			} else {
				c.d.state.AppendLog(fmt.Sprintf(
					"ACTION: removed orphaned hostpath volume dir %s (%s, %d bytes)",
					cd.path, why, size))
				c.d.actions.WithLabelValues(checkOrphanHP, "rm_dir").Inc()
			}
		} else {
			c.d.state.AppendLog(fmt.Sprintf(
				"suspect: orphan hostpath %s holds data (%s, %d bytes) — left in place",
				cd.path, why, size))
		}
	}
	if apiOK {
		c.d.orphanHostPathBytes = totalBytes
		c.d.orphanHostPathDirs = orphans
	}
	c.d.cycles.WithLabelValues(checkOrphanHP, "ok").Inc()
}

// checkOrphanedHostPathVolumes forwards to the migrated Check —
// tests written before the interface still call the old method
// shape.
func (h *Hygiene) checkOrphanedHostPathVolumes(ctx context.Context,
	workerActive bool) {
	h.orphanHP.Run(ctx, &cycleEnv{workerActive: workerActive})
}

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

// diskUsageAboveWatermark reports whether the filesystem holding dir is above
// the ST2 removal watermark — statfs through the injectable seam.
func (d *deps) diskUsageAboveWatermark(dir string) bool {
	var st unix.Statfs_t
	if err := d.cfg.Seams.statfsFn(dir, &st); err != nil || st.Blocks == 0 {
		return false // can't measure → don't remove (fail closed)
	}
	used := 1.0 - float64(st.Bavail)/float64(st.Blocks)
	return used > orphanHostPathDiskHigh
}

// --- W10 node_agent_* textfile metrics ---

// promTextfileDirOverride wins over the K0sDataDir-derived textfile
// dir in tests (controllerhygiene's kineTextfileDirOverride parity).
var promTextfileDirOverride string

// promTextfileDir resolves the node-exporter textfile drop dir —
// <K0sDataDir's parent>/node-exporter/textfile, i.e.
// <hostRoot>/var/lib/node-exporter/textfile in both pod and
// standalone layouts (same derivation controllerhygiene uses).
func (d *deps) promTextfileDir() string {
	if promTextfileDirOverride != "" {
		return promTextfileDirOverride
	}
	return filepath.Join(filepath.Dir(d.cfg.Disk.K0sDataDir),
		"node-exporter", "textfile")
}

// writeNodeAgentPromTextfile emits the W10 node_agent_* series once per cycle:
// host_oom_kills_total + conntrack_drops_detected_total read the
// hostmetrics kmsg markers (cumulative — monotonic across restarts),
// orphan_hostpath_{bytes,dirs} carry this cycle's ST2 measurement.
// tmp+rename keeps node_exporter from reading a partial file.
func (d *deps) writeNodeAgentPromTextfile() {
	dir := d.promTextfileDir()
	fail := func(err error) {
		d.state.AppendLog(fmt.Sprintf(
			"suspect: node-agent prom textfile unwritable (dir=%s): %v", dir, err))
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fail(err)
		return
	}
	var b strings.Builder
	gauge := func(name, help string, v float64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s %s\n",
			name, help, name, name,
			strconv.FormatFloat(v, 'f', -1, 64))
	}
	counter := func(name, help string, v int64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n%s %d\n",
			name, help, name, name, v)
	}
	if v, err := strconv.ParseInt(strings.TrimSpace(
		readSmallFile(d.cfg.Host.OOMCountFile)), 10, 64); err == nil {
		counter("node_agent_host_oom_kills_total",
			"Host-level OOM kills observed by the kernel dmesg scanner (outside /kubepods or host daemons).", v)
	} else {
		counter("node_agent_host_oom_kills_total",
			"Host-level OOM kills observed by the kernel dmesg scanner (outside /kubepods or host daemons).", 0)
	}
	if v, err := strconv.ParseInt(strings.TrimSpace(
		readSmallFile(d.cfg.Host.ConntrackDropsFile)), 10, 64); err == nil {
		counter("node_agent_conntrack_drops_detected_total",
			"nf_conntrack table-full records observed by the kernel dmesg scanner.", v)
	} else {
		counter("node_agent_conntrack_drops_detected_total",
			"nf_conntrack table-full records observed by the kernel dmesg scanner.", 0)
	}
	gauge("node_agent_orphan_hostpath_bytes",
		"Bytes held by orphaned pvc-* hostPath dirs whose PV is gone.",
		float64(d.orphanHostPathBytes))
	gauge("node_agent_orphan_hostpath_dirs",
		"Orphaned pvc-* hostPath dirs whose PV is gone from the apiserver.",
		float64(d.orphanHostPathDirs))
	name := "node-agent-hygiene.prom"
	tmp := filepath.Join(dir, "."+name+".tmp")
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		fail(err)
		return
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		fail(err)
	}
}

// readSmallFile reads a marker file, capped — the kmsg markers are
// tiny; a runaway file must not be slurped whole.
func readSmallFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	b, _ := io.ReadAll(io.LimitReader(f, 4096))
	return string(b)
}
