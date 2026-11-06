// textfile.go — the W10 node_agent_* textfile surface: the dir
// resolution, the once-per-cycle writer (the ONLY reader of the
// embedded Series + OrphanHostPath gauges + the hostmetrics kmsg
// markers), and the two generic host-side helpers several domains
// share (bounded dir-size walk, small marker file read, statfs
// watermark probe).
package wdeps

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
)

// maxBloatWalkEntries is the walk cap per scanned dir — the walk
// must never become its own IO problem on the disk that is already
// full.
const maxBloatWalkEntries = 10000

// orphanHostPathDiskHigh is the ST2 removal gate — empty/.deleted
// remnants are only reclaimed when the backing filesystem is above
// 80% used (the plan's disk-pressure qualifier).
const orphanHostPathDiskHigh = 0.80

// WalkBytes sums regular-file sizes under root. The walk is bounded:
// after maxBloatWalkEntries entries it stops and reports
// truncated=true — the total is then a lower bound (a tree that
// huge is bloat by definition, but the walk must never become its
// own IO problem on the disk that is already full). Shared: the
// disk-bloat and orphan-hostpath checks walk with it.
func (d *Deps) WalkBytes(root string) (total int64, truncated bool) {
	entries := 0
	_ = filepath.WalkDir(root, func(path string, de fs.DirEntry, err error) error {
		if err != nil {
			logger().Debug("workerhygiene: bloat walk entry skipped — unreadable",
				"path", path, "error", err)
			return nil // unreadable entries are skipped, never fatal
		}
		entries++
		if entries > maxBloatWalkEntries {
			truncated = true
			return fs.SkipAll
		}
		if de.Type().IsRegular() {
			if fi, ierr := de.Info(); ierr == nil {
				total += fi.Size()
			}
		}
		return nil
	})
	return total, truncated
}

// DiskUsageAboveWatermark reports whether the filesystem holding dir is above
// the ST2 removal watermark — statfs through the injectable seam.
func (d *Deps) DiskUsageAboveWatermark(dir string) bool {
	var st unix.Statfs_t
	if err := d.Cfg.Seams.Host.StatfsFn(dir, &st); err != nil || st.Blocks == 0 {
		return false // can't measure → don't remove (fail closed)
	}
	used := 1.0 - float64(st.Bavail)/float64(st.Blocks)
	return used > orphanHostPathDiskHigh
}

// PromTextfileDirOverride wins over the K0sDataDir-derived textfile
// dir in tests (controllerhygiene's kineTextfileDirOverride parity).
var PromTextfileDirOverride string

// PromTextfileDir resolves the node-exporter textfile drop dir —
// <K0sDataDir's parent>/node-exporter/textfile, i.e.
// <hostRoot>/var/lib/node-exporter/textfile in both pod and
// standalone layouts (same derivation controllerhygiene uses).
func (d *Deps) PromTextfileDir() string {
	if PromTextfileDirOverride != "" {
		return PromTextfileDirOverride
	}
	return filepath.Join(filepath.Dir(d.Cfg.K0sDataDir),
		"node-exporter", "textfile")
}

// WriteNodeAgentPromTextfile emits the W10 node_agent_* series once per cycle:
// host_oom_kills_total + conntrack_drops_detected_total read the
// hostmetrics kmsg markers (cumulative — monotonic across restarts),
// orphan_hostpath_{bytes,dirs} carry this cycle's ST2 measurement.
// promfile.Write stages + renames with payload/dir fsyncs — the
// collector must never read a partial file (the other nine
// textfile writers take the same path).
func (d *Deps) WriteNodeAgentPromTextfile() {
	dir := d.PromTextfileDir()
	fail := func(err error) {
		d.State.AppendLog(fmt.Sprintf(
			"suspect: node-agent prom textfile unwritable (dir=%s): %v", dir, err))
	}
	var b promfile.Builder
	// Builder has no counter helper — a counter family is its
	// header plus a bare `name v` sample line.
	counter := func(name, help string, v int64) {
		b.HeaderType(name, help, "counter")
		b.Line(fmt.Sprintf("%s %d", name, v))
	}
	if v, err := strconv.ParseInt(strings.TrimSpace(
		ReadSmallFile(d.Cfg.Host.OOMCountFile)), 10, 64); err == nil {
		counter("node_agent_host_oom_kills_total",
			"Host-level OOM kills observed by the kernel dmesg scanner (outside /kubepods or host daemons).", v)
	} else {
		counter("node_agent_host_oom_kills_total",
			"Host-level OOM kills observed by the kernel dmesg scanner (outside /kubepods or host daemons).", 0)
	}
	if v, err := strconv.ParseInt(strings.TrimSpace(
		ReadSmallFile(d.Cfg.Host.ConntrackDropsFile)), 10, 64); err == nil {
		counter("node_agent_conntrack_drops_detected_total",
			"nf_conntrack table-full records observed by the kernel dmesg scanner.", v)
	} else {
		counter("node_agent_conntrack_drops_detected_total",
			"nf_conntrack table-full records observed by the kernel dmesg scanner.", 0)
	}
	b.Gauge("node_agent_orphan_hostpath_bytes",
		"Bytes held by orphaned pvc-* hostPath dirs whose PV is gone.",
		float64(d.OrphanHostPathBytes))
	b.Gauge("node_agent_orphan_hostpath_dirs",
		"Orphaned pvc-* hostPath dirs whose PV is gone from the apiserver.",
		float64(d.OrphanHostPathDirs))
	// Runtime-resource guard series — the checks refresh these
	// fields each cycle (counters accumulate in-agent). Read via
	// d.Series explicitly: the embedded struct is the ownership
	// boundary, and this writer is its only reader.
	b.Gauge("node_agent_cgroup_dying_descendants",
		"nr_dying_descendants on the cgroup-v2 root / kubepods.slice (max of the two).",
		float64(d.Series.CgroupDyingDescendants))
	counter("node_agent_cgroup_reclaim_runs_total",
		"drop_caches + memory.reclaim reclaim runs for the cgroup-dying-leak guard.",
		d.Series.CgroupReclaimRuns)
	b.Gauge("node_agent_systemd_sessions_total",
		"logind session state files under /run/systemd/sessions.",
		float64(d.Series.SystemdSessionsTotal))
	b.Gauge("node_agent_systemd_abandoned_sessions",
		"logind sessions in STATE=closing/abandoned older than 2h.",
		float64(d.Series.SystemdSessionsStale))
	b.Gauge("node_agent_systemd_dbus_latency_seconds",
		"Wall time of `systemctl is-system-running` — the D-Bus round trip.",
		d.Series.SystemdDbusLatencySec)
	counter("node_agent_systemd_sessions_reaped_total",
		"loginctl terminate-session calls issued by the session janitor.",
		d.Series.SystemdSessionsReaped)
	counter("node_agent_overlayfs_stale_mounts_total",
		"Stale-overlay (ESTALE/missing lowerdir) pod detections on this node.",
		d.Series.OverlayFSStaleMounts)
	b.Gauge("node_agent_disk_io_util_ratio",
		"Whole-disk io_ticks utilization, max across devices, per cycle delta.",
		d.Series.DiskIOUtilRatio)
	b.Gauge("node_agent_disk_write_await_ms",
		"Average write await in ms across whole disks, per cycle delta.",
		d.Series.DiskWriteAwaitMs)
	b.Gauge("node_agent_io_psi_full_avg60",
		"/proc/pressure/io full avg60 (percent of wall time all tasks stalled on IO).",
		d.Series.IOPSIFullAvg60)
	b.Gauge("node_agent_io_psi_full_avg300",
		"/proc/pressure/io full avg300 (percent of wall time all tasks stalled on IO).",
		d.Series.IOPSIFullAvg300)
	counter("node_agent_io_throttled_procs_total",
		"Background IO-heavy processes deprioritized (renice +19 + ionice idle).",
		d.Series.IOThrottledProcs)
	counter("node_agent_conntrack_liberal_fixes_total",
		"nf_conntrack_tcp_be_liberal 0→1 fixes written on neb1 nodes.",
		d.Series.ConntrackLiberalFixes)
	b.Gauge("node_agent_unlinked_open_file_bytes",
		"Bytes held by deleted-but-open regular files under /proc/*/fd (deduped by dev,ino).",
		float64(d.Series.UnlinkedOpenFileBytes))
	b.Gauge("node_agent_unlinked_open_files_count",
		"Deleted-but-open regular files >=64MiB held under /proc/*/fd.",
		float64(d.Series.UnlinkedOpenFileCount))
	b.Gauge("node_agent_kubepods_swap_used_bytes",
		"memory.swap.current of kubepods.slice — pod swap-out in progress.",
		float64(d.Series.KubepodsSwapUsedBytes))
	b.Gauge("node_agent_kubelet_pleg_last_seen_age_seconds",
		"kubelet_pleg_last_seen_seconds — seconds since PLEG last saw a container state change.",
		d.Series.KubeletPLEGLastSeenAgeSec)
	counter("node_agent_kubelet_pleg_discard_events_total",
		"kubelet_pleg_discard_events counter passthrough — PLEG events dropped under backlog.",
		d.Series.KubeletPLEGDiscardEvents)
	counter("node_agent_pod_cgroup_memory_throttled",
		"Pod cgroups with memory.pressure full avg60 >40% and rising memory.events high while node PSI is quiet — memory.high throttle without OOM (W12-KR1).",
		d.Series.PodCgroupMemoryThrottled)
	b.Gauge("node_cgroup_pids_utilization_max_ratio",
		"Max pids.current/pids.max ratio across kubepods pod cgroups — near 1 means fork() denials are next.",
		d.Series.PodCgroupPIDsMaxUtilRatio)
	counter("node_kubelet_storage_operation_errors_total",
		"storage_operation_errors_total summed over volume_plugin/operation labels from the kubelet :10250/metrics scrape (W12-KR4).",
		d.Series.KubeletStorageOperationErrors)
	if err := promfile.Write(dir, "node-agent-hygiene.prom",
		[]byte(b.String())); err != nil {
		fail(err)
	}
}

// ReadSmallFile reads a marker file, capped — the kmsg markers are
// tiny; a runaway file must not be slurped whole.
func ReadSmallFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	b, _ := io.ReadAll(io.LimitReader(f, 4096))
	return string(b)
}
