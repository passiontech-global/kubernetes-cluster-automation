// config_disk.go — the disk knobs: DiskConfig and its defaults (the
// /var/lib/k0s watermark that triggers the ingest GC, the W6.3
// disk-bloat runaway detector, the /var/log/pods walk and the
// W10-ST2 orphan-hostPath roots). K0sDataDir itself promoted to the
// top-level Config (ctr + runtime both read it). The domain reads no
// env rows of its own.
package wdeps

import (
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// DiskConfig groups the disk knobs: the /var/lib/k0s watermark that
// triggers the ingest GC, the W6.3 disk-bloat runaway detector, the
// /var/log/pods walk (BUG-H8) and the W10-ST2 orphan-hostPath roots.
type DiskConfig struct {
	HighWatermark float64 // /var/lib/k0s used ratio triggering GC
	// W6.3 disk-bloat runaway detector: above BloatWatermark
	// the bounded emptyDir/snapshot walk runs (gated by
	// BloatScanInterval — the walk costs IO on the disk that is
	// already full); above BloatCriticalWatermark a
	// non-system pod holding more than BloatPodThresholdBytes
	// may be evicted through the API (last-disk-bloat-evict budget).
	BloatWatermark         float64
	BloatCriticalWatermark float64
	BloatPodThresholdBytes int64
	BloatScanInterval      time.Duration
	PodLogsDir             string // /var/log/pods walk root (BUG-H8)
	// OrphanHostPathDirs are the host-side local-provisioner roots
	// ST2 scans for pvc-* dirs whose PV is gone.
	OrphanHostPathDirs []string
	// LocalPVQuotaRatio is the localpv-quota hard-quota multiplier: a
	// pvc-* dir under OrphanHostPathDirs (or LocalPVQuotaDir when
	// set) larger than ratio x its PV capacity while the backing
	// filesystem is >80% full gets the owning pod deprioritized.
	LocalPVQuotaRatio float64
	// LocalPVQuotaDir, when set, replaces OrphanHostPathDirs as the
	// quota-scan root list (single dir — the OpenEBS hostpath root).
	LocalPVQuotaDir string
	// HostRunDir is the host /run tmpfs as the agent sees it
	// (/host/run in the DaemonSet) — the run-tmpfs guard statfs's it
	// and sweeps orphan .tmp files under it.
	HostRunDir string
	// JournalVacuumDir is the journal directory passed to
	// `journalctl --directory= --vacuum-size` by the /run guard —
	// the HOST view (/run/log/journal): the systemd exec seam runs
	// nsenter -m wrapped, so container-side /host paths would not
	// resolve.
	JournalVacuumDir string
	// WLayerSnapshotsDir is the ACTIVE overlayfs snapshotter
	// root the writable-layer runaway scan walks (<id>/fs is the
	// container's writable upperdir); CoredumpDir is the host
	// systemd coredump store the coredump-storm guard sweeps
	// once its filesystem crosses BloatWatermark. Both are /host-
	// prefixed agent views like the wiring block.
	WLayerSnapshotsDir string
	CoredumpDir        string
	// WLayerBloatThresholdBytes is the writable-layer scan's
	// Warning threshold (default 5 GiB) — deliberately separate from
	// BloatPodThresholdBytes, which stays the W6.3 eviction path's
	// threshold so the plan's parity does not alter eviction
	// behavior.
	WLayerBloatThresholdBytes int64
}

func (d *DiskConfig) applyDefaults() {
	if d.HighWatermark <= 0 {
		d.HighWatermark = k0sDiskHighWatermark
	}
	if d.BloatWatermark <= 0 {
		d.BloatWatermark = k0sDiskBloatWatermark
	}
	if d.BloatCriticalWatermark <= 0 {
		d.BloatCriticalWatermark = k0sDiskBloatCriticalWatermark
	}
	if d.BloatPodThresholdBytes <= 0 {
		d.BloatPodThresholdBytes = diskBloatPodThresholdBytes
	}
	if d.BloatScanInterval <= 0 {
		d.BloatScanInterval = diskBloatScanInterval
	}
	if d.PodLogsDir == "" {
		d.PodLogsDir = defaultPodLogsDir
	}
	if len(d.OrphanHostPathDirs) == 0 {
		// Paths are used RAW (no HostRoot prefix): the DaemonSet
		// mounts host /var/openebs/local at the SAME container path
		// (sweeper contract). /opt/local-path-provisioner has no
		// container mount — ReadDir just misses there — but is the
		// real host path in standalone mode. Extra provisioner
		// roots need a matching DS hostPath mount to be scanned.
		d.OrphanHostPathDirs = []string{
			"/var/openebs/local",
			"/opt/local-path-provisioner",
		}
	}
	if d.LocalPVQuotaRatio <= 0 {
		d.LocalPVQuotaRatio = localPVQuotaRatio
	}
	if d.HostRunDir == "" {
		d.HostRunDir = defaultHostRunDir
	}
	if d.JournalVacuumDir == "" {
		d.JournalVacuumDir = defaultJournalVacuumDir
	}
	if d.WLayerSnapshotsDir == "" {
		d.WLayerSnapshotsDir = defaultWLayerSnapshotsDir
	}
	if d.CoredumpDir == "" {
		d.CoredumpDir = defaultCoredumpDir
	}
	if d.WLayerBloatThresholdBytes <= 0 {
		d.WLayerBloatThresholdBytes = wlayerBloatThresholdBytes
	}
}

// envKnobs returns the disk-guard env rows — hostPath defaults
// for the /run view like the wiring block.
func (d *DiskConfig) envKnobs(hostPath func(string) string) []envx.Knob {
	return []envx.Knob{
		envx.StringKnob(envnames.EnvLocalPVQuotaDir, &d.LocalPVQuotaDir, ""),
		envx.StringKnob(envnames.EnvHostRunDir, &d.HostRunDir,
			hostPath("/run")),
		envx.StringKnob(envnames.EnvWLayerSnapshotsDir, &d.WLayerSnapshotsDir,
			hostPath("/run/k0s/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots")),
		envx.StringKnob(envnames.EnvCoredumpDir, &d.CoredumpDir,
			hostPath("/var/lib/systemd/coredump")),
		envx.Int64Knob(envnames.EnvWLayerBloatThresholdBytes,
			&d.WLayerBloatThresholdBytes, wlayerBloatThresholdBytes),
	}
}
