// config_disk.go — the disk knobs: DiskConfig and its defaults (the
// /var/lib/k0s watermark that triggers the ingest GC, the W6.3
// disk-bloat runaway detector, the /var/log/pods walk and the
// W10-ST2 orphan-hostPath roots). K0sDataDir itself promoted to the
// top-level Config (ctr + runtime both read it). The domain reads no
// env rows of its own.
package wdeps

import (
	"time"
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
}
