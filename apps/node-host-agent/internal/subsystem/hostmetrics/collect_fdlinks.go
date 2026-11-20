// collect_fdlinks.go — shared /proc/*/fd/* cache and bpffs pin walk
// feeding BOTH fdinfo consumers: the inotify instance/watch census
// (collect_inotify.go) and the eBPF prog/map id census (collect_ebpf.go).
//
// The /proc/*/fd walk delegates to procfs.SharedFDCache so hostmetrics
// and workerhygiene share one /proc/*/fd sweep per TTL window without
// cross-importing. The bpffs pin walk stays cached locally at
// EBPFScanInterval.
package hostmetrics

import (
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
)

// fdLinkCache holds the shared procfs FDCache handle alongside the
// locally-cached bpffs pin walk (procfs.FDCache covers /proc/*/fd only).
type fdLinkCache struct {
	proc    *procfs.FDCache
	mu      sync.Mutex
	bpffsAt time.Time
	pins    int
	bpffsOK bool
}

// fdCache returns the shared procfs.FDCache for c.cfg.ProcRoot, with a
// lazy fallback if a test constructed &Collector{} directly without New.
func (c *Collector) fdCache() *procfs.FDCache {
	c.fdscan.mu.Lock()
	p := c.fdscan.proc
	if p == nil {
		p = procfs.SharedFDCache(c.cfg.ProcRoot, c.cfg.Clock.Now)
		c.fdscan.proc = p
	}
	c.fdscan.mu.Unlock()
	return p
}

// bpffsPins walks c.cfg.BpffsDir for pinned objects, cached for interval.
// A backward clock step (age < 0) forces a fresh walk.
func (c *Collector) bpffsPins(interval time.Duration) (int, bool) {
	now := c.cfg.Clock.Now()
	c.fdscan.mu.Lock()
	if !c.fdscan.bpffsAt.IsZero() && interval > 0 {
		age := now.Sub(c.fdscan.bpffsAt)
		if age >= 0 && age < interval {
			pins, ok := c.fdscan.pins, c.fdscan.bpffsOK
			c.fdscan.mu.Unlock()
			return pins, ok
		}
	}
	c.fdscan.mu.Unlock()

	pins := 0
	bpffsOK := false
	// bpffs half of the ebpf census — a WALK, not an open (bpffs
	// rejects readmode opens for whole pin classes; every walked
	// non-dir entry IS a pinned object).
	if _, err := os.Stat(c.cfg.BpffsDir); err == nil {
		bpffsOK = true
		_ = filepath.WalkDir(c.cfg.BpffsDir,
			func(path string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil //nolint:nilerr // unreadable entries are skipped, never fatal
				}
				pins++
				return nil
			})
	}

	c.fdscan.mu.Lock()
	c.fdscan.pins = pins
	c.fdscan.bpffsOK = bpffsOK
	c.fdscan.bpffsAt = c.cfg.Clock.Now()
	c.fdscan.mu.Unlock()
	return pins, bpffsOK
}
