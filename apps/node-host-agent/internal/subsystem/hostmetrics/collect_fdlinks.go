// collect_fdlinks.go — the ONE /proc/*/fd/* readlink sweep per
// interval feeding BOTH fdinfo consumers: the inotify
// instance/watch census (collect_inotify.go) and the eBPF
// prog/map id census (collect_ebpf.go). They used to walk the same
// ~1,500 pid fd-dirs independently — ~40k readlinkat + ~1,500
// ReadDir calls per node per minute, doubled. One pass now
// classifies each fd link once (anon_inode:inotify vs
// anon_inode:bpf-*) and reads fdinfo only for the fds that match.
//
// singleflight: concurrent scrapes share one in-flight walk — the
// first caller leads, followers park on the done channel and read
// the leader's result instead of starting a second sweep.
package hostmetrics

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
)

// fdLinkResult is the merged sweep payload — the inotify half
// (instances/watches/top-holders) and the ebpf half (unique
// prog/map id sets + bpffs pin count) harvested from the same
// readlink pass.
type fdLinkResult struct {
	at     time.Time
	procOK bool // /proc root listed — inotify emits zeros without it

	inst  uint64
	watch uint64
	top   []inotifyConsumer

	progs   map[uint64]bool
	maps    map[uint64]bool
	pins    int
	bpffsOK bool // bpffs dir stat'd — ebpf's second scanned source
}

// fdLinkCache is the shared sweep cache — one mutex over the latest
// result plus the in-flight dedup channel. The two consumers keep
// their own freshness intervals: each checks the shared result's
// age against ITS interval, so a sweep triggered by the shorter
// interval refreshes both (fresher data, never staler).
type fdLinkCache struct {
	mu       sync.Mutex
	res      *fdLinkResult
	inflight chan struct{} // non-nil while a sweep runs
}

// snapshot returns the cached sweep while it is younger than
// interval; on expiry the caller either leads the walk or parks on
// the in-flight one. The leader stores the result stamped with the
// post-walk clock reading.
func (c *Collector) fdLinkSnapshot(interval time.Duration) *fdLinkResult {
	now := c.cfg.Clock.Now()
	c.fdscan.mu.Lock()
	if c.fdscan.res != nil && now.Sub(c.fdscan.res.at) < interval {
		res := c.fdscan.res
		c.fdscan.mu.Unlock()
		return res
	}
	if c.fdscan.inflight != nil {
		done := c.fdscan.inflight
		c.fdscan.mu.Unlock()
		<-done
		c.fdscan.mu.Lock()
		res := c.fdscan.res
		c.fdscan.mu.Unlock()
		return res
	}
	done := make(chan struct{})
	c.fdscan.inflight = done
	c.fdscan.mu.Unlock()

	res := c.sweepFDLinks()

	c.fdscan.mu.Lock()
	res.at = c.cfg.Clock.Now()
	c.fdscan.res = res
	c.fdscan.inflight = nil
	close(done)
	c.fdscan.mu.Unlock()
	return res
}

// sweepFDLinks walks ProcRoot's pid fd-dirs ONCE: every fd's
// readlink target is classified — "anon_inode:inotify" feeds the
// instance/watch census (fdinfo "inotify wd:" line count), the
// "anon_inode:bpf-" prefix feeds the eBPF id harvest. fdinfo is
// opened only for matching fds, same as the two sweeps did
// separately — the saving is the single readlink pass and the
// single fd-dir listing, not fewer fdinfo reads.
func (c *Collector) sweepFDLinks() *fdLinkResult {
	res := &fdLinkResult{
		progs: map[uint64]bool{},
		maps:  map[uint64]bool{},
	}
	cons := map[int]*inotifyConsumer{}
	pids, err := os.ReadDir(c.cfg.ProcRoot)
	if err == nil {
		res.procOK = true
		for _, p := range pids {
			if !p.IsDir() || !procfs.IsDigits(p.Name()) {
				continue
			}
			pid, _ := strconv.Atoi(p.Name())
			pidDir := filepath.Join(c.cfg.ProcRoot, p.Name())
			fds, err := os.ReadDir(filepath.Join(pidDir, "fd"))
			if err != nil {
				continue
			}
			for _, fd := range fds {
				target, err := os.Readlink(filepath.Join(
					pidDir, "fd", fd.Name()))
				if err != nil {
					continue
				}
				switch {
				case target == inotifyFDTarget:
					c.sweepInotifyFD(pidDir, pid, fd.Name(), cons, res)
				case strings.Contains(target, ebpfFDTarget):
					c.sweepEBPFFD(pidDir, fd.Name(), res)
				}
			}
		}
	}
	// bpffs half of the ebpf census — a WALK, not an open (bpffs
	// rejects readmode opens for whole pin classes; every walked
	// non-dir entry IS a pinned object).
	if _, err := os.Stat(c.cfg.BpffsDir); err == nil {
		res.bpffsOK = true
		_ = filepath.WalkDir(c.cfg.BpffsDir,
			func(path string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil //nolint:nilerr // unreadable entries are skipped, never fatal
				}
				res.pins++
				return nil
			})
	}
	// Bounded top-3 insertion — the sweep never retains the full
	// holder set just to sort it away.
	for _, cc := range cons {
		res.top = inotifyTopInsert(res.top, *cc)
	}
	// Top-3 inotify holder names — comm reads pay only for the
	// three pids the warn report prints (not every inotify holder).
	for i := range res.top {
		if data, err := os.ReadFile(filepath.Join(
			c.cfg.ProcRoot, strconv.Itoa(res.top[i].pid), "comm")); err == nil {
			res.top[i].name = strings.TrimSpace(string(data))
		}
	}
	return res
}

// sweepInotifyFD accounts one anon_inode:inotify fd: the instance
// counts even when fdinfo is absent/unreadable (the zero-watch
// inotify_init leak the instances ratio exists to catch); watches
// come from the "inotify wd:" line count.
func (c *Collector) sweepInotifyFD(pidDir string, pid int,
	fdName string, cons map[int]*inotifyConsumer, res *fdLinkResult) {
	var w uint64
	if data, err := os.ReadFile(filepath.Join(
		pidDir, "fdinfo", fdName)); err == nil {
		w = uint64(strings.Count(string(data), "inotify wd:"))
	}
	res.inst++
	res.watch += w
	cc := cons[pid]
	if cc == nil {
		cc = &inotifyConsumer{pid: pid}
		cons[pid] = cc
	}
	cc.instances++
	cc.watches += w
}

// sweepEBPFFD harvests prog_id:/map_id: lines from one bpf-object
// fd's fdinfo into the dedup sets.
func (c *Collector) sweepEBPFFD(pidDir, fdName string, res *fdLinkResult) {
	data, err := os.ReadFile(filepath.Join(pidDir, "fdinfo", fdName))
	if err != nil {
		return
	}
	scanBPFIDLines(data, res.progs, res.maps)
}
