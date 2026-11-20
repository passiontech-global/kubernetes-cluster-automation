// collect_inotify.go — A1/H8 inotify instance/watch pressure: the
// cached /proc/*/fdinfo sweep vs the max_user_* limits, plus the
// top-3 holder warn report. Split out of hostmetrics.go.
package hostmetrics

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

const (
	// The inotify fdinfo sweep is cached — walking every fdinfo file
	// per scrape is too heavy on a busy node.
	defaultInotifyScanInterval = 60 * time.Second
	defaultInotifyMaxInstFile  = "/proc/sys/fs/inotify/max_user_instances"
	defaultInotifyMaxWatchFile = "/proc/sys/fs/inotify/max_user_watches"
	// inotifyWarnRatio is the fill ratio that logs the top-3 holder
	// report — early enough to find the leaker before
	// max_user_instances is hit.
	inotifyWarnRatio = 0.80
)

// inotifyConsumer is one process's inotify footprint — kept for the
// top-3 holder report when a used ratio crosses the warn line.
type inotifyConsumer struct {
	pid       int
	name      string
	instances uint64
	watches   uint64
}

// inotifyCache holds the edge-triggered >80% top-3-holder Warn flags
// plus the memoized aggregation over the latest *procfs.FDSnapshot
// pointer from the shared fdCache.
type inotifyCache struct {
	mu          sync.Mutex
	warnedInst  bool // edge-triggered >80% Warn per episode
	warnedWatch bool

	lastSnap *procfs.FDSnapshot
	inst     uint64
	watch    uint64
	top      []inotifyConsumer
}

// noteWarned edge-updates the per-kind warn flag (over replaces the
// stored edge) and returns the previous value — the caller logs
// only on the false→true transition.
func (s *inotifyCache) noteWarned(kind string, over bool) (was bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	warned := &s.warnedWatch
	if kind == "instances" {
		warned = &s.warnedInst
	}
	was = *warned
	*warned = over
	return was
}

// inotifyTopN is the holder count the warn report prints.
const inotifyTopN = 3

// inotifyTopLess ranks a before b — watches-desc, pid-asc (the
// top-3 holder report's order).
func inotifyTopLess(a, b inotifyConsumer) bool {
	if a.watches != b.watches {
		return a.watches > b.watches
	}
	return a.pid < b.pid
}

// inotifyTopInsert keeps top at the bounded top-3 holders the warn
// report prints, watches-desc/pid-asc — the bounded-insert form of
// the old sort-every-consumer-then-truncate, which the sort's
// by-value slice param silently turned into a no-op (SA4006): the
// full holder set was retained per sweep just to throw all but
// three away. Worse-than-tail entries return unchanged.
func inotifyTopInsert(top []inotifyConsumer, cc inotifyConsumer) []inotifyConsumer {
	pos := len(top)
	for pos > 0 && inotifyTopLess(cc, top[pos-1]) {
		pos--
	}
	if pos == inotifyTopN {
		return top
	}
	if len(top) < inotifyTopN {
		top = append(top, inotifyConsumer{})
	}
	copy(top[pos+1:], top[pos:])
	top[pos] = cc
	return top
}

// inotifySnapshot returns the inotify counts and top-3 holders from the
// shared procfs.FDCache snapshot, memoized on the snapshot pointer so
// repeat reads within InotifyScanInterval do not re-aggregate or re-read
// /proc/<pid>/comm. Returns ok=false on !ProcOK or Partial walks so
// callers neither emit bogus zero metrics nor falsely reset warn flags.
func (c *Collector) inotifySnapshot() (uint64, uint64, []inotifyConsumer, bool) {
	snap := c.fdCache().Snapshot(c.cfg.InotifyScanInterval)
	if snap == nil || !snap.ProcOK || snap.Partial {
		return 0, 0, nil, false
	}
	c.ino.mu.Lock()
	if c.ino.lastSnap == snap {
		inst, watch, top := c.ino.inst, c.ino.watch, c.ino.top
		c.ino.mu.Unlock()
		return inst, watch, top, true
	}
	c.ino.mu.Unlock()

	var inst, watch uint64
	cons := map[int]*inotifyConsumer{}
	for _, fd := range snap.Inotify {
		var w uint64
		if fd.Watches > 0 {
			w = uint64(fd.Watches)
		}
		inst++
		watch += w
		cc := cons[fd.PID]
		if cc == nil {
			cc = &inotifyConsumer{pid: fd.PID}
			cons[fd.PID] = cc
		}
		cc.instances++
		cc.watches += w
	}
	// Bounded top-3 insertion — never retain the full holder set.
	var top []inotifyConsumer
	for _, cc := range cons {
		top = inotifyTopInsert(top, *cc)
	}
	// Top-3 inotify holder names — comm reads pay only for the
	// three pids the warn report prints.
	for i := range top {
		if data, err := os.ReadFile(filepath.Join(
			c.cfg.ProcRoot, strconv.Itoa(top[i].pid), "comm")); err == nil {
			top[i].name = strings.TrimSpace(string(data))
		}
	}

	c.ino.mu.Lock()
	if c.ino.lastSnap != snap {
		c.ino.lastSnap = snap
		c.ino.inst = inst
		c.ino.watch = watch
		c.ino.top = top
	} else {
		inst, watch, top = c.ino.inst, c.ino.watch, c.ino.top
	}
	c.ino.mu.Unlock()
	return inst, watch, top, true
}

// warnInotifyTop edge-logs the top-3 holder report once per
// over-threshold episode (the fs probe's noteStall pattern).
func (c *Collector) warnInotifyTop(kind string, over bool,
	top []inotifyConsumer) {
	was := c.ino.noteWarned(kind, over)
	if !over || was {
		return
	}
	parts := make([]string, 0, len(top))
	for _, p := range top {
		parts = append(parts, fmt.Sprintf("pid=%d %s instances=%d watches=%d",
			p.pid, p.name, p.instances, p.watches))
	}
	logger().Warn("hostmetrics: inotify "+kind+" above "+
		strconv.FormatFloat(inotifyWarnRatio*100, 'f', -1, 64)+
		"% of the limit — top holders: "+strings.Join(parts, "; "),
		"kind", kind)
}

var (
	descInotifyInst = prometheus.NewDesc(
		"node_host_agent_inotify_instances_used_ratio",
		"inotify fds in use / max_user_instances (emitted only when the limit parses and is > 0).",
		[]string{"node"}, nil)
	descInotifyWatches = prometheus.NewDesc(
		"node_host_agent_inotify_watches_used_ratio",
		"inotify watches in use / max_user_watches (emitted only when the limit parses and is > 0).",
		[]string{"node"}, nil)
)

// collectInotify emits the two fill ratios — each only when the proc
// walk succeeded cleanly AND its own limit file parses (same per-source
// rule as conntrack).
func (c *Collector) collectInotify(ch chan<- prometheus.Metric) {
	inst, watch, top, ok := c.inotifySnapshot()
	if !ok {
		return
	}
	maxI, instOK := fsx.ReadUintFile(c.cfg.InotifyMaxInstancesFile)
	maxW, watchOK := fsx.ReadUintFile(c.cfg.InotifyMaxWatchesFile)
	if instOK && maxI > 0 {
		r := float64(inst) / float64(maxI)
		ch <- prometheus.MustNewConstMetric(descInotifyInst,
			prometheus.GaugeValue, r, c.cfg.NodeName)
		c.warnInotifyTop("instances", r >= inotifyWarnRatio, top)
	}
	if watchOK && maxW > 0 {
		r := float64(watch) / float64(maxW)
		ch <- prometheus.MustNewConstMetric(descInotifyWatches,
			prometheus.GaugeValue, r, c.cfg.NodeName)
		c.warnInotifyTop("watches", r >= inotifyWarnRatio, top)
	}
}
