// collect_inotify.go — A1/H8 inotify instance/watch pressure: the
// cached /proc/*/fdinfo sweep vs the max_user_* limits, plus the
// top-3 holder warn report. Split out of hostmetrics.go.
package hostmetrics

import (
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
	"github.com/prometheus/client_golang/prometheus"
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

// --- A1: inotify instances/watches pressure ---
var pidDirRe = regexp.MustCompile(`^[0-9]+$`)

// inotifyFDTarget is the /proc/<pid>/fd/<fd> symlink target the
// kernel gives an inotify group fd — the same source
// node_exporter/procfs uses to count instances.
const inotifyFDTarget = "anon_inode:inotify"

// sweepInotify walks every /proc/<pid>/fd/* counting inotify
// INSTANCES by fd symlink target and WATCHES by `inotify wd:` lines
// in the matching fdinfo file. The symlink read is mandatory: an
// inotify group holding ZERO watches emits no identifying line in
// fdinfo — the classic inotify_init() fd leak (exactly what the
// instances-used ratio exists to catch) is invisible to any
// fdinfo-only count while the host races max_user_instances.
func (c *Collector) sweepInotify() (inst, watch uint64, top []inotifyConsumer) {
	pids, err := os.ReadDir(c.cfg.ProcRoot)
	if err != nil {
		return 0, 0, nil
	}
	cons := map[int]*inotifyConsumer{}
	for _, p := range pids {
		if !p.IsDir() || !pidDirRe.MatchString(p.Name()) {
			continue
		}
		pid, _ := strconv.Atoi(p.Name())
		fds, err := os.ReadDir(filepath.Join(c.cfg.ProcRoot, p.Name(), "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(
				c.cfg.ProcRoot, p.Name(), "fd", fd.Name()))
			if err != nil || target != inotifyFDTarget {
				continue
			}
			// fdinfo may be absent or unreadable for a raced fd —
			// the instance still counts, with zero watches.
			var w uint64
			if data, rerr := os.ReadFile(filepath.Join(
				c.cfg.ProcRoot, p.Name(), "fdinfo", fd.Name())); rerr == nil {
				w = uint64(strings.Count(string(data), "inotify wd:"))
			}
			inst++
			watch += w
			cc := cons[pid]
			if cc == nil {
				cc = &inotifyConsumer{pid: pid}
				cons[pid] = cc
			}
			cc.instances++
			cc.watches += w
		}
	}
	for _, cc := range cons {
		data, err := os.ReadFile(filepath.Join(
			c.cfg.ProcRoot, strconv.Itoa(cc.pid), "comm"))
		if err == nil {
			cc.name = strings.TrimSpace(string(data))
		}
	}
	all := make([]inotifyConsumer, 0, len(cons))
	for _, cc := range cons {
		all = append(all, *cc)
	}
	slices.SortFunc(all, func(a, b inotifyConsumer) int {
		if a.watches != b.watches {
			return cmp.Compare(b.watches, a.watches)
		}
		return cmp.Compare(a.pid, b.pid)
	})
	if len(all) > 3 {
		all = all[:3]
	}
	return inst, watch, all
}

// inotifySnapshot returns the cached sweep, re-walking the procfs
// at most once per InotifyScanInterval.
func (c *Collector) inotifySnapshot() (uint64, uint64, []inotifyConsumer) {
	c.mu.Lock()
	if c.cfg.nowFn().Sub(c.inoAt) < c.cfg.InotifyScanInterval {
		inst, watch, top := c.inoInstances, c.inoWatches, c.inoTop
		c.mu.Unlock()
		return inst, watch, top
	}
	c.mu.Unlock()

	// The /proc/*/fdinfo sweep can take seconds on a busy node —
	// run it WITHOUT mu so concurrent scrapes aren't blocked for
	// the whole walk (mu also guards every other collector
	// section's bookkeeping). Two scrapes may then sweep in
	// parallel; the later store wins, harmless for a cache.
	inst, watch, top := c.sweepInotify()
	c.mu.Lock()
	c.inoInstances, c.inoWatches, c.inoTop = inst, watch, top
	c.inoAt = c.cfg.nowFn()
	c.mu.Unlock()
	return inst, watch, top
}

// warnInotifyTop edge-logs the top-3 holder report once per
// over-threshold episode (the fsStalledLogged pattern).
func (c *Collector) warnInotifyTop(kind string, over bool,
	top []inotifyConsumer) {
	c.mu.Lock()
	var warned *bool
	if kind == "instances" {
		warned = &c.inoWarnedInst
	} else {
		warned = &c.inoWarnedWatch
	}
	was := *warned
	*warned = over
	c.mu.Unlock()
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

// collectInotify emits the two fill ratios — each only when its own
// limit file parses (same per-source rule as conntrack).
func (c *Collector) collectInotify(ch chan<- prometheus.Metric) {
	inst, watch, top := c.inotifySnapshot()
	maxI, instOK := hostutil.ReadUintFile(c.cfg.InotifyMaxInstancesFile)
	maxW, watchOK := hostutil.ReadUintFile(c.cfg.InotifyMaxWatchesFile)
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
