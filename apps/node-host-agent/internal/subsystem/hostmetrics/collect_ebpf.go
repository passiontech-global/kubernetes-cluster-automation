// collect_ebpf.go — W13-OBS1 eBPF program/map inventory: unique
// prog_id/map_id across /proc/<pid>/fdinfo/* plus pinned objects
// under the bpffs mount — zero forks, the leak-audit counters a
// cilium/eBPF map leak grows against.
package hostmetrics

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	// defaultEBPFScanInterval caches the fdinfo sweep — a full
	// /proc/*/fdinfo walk per scrape is too heavy (inotify parity).
	defaultEBPFScanInterval = 60 * time.Second
	defaultBpffsDir         = "/sys/fs/bpf"
)

// ebpfCache is the sweep's scrape-side cache — the same shape as
// inotifyCache: a private mutex over the stamped result, refreshed
// at most once per EBPFScanInterval.
type ebpfCache struct {
	mu      sync.Mutex
	at      time.Time
	progs   int
	maps    int
	scanned bool
}

var (
	descEBPFProgs = prometheus.NewDesc(
		"node_host_agent_ebpf_programs_count",
		"Unique eBPF prog_id referenced by /proc/<pid>/fdinfo plus objects pinned in bpffs.",
		[]string{"node"}, nil)
	descEBPFMaps = prometheus.NewDesc(
		"node_host_agent_ebpf_maps_count",
		"Unique eBPF map_id referenced by /proc/<pid>/fdinfo plus objects pinned in bpffs.",
		[]string{"node"}, nil)
)

// scanBPFIDLines harvests prog_id:/map_id: lines from one fdinfo
// blob into the dedup sets — a link fd can list several prog_ids.
func scanBPFIDLines(data []byte, progs, maps map[uint64]bool) {
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		id, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch strings.TrimSuffix(f[0], ":") {
		case "prog_id":
			progs[id] = true
		case "map_id":
			maps[id] = true
		}
	}
}

// ebpfFDTarget is the /proc/<pid>/fd/<fd> symlink-target prefix the
// kernel gives a bpf object fd (anon_inode:bpf-prog / bpf-map /
// bpf-link) — the cheap pre-filter that keeps the sweep from
// opening every fdinfo file on the host (inotify sweep parity).
const ebpfFDTarget = "anon_inode:bpf-"

// sweepEBPF counts unique eBPF prog/map ids: every prog_id:/map_id:
// line in the fdinfo of fds whose /proc/<pid>/fd link target names
// a bpf object, plus pinned objects under BpffsDir — a pinned
// object no process fd references (the leak signature) resolves by
// OPENING it and reading the fresh fd's own fdinfo. scanned=false
// when neither source read.
func (c *Collector) sweepEBPF() (progs, maps map[uint64]bool, scanned bool) {
	progs, maps = map[uint64]bool{}, map[uint64]bool{}
	if pids, err := os.ReadDir(c.cfg.ProcRoot); err == nil {
		scanned = true
		for _, p := range pids {
			if !p.IsDir() || !pidDirRe.MatchString(p.Name()) {
				continue
			}
			fds, err := os.ReadDir(filepath.Join(c.cfg.ProcRoot,
				p.Name(), "fd"))
			if err != nil {
				continue
			}
			for _, fd := range fds {
				// Readlink is one cheap syscall per fd — only
				// bpf-object fds earn the fdinfo open+read.
				target, err := os.Readlink(filepath.Join(
					c.cfg.ProcRoot, p.Name(), "fd", fd.Name()))
				if err != nil || !strings.Contains(target, ebpfFDTarget) {
					continue
				}
				data, err := os.ReadFile(filepath.Join(c.cfg.ProcRoot,
					p.Name(), "fdinfo", fd.Name()))
				if err != nil {
					continue
				}
				scanBPFIDLines(data, progs, maps)
			}
		}
	}
	if _, err := os.Stat(c.cfg.BpffsDir); err == nil {
		scanned = true
		_ = filepath.WalkDir(c.cfg.BpffsDir,
			func(path string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil //nolint:nilerr // unreadable entries are skipped, never fatal
				}
				// Opening the pin yields a real bpf-object fd —
				// its own fdinfo names the prog/map id (the only
				// id source for an unreferenced pin).
				f, err := os.Open(path)
				if err != nil {
					return nil //nolint:nilerr // unreadable pins are skipped, never fatal
				}
				data, err := os.ReadFile(filepath.Join(c.selfFdinfoDir(),
					strconv.FormatUint(uint64(f.Fd()), 10)))
				_ = f.Close()
				if err == nil {
					scanBPFIDLines(data, progs, maps)
				}
				return nil
			})
	}
	return progs, maps, scanned
}

// selfFdinfoDir is the agent's own fdinfo dir — ProcRoot-joined so
// tests point it at the fixture (a fake root simply yields
// unreadable fdinfo; entries skip, never fail the sweep).
func (c *Collector) selfFdinfoDir() string {
	return filepath.Join(c.cfg.ProcRoot, "self", "fdinfo")
}

// ebpfSnapshot returns the cached sweep, re-walking at most once per
// EBPFScanInterval.
func (c *Collector) ebpfSnapshot() (progs, maps int, scanned bool) {
	c.ebpf.mu.Lock()
	if c.cfg.Clock.Now().Sub(c.ebpf.at) < c.cfg.EBPFScanInterval && c.ebpf.scanned {
		p, m, s := c.ebpf.progs, c.ebpf.maps, c.ebpf.scanned
		c.ebpf.mu.Unlock()
		return p, m, s
	}
	c.ebpf.mu.Unlock()

	// Sweep unlocked — two scrapes may walk in parallel; the later
	// store wins, harmless for a cache (inotifySnapshot parity).
	ps, ms, ok := c.sweepEBPF()
	c.ebpf.mu.Lock()
	c.ebpf.at = c.cfg.Clock.Now()
	c.ebpf.progs, c.ebpf.maps, c.ebpf.scanned = len(ps), len(ms), ok
	c.ebpf.mu.Unlock()
	return len(ps), len(ms), ok
}

// collectEBPF emits the unique-id counts — 0 is real data (a node
// whose cilium datapath failed to load carries no programs), so the
// series emits whenever either source scanned.
func (c *Collector) collectEBPF(ch chan<- prometheus.Metric) {
	progs, maps, ok := c.ebpfSnapshot()
	if !ok {
		return
	}
	ch <- prometheus.MustNewConstMetric(descEBPFProgs,
		prometheus.GaugeValue, float64(progs), c.cfg.NodeName)
	ch <- prometheus.MustNewConstMetric(descEBPFMaps,
		prometheus.GaugeValue, float64(maps), c.cfg.NodeName)
}
