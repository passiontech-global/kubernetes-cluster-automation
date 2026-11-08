// collect_procs_scan.go — the ONE /proc/<pid> walk per scan interval
// the per-process collectors share. collect_daemon_fd.go (comm +
// cmdline + fd count per pid) and collect_procs_cgroup.go's zombie /
// D-state counters (stat state char per pid) each used to walk the
// same ProcRoot every scrape — on a busy node that is three+ stats
// and two file reads per pid per scrape for data that moves on
// process-lifecycle timescales, not scrape timescales. The snapshot
// caches the union of both collectors' per-pid reads (stat + comm +
// cmdline-for-k0s + fd-dir count) behind the same mutex+TTL shape as
// the inotify/ebpf sweep caches; limits (per watched daemon) stay at
// consume time — only the handful of matched pids pay it.
package hostmetrics

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// defaultProcScanInterval caches the shared /proc walk — one walk per
// interval serves daemon-fd and zombies/d-state (ebpf/inotify parity:
// a full /proc pass per scrape is too heavy on a busy node).
const defaultProcScanInterval = 60 * time.Second

// procScan is one pid's cheap per-process read set.
type procScan struct {
	state   byte   // stat state char after the last ')' — 0 when unread
	comm    string // /proc/<pid>/comm, trimmed — "" when unread
	cmdline string // raw cmdline bytes, read only for comm "k0s"
	fds     int    // len(/proc/<pid>/fd) — -1 when the dir didn't list
}

// procScanCache holds the last shared sweep.
type procScanCache struct {
	mu      sync.Mutex
	at      time.Time
	scanned bool
	procs   map[string]procScan
}

// procSnapshot returns the cached /proc scan, re-walking at most once
// per defaultProcScanInterval. ok=false only when ProcRoot itself
// didn't list (collectors then emit nothing, pre-cache parity).
func (c *Collector) procSnapshot() (map[string]procScan, bool) {
	c.proc.mu.Lock()
	if c.proc.scanned && c.cfg.Clock.Now().Sub(c.proc.at) < defaultProcScanInterval {
		procs, ok := c.proc.procs, c.proc.scanned
		c.proc.mu.Unlock()
		return procs, ok
	}
	c.proc.mu.Unlock()

	procs := sweepProcs(c.cfg.ProcRoot)
	c.proc.mu.Lock()
	c.proc.at = c.cfg.Clock.Now()
	c.proc.procs, c.proc.scanned = procs, procs != nil
	c.proc.mu.Unlock()
	return procs, procs != nil
}

// sweepProcs walks ProcRoot once collecting every pid's read set —
// nil when the root doesn't list. Failed per-pid reads degrade that
// pid's fields (0/""/-1), never the walk.
func sweepProcs(procRoot string) map[string]procScan {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	procs := make(map[string]procScan, len(entries))
	for _, e := range entries {
		if !e.IsDir() || !pidDirRe.MatchString(e.Name()) {
			continue
		}
		dir := filepath.Join(procRoot, e.Name())
		ps := procScan{fds: -1}
		if data, err := os.ReadFile(filepath.Join(dir, "stat")); err == nil {
			// The state char sits right after the LAST ')' — comm can
			// contain spaces and parens (zombies scan's trick).
			s := string(data)
			if i := strings.LastIndexByte(s, ')'); i >= 0 {
				if f := strings.Fields(s[i+1:]); len(f) > 0 {
					ps.state = f[0][0]
				}
			}
		}
		if commB, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
			ps.comm = strings.TrimSpace(string(commB))
			if ps.comm == "k0s" {
				// Only the k0s daemons need cmdline (worker vs
				// controller share comm) — nobody else pays the read.
				if b, rerr := os.ReadFile(filepath.Join(dir, "cmdline")); rerr == nil {
					ps.cmdline = string(b)
				}
			}
		}
		if fds, err := os.ReadDir(filepath.Join(dir, "fd")); err == nil {
			ps.fds = len(fds)
		}
		procs[e.Name()] = ps
	}
	return procs
}
