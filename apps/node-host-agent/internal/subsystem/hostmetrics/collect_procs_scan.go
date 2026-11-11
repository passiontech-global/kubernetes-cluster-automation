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
	"bytes"
	"os"
	"path/filepath"
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
//
// comm AND state both come out of the single /proc/<pid>/stat read —
// comm is the parenthesized field 2, state the first token after the
// LAST ')' — so the /proc/<pid>/comm file read and the strings.Fields
// slice alloc are both gone. The fd-dir ReadDir (the expensive half:
// ~30 entries per pid × ~1,500 pids) runs ONLY for pids whose comm
// is a watched daemon — every other pid's fds field stays -1, which
// collectDaemonFD already treats as "not a candidate".
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
			ps.state, ps.comm = parseStatHead(data)
		}
		if !daemonFDComm(ps.comm) {
			procs[e.Name()] = ps
			continue
		}
		var cmdline string
		if ps.comm == "k0s" {
			// Only the k0s daemons need cmdline (worker vs
			// controller share comm) — nobody else pays the read.
			if b, rerr := os.ReadFile(filepath.Join(dir, "cmdline")); rerr == nil {
				cmdline = string(b)
			}
		}
		if matchDaemon(ps.comm, cmdline) == "" {
			procs[e.Name()] = ps
			continue
		}
		ps.cmdline = cmdline
		if fds, err := os.ReadDir(filepath.Join(dir, "fd")); err == nil {
			ps.fds = len(fds)
		}
		procs[e.Name()] = ps
	}
	return procs
}

// daemonFDComm reports whether comm is one of the daemonFDTargets
// comm values — the cheap gate that keeps the fd ReadDir off the
// ~1,490 non-daemon pids. "k0s" covers both worker and controller;
// the argv[1] discriminator runs later in matchDaemon.
func daemonFDComm(comm string) bool {
	for _, d := range daemonFDTargets {
		if comm == d.comm {
			return true
		}
	}
	return false
}

// parseStatHead extracts (state, comm) from a raw /proc/<pid>/stat
// blob with no strings.Fields allocation: comm is the text between
// the FIRST '(' and the LAST ')' (it can itself contain spaces and
// parens), state the first byte after the last ')' + space. ok=false
// halves degrade to zero values — same verdict the Fields parse
// gave callers.
func parseStatHead(data []byte) (state byte, comm string) {
	i := bytes.LastIndexByte(data, ')')
	if i < 0 || i+2 >= len(data) {
		return 0, ""
	}
	state = data[i+2]
	if open := bytes.IndexByte(data, '('); open >= 0 && open < i {
		comm = string(data[open+1 : i])
	}
	return state, comm
}
