// unlinked_open_files.go — the unlinked-open-files guard
// (wdeps.CheckUnlinkedOpenFiles). A process holding an fd on a
// deleted regular file pins the inode: `rm` freed the name, not the
// space, and the block stays accounted until the last fd closes or
// the process dies. On a node already past the disk watermark the
// difference between "rm fixed it" and "rm did nothing" is exactly
// these leaked files — log shippers are the classic offender
// (fluent-bit/vector hold the rotated log's fd until a reopen
// signal makes them drop it).
//
// The check runs only under disk pressure (the sweep is a /proc fd
// walk — IO on the disk that is already full, so it also stamps a
// lastScan like disk-bloat): it walks <ProcRoot>/<pid>/fd, selects
// regular files whose link target ends in " (deleted)" and whose
// size crosses the 64MiB floor, dedups by (dev,ino) — several
// processes can hold the same leaked file — and exports the held
// bytes/count as node_agent_* series. When the log-shipper comms
// hold >=512MiB of deleted-but-open bytes they get SIGHUP on the
// last-unlinked-fd-sighup 30m budget (vector reloads on SIGHUP;
// fluent-bit hot-reloads only with -Y and otherwise shuts down —
// either way the deleted inode is released, by reopen or restart).
package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	// unlinkedFDsWatermark is the /var/lib/k0s used ratio above
	// which the fd sweep runs — deleted-but-open space only matters
	// under disk pressure (same statfs source as disk-bloat).
	unlinkedFDsWatermark = 0.80
	// unlinkedFDsMinBytes is the per-file floor — below 64MiB the
	// pinned space is noise, not the runaway the check exists for.
	unlinkedFDsMinBytes = int64(64) << 20
	// unlinkedSighupBytes is the log-shipper held-bytes total that
	// arms the reopen signal — small leaked files don't justify
	// signalling anything (512MiB).
	unlinkedSighupBytes = int64(512) << 20
	// unlinkedSighupInterval is the last-unlinked-fd-sighup budget.
	unlinkedSighupInterval = 30 * time.Minute
)

// unlinkedSighupComms are the log-shipper process names that
// release deleted fds on SIGHUP — vector by hot reload, fluent-bit
// by hot reload (-Y) or graceful shutdown (kubelet restarts it).
// Either disposition drops the deleted inode the same sweep.
var unlinkedSighupComms = map[string]bool{
	"fluent-bit": true,
	"vector":     true,
}

// UnlinkedOpenFilesCheck is the deleted-but-open fd guard as a
// Check; it owns the scan stamp (the /proc fd walk is bounded like
// disk-bloat's — once per BloatScanInterval while over the
// watermark).
type UnlinkedOpenFilesCheck struct {
	d        *wdeps.Deps
	lastScan time.Time
}

// Name returns the check label / WD_SIG key.
func (c *UnlinkedOpenFilesCheck) Name() string { return wdeps.CheckUnlinkedOpenFiles }

// Run executes one unlinked-open-files round.
func (c *UnlinkedOpenFilesCheck) Run(_ context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckUnlinkedOpenFiles) {
		return
	}
	used, ok := c.d.DiskUsageRatio(c.d.Cfg.K0sDataDir)
	if !ok {
		// statfs failed or returned garbage — inconclusive; keep
		// the series like a failed probe.
		c.d.CycleResult(wdeps.CheckUnlinkedOpenFiles, "abort")
		return
	}
	if used <= unlinkedFDsWatermark {
		c.d.UnlinkedOpenFileBytes = 0
		c.d.UnlinkedOpenFileCount = 0
		c.d.CycleResult(wdeps.CheckUnlinkedOpenFiles, "ok")
		return
	}
	// The fd walk is IO on the disk that is already full — at most
	// once per BloatScanInterval while over the watermark; the last
	// exported series values persist meanwhile.
	if c.d.Cfg.Seams.Host.Clock.Now().Sub(c.lastScan) < c.d.Cfg.Disk.BloatScanInterval {
		c.d.CycleResult(wdeps.CheckUnlinkedOpenFiles, "ok")
		return
	}
	c.lastScan = c.d.Cfg.Seams.Host.Clock.Now()
	total, count, holderBytes, holderPids := c.sweep(e)
	c.d.UnlinkedOpenFileBytes = total
	c.d.UnlinkedOpenFileCount = int64(count)
	if len(holderPids) == 0 {
		c.d.CycleResult(wdeps.CheckUnlinkedOpenFiles, "ok")
		return
	}
	var shipperBytes int64
	for _, pid := range holderPids {
		shipperBytes += holderBytes[pid]
	}
	if shipperBytes < unlinkedSighupBytes {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: unlinked-open-files shipper-held=%d below %d — no SIGHUP (total=%d files=%d)",
			shipperBytes, unlinkedSighupBytes, total, count))
		c.d.CycleResult(wdeps.CheckUnlinkedOpenFiles, "ok")
		return
	}
	if !c.d.State.RateTrySpend("last-unlinked-fd-sighup", unlinkedSighupInterval) {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: unlinked-open-files shipper-held=%d files=%d - SIGHUP cooldown (<30m), skip",
			shipperBytes, count))
		c.d.CycleResult(wdeps.CheckUnlinkedOpenFiles, "ok")
		return
	}
	// Budget spent atomically BEFORE signalling (rate_spend parity —
	// a failed signal still consumed it).
	slices.Sort(holderPids) // deterministic signal order, same convention as dnsStale sort
	for _, pid := range holderPids {
		if err := c.d.Cfg.Seams.Host.KillFn(pid, syscall.SIGHUP); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: unlinked-open-files SIGHUP pid=%d failed: %v", pid, err))
			continue
		}
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: unlinked-open-files SIGHUP pid=%d - %d deleted-but-open bytes held (shipper-held total %d, disk %.1f%%)",
			pid, holderBytes[pid], shipperBytes, used*100))
		c.d.Actions.WithLabelValues(wdeps.CheckUnlinkedOpenFiles, "sighup").Inc()
	}
	c.d.CycleResult(wdeps.CheckUnlinkedOpenFiles, "ok")
}

// sweep walks <ProcRoot>/<pid>/fd and returns the deduped
// deleted-file bytes/count plus the per-pid held bytes of the
// log-shipper comms (holderBytes/holderPids — only comms in
// unlinkedSighupComms appear, sorted pid list for the caller).
func (c *UnlinkedOpenFilesCheck) sweep(e *wdeps.CycleEnv) (total int64,
	count int, holderBytes map[int]int64, holderPids []int) {
	pids := []int(nil)
	if e != nil && e.PidsOnce != nil {
		pids = e.PidsOnce()
	} else {
		pids, _ = c.d.Proc.PIDs()
	}
	type inodeKey struct{ dev, ino uint64 }
	seen := map[inodeKey]bool{}
	shipperSeen := map[int]map[inodeKey]bool{}
	holderBytes = map[int]int64{}
	for _, pid := range pids {
		fdDir := c.d.Proc.File(pid, "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link := filepath.Join(fdDir, fd.Name())
			target, err := os.Readlink(link)
			if err != nil || !strings.HasSuffix(target, " (deleted)") {
				continue
			}
			// memfd/shm deleted files pin anonymous memory or tmpfs,
			// not the filesystem that is full — counting them would
			// inflate the metric and could attribute shipper-held
			// bytes no remedy can release.
			if strings.HasPrefix(target, "/memfd:") ||
				strings.HasPrefix(target, "/dev/shm/") ||
				strings.HasPrefix(target, "/run/shm/") {
				continue
			}
			dev, ino, size, ok := c.d.Cfg.Seams.Host.DeletedFDStatFn(link)
			if !ok || size < unlinkedFDsMinBytes {
				continue
			}
			k := inodeKey{dev: dev, ino: ino}
			if !seen[k] {
				seen[k] = true
				total += size
				count++
			}
			// Shipper attribution is per-(pid,inode), independent
			// of the global dedup — a file shared with a non-shipper
			// holder still counts toward the shipper's SIGHUP call.
			if comm := c.procComm(pid); unlinkedSighupComms[comm] {
				if shipperSeen[pid] == nil {
					shipperSeen[pid] = map[inodeKey]bool{}
				}
				if !shipperSeen[pid][k] {
					shipperSeen[pid][k] = true
					holderBytes[pid] += size
				}
			}
		}
	}
	for pid := range holderBytes {
		holderPids = append(holderPids, pid)
	}
	return total, count, holderBytes, holderPids
}

// procComm reads /proc/<pid>/comm trimmed — "" on a raced exit.
func (c *UnlinkedOpenFilesCheck) procComm(pid int) string {
	data, err := os.ReadFile(c.d.Proc.File(pid, "comm"))
	if err != nil {
		// comm file is absent in the fake-proc tests too — fall
		// back to the stat comm field so a fixture that only
		// writes stat still attributes.
		if st, ok := c.d.Proc.Stat(pid); ok && st.HasComm {
			return st.Comm
		}
		return ""
	}
	return strings.TrimSpace(string(data))
}
