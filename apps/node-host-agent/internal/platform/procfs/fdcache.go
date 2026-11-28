// fdcache.go — shared, race-safe, bounded-memory /proc/*/fd snapshot
// and TTL cache for anon_inode:inotify and anon_inode:bpf-* descriptors.
// Both hostmetrics (inotify/eBPF collectors) and workerhygiene
// (runtime_inotify_pressure) share one /proc/*/fd walk per TTL window
// through SharedFDCache without cross-importing (depguard keeps
// internal/platform as the leaf).
package procfs

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	inotifyFDTarget = "anon_inode:inotify"
	ebpfFDTarget    = "anon_inode:bpf-"
	// maxFDInfoBytes caps one fdinfo read so a pathological file cannot
	// cause unbounded CPU/RAM work.
	maxFDInfoBytes = 64 << 20
)

var inotifyWDPrefix = []byte("inotify wd:")

// InotifyFD records one anon_inode:inotify open fd observed on a process.
type InotifyFD struct {
	PID     int
	FD      int   // numeric fd (strconv.Itoa(FD) gives fdName)
	Watches int64 // count of "inotify wd:" lines in fdinfo/<fd>
}

// FDSnapshot is an immutable point-in-time /proc/*/fd sweep covering
// anon_inode:inotify and anon_inode:bpf-* descriptors. Callers MUST
// treat the returned struct and its slices as read-only.
type FDSnapshot struct {
	At       time.Time // post-walk timestamp
	ProcOK   bool      // true when proc root listed successfully (or explicit pids provided)
	Partial  bool      // true when any per-pid fd, readlink, or fdinfo read failed with non-ENOENT/ESRCH
	Inotify  []InotifyFD
	BPFProgs []uint64 // sorted, deduplicated prog_ids across anon_inode:bpf-* fdinfo
	BPFMaps  []uint64 // sorted, deduplicated map_ids across anon_inode:bpf-* fdinfo
}

// isTransientGone reports whether err reflects a process or descriptor
// that vanished mid-scan (ENOENT / ESRCH), as opposed to a permission
// or layout failure such as EACCES / ENOTDIR.
func isTransientGone(err error) bool {
	return os.IsNotExist(err) || errors.Is(err, syscall.ESRCH)
}

// ScanFDs walks <f.root>/<pid>/fd/* once (or only the supplied pids when
// pids != nil; when pids == nil it lists f.root via Open+Readdirnames).
// D/Z-state safe (fd/readlink/fdinfo do not touch mm->mmap_lock); skips
// transient ENOENT/ESRCH exited-PID races and records Partial=true on
// non-ENOENT/ESRCH per-pid/fd errors (e.g. EACCES/ENOTDIR) so FDCache
// does not cache incomplete snapshots.
func (f FS) ScanFDs(pids []int) *FDSnapshot {
	snap := &FDSnapshot{}
	if pids == nil {
		var ok bool
		pids, ok = listNumericPIDs(f.root)
		if !ok {
			snap.At = time.Now()
			return snap
		}
	}
	snap.ProcOK = true
	if len(pids) == 0 {
		snap.At = time.Now()
		return snap
	}
	sortedPIDs := slices.Clone(pids)
	slices.Sort(sortedPIDs)

	progSet := map[uint64]struct{}{}
	mapSet := map[uint64]struct{}{}

	for _, pid := range sortedPIDs {
		fdDirPath := f.File(pid, "fd")
		fdDir, err := os.Open(fdDirPath)
		if err != nil {
			if !isTransientGone(err) {
				snap.Partial = true
			}
			continue
		}
		fdNames, rerr := fdDir.Readdirnames(-1)
		_ = fdDir.Close()
		if rerr != nil {
			if !isTransientGone(rerr) {
				snap.Partial = true
			}
			continue
		}
		for _, fdName := range fdNames {
			target, err := os.Readlink(filepath.Join(fdDirPath, fdName))
			if err != nil {
				if !isTransientGone(err) {
					snap.Partial = true
				}
				continue
			}
			switch {
			case target == inotifyFDTarget:
				fdNum, ferr := strconv.Atoi(fdName)
				if ferr != nil {
					continue
				}
				watches, ok := countInotifyWatches(f.File(pid, "fdinfo", fdName))
				if !ok {
					snap.Partial = true
				}
				snap.Inotify = append(snap.Inotify, InotifyFD{
					PID:     pid,
					FD:      fdNum,
					Watches: watches,
				})
			case strings.Contains(target, ebpfFDTarget):
				if !scanBPFFDInfo(f.File(pid, "fdinfo", fdName), progSet, mapSet) {
					snap.Partial = true
				}
			}
		}
	}

	if len(progSet) > 0 {
		snap.BPFProgs = make([]uint64, 0, len(progSet))
		for id := range progSet {
			snap.BPFProgs = append(snap.BPFProgs, id)
		}
		slices.Sort(snap.BPFProgs)
	}
	if len(mapSet) > 0 {
		snap.BPFMaps = make([]uint64, 0, len(mapSet))
		for id := range mapSet {
			snap.BPFMaps = append(snap.BPFMaps, id)
		}
		slices.Sort(snap.BPFMaps)
	}
	snap.At = time.Now()
	return snap
}

func listNumericPIDs(root string) ([]int, bool) {
	d, err := os.Open(root)
	if err != nil {
		return nil, false
	}
	names, rerr := d.Readdirnames(-1)
	_ = d.Close()
	if rerr != nil {
		return nil, false
	}
	pids := make([]int, 0, len(names))
	for _, name := range names {
		if !IsDigits(name) {
			continue
		}
		if pid, err := strconv.Atoi(name); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids, true
}

func countInotifyWatches(path string) (int64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, isTransientGone(err)
	}
	defer func() { _ = f.Close() }()

	br := bufio.NewReaderSize(io.LimitReader(f, maxFDInfoBytes), 4096)
	var count int64
	atLineStart := true
	for {
		line, err := br.ReadSlice('\n')
		if atLineStart && bytes.HasPrefix(line, inotifyWDPrefix) {
			count++
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			atLineStart = false
			continue
		}
		atLineStart = true
		if err != nil {
			return count, errors.Is(err, io.EOF) || isTransientGone(err)
		}
	}
}

func scanBPFFDInfo(path string, progs, maps map[uint64]struct{}) bool {
	f, err := os.Open(path)
	if err != nil {
		return isTransientGone(err)
	}
	defer func() { _ = f.Close() }()

	br := bufio.NewReaderSize(io.LimitReader(f, maxFDInfoBytes), 4096)
	skipLongLine := false
	for {
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			skipLongLine = true
			continue
		}
		if skipLongLine {
			skipLongLine = false
		} else if len(line) > 0 {
			parseBPFFDInfoLine(string(line), progs, maps)
		}
		if err != nil {
			return errors.Is(err, io.EOF) || isTransientGone(err)
		}
	}
}

func parseBPFFDInfoLine(line string, progs, maps map[uint64]struct{}) {
	fields := strings.Fields(line)
	if len(fields) != 2 {
		return
	}
	id, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return
	}
	switch strings.TrimSuffix(fields[0], ":") {
	case "prog_id":
		progs[id] = struct{}{}
	case "map_id":
		maps[id] = struct{}{}
	}
}

type fdFlight struct {
	done chan struct{}
	snap *FDSnapshot
}

// FDCache provides a singleflighted, TTL-cached *FDSnapshot over one proc root.
type FDCache struct {
	root string
	now  func() time.Time

	mu       sync.Mutex
	snap     *FDSnapshot
	inflight *fdFlight
}

// NewFDCache constructs an isolated FDCache rooted at root using now (nil → time.Now).
func NewFDCache(root string, now func() time.Time) *FDCache {
	if now == nil {
		now = time.Now
	}
	return &FDCache{
		root: filepath.Clean(root),
		now:  now,
	}
}

var (
	sharedFDCacheMu sync.Mutex
	sharedFDCaches  = map[string]*FDCache{}
)

// SharedFDCache returns the process-wide FDCache for canonical root.
// Production wiring calls this so hostmetrics and workerhygiene share
// one /proc/*/fd walk per TTL window without cross-importing.
func SharedFDCache(root string, now func() time.Time) *FDCache {
	key := filepath.Clean(root)
	sharedFDCacheMu.Lock()
	defer sharedFDCacheMu.Unlock()
	if c, ok := sharedFDCaches[key]; ok {
		return c
	}
	c := NewFDCache(key, now)
	sharedFDCaches[key] = c
	return c
}

// Snapshot returns the cached *FDSnapshot when younger than maxAge
// (with backward-clock safety: age < 0 always forces a fresh walk);
// otherwise runs or joins a singleflighted ScanFDs(nil). Snapshots
// with !ProcOK or Partial (e.g. EACCES/ENOTDIR on /proc, /proc/<pid>/fd,
// or fdinfo/<fd>) are returned to the current caller/waiters but never
// cached across the TTL so recovery is immediate once readable again.
func (c *FDCache) Snapshot(maxAge time.Duration) *FDSnapshot {
	c.mu.Lock()
	entryLocked := true
	defer func() {
		if entryLocked {
			c.mu.Unlock()
		}
	}()
	now := c.now()
	if c.snap != nil && maxAge > 0 {
		age := now.Sub(c.snap.At)
		if age >= 0 && age < maxAge {
			snap := c.snap
			entryLocked = false
			c.mu.Unlock()
			return snap
		}
	}
	if f := c.inflight; f != nil {
		entryLocked = false
		c.mu.Unlock()
		<-f.done
		if f.snap == nil {
			return &FDSnapshot{}
		}
		return f.snap
	}
	f := &fdFlight{done: make(chan struct{})}
	c.inflight = f
	entryLocked = false
	c.mu.Unlock()

	var snap *FDSnapshot
	settled := false
	locked := false
	defer func() {
		if !settled {
			if !locked {
				c.mu.Lock()
				locked = true
			}
			if c.inflight == f {
				c.inflight = nil
			}
			close(f.done)
			c.mu.Unlock()
			locked = false
		} else if locked {
			c.mu.Unlock()
			locked = false
		}
	}()

	snap = New(c.root).ScanFDs(nil)
	snap.At = c.now()

	c.mu.Lock()
	locked = true
	f.snap = snap
	if snap.ProcOK && !snap.Partial {
		c.snap = snap
	} else {
		c.snap = nil
	}
	if c.inflight == f {
		c.inflight = nil
	}
	close(f.done)
	settled = true
	c.mu.Unlock()
	locked = false
	return snap
}
