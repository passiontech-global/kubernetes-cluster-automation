// dirwatcher.go — DirWatcher, the poll-a-content-fingerprint watcher
// behind hostconfig's and hubsync's vars/nebula-certs change edges.
// Lives in platform/fileconf so the two subsystems can share it
// without importing each other (it was a hostconfig package type
// before the subsystem-isolation depguard rule).
package fileconf

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// defaultWatchPoll is the DirWatcher rescan cadence when Period is
// unset — hostconfig's historical default.
const defaultWatchPoll = 15 * time.Second

// DirWatcher polls a fingerprint over (name, size, mtime, content
// hash) of every file under the watched dirs every period. The per-
// file content read+hash runs only when a file's (size, mtime) stat
// differs from the previous scan — an unchanged stat reuses the
// cached hash, so a quiet dir costs stats only. Residual risk,
// accepted: a rewrite that keeps BOTH size and mtime identical is
// trusted as unchanged (mtime granularity) and will not fire an edge.
type DirWatcher struct {
	Dirs   []string
	Period time.Duration

	// Log receives the watcher's debug lines; nil falls back to the
	// fileconf logger. The message texts keep their historical
	// "hostconfig:" prefix — a grep contract carried over from the
	// watcher's original home in the hostconfig subsystem.
	Log *slog.Logger

	mu     sync.Mutex // guards last, dirty, polled — Poll writes, Changed reads
	last   string
	dirty  bool // Poll-latched change edge, consumed by Changed
	polled bool // Poll has observed the dir at least once

	// stats caches the last scan's per-file (size, mtime, hash);
	// fingerprint reads+writes it under fpMu — Changed runs a
	// fingerprint OUTSIDE w.mu by design, so scans may overlap.
	fpMu  sync.Mutex
	stats map[string]dirWatchFile
}

// dirWatchFile is one file's cached fingerprint inputs.
type dirWatchFile struct {
	size    int64
	mtimeNS int64
	sum     []byte
}

// readFile is the content-read seam — tests count reads to prove the
// stat-unchanged fast path skips hashing.
var readFile = os.ReadFile

// log resolves the per-consumer logger: the injected one when set,
// else the fileconf default.
func (w *DirWatcher) log() *slog.Logger {
	if w.Log != nil {
		return w.Log
	}
	return logger()
}

func (w *DirWatcher) fingerprint() string {
	h := sha256.New()
	var files []string
	for _, d := range w.Dirs {
		_ = filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				w.log().Debug("hostconfig: watcher walk error — entry skipped",
					"dir", d, "path", p, "error", err)
				return nil
			}
			if !e.IsDir() {
				files = append(files, p)
			}
			return nil
		})
	}
	sort.Strings(files)
	w.fpMu.Lock()
	defer w.fpMu.Unlock()
	next := make(map[string]dirWatchFile, len(files))
	for _, f := range files {
		var sum []byte
		st, err := os.Stat(f)
		if err != nil {
			w.log().Debug("hostconfig: watcher cannot stat file — excluded from fingerprint",
				"file", f, "error", err)
			continue
		}
		if c, ok := w.stats[f]; ok && c.size == st.Size() && c.mtimeNS == st.ModTime().UnixNano() {
			// Stat unchanged → trust the cached content hash; the
			// file's bytes are not re-read this scan.
			sum = c.sum
		} else {
			b, err := readFile(f)
			if err != nil {
				w.log().Debug("hostconfig: watcher cannot read file — excluded from fingerprint",
					"file", f, "error", err)
				continue
			}
			s := sha256.Sum256(b)
			sum = s[:]
		}
		next[f] = dirWatchFile{size: st.Size(), mtimeNS: st.ModTime().UnixNano(), sum: sum}
		h.Write([]byte(f))
		h.Write(sum)
	}
	w.stats = next
	return hex.EncodeToString(h.Sum(nil))
}

func (w *DirWatcher) Poll(ctx context.Context) {
	p := w.Period
	if p <= 0 {
		p = defaultWatchPoll
	}
	initFP := w.fingerprint()
	w.mu.Lock()
	if w.last == "" {
		w.last = initFP
	}
	w.polled = true
	w.mu.Unlock()

	t := time.NewTicker(p)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fp := w.fingerprint()
			w.mu.Lock()
			if fp != w.last {
				w.dirty = true
				w.last = fp
			}
			w.mu.Unlock()
		}
	}
}

// Changed reports a change edge. Once Poll has run it just consumes
// the edge Poll latched — the main loop does not re-read and re-hash
// every file a second time, and an edge observed between two Changed
// calls is never lost. When Poll has never run (unit tests calling
// Changed directly) it falls back to comparing a fresh fingerprint
// against the last snapshot.
func (w *DirWatcher) Changed() bool {
	w.mu.Lock()
	if w.polled {
		d := w.dirty
		w.dirty = false
		w.mu.Unlock()
		return d
	}
	w.mu.Unlock()

	// No Poll yet — fingerprint outside the lock (dir walk + file
	// reads) so a racing first Poll scan is not stalled on disk IO.
	fp := w.fingerprint()
	w.mu.Lock()
	defer w.mu.Unlock()
	// Poll may have started meanwhile — its dirty latch is then the
	// authoritative edge and the fingerprint is discarded.
	if w.polled {
		d := w.dirty
		w.dirty = false
		return d
	}
	changed := fp != w.last
	w.last = fp
	return changed
}
