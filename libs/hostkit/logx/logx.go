// Package logx provides named slog loggers for packages across the
// apps in this monorepo (it lives in libs/hostkit, shared via replace).
//
// For resolves slog.With per call so the handler picked up is always the
// current slog.Default() — a package-level var would bind the pre-main
// default before slog.SetDefault installs the JSON handler in main().
// The resolved loggers themselves ARE cached per (slog.Default(), name):
// hundreds of callsites invoke logger().Info(...) per sweep, and each
// uncached call allocates a fresh *slog.Logger plus a handler clone.
package logx

import (
	"log/slog"
	"maps"
	"sync"
	"sync/atomic"
)

// forSnapshot is one immutable (default → name-cache) binding.
// Publication is copy-on-write: readers load the pointer once and never
// lock — a published snapshot is never mutated, so there is no torn-map
// window; rebuilders copy the current map under forMu and swap in a
// fresh snapshot by pointer store. This replaced an RWMutex + shared
// map, where every cache miss promoted to a write lock and briefly
// stopped all logging in every subsystem.
type forSnapshot struct {
	def     *slog.Logger
	loggers map[string]*slog.Logger
}

var (
	// forSnap is the currently published snapshot; nil until the first
	// For builds one.
	forSnap atomic.Pointer[forSnapshot]
	// forMu serializes snapshot rebuilds — the miss path only; a
	// cached hit never takes it.
	forMu sync.Mutex
)

// forCacheCap bounds the per-name logger table inside one snapshot.
// Component names are a small fixed set in practice, but For is a
// public API — a caller passing dynamic names (hostnames, request
// ids) would otherwise grow every snapshot without limit. Past the
// cap a name resolves to an UNCACHED logger: correct output, just
// no memoization for the overflow names.
const forCacheCap = 256

// For returns a logger tagged with the given name. The name is emitted as
// the "logger" attribute on every record. Loggers are cached keyed on the
// current slog.Default(): if slog.SetDefault swaps in a new handler the
// cache is dropped and rebuilt against it, so the JSON handler installed
// by main() is always the one that emits.
//
// Concurrency: the hot path is one atomic load — concurrent For calls
// share no lock. Rebuilds serialize on forMu and re-check the freshly
// published snapshot before building, so two goroutines racing the same
// name's first resolve still get the identical *slog.Logger, and a
// rebuild copies the latest snapshot so concurrent misses for different
// names keep each other's entries.
func For(name string) *slog.Logger {
	def := slog.Default()
	// Fast path: a single atomic load — logger() runs on every log
	// line in every subsystem, so the common case (cached name,
	// unchanged default) must not even share a read lock.
	if s := forSnap.Load(); s != nil && s.def == def {
		if l, ok := s.loggers[name]; ok {
			return l
		}
	}
	forMu.Lock()
	defer forMu.Unlock()
	// Re-read under the rebuild lock: another goroutine may have
	// published a snapshot for this exact default while we waited,
	// or dropped the cache after a SetDefault swap.
	s := forSnap.Load()
	if s == nil || s.def != def {
		s = &forSnapshot{def: def, loggers: map[string]*slog.Logger{}}
	}
	if l, ok := s.loggers[name]; ok {
		return l
	}
	l := def.With("logger", name)
	if len(s.loggers) >= forCacheCap {
		// Cache full — serve the logger without caching it (see
		// forCacheCap). The snapshot is left untouched so the
		// bounded entries stay warm.
		return l
	}
	next := &forSnapshot{
		def:     def,
		loggers: make(map[string]*slog.Logger, len(s.loggers)+1),
	}
	maps.Copy(next.loggers, s.loggers)
	next.loggers[name] = l
	forSnap.Store(next)
	return l
}
