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
	"sync"
)

var (
	forMu      sync.RWMutex
	forDefault *slog.Logger
	forCache   = map[string]*slog.Logger{}
)

// For returns a logger tagged with the given name. The name is emitted as
// the "logger" attribute on every record. Loggers are cached keyed on the
// current slog.Default(): if slog.SetDefault swaps in a new handler the
// cache is dropped and rebuilt against it, so the JSON handler installed
// by main() is always the one that emits.
func For(name string) *slog.Logger {
	def := slog.Default()
	// Read-lock fast path: logger() is called on every log line in
	// every subsystem, so the common case (cached name, unchanged
	// default) must not serialize all goroutines on one mutex.
	forMu.RLock()
	if def == forDefault {
		if l, ok := forCache[name]; ok {
			forMu.RUnlock()
			return l
		}
	}
	forMu.RUnlock()
	forMu.Lock()
	defer forMu.Unlock()
	if def != forDefault {
		forDefault = def
		forCache = map[string]*slog.Logger{}
	}
	if l, ok := forCache[name]; ok {
		return l
	}
	l := def.With("logger", name)
	forCache[name] = l
	return l
}
