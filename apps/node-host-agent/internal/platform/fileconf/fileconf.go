// Package fileconf is the shared "re-read a small conf file on every
// Get, keep the last good parse" skeleton behind
// watchdogconf.Reloader (/etc/node-watchdog.conf) and
// apiprober.GuardReloader (/etc/api-backend-guard.conf). Both files
// are hostconfig-managed rewrites that land mid-run, so consumers
// must not pin a startup parse — the runner re-sourced its confs
// every run. The files are a few KB at most; a plain re-read per Get
// is the simplest correct semantics, with no mtime/size window where
// a same-second rewrite is missed.
//
// Semantics (shell `source` parity — "read fresh each run, defaults
// on absent"):
//   - a MISSING file is not an error: it parses as empty content, so
//     Get returns whatever the parser yields for empty input (the
//     all-defaults value);
//   - a read or parse failure keeps the last good value and warns —
//     once per failure episode by default (edge-latched, with a
//     matching "readable again" info line on recovery), or on every
//     Get with Options.WarnEveryGet (watchdogconf's legacy mode);
//   - an empty Path reads like any other name — the open fails
//     ENOENT and parses as an absent file — unless
//     Options.BlankPathHolds, which returns the current value
//     untouched (the guard conf's legacy early return).
//
// Each consumer's exported wrapper keeps its own logger name and
// message text via Options — the log lines are a grep contract.
package fileconf

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
)

// Parse turns raw conf bytes into a T. A nil/empty slice means the
// file was absent — the parser must yield the all-defaults value
// then, exactly like the shell modules did on an unsourced conf. A
// successful parse always becomes the reloader's new current value:
// parsers return an error to make Get keep the last good value, never
// a (zero, nil) pair.
type Parse[T any] func(data []byte) (T, error)

// Options tunes a Reloader's failure handling; the zero value is the
// api-backend-guard.conf behaviour (warn once per unreadable episode
// plus a recovery info, empty Path re-reads like any name).
type Options struct {
	// Log receives the warn/info lines — callers pass their own
	// package logger so the logger name in the log contract is
	// unchanged; nil falls back to the fileconf logger.
	Log *slog.Logger
	// WarnMsg is the failure message text; consumers keep their own
	// subsystem-prefixed wording (the text is a log-grep contract).
	WarnMsg string
	// RecoveredMsg is logged once when the file becomes readable
	// again after a failed episode; empty disables the line.
	RecoveredMsg string
	// WarnEveryGet warns on EVERY failed Get instead of latching one
	// warn per episode — watchdogconf's behaviour: its consumers
	// cycle once per watchdog period and the conf is
	// hostconfig-managed, so a persistent unreadable conf must stay
	// loud rather than go quiet after the first failure.
	WarnEveryGet bool
	// BlankPathHolds makes an empty Path return the current value
	// untouched — the guard conf's early return. Unset, an empty
	// Path is opened like any name, fails ENOENT, and parses as an
	// absent file.
	BlankPathHolds bool
}

// Reloader hands out the freshest parse of Path, falling back to the
// last good value on read/parse errors. The zero value is NOT ready —
// build it with New.
type Reloader[T any] struct {
	// Path is re-read on every Get — the wrappers keep it exported
	// because their callers repoint or inspect it (hostctx's env
	// test asserts on WatchdogSrc.Path).
	Path string

	parse   Parse[T]
	opts    Options
	mu      sync.Mutex
	cur     T
	loadErr bool // edge-latch for the unreadable-conf Warn
}

// New seeds the reloader with initial and points it at path — the
// first Get re-reads regardless, so a zero initial is fine.
func New[T any](path string, parse Parse[T], initial T, opts Options) *Reloader[T] {
	if opts.Log == nil {
		opts.Log = logger()
	}
	if opts.WarnMsg == "" {
		opts.WarnMsg = "fileconf: reload failed — keeping last good value"
	}
	return &Reloader[T]{Path: path, parse: parse, opts: opts, cur: initial}
}

// Get returns the freshest parse of Path, falling back to the last
// good value on read/parse errors. A persistent failure warns once
// per episode (and logs recovery once) unless WarnEveryGet — Get runs
// each consumer cycle. Safe for concurrent use; when T is a pointer
// type the returned value is SHARED across callers and retained by
// the reloader — consumers must not mutate it.
func (r *Reloader[T]) Get() T {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.opts.BlankPathHolds && r.Path == "" {
		return r.cur
	}
	if v, err := Load(r.Path, r.parse); err == nil {
		if r.loadErr {
			r.loadErr = false
			if r.opts.RecoveredMsg != "" {
				r.opts.Log.Info(r.opts.RecoveredMsg, "path", r.Path)
			}
		}
		r.cur = v
	} else if r.opts.WarnEveryGet || !r.loadErr {
		r.loadErr = true
		r.opts.Log.Warn(r.opts.WarnMsg, "path", r.Path, "error", err)
	}
	return r.cur
}

// Load reads path and parses the content — separated from Reloader
// so one-shot callers (startup parses, tests) go through the
// identical file contract: a missing file parses as empty content
// (NOT an error — nodes without the file run on defaults exactly
// like the shell modules did), and any other read failure wraps as
// "read <path>: <err>".
func Load[T any](path string, parse Parse[T]) (T, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Missing file = empty-content parse (shell parity:
			// modules ran on defaults without a sourced conf).
			return parse(nil)
		}
		var zero T
		return zero, fmt.Errorf("read %s: %w", path, err)
	}
	return parse(data)
}
