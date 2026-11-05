// Package logx provides named slog loggers for packages across the
// apps in this monorepo (it lives in libs/hostkit, shared via replace).
//
// For resolves slog.With per call so the handler picked up is always the
// current slog.Default() — a package-level var would bind the pre-main
// default before slog.SetDefault installs the JSON handler in main().
package logx

import "log/slog"

// For returns a logger tagged with the given name. The name is emitted as
// the "logger" attribute on every record. slog.With is resolved per call —
// never cached in a package-level var — so the handler picked up is always
// the current slog.Default(), including the JSON handler installed by
// slog.SetDefault in main().
func For(name string) *slog.Logger { return slog.With("logger", name) }
