package envx

import "log/slog"

// logger returns the package logger. slog.With is resolved per call so
// the handler picked up is always the current slog.Default() — a
// package-level var would bind the pre-main default before
// slog.SetDefault installs the JSON handler.
func logger() *slog.Logger { return slog.With("logger", "envx") }
