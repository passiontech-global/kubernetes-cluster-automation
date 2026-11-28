// localbin.go — ResolveLocalBinary, shared self-binary path resolver
// for cmd/agent (hubsync mirror source) and hostconfig (host self-stage).
package hostctx

import (
	"os"
	"strings"
)

// DefaultLocalBinary is the DaemonSet container binary fallback when
// os.Executable is unavailable or points to a deleted/missing path.
const DefaultLocalBinary = "/node-host-agent"

// ResolveLocalBinary returns the running binary path, stripping any
// " (deleted)" suffix from os.Executable and falling back to fallback
// (DefaultLocalBinary if empty) when unreadable.
func ResolveLocalBinary(fallback string) string {
	return ResolveLocalBinaryWith(os.Executable, fallback)
}

// ResolveLocalBinaryWith is ResolveLocalBinary with an injectable
// executable-path reader for tests.
func ResolveLocalBinaryWith(execFn func() (string, error), fallback string) string {
	if fallback == "" {
		fallback = DefaultLocalBinary
	}
	if execFn == nil {
		execFn = os.Executable
	}
	exe, err := execFn()
	if err != nil || exe == "" {
		return fallback
	}
	exe = strings.TrimSuffix(exe, " (deleted)")
	if _, err := os.Stat(exe); err != nil {
		return fallback
	}
	return exe
}
