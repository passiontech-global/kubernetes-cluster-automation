// read.go — the small host-level read/stat helpers ported verbatim
// from node-host-agent's platform/hostutil: trimmed file reads,
// uint parses, the mtime freshness touch, /host-prefix mapping,
// shell quoting and the stat-key fingerprint.
package fsx

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// ReadTrimmed returns the file's trimmed content, "" on any error.
func ReadTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// ReadUintFile parses a file holding a single unsigned integer —
// "" ok=false on absent/unparseable content.
func ReadUintFile(path string) (uint64, bool) {
	v, err := strconv.ParseUint(strings.TrimSpace(
		ReadTrimmed(path)), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// TouchIfDue refreshes path's atime/mtime to now via Chtimes ONLY
// when the file's current mtime is at least minAge old — the
// callers already hold the os.Stat result, so a fresh latch costs
// zero extra syscalls (the comparison is pure arithmetic on
// fi.ModTime). Held latches used to Chtimes on every check cycle;
// with the janitor reaping at 24h a 15min cadence is already
// generous. Returns the Chtimes error, nil when skipped or touched.
func TouchIfDue(path string, fi os.FileInfo, now time.Time, minAge time.Duration) error {
	age := now.Sub(fi.ModTime())
	// Skip only on a genuinely fresh mtime. A NEGATIVE age means the
	// file's mtime sits ahead of this clock (fake test clocks, an
	// NTP step-back) — that is exactly the case a touch must fix,
	// not skip.
	if age >= 0 && age < minAge {
		return nil
	}
	return os.Chtimes(path, now, now)
}

// HostSidePath maps an in-pod /host-mounted path back to the path a
// host process reports: "/host/x" → "/x", "/host" → "/", anything
// else unchanged (standalone "/" HostRoot paths and fixture paths
// carry no prefix and pass through verbatim). The strip is
// boundary-checked — strings.TrimPrefix(p, "/host") would also
// mangle legitimate paths like "/hostname/..." or "/hostile/...".
func HostSidePath(p string) string {
	if rest, ok := strings.CutPrefix(p, "/host/"); ok {
		return "/" + rest
	}
	if p == "/host" {
		return "/"
	}
	return p
}

// ShellQuote single-quotes a shell word. The paths and configured
// names it guards are admin-controlled, but quoting keeps `sh -c`
// command strings robust against a stray space or metachar that
// would otherwise split or glob the word.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
