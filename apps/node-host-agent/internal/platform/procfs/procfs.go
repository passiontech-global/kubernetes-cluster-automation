// Package procfs consolidates the /proc filesystem helpers the
// hygiene subsystems (workerhygiene, controllerhygiene and the
// workerhygiene janitor) each carried their own copy of: pid-dir
// listing, per-pid file reads (cmdline/environ/stat/comm), the
// post-comm stat field parsing and the kill(0)+not-zombie liveness
// probe.
//
// FS is rooted at a configurable proc root — "/proc" on hostPID
// pods/host binaries, or a host-mounted path like "/host/proc".
// Reads are best-effort and degrade to the same zero values the
// per-subsystem copies returned (nil argv, "" env, ok=false), so
// callers keep their existing fail-open / fail-closed choices.
package procfs

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// FS is a /proc filesystem view bound to one proc root.
type FS struct {
	root string
}

// New returns an FS rooted at root — "/proc" or a host-mounted
// path like "/host/proc".
func New(root string) FS {
	return FS{root: root}
}

// KillFn delivers a signal to a pid — signal 0 is the kill -0
// liveness probe. Injectable so tests never signal real processes
// (the subsystems' killFn seams plug in directly).
type KillFn func(pid int, sig syscall.Signal) error

// isPIDName reports whether a /proc entry name is a numeric pid —
// the plain digit scan replaces the old ^[0-9]+$ regex on the hot
// per-entry path (every dir entry of every /proc sweep).
func isPIDName(name string) bool {
	if name == "" {
		return false
	}
	for i := range name {
		if name[i] < '0' || name[i] > '9' {
			return false
		}
	}
	return true
}

// File joins <root>/<pid>/<elems...> — /proc/<pid>/stat and friends.
func (f FS) File(pid int, elems ...string) string {
	parts := append([]string{f.root, strconv.Itoa(pid)}, elems...)
	return filepath.Join(parts...)
}

// PIDs lists the numeric pid dirs under the root in os.ReadDir
// order — filename order, NOT numeric. The read error is returned
// rather than swallowed so callers can log an unreadable root
// instead of silently seeing "no processes". Callers needing
// numeric order sort the result (FindByComm does).
func (f FS) PIDs() ([]int, error) {
	entries, err := os.ReadDir(f.root)
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, e := range entries {
		if !e.IsDir() || !isPIDName(e.Name()) {
			continue
		}
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// Cmdline returns the argv of pid (NUL-separated in /proc).
func (f FS) Cmdline(pid int) []string {
	data, err := os.ReadFile(f.File(pid, "cmdline"))
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
}

// EnvValue reads KEY=<value> from /proc/<pid>/environ — "" when the
// file is unreadable or the key is absent.
func (f FS) EnvValue(pid int, key string) string {
	data, err := os.ReadFile(f.File(pid, "environ"))
	if err != nil {
		return ""
	}
	prefix := key + "="
	for e := range strings.SplitSeq(string(data), "\x00") {
		if v, ok := strings.CutPrefix(e, prefix); ok {
			return v
		}
	}
	return ""
}

// Stat is a parsed /proc/<pid>/stat.
//
// The comm field (field 2, in parens) can itself contain spaces and
// parens, so every field is read AFTER the LAST ')' — Fields[0] is
// state (field 3), Fields[1] ppid (field 4), Fields[19] starttime
// in clock ticks (field 22). Comm is the text between the FIRST '('
// and that last ')'; HasComm is false when the parens are missing
// or misordered.
type Stat struct {
	Comm    string
	HasComm bool
	Fields  []string
}

// parseStat splits a raw stat line. ok=false when there is no ')' or
// no fields after it — the same "unparseable" verdict every caller
// collapsed to.
func parseStat(s string) (st Stat, ok bool) {
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return Stat{}, false
	}
	st.Fields = strings.Fields(s[i+1:])
	if len(st.Fields) == 0 {
		return Stat{}, false
	}
	if open := strings.IndexByte(s, '('); open >= 0 && open < i {
		st.Comm = s[open+1 : i]
		st.HasComm = true
	}
	return st, true
}

// Stat reads and parses /proc/<pid>/stat — ok=false when the file is
// unreadable, has no ')' or has no fields after it.
func (f FS) Stat(pid int) (Stat, bool) {
	data, err := os.ReadFile(f.File(pid, "stat"))
	if err != nil {
		return Stat{}, false
	}
	return parseStat(string(data))
}

// Live mirrors the shell liveness check: kill -0 succeeds AND the
// /proc/<pid>/stat state field is not "Z" (zombie). An unreadable or
// unparseable stat after a successful kill -0 counts as LIVE — fail
// toward not-killing / not-force-deleting on uncertainty. The stat
// state field is parsed after the LAST ')' because comm (field 2)
// can contain spaces and parens (same trick as read_cpu_jiffies).
func (f FS) Live(pid int, killFn KillFn) bool {
	if pid <= 0 {
		return false
	}
	if killFn(pid, 0) != nil {
		return false
	}
	st, ok := f.Stat(pid)
	if !ok {
		return true
	}
	return st.Fields[0] != "Z"
}

// PPID returns the parent pid from /proc/<pid>/stat field 4 — the
// field sits right after comm, parsed after the LAST ')' because
// comm can contain spaces and parens.
func (f FS) PPID(pid int) (int, bool) {
	st, ok := f.Stat(pid)
	if !ok || len(st.Fields) < 2 { // Fields[0]=state, Fields[1]=ppid
		return 0, false
	}
	ppid, err := strconv.Atoi(st.Fields[1])
	if err != nil || ppid < 0 {
		return 0, false
	}
	return ppid, true
}

// Age returns the age of a /proc/<pid> dir against now — shell
// `now - stat -c %Y` parity: a shim that just spawned still has a
// fresh mtime, so the 5m window can't kill a starting task. 0 when
// the dir is gone or stat fails.
func (f FS) Age(pid int, now time.Time) time.Duration {
	fi, err := os.Stat(f.File(pid))
	if err != nil {
		return 0
	}
	return now.Sub(fi.ModTime())
}

// UptimeSeconds parses <root>/uptime via the package-level reader
// in sysinfo.go.
func (f FS) UptimeSeconds() (float64, error) {
	return UptimeSeconds(filepath.Join(f.root, "uptime"))
}

// PIDAgeSeconds returns the process age in seconds — `ps -o
// etimes=` parity. Computed from /proc/<pid>/stat starttime
// (field 22, jiffies) against <root>/uptime; clkTck is the kernel
// clock tick (getconf CLK_TCK — 100 on x86_64). A negative age
// (stat jiffies ahead of uptime) clamps to 0.
func (f FS) PIDAgeSeconds(pid int, clkTck float64) (float64, error) {
	data, err := os.ReadFile(f.File(pid, "stat"))
	if err != nil {
		return 0, err
	}
	s := string(data)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, errors.New("bad stat")
	}
	fields := strings.Fields(s[i+1:])
	if len(fields) < 20 {
		return 0, errors.New("short stat")
	}
	start, err := strconv.ParseFloat(fields[19], 64) // field 22 overall
	if err != nil {
		return 0, err
	}
	up, err := f.UptimeSeconds()
	if err != nil {
		return 0, err
	}
	age := up - start/clkTck
	if age < 0 {
		return 0, nil
	}
	return age, nil
}

// FindByComm returns the lowest pid whose /proc/<pid>/comm equals
// name — `pgrep -x <name> | head -1` parity (lowest pid wins).
// 0 when absent or the root is unreadable.
func (f FS) FindByComm(name string) int {
	pids, err := f.PIDs()
	if err != nil {
		return 0
	}
	slices.Sort(pids) // lowest pid wins — pgrep | head -1 parity
	for _, pid := range pids {
		if comm, ok := f.comm(pid); ok && comm == name {
			return pid
		}
	}
	return 0
}

// comm reads /proc/<pid>/comm trimmed — ok=false when unreadable.
func (f FS) comm(pid int) (string, bool) {
	data, err := os.ReadFile(f.File(pid, "comm"))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(data)), true
}
