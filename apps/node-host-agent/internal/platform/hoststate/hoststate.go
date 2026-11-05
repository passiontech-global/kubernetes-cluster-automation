// Package hoststate implements the shared on-disk "watchdog state"
// contract every subsystem reads or writes under the node-watchdog
// state dir (/var/lib/node-watchdog, or a subsystem-private dir like
// kinedb's compact-guard dir):
//
//	state-<name>   : latch file, content = epoch of entry. Held while
//	                 a failure signal is active; nodereporter maps
//	                 each to a NodeCondition, hostmetrics exports a
//	                 watchdog_state series, the janitor reaps files
//	                 older than 24h.
//	last-*         : rate-limit budget, content = epoch of last spend.
//	                 The janitor deliberately never touches these —
//	                 deleting one would silently bypass cooldowns.
//	consecutive-*  : on-disk fail counters (controllerhygiene).
//	installed/     : heartbeat pair — `installed` seeds once (baseline
//	last-run       epoch), `last-run` refreshes every cycle; NHC's
//	                 watchdog-stale gate reads the pair.
//	watchdog log   : "<rfc3339> <msg>" appended to LogFile — the NPD
//	                 filelog tails it, so message text is a contract.
//
// Store is the single implementation of lib.sh state_enter /
// state_exit / rate_ok / rate_spend / log parity — it was previously
// re-implemented per subsystem and the copies diverged (suspect-log
// cleanup on exit, atomic vs plain budget writes). File formats are
// unchanged: this is a code consolidation, not a contract change.
package hoststate

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
)

// SuspectBudgetPrefix prefixes the suspect-log dedupe budgets:
// last-suspect-<key> epoch files spent at most once per cadence —
// the same rateOK/last-* convention as the action budgets.
const SuspectBudgetPrefix = "last-suspect-"

// Store is a handle to one state dir. Dir may be "" — path helpers
// then produce bare filenames (callers that gate on an empty dir
// keep that gate; StampLastRun no-ops on "").
type Store struct {
	// Dir is the state dir — e.g. /var/lib/node-watchdog, or
	// kinedb's GuardStateDir.
	Dir string
	// LogFile is the watchdog log appended by AppendLog* — ""
	// disables the file half (slog mirror still fires).
	LogFile string
	// Now supplies the current time — the test seam every subsystem
	// carried as cfg.nowFn. IMPORTANT: pass a closure over the live
	// config field (`func() time.Time { return cfg.nowFn() }`), not
	// the func value captured at New() — tests re-stub cfg.nowFn
	// after construction and the store must observe the new clock.
	// nil → time.Now.
	Now func() time.Time
	// Log resolves the slog logger per call — pass the package
	// `logger` func itself so the "logger"=<pkg> attr and any
	// post-construction slog.SetDefault are honored exactly like the
	// per-call logger() invocations this replaces. nil →
	// slog.Default().
	Log func() *slog.Logger

	// mu serializes RateTrySpend across goroutines — the feeder
	// remediate path and Cycle compete on the shared last-restart
	// budget ("last-restart" above all): without it a feeder "ok"
	// and a Cycle check "ok" could both pass in the same window and
	// double-spend a restart.
	mu sync.Mutex
}

// New returns a Store for dir/logFile. now and log may be nil.
func New(dir, logFile string, now func() time.Time,
	log func() *slog.Logger) *Store {

	if now == nil {
		now = time.Now
	}
	return &Store{Dir: dir, LogFile: logFile, Now: now, Log: log}
}

func (s *Store) log() *slog.Logger {
	if s.Log != nil {
		return s.Log()
	}
	return slog.Default()
}

// --- state-* latches ---

// Path returns Dir/state-<name> — the latch file path.
func (s *Store) Path(name string) string {
	return filepath.Join(s.Dir, "state-"+name)
}

// Exists reports whether state-<name> is present (e.g. the
// node-overloaded latch written by another writer).
func (s *Store) Exists(name string) bool {
	_, err := os.Stat(s.Path(name))
	return err == nil
}

// Enter creates state-<name> with the current epoch — only when
// absent (the file's mtime/content is when the condition STARTED) —
// and logs the transition once, lib.sh STATE-ENTER parity. An
// existing latch gets its mtime refreshed (BUG-H6): the janitor reaps
// state-* files older than 24h, so a latch maintained for days by an
// owner still evaluating the condition would otherwise be reaped
// mid-episode.
func (s *Store) Enter(name, extra string) {
	p := s.Path(name)
	if _, err := os.Stat(p); err == nil {
		now := s.Now()
		if cerr := os.Chtimes(p, now, now); cerr != nil {
			s.log().Debug("state latch touch failed",
				"state", name, "path", p, "error", cerr)
		}
		return
	}
	if !s.WriteEpochFile(p, s.Now().Unix()) {
		return
	}
	if extra != "" {
		s.AppendLog(fmt.Sprintf("STATE-ENTER: %s %s", name, extra))
	} else {
		s.AppendLog("STATE-ENTER: " + name)
	}
}

// Exit removes state-<name> if present and logs the transition —
// clears the NPD permanent condition. cleanup, when non-nil, runs
// after the removal and before the log line: subsystems drop their
// per-latch dedupe budgets there. The two shared suspect-budget
// divergences have named wrappers — ExitClearSuspect (drop only
// last-suspect-<name>; controllerhygiene) and ExitClearAllSuspects
// (drop the whole last-suspect-* family; nethealth) — workerhygiene
// and everyone else pass nil.
func (s *Store) Exit(name string, cleanup func()) {
	p := s.Path(name)
	if _, err := os.Stat(p); err != nil {
		return
	}
	if err := os.Remove(p); err != nil {
		s.log().Warn("state latch remove failed",
			"state", name, "path", p, "error", err)
		return
	}
	if cleanup != nil {
		cleanup()
	}
	s.AppendLog("STATE-EXIT: " + name)
}

// ExitClearSuspect is Exit plus removal of this latch's suspect-log
// dedupe budget (last-suspect-<name>): the budget is spent under the
// Store's own dir by SuspectLog, and a cleared condition must not
// suppress the first line of a re-incident under a stale epoch from
// the previous one.
func (s *Store) ExitClearSuspect(name string) {
	s.Exit(name, func() { s.ClearSuspect(name) })
}

// ExitClearAllSuspects is Exit plus removal of the WHOLE
// last-suspect-* family — a latch exit IS an incident boundary. The
// NON-latch keys (egress-probe-<ip>, conntrack-parse, ...) have no
// state-* twin to exit with, so a cleared condition would otherwise
// suppress the first line of a re-incident for up to the suspect
// cadence. No clean per-key pairing exists; a still-held condition
// pays at most one early re-log line.
func (s *Store) ExitClearAllSuspects(name string) {
	s.Exit(name, func() { s.ClearAllSuspects() })
}

// ClearSuspect drops the last-suspect-<name> dedupe budget so the
// next SuspectLog for the key logs immediately.
func (s *Store) ClearSuspect(name string) {
	_ = os.Remove(filepath.Join(s.Dir, SuspectBudgetPrefix+name))
}

// ClearAllSuspects drops every last-suspect-* dedupe budget in the
// Store's dir.
func (s *Store) ClearAllSuspects() {
	files, err := filepath.Glob(filepath.Join(s.Dir, SuspectBudgetPrefix+"*"))
	if err != nil {
		return
	}
	for _, f := range files {
		_ = os.Remove(f)
	}
}

// --- epoch files ---

// Epoch reads an epoch file — absent/garbage → 0 (rate_ok parity:
// non-numeric content collapses to 0).
func (s *Store) Epoch(path string) int64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// WriteEpochFile writes "<epoch>\n" via the hostutil atomic
// tmp+rename contract and reports whether the file landed. The
// leading dot keeps the tmp name out of hostmetrics' state-* scan.
func (s *Store) WriteEpochFile(path string, epoch int64) bool {
	if err := writeEpochFile(path, epoch); err != nil {
		s.log().Warn("state file write failed",
			"path", path, "error", err)
		return false
	}
	return true
}

// writeEpochFile is the error-returning core — InitHeartbeatFiles
// propagates failures instead of warn-and-continue.
func writeEpochFile(path string, epoch int64) error {
	return hostutil.WriteFileAtomic(path,
		strconv.FormatInt(epoch, 10)+"\n")
}

// --- rate-limit budgets (last-*) ---

// RateOK reports whether the budget file <dir>/<name> is absent,
// unparseable, or older than interval — lib.sh rate_ok parity
// (garbage → 0 → ok). dir="" means s.Dir.
func (s *Store) RateOK(name string, interval time.Duration) bool {
	return s.RateOKIn(s.Dir, name, interval)
}

// RateOKIn is RateOK with an explicit dir — controllerhygiene's
// rateOK(dir, name, interval) parity for budgets outside Dir.
func (s *Store) RateOKIn(dir, name string, interval time.Duration) bool {
	if dir == "" {
		dir = s.Dir
	}
	last := s.Epoch(filepath.Join(dir, name))
	return s.Now().Unix()-last >= int64(interval.Seconds())
}

// RateSpend stamps the budget file with the current epoch —
// lib.sh rate_spend parity, atomically (a torn write parses as
// garbage in RateOK and silently bypasses the cooldown — hostconfig's
// note). The spend is recorded on the action ATTEMPT, so a failing
// remediation cannot spam retries every cycle.
func (s *Store) RateSpend(name string) {
	s.RateSpendIn(s.Dir, name)
}

// RateSpendIn is RateSpend with an explicit dir.
func (s *Store) RateSpendIn(dir, name string) {
	if dir == "" {
		dir = s.Dir
	}
	s.WriteEpochFile(filepath.Join(dir, name), s.Now().Unix())
}

// RateTrySpend is the atomic check+spend used for the budgets two
// goroutines compete on (feeder remediate vs Cycle — "last-restart"
// above all): without the mutex a feeder "ok" and a Cycle check "ok"
// could both pass in the same window and double-spend a restart. The
// spend lands BEFORE the caller acts — a failed action still
// consumed the budget (lib.sh rate_spend parity).
func (s *Store) RateTrySpend(name string, interval time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.RateOK(name, interval) {
		return false
	}
	s.RateSpend(name)
	return true
}

// --- consecutive-* counters (controllerhygiene) ---

// Counter reads <Dir>/<name> as an int — absent/garbage → 0.
func (s *Store) Counter(name string) int {
	return int(s.Epoch(filepath.Join(s.Dir, name)))
}

// Incr mirrors lib.sh ctr_inc: read + increment + write + return.
// Garbage → 1. A failed write returns 0 (the streak is lost, never
// invented).
func (s *Store) Incr(name string) int {
	n := s.Counter(name) + 1
	if !s.WriteEpochFile(filepath.Join(s.Dir, name), int64(n)) {
		return 0
	}
	return n
}

// ResetCounter removes a consecutive-* file.
func (s *Store) ResetCounter(name string) {
	_ = os.Remove(filepath.Join(s.Dir, name))
}

// --- suspect-log dedupe ---

// SuspectLog emits msg at most once per cadence per key — a
// last-suspect-<key> epoch file under the same rateOK/rateSpend
// convention as the action budgets. It replaces the per-cycle
// AppendLog for lines whose condition persists: STATE-ENTER still
// announces the transition and a cadence re-reminder keeps a
// long-held condition visible in the tail. Counters, latches and
// metrics keep updating every cycle — only the LOG line is throttled.
func (s *Store) SuspectLog(key, msg string, cadence time.Duration) {
	if !s.RateOK(SuspectBudgetPrefix+key, cadence) {
		return
	}
	s.RateSpend(SuspectBudgetPrefix + key)
	s.AppendLog(msg)
}

// --- watchdog log ---

// AppendLog mirrors lib.sh log(): "<rfc3339> <msg>" appended to
// LogFile (the NPD filelog tails it — message text is a contract),
// plus a slog mirror for `kubectl logs` debugging. Best-effort: an
// unwritable log file never fails a check.
func (s *Store) AppendLog(msg string) {
	s.log().Info(msg)
	s.appendFile(msg)
}

// AppendLogWarn is AppendLog for failure/degraded paths — the file
// line is identical (NPD contract), the slog mirror is Warn-level.
func (s *Store) AppendLogWarn(msg string) {
	s.log().Warn(msg)
	s.appendFile(msg)
}

func (s *Store) appendFile(msg string) {
	if s.LogFile == "" {
		return
	}
	f, err := os.OpenFile(s.LogFile,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		s.log().Warn("watchdog log file unwritable",
			"file", s.LogFile, "error", err)
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", s.Now().Format(time.RFC3339), msg)
}

// --- heartbeat (installed/last-run pair) ---

// StampLastRun refreshes <Dir>/last-run with the current epoch — the
// per-cycle liveness stamp the watchdog-stalled alert reads (BUG-H1).
// No MkdirAll: the dir is provisioned by hostconfig/Docker volume —
// an absent dir means this host runs no watchdog state at all.
func (s *Store) StampLastRun() {
	if s.Dir == "" {
		return
	}
	s.WriteEpochFile(filepath.Join(s.Dir, "last-run"), s.Now().Unix())
}

// Heartbeat is the workerhygiene variant: MkdirAll + `installed`
// seeded once (baseline epoch, ansible force:false parity) +
// `last-run` rewritten every call — nodereporter's watchdogStale()
// reads exactly this pair.
func (s *Store) Heartbeat() {
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		s.log().Warn("watchdog heartbeat failed",
			"dir", s.Dir, "error", err)
		return
	}
	now := s.Now().Unix()
	installed := filepath.Join(s.Dir, "installed")
	if _, err := os.Stat(installed); os.IsNotExist(err) {
		s.WriteEpochFile(installed, now)
	}
	s.WriteEpochFile(filepath.Join(s.Dir, "last-run"), now)
}

// InitHeartbeatFiles seeds the installed/last-run pair ONCE — only
// for files that don't already exist (BUG-H1, nodereporter startup
// variant). A missing `installed` disables the staleness gate
// entirely and a missing `last-run` reads as epoch 0, so the
// reporter initializes them on a fresh state dir where no hygiene
// subsystem has run yet. `installed` is created only when absent
// (ansible force:false parity — presence activates the probe's
// gate); writes go through the atomic tmp+rename so a reader never
// observes a truncated epoch.
func (s *Store) InitHeartbeatFiles() error {
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", s.Dir, err)
	}
	now := s.Now().Unix()
	for _, name := range []string{"installed", "last-run"} {
		p := filepath.Join(s.Dir, name)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			if err := writeEpochFile(p, now); err != nil {
				return fmt.Errorf("write %s: %w", p, err)
			}
		}
	}
	return nil
}
