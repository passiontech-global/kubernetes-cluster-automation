// budgets.go — epoch files and the rate-limit budgets (last-*):
// Epoch reads, atomic WriteEpochFile, and the RateOK/RateSpend/
// RateTrySpend lib.sh rate_ok/rate_spend parity layer. Latch
// lifecycle is store.go; the suspect-log budgets that reuse the
// same last-* convention are suspect.go.

package hoststate

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

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
	return fsx.WriteFileAtomic(path,
		strconv.FormatInt(epoch, 10)+"\n")
}

// writeEpochFileNoSync is writeEpochFile minus the durability
// fsyncs — same tmp+rename atomicity. Reserved for the per-cycle
// liveness stamps (last-run): the watchdog-stalled alert reads the
// VALUE, and a crash losing the newest stamp just reads as a few
// seconds staler — the next cycle rewrites it. Latch creation and
// rate budgets keep the durable writeEpochFile: a lost budget
// silently re-opens a cooldown, a lost latch clears a live fault.
func writeEpochFileNoSync(path string, epoch int64) error {
	return fsx.WriteFileAtomicNoSync(path,
		strconv.FormatInt(epoch, 10)+"\n")
}

// --- rate-limit budgets (last-*) ---

// RateOK reports whether the budget file <dir>/<name> is absent,
// unparseable, or older than interval — lib.sh rate_ok parity
// (garbage → 0 → ok). dir="" means s.Dir.
func (s *Store) RateOK(name string, interval time.Duration) bool {
	return s.RateOKIn(s.Dir, name, interval)
}

// rateSpendKey is the lastSpent map key — dir+name under a NUL
// separator no path component can contain.
func rateSpendKey(dir, name string) string { return dir + "\x00" + name }

// RateOKIn is RateOK with an explicit dir — controllerhygiene's
// rateOK(dir, name, interval) parity for budgets outside Dir.
// A clock step-back (NTP correction, manual set) must not open the
// gate: a stamp from the future makes age negative, and "negative
// age >= interval" passes every interval — a silent budget bypass.
// Clamp to 0: a future stamp is simply not expired yet. This is the
// ONLY now-last comparison in the package, so RateTrySpend's check
// branch (and everything built on RateOK) inherits the clamp.
//
// The verdict is max(disk epoch, RAM lastSpent): a spend whose
// disk write failed (ENOSPC/EROFS) still counts — the RAM mirror
// is what stops the restart storm a dead state dir would otherwise
// cause. Runs under s.shared.mu so a racing RateSpendIn cannot
// slip a spend between the read and the caller's act.
func (s *Store) RateOKIn(dir, name string, interval time.Duration) bool {
	s.shared.mu.Lock()
	defer s.shared.mu.Unlock()
	return s.rateOKInLocked(dir, name, interval)
}

// rateOKInLocked is RateOKIn's body — the caller HOLDS s.shared.mu.
func (s *Store) rateOKInLocked(dir, name string, interval time.Duration) bool {
	if dir == "" {
		dir = s.Dir
	}
	// Clean BOTH sides of the spend key: callers spell the same dir
	// differently across cycles ("x/" vs "x", "a/b/../b"), and the
	// RAM lastSpent key is dir+name verbatim — an uncleaned spelling
	// would miss the RAM mirror and re-open a just-spent budget
	// (filepath.Join alone cleans the FILE path, not the key).
	dir = filepath.Clean(dir)
	last := s.Epoch(filepath.Join(dir, name))
	if ram := s.shared.lastSpent[rateSpendKey(dir, name)]; ram > last {
		last = ram
	}
	age := s.Now().Unix() - last
	if age < 0 {
		age = 0
	}
	return age >= int64(interval.Seconds())
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
	s.shared.mu.Lock()
	defer s.shared.mu.Unlock()
	s.rateSpendInLocked(dir, name)
}

// rateSpendInLocked is RateSpendIn's body — the caller HOLDS
// s.shared.mu. The RAM lastSpent stamp lands BEFORE the disk write:
// an ENOSPC/EROFS WriteEpochFile failure must still consume the
// budget, or RateOKIn keeps passing and the gated action storms.
// The dir is Cleaned to the same spelling rateOKInLocked keys with —
// a differently-spelled dir would write a mirror the checker never
// sees.
func (s *Store) rateSpendInLocked(dir, name string) {
	if dir == "" {
		dir = s.Dir
	}
	dir = filepath.Clean(dir)
	now := s.Now().Unix()
	if s.shared.lastSpent == nil {
		s.shared.lastSpent = map[string]int64{}
	}
	s.shared.lastSpent[rateSpendKey(dir, name)] = now
	s.WriteEpochFile(filepath.Join(dir, name), now)
}

// ClearBudget removes a rate-budget file AND its RAM lastSpent
// mirror — required wherever a budget file is deleted outside
// RateSpend: the mirror would otherwise keep the cooldown alive
// after the file is gone (RateOKIn verdicts on max(disk, ram)).
// Best-effort like ClearSuspect: an absent file is already clear.
func (s *Store) ClearBudget(name string) {
	if err := os.Remove(filepath.Join(s.Dir, name)); err != nil &&
		!os.IsNotExist(err) {
		s.log().Debug("hoststate: failed to clear budget file",
			"name", name, "error", err)
	}
	s.forgetSpent(name)
}

// RateTrySpend is the atomic check+spend used for the budgets two
// goroutines compete on (feeder remediate vs Cycle — "last-restart"
// above all): without the mutex a feeder "ok" and a Cycle check "ok"
// could both pass in the same window and double-spend a restart. The
// spend lands BEFORE the caller acts — a failed action still
// consumed the budget (lib.sh rate_spend parity).
func (s *Store) RateTrySpend(name string, interval time.Duration) bool {
	s.shared.mu.Lock()
	defer s.shared.mu.Unlock()
	if !s.rateOKInLocked(s.Dir, name, interval) {
		return false
	}
	s.rateSpendInLocked(s.Dir, name)
	return true
}
