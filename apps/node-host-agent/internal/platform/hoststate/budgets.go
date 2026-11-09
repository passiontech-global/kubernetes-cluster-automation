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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
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
// A clock step-back (NTP correction, manual set) must not open the
// gate: a stamp from the future makes age negative, and "negative
// age >= interval" passes every interval — a silent budget bypass.
// Clamp to 0: a future stamp is simply not expired yet. This is the
// ONLY now-last comparison in the package, so RateTrySpend's check
// branch (and everything built on RateOK) inherits the clamp.
func (s *Store) RateOKIn(dir, name string, interval time.Duration) bool {
	if dir == "" {
		dir = s.Dir
	}
	last := s.Epoch(filepath.Join(dir, name))
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
	s.shared.mu.Lock()
	defer s.shared.mu.Unlock()
	if !s.RateOK(name, interval) {
		return false
	}
	s.RateSpend(name)
	return true
}
