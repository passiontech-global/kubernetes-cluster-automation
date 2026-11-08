// heartbeat.go — the installed/last-run heartbeat pair and its
// one-shot seeding variant. Latch lifecycle is store.go; the epoch
// writes go through the atomic core in budgets.go.

package hoststate

import (
	"fmt"
	"os"
	"path/filepath"
)

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
