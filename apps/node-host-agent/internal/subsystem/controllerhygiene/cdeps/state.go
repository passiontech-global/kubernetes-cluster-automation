// state.go — the on-disk bookkeeping helpers the shared hoststate
// Store does not cover: the raw-text read/write for the non-epoch
// files (last-rvc/last-prvc string compare, the empty-line
// oomloop-shielded marker).
package cdeps

import (
	"os"
	"path/filepath"
	"strings"
)

// --- watchdog file helpers (lib.sh parity) ---
// state-<name>    : latch file, content = epoch of entry
// last-*          : rate-limit budget, content = epoch of last spend
// consecutive-*   : consecutive-fail counters (on-disk parity — the
//                   files are shared with still-deployed shell pieces)
// watchdog log    : "<rfc3339> <msg>" appended to WatchdogLogFile
//
// The on-disk contract itself lives in platform/hoststate — the
// deps' Store field is the single implementation of state_enter/state_exit,
// rate_ok/rate_spend, ctr_inc/ctr_read/ctr_reset, suspectLog's
// last-suspect-* budgets, the watchdog log append and the last-run
// stamp. The per-subsystem copies that used to live here are gone;
// what remains below is only what Store does not cover.

// StateExit removes state-<name> if present and logs the
// transition — the controllerhygiene suspect-budget divergence,
// named on the Store: Store.ExitClearSuspect drops the latch's
// last-suspect-<name> dedupe budget with it, so a later re-entry
// logs a fresh first line instead of staying throttled by a stale
// epoch from the previous incident.
func (d *Deps) StateExit(name string) {
	d.State.ExitClearSuspect(name)
}

// ReadState reads an arbitrary bookkeeping file under the Store's
// dir and returns its trimmed contents ("" on any error). Kept as a
// thin helper because Store has no "read raw text" equivalent —
// Store.Epoch collapses absent/garbage to int64 0, which would make
// an absent last-rvc/last-prvc file compare EQUAL to a real
// resourceVersion of 0; the string compare preserves the
// empty-vs-zero distinction the frozen-rv check needs.
func (d *Deps) ReadState(name string) string {
	data, err := os.ReadFile(filepath.Join(d.State.Dir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// splitLines was removed: line iteration is done in place with
// strings.Cut at each call site — no intermediate []string on
// potentially multi-MiB journal/proc text.

// WriteState writes "<content>\n" under the Store's dir, warn-only
// on error — kept for the one non-epoch bookkeeping file
// (oomloop-shielded, whose content is an empty line — Store only
// writes "<epoch>\n" via WriteEpochFile; epoch-valued files
// (last-rvc/last-prvc/ttl-last-wedged-pid/oomloop-seen) use
// the Store's WriteEpochFile directly).
func (d *Deps) WriteState(name, content string) {
	p := filepath.Join(d.State.Dir, name)
	if err := os.WriteFile(p, []byte(content+"\n"), 0o644); err != nil {
		logger().Warn("controllerhygiene: state file write failed",
			"path", p, "error", err)
	}
}
