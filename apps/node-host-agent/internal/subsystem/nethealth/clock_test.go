// clock_test.go — clock-unsync latch and rate-limited NTP daemon restart.

package nethealth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// --- clock-sync (H1) ---

func TestClockSyncLatchAndRateLimitedRestart(t *testing.T) {
	e := fixture(t, nil)
	e.timex.Status = unix.STA_UNSYNC
	e.sd.On("is-enabled systemd-timesyncd.service", "enabled\n")
	e.sd.On("is-active systemd-timesyncd.service", "active\n")
	e.sd.On("restart systemd-timesyncd.service", "")

	// Cycle 1: first failure — no latch, no restart yet.
	e.n.Cycle(context.Background())
	if stateExists(e, "clock-unsync") {
		t.Fatal("clock-unsync latch before ConsecNeeded")
	}
	if e.sd.Ran("restart") {
		t.Fatal("ntp restart before ConsecNeeded")
	}

	// Cycle 2: second consecutive failure → latch + restart.
	e.n.Cycle(context.Background())
	if !stateExists(e, "clock-unsync") {
		t.Fatal("clock-unsync latch missing after ConsecNeeded")
	}
	if !e.sd.Ran("restart systemd-timesyncd.service") {
		t.Fatalf("timesyncd not restarted, cmds=%v", e.sd.Cmds())
	}
	if _, err := os.Stat(filepath.Join(e.state, "last-ntp-restart")); err != nil {
		t.Fatal("last-ntp-restart budget not spent")
	}

	// Cycle 3 (still failing): the 30m budget blocks a re-restart.
	e.sd.ClearLog()
	e.n.Cycle(context.Background())
	if e.sd.Ran("restart systemd-timesyncd.service") {
		t.Fatal("restart inside last-ntp-restart cooldown")
	}

	// Budget expired → next failing cycle restarts again.
	e.now = e.now.Add(31 * time.Minute)
	e.n.Cycle(context.Background())
	if !e.sd.Ran("restart systemd-timesyncd.service") {
		t.Fatal("no restart after last-ntp-restart window elapsed")
	}

	// Clock syncs again → latch clears.
	e.timex.Status = 0
	e.n.Cycle(context.Background())
	if stateExists(e, "clock-unsync") {
		t.Fatal("clock-unsync latch kept after resync")
	}
}

func TestClockSyncEsterrorTooLarge(t *testing.T) {
	e := fixture(t, nil)
	// No STA_UNSYNC — but esterror above 500ms is unhealthy on its own.
	e.timex.Esterror = 600_000
	e.sd.On("is-enabled chronyd.service", "enabled\n")
	e.sd.On("is-active chronyd.service", "active\n")
	e.sd.On("restart chronyd.service", "")
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background())
	if !stateExists(e, "clock-unsync") {
		t.Fatal("clock-unsync latch missing on esterror > 500ms")
	}
	// timesyncd absent → falls through to the first enabled/active unit.
	if !e.sd.Ran("restart chronyd.service") {
		t.Fatalf("chronyd not restarted, cmds=%v", e.sd.Cmds())
	}
}

// On a chrony node, timesyncd's unit FILE exists (it ships with
// systemd) but the daemon is disabled — restarting it would start a
// second clock-discipline daemon fighting chrony over adjtimex. The
// picker must prefer the enabled/active unit, not UnitExists order.
func TestClockSyncPrefersEnabledDaemonOverInstalled(t *testing.T) {
	e := fixture(t, nil)
	e.timex.Status = unix.STA_UNSYNC
	// timesyncd installed but disabled (is-enabled → error), chrony
	// is the live daemon.
	e.sd.On("is-enabled chrony.service", "enabled\n")
	e.sd.On("is-active chrony.service", "active\n")
	e.sd.On("LoadState --value systemd-timesyncd.service", "loaded\n")
	e.sd.On("restart chrony.service", "")
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background())
	if e.sd.Ran("restart systemd-timesyncd.service") {
		t.Fatal("disabled timesyncd restarted on a chrony node — " +
			"would start a second sync daemon")
	}
	if !e.sd.Ran("restart chrony.service") {
		t.Fatalf("chrony not restarted, cmds=%v", e.sd.Cmds())
	}
}

func TestClockSyncAdjtimexErrorAborts(t *testing.T) {
	e := fixture(t, nil)
	e.adjErr = errors.New("operation not permitted")
	e.sd.On("is-enabled systemd-timesyncd.service", "enabled\n")
	e.sd.On("is-active systemd-timesyncd.service", "active\n")
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background())
	if stateExists(e, "clock-unsync") {
		t.Fatal("adjtimex error must not false-latch clock-unsync")
	}
	if e.sd.Ran("restart") {
		t.Fatal("ntp restart on adjtimex read failure")
	}
}
