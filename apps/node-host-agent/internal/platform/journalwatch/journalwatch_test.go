package journalwatch

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
)

// The tracker drives the store's multi-owner API; the caller policy
// these tests encode is wdeps/cdeps NoteJournalRead: failed read →
// EnterFrom (exit edge on !Present via ExitFrom), ok read → ExitFrom.

func TestEnterAfterNeededFailures(t *testing.T) {
	dir := t.TempDir()
	tr := &Tracker{Needed: 3, Dirs: []string{dir}}
	const owner, latch = "workerhygiene", "journal-unreadable"
	for i := 1; i <= 2; i++ {
		if tr.EnterFrom(owner, latch) {
			t.Fatalf("fail %d: premature enter", i)
		}
	}
	if !tr.EnterFrom(owner, latch) {
		t.Fatal("fail 3: want the enter edge")
	}
	// Once latched, further failures re-fire nothing (dedupe).
	for range 3 {
		if tr.EnterFrom(owner, latch) {
			t.Fatal("latched fail re-fired the enter edge")
		}
	}
	if !tr.Latched() {
		t.Fatal("tracker must report latched")
	}
}

func TestNoFireWithoutJournalDir(t *testing.T) {
	tr := &Tracker{Needed: 2, Dirs: []string{filepath.Join(t.TempDir(), "missing")}}
	for i := range 10 {
		if tr.EnterFrom("workerhygiene", "journal-unreadable") {
			t.Fatalf("fail %d entered with no journal dir", i)
		}
	}
}

func TestRecoveryExitsOnce(t *testing.T) {
	dir := t.TempDir()
	tr := &Tracker{Needed: 2, Dirs: []string{dir}}
	const owner, latch = "workerhygiene", "journal-unreadable"
	tr.EnterFrom(owner, latch)
	if !tr.EnterFrom(owner, latch) {
		t.Fatal("expected enter after Needed failures")
	}
	if !tr.ExitFrom(owner, latch) {
		t.Fatal("recovery while latched must report the exit edge")
	}
	if tr.ExitFrom(owner, latch) {
		t.Fatal("already-clear recovery must not re-fire the exit edge")
	}
}

func TestSuccessResetsStreak(t *testing.T) {
	dir := t.TempDir()
	tr := &Tracker{Needed: 3, Dirs: []string{dir}}
	const owner, latch = "workerhygiene", "journal-unreadable"
	tr.EnterFrom(owner, latch)
	tr.EnterFrom(owner, latch)
	tr.ExitFrom(owner, latch) // blip recovered — streak must restart
	for i := range 2 {
		if tr.EnterFrom(owner, latch) {
			t.Fatalf("streak should have restarted; premature enter at fail %d", i+1)
		}
	}
	if !tr.EnterFrom(owner, latch) {
		t.Fatal("enter expected only after a fresh full streak")
	}
}

// TestOwnerStreaksAreIndependent: the two producers of the shared
// latch each keep their own streak — a sibling's recovery must not
// reset this owner's count (the owner-scoped-counter rationale).
func TestOwnerStreaksAreIndependent(t *testing.T) {
	dir := t.TempDir()
	tr := &Tracker{Needed: 2, Dirs: []string{dir}}
	const latch = "journal-unreadable"
	if tr.EnterFrom(OwnerWorkerHygiene, latch) {
		t.Fatal("worker first failure must not enter")
	}
	if !tr.EnterFrom(OwnerWorkerHygiene, latch) {
		t.Fatal("worker streak should enter at its own Needed")
	}
	// The controller owner starts from zero — its first failing read
	// must not ride the worker's streak.
	if tr.EnterFrom(OwnerControllerHygiene, latch) {
		t.Fatal("controller streak must start at zero, not inherit the worker's")
	}
	if got := tr.Fails(); got < 1 {
		t.Fatalf("Fails()=%d want the strongest streak (≥1)", got)
	}
}

func TestStorageVanishWhileLatchedExits(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "journal")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	tr := &Tracker{Needed: 1, Dirs: []string{dir}}
	const owner, latch = "workerhygiene", "journal-unreadable"
	if !tr.EnterFrom(owner, latch) {
		t.Fatal("expected enter")
	}
	// Journal storage removed under the latch — the host's journald
	// config changed (e.g. volatile-only), this is no longer a
	// journald-broken signal. The caller classifies that via Present
	// and routes the read through the exit path.
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if tr.Present() {
		t.Fatal("storage gone — Present must flip false")
	}
	if !tr.ExitFrom(owner, latch) {
		t.Fatal("expected the exit edge when journal storage vanished while latched")
	}
}

func TestAnyDirCountsAsPresent(t *testing.T) {
	root := t.TempDir()
	volatile := filepath.Join(root, "run-log-journal")
	if err := os.Mkdir(volatile, 0o755); err != nil {
		t.Fatal(err)
	}
	tr := &Tracker{Needed: 1,
		Dirs: []string{filepath.Join(root, "missing"), volatile}}
	if !tr.EnterFrom(OwnerWorkerHygiene, "journal-unreadable") {
		t.Fatal("volatile /run/log/journal presence must satisfy the gate")
	}
}

// TestUnreadableOwnersMatchLatchRegistry: the owner consts the two
// hygiene wiring files pass must byte-match the latchdefs Owners
// declaration — the store's legacy-file seed derives the synthetic
// hold set from that declaration, so a drift would let a post-restart
// ExitFrom clear a latch the other hygiene is still failing under.
func TestUnreadableOwnersMatchLatchRegistry(t *testing.T) {
	got := latchdefs.SharedOwners(latchdefs.LatchJournalUnreadable)
	want := []string{OwnerWorkerHygiene, OwnerControllerHygiene}
	if !slices.Equal(got, want) {
		t.Fatalf("SharedOwners(journal-unreadable) = %v, want %v", got, want)
	}
}

func TestFilesGoneMarker(t *testing.T) {
	for out, want := range map[string]bool{
		"No journal files were found.\n":    true,
		"foo\nNo Journal Files were opened": true,
		"-- No entries --\n":                false,
		"Oct 01 node systemd[1]: ok\n":      false,
		"":                                  false,
	} {
		if got := FilesGone(out); got != want {
			t.Fatalf("FilesGone(%q) = %v, want %v", out, got, want)
		}
	}
}
