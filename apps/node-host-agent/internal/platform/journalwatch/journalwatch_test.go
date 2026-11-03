package journalwatch

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnterAfterNeededFailures(t *testing.T) {
	dir := t.TempDir()
	tr := &Tracker{Needed: 3, Dirs: []string{dir}}
	for i := 1; i <= 2; i++ {
		if enter, exit := tr.NoteRead(false); enter || exit {
			t.Fatalf("fail %d: enter=%v exit=%v, want neither", i, enter, exit)
		}
	}
	enter, exit := tr.NoteRead(false)
	if !enter || exit {
		t.Fatalf("fail 3: enter=%v exit=%v, want enter", enter, exit)
	}
	// Once latched, further failures re-fire nothing (dedupe).
	for i := 0; i < 3; i++ {
		if enter, exit := tr.NoteRead(false); enter || exit {
			t.Fatalf("latched fail: enter=%v exit=%v, want neither", enter, exit)
		}
	}
}

func TestNoFireWithoutJournalDir(t *testing.T) {
	tr := &Tracker{Needed: 2, Dirs: []string{filepath.Join(t.TempDir(), "missing")}}
	for i := 0; i < 10; i++ {
		if enter, exit := tr.NoteRead(false); enter || exit {
			t.Fatalf("fail %d with no journal dir: enter=%v exit=%v", i, enter, exit)
		}
	}
}

func TestRecoveryExitsOnce(t *testing.T) {
	dir := t.TempDir()
	tr := &Tracker{Needed: 2, Dirs: []string{dir}}
	tr.NoteRead(false)
	if enter, _ := tr.NoteRead(false); !enter {
		t.Fatal("expected enter after Needed failures")
	}
	enter, exit := tr.NoteRead(true)
	if enter || !exit {
		t.Fatalf("recovery: enter=%v exit=%v, want exit", enter, exit)
	}
	if enter, exit := tr.NoteRead(true); enter || exit {
		t.Fatalf("already-clear: enter=%v exit=%v, want neither", enter, exit)
	}
}

func TestSuccessResetsStreak(t *testing.T) {
	dir := t.TempDir()
	tr := &Tracker{Needed: 3, Dirs: []string{dir}}
	tr.NoteRead(false)
	tr.NoteRead(false)
	tr.NoteRead(true) // blip recovered — streak must restart
	for i := 0; i < 2; i++ {
		if enter, _ := tr.NoteRead(false); enter {
			t.Fatalf("streak should have restarted; premature enter at fail %d", i+1)
		}
	}
	if enter, _ := tr.NoteRead(false); !enter {
		t.Fatal("enter expected only after a fresh full streak")
	}
}

func TestStorageVanishWhileLatchedExits(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "journal")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	tr := &Tracker{Needed: 1, Dirs: []string{dir}}
	if enter, _ := tr.NoteRead(false); !enter {
		t.Fatal("expected enter")
	}
	// Journal storage removed under the latch — the host's journald
	// config changed (e.g. volatile-only), this is no longer a
	// journald-broken signal.
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if _, exit := tr.NoteRead(false); !exit {
		t.Fatal("expected exit when journal storage vanished while latched")
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
	if enter, _ := tr.NoteRead(false); !enter {
		t.Fatal("volatile /run/log/journal presence must satisfy the gate")
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
