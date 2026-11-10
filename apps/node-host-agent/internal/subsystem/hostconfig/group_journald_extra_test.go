// group_journald_extra_test.go — journald persistence/integrity
// failure arms: journal-dir creation failing, chgrp failing, and the
// rotate remedy itself failing (counted once, cooldown-spent).
package hostconfig

import (
	"strings"
	"testing"
)

// TestJournalDirCreateFailureWarns — /var/log/journal is a FILE: the
// persistence dir cannot be created; warn-only (the drop-in still
// converges, the dir lands at the next window).
func TestJournalDirCreateFailureWarns(t *testing.T) {
	vars := writeVarsDir(t, "journald_persistent: true\n")
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), Standalone: true, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/machine-id", "abcdef1234567890\n")
	hostWrite(t, r, "/var/log/journal", "not a dir\n")
	c := loadCyc(t, r, vars, "node-b")
	created := c.ensureJournalDir()
	if c.errs != 0 {
		t.Fatalf("errs = %d — dir creation failure is a warning", c.errs)
	}
	if !created {
		t.Fatal("create failure reported the dir as pre-existing")
	}
}

// TestJournalDirChgrpFailureWarns — the chgrp systemd-journal exec
// failing warns without counting (best-effort ownership).
func TestJournalDirChgrpFailureWarns(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := newScripted(nil, nil)
	sr.FailOn("chgrp systemd-journal", nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Standalone: true, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/machine-id", "abcdef1234567890\n")
	c := loadCyc(t, r, vars, "node-b")
	c.ensureJournalDir()
	if c.errs != 0 {
		t.Fatalf("errs = %d — chgrp failure is a warning", c.errs)
	}
	if !hostExists(r, "/var/log/journal/abcdef1234567890") {
		t.Fatal("journal dir not created despite the chgrp failure")
	}
}

// TestJournaldRotateRemedyFailureCounts — corruption detected, rotate
// exec failing: the failure counts AND the cooldown is spent (the
// retry must not hammer the journal every cycle).
func TestJournaldRotateRemedyFailureCounts(t *testing.T) {
	c, _, sr := journaldEnv(t, map[string]string{
		"journalctl -n 5": "File corruption detected at /var/log/journal/x/system.journal:0",
	}, map[string]bool{})
	sr.FailOn("journalctl --rotate", nil)
	c.groupBase()
	if c.errs == 0 {
		t.Fatal("failed rotate+vacuum did not count a cycle error")
	}
	if !strings.Contains(strings.Join(sr.Calls(), "\n"), "journalctl --rotate --vacuum-time=3d") {
		t.Fatal("remedy command not issued")
	}

	// The budget is spent on the attempt: an immediate second cycle
	// with the same corruption must NOT re-issue the remedy.
	sr.ClearLog()
	c.errs = 0
	c.groupBase()
	if len(sr.CallsMatching("journalctl --rotate")) != 0 {
		t.Fatal("rotate re-issued inside the cooldown window")
	}
}
