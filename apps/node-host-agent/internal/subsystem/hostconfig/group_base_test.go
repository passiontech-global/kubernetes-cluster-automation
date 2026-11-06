// group_base_test.go — groupBase converge: self-staged agent
// binary, hostname hosts pin, and journald integrity/silent
// restart remediation with its cooldown latches.
package hostconfig

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------- self-stage /usr/local/bin/node-host-agent ----------

func TestSelfStageBinaryCopiesAndIsIdempotent(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	srcb, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	srcSum := sha256.Sum256(srcb)
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")
	// stale/different host binary -> must be replaced by the running build
	hostWrite(t, r, "/usr/local/bin/node-host-agent", "stale-binary")

	c := loadCyc(t, r, vars, "node-b")
	c.groupBase()

	dst := filepath.Join(r.cfg.HostRoot, "/usr/local/bin/node-host-agent")
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("staged binary missing: %v", err)
	}
	if sha256.Sum256(got) != srcSum {
		t.Fatal("staged binary sha256 != running binary")
	}
	if fi, err := os.Stat(dst); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("staged binary mode = %v want 0755", fi)
	}
	// second cycle: hash matches -> writeManaged must not rewrite
	// (the staged content survives untouched).
	c.groupBase()
	got2, _ := os.ReadFile(dst)
	if string(got2) != string(got) {
		t.Fatal("staged binary rewritten despite matching sha256")
	}
}

func TestSelfStageSkippedOnStandalone(t *testing.T) {
	vars := writeVarsDir(t, "")
	sr := &scriptedRunner{res: map[string]string{}, errs: map[string]bool{}}
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: vars, Standalone: true, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")
	c := loadCyc(t, r, vars, "node-b")
	c.groupBase()
	if hostExists(r, "/usr/local/bin/node-host-agent") {
		t.Fatal("binary staged on a standalone host — /host/usr/local not mounted there")
	}
}

func TestJournaldCorruptOutputRotates(t *testing.T) {
	c, _, sr := journaldEnv(t, map[string]string{
		"journalctl -n 5": "File corruption detected at /var/log/journal/x/system.journal:0 (of 20971520 bytes, 0%)",
	}, map[string]bool{})
	// groupBase runs the probe; corrupted output must trigger the
	// rotate+vacuum remediation.
	c.groupBase()
	if len(sr.callsMatching("journalctl --rotate --vacuum-time=3d")) == 0 {
		t.Fatalf("corrupt journal not remediated: %v", sr.callsMatching("journalctl"))
	}
}

func TestJournaldAbnormallyEmptyRotates(t *testing.T) {
	// journalctl answers but returns nothing while journal files are
	// on disk — post-hard-reboot truncated/misindexed journal.
	c, r, sr := journaldEnv(t, map[string]string{}, map[string]bool{})
	if err := os.MkdirAll(filepath.Join(r.cfg.HostRoot, "/var/log/journal/machine-x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.cfg.HostRoot,
		"/var/log/journal/machine-x/system.journal"), []byte("journal"), 0o644); err != nil {
		t.Fatal(err)
	}
	c.groupBase()
	if len(sr.callsMatching("journalctl --rotate --vacuum-time=3d")) == 0 {
		t.Fatalf("abnormally empty journal not remediated: %v", sr.callsMatching("journalctl"))
	}
}

func TestJournaldHealthyNoRotate(t *testing.T) {
	c, _, sr := journaldEnv(t, map[string]string{
		"journalctl -n 5": "Oct 01 10:00:00 node-b systemd[1]: Started node-host-agent.service",
	}, map[string]bool{})
	c.groupBase()
	if len(sr.callsMatching("journalctl --rotate")) > 0 {
		t.Fatalf("healthy journal rotated: %v", sr.callsMatching("journalctl"))
	}
}

func TestJournaldMissingBinaryNoRotate(t *testing.T) {
	// journalctl absent → probe errors with empty output; that is not
	// corruption evidence (rotating would fail anyway) — no action.
	c, _, sr := journaldEnv(t, map[string]string{}, map[string]bool{"journalctl": true})
	c.groupBase()
	if len(sr.callsMatching("--rotate")) > 0 {
		t.Fatalf("rotate attempted without journalctl: %v", sr.callsMatching("journalctl"))
	}
}

func TestJournaldRotateRateLimited(t *testing.T) {
	// A persistently-corrupt probe must not re-run rotate+vacuum every
	// cycle — the last-journald-rotate latch caps it to once per
	// cooldown window (a false positive would otherwise pin errs and
	// hammer the journal on every converge).
	c, _, sr := journaldEnv(t, map[string]string{
		"journalctl -n 5": "File corruption detected at /var/log/journal/x/system.journal:0 (of 20971520 bytes, 0%)",
	}, map[string]bool{})
	c.groupBase()
	c.groupBase()
	if got := len(sr.callsMatching("journalctl --rotate --vacuum-time=3d")); got != 1 {
		t.Fatalf("rotate ran %d times, want 1 (cooldown latch)", got)
	}
}

func TestJournaldSilentNoFilesRestarts(t *testing.T) {
	// Incident shape: journalctl answers "No journal files were
	// found." while a journal storage root exists — journald is
	// writing nowhere and must be restarted (rotate cannot create
	// files).
	c, r, sr := journaldEnv(t, map[string]string{
		"journalctl -n 5": "No journal files were found.\n",
	}, map[string]bool{})
	if err := os.MkdirAll(filepath.Join(r.cfg.HostRoot, "/var/log/journal/machine-x"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.groupBase()
	if len(sr.callsMatching("systemctl restart systemd-journald.service")) == 0 {
		t.Fatalf("silent journald not restarted: %v", sr.callsMatching("systemctl"))
	}
	if len(sr.callsMatching("journalctl --rotate")) > 0 {
		t.Fatal("rotate ran for a file-less journal — rotate cannot create files")
	}
}

func TestJournaldSilentEmptyNoFilesRestarts(t *testing.T) {
	// Same verdict without the notice text (suppressed/locale): a
	// literally empty read + a storage root + zero *.journal files.
	c, r, sr := journaldEnv(t, map[string]string{}, map[string]bool{})
	if err := os.MkdirAll(filepath.Join(r.cfg.HostRoot, "/var/log/journal/machine-x"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.groupBase()
	if len(sr.callsMatching("systemctl restart systemd-journald.service")) == 0 {
		t.Fatalf("empty journal with storage root not restarted: %v", sr.callsMatching("systemctl"))
	}
}

func TestJournaldSilentNoStorageNoRestart(t *testing.T) {
	// No journal storage at all → journald legitimately absent —
	// silence is configuration, not a fault: no restart, no rotate.
	c, _, sr := journaldEnv(t, map[string]string{
		"journalctl -n 5": "No journal files were found.\n",
	}, map[string]bool{})
	c.groupBase()
	if len(sr.callsMatching("systemctl restart systemd-journald.service")) > 0 {
		t.Fatal("journald restarted with no storage configured")
	}
	if len(sr.callsMatching("journalctl --rotate")) > 0 {
		t.Fatal("rotate ran with no storage configured")
	}
}

func TestJournaldSilentRestartRateLimited(t *testing.T) {
	c, r, sr := journaldEnv(t, map[string]string{
		"journalctl -n 5": "No journal files were found.\n",
	}, map[string]bool{})
	if err := os.MkdirAll(filepath.Join(r.cfg.HostRoot, "/var/log/journal/machine-x"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.groupBase()
	c.groupBase()
	if got := len(sr.callsMatching("systemctl restart systemd-journald.service")); got != 1 {
		t.Fatalf("journald restarts = %d, want 1 (last-journald-restart cooldown)", got)
	}
}

// TestHostnamePinNoGlueOnMissingNewline — a hosts file without a
// trailing newline must not fuse the 127.0.1.1 pin onto the last
// existing line.
func TestHostnamePinNoGlueOnMissingNewline(t *testing.T) {
	c, r, _ := journaldEnv(t, map[string]string{
		"journalctl -n 5": "ok",
	}, map[string]bool{})
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost") // NO trailing \n
	c.groupBase()
	hosts := hostRead(t, r, "/etc/hosts")
	if !strings.Contains(hosts, "127.0.0.1 localhost\n127.0.1.1 node-b\n") {
		t.Fatalf("hostname pin glued onto the last line:\n%q", hosts)
	}
}
