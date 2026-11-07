// group_journald_test.go — standalone journald persistence
// drop-in + storage-dir converge and its restart dedupe
// against the integrity probe.
package hostconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// ---------- journald persistence (standalone) + silent restart ----------

// standaloneJournaldEnv is journaldEnv for the standalone (HostRoot
// "/" — on-host systemd) path journaldPersistence gates on.
func standaloneJournaldEnv(t *testing.T, res map[string]string, errs map[string]bool) (*cyc, *Reconciler, *testutil.FakeRunner) {
	t.Helper()
	vars := writeVarsDir(t, "")
	sr := newScripted(res, errs)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, Standalone: true, Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, r, "/etc/hosts", "127.0.0.1 localhost\n")
	hostWrite(t, r, "/etc/machine-id", "abcdef1234567890\n")
	return loadCyc(t, r, vars, "node-a"), r, sr
}

func TestJournaldPersistenceStandaloneConverge(t *testing.T) {
	c, r, sr := standaloneJournaldEnv(t, map[string]string{
		"journalctl -n 5": "ok line",
	}, map[string]bool{})
	c.groupBase()

	jd := hostRead(t, r, "/etc/systemd/journald.conf.d/50-node-config-agent.conf")
	if !strings.Contains(jd, "[Journal]") || !strings.Contains(jd, "Storage=persistent") {
		t.Fatalf("bad journald drop-in:\n%s", jd)
	}
	fi, err := os.Stat(filepath.Join(r.cfg.HostRoot, "/var/log/journal/abcdef1234567890"))
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o755 || fi.Mode()&os.ModeSetgid == 0 {
		t.Fatalf("journal dir missing/wrong mode (want 02755): fi=%v err=%v", fi.Mode(), err)
	}
	if len(sr.CallsMatching("chgrp systemd-journal /var/log/journal/abcdef1234567890")) == 0 {
		t.Fatalf("journal dir not chgrp'd: %v", sr.CallsMatching("chgrp"))
	}
	// First converge: drop-in write + fresh dir → exactly one restart.
	if got := len(sr.CallsMatching("systemctl restart systemd-journald.service")); got != 1 {
		t.Fatalf("journald restarts = %d, want 1: %v", got, sr.CallsMatching("systemctl"))
	}
}

func TestJournaldPersistenceSkipsContainer(t *testing.T) {
	c, r, sr := journaldEnv(t, map[string]string{
		"journalctl -n 5": "ok line",
	}, map[string]bool{})
	c.groupBase()
	if hostExists(r, "/etc/systemd/journald.conf.d/50-node-config-agent.conf") {
		t.Fatal("standalone drop-in written on a DaemonSet host")
	}
	if len(sr.CallsMatching("systemctl restart systemd-journald.service")) > 0 {
		t.Fatal("journald restarted on a DaemonSet host by the persistence converge")
	}
}

func TestJournaldPersistenceIdempotent(t *testing.T) {
	c, _, sr := standaloneJournaldEnv(t, map[string]string{
		"journalctl -n 5": "ok line",
	}, map[string]bool{})
	c.groupBase()
	c.groupBase()
	// Second converge: drop-in unchanged, dir exists → no more
	// restarts (journald restart is a bounded side-effect, not a
	// per-cycle action).
	if got := len(sr.CallsMatching("systemctl restart systemd-journald.service")); got != 1 {
		t.Fatalf("journald restarts across 2 cycles = %d, want 1", got)
	}
}

func TestJournaldPersistenceRestartNotDoubled(t *testing.T) {
	// Standalone + silent probe: the persistence converge's own
	// restart must satisfy the integrity probe — one bounce per
	// cycle, never two (journaldRestarted dedupe).
	c, r, sr := standaloneJournaldEnv(t, map[string]string{
		"journalctl -n 5": "No journal files were found.\n",
	}, map[string]bool{})
	if err := os.MkdirAll(filepath.Join(r.cfg.HostRoot, "/var/log/journal"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.groupBase()
	if got := len(sr.CallsMatching("systemctl restart systemd-journald.service")); got != 1 {
		t.Fatalf("journald restarts = %d, want 1 (converge restart covers the probe)", got)
	}
}
