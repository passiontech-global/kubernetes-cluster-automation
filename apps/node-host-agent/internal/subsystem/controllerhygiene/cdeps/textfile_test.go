// textfile_test.go — the node-exporter textfile channel helpers: the
// K0sDir-sibling dir resolution (override wins) and the atomic
// install with the suspectLog failure channel.
package cdeps

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
)

func newTextfileDeps(t *testing.T) *Deps {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "watchdog.log")
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return &Deps{
		Cfg: Config{
			K0sDir:            filepath.Join(dir, "host", "var", "lib", "k0s"),
			SuspectLogCadence: time.Hour,
		},
		State: hoststate.New(stateDir, log, nil, nil),
	}
}

func TestTextfilePromDir(t *testing.T) {
	d := newTextfileDeps(t)
	old := TextfileDirOverride
	t.Cleanup(func() { TextfileDirOverride = old })

	// The override wins — the test seam.
	TextfileDirOverride = "/tmp/textfile-override"
	if got := d.textfilePromDir(); got != "/tmp/textfile-override" {
		t.Fatalf("override ignored: dir=%q", got)
	}

	// K0sDir is <root>/var/lib/k0s → the sibling node-exporter dir.
	TextfileDirOverride = ""
	want := filepath.Join(filepath.Dir(d.Cfg.K0sDir),
		"node-exporter", "textfile")
	if got := d.textfilePromDir(); got != want {
		t.Fatalf("dir=%q want sibling %q", got, want)
	}
}

func TestWriteTextfileProm(t *testing.T) {
	d := newTextfileDeps(t)
	old := TextfileDirOverride
	t.Cleanup(func() { TextfileDirOverride = old })
	outDir := filepath.Join(t.TempDir(), "textfile")
	TextfileDirOverride = outDir

	d.WriteTextfileProm("node-agent-test.prom",
		"# HELP node_agent_test_probe Help text.\n")

	b, err := os.ReadFile(filepath.Join(outDir, "node-agent-test.prom"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "node_agent_test_probe") {
		t.Fatalf("installed content wrong:\n%s", b)
	}
}

func TestWriteTextfilePromFailureSuspects(t *testing.T) {
	d := newTextfileDeps(t)
	old := TextfileDirOverride
	t.Cleanup(func() { TextfileDirOverride = old })
	// The override names a path UNDER an existing file — MkdirAll
	// cannot succeed there, so the install fails and the failure
	// must land in the watchdog tail via suspectLog.
	blocked := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(blocked, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	TextfileDirOverride = filepath.Join(blocked, "textfile")

	d.WriteTextfileProm("node-agent-test.prom", "x\n") // must not panic

	log := readFile(t, d.State.LogFile)
	if !strings.Contains(log, "textfile prom") ||
		!strings.Contains(log, "unwritable") {
		t.Fatalf("install failure not suspect-logged:\n%s", log)
	}
}
