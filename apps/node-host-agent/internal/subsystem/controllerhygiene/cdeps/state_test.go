// state_test.go — the on-disk bookkeeping helpers Store does not
// cover: StateExit's suspect-budget drop, the raw-text ReadState
// (empty-vs-zero preservation) and WriteState.
package cdeps

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
)

func newStateDeps(t *testing.T) *Deps {
	t.Helper()
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return &Deps{
		Cfg: Config{WatchdogStateDir: stateDir},
		State: hoststate.New(stateDir,
			filepath.Join(dir, "watchdog.log"), nil, nil),
	}
}

func TestStateExit(t *testing.T) {
	d := newStateDeps(t)
	latch := d.State.Path("testx")
	if err := os.WriteFile(latch, []byte("1700000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	budget := filepath.Join(d.State.Dir, "last-suspect-testx")
	if err := os.WriteFile(budget, []byte("1700000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	d.StateExit("testx")

	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("state latch not removed")
	}
	if _, err := os.Stat(budget); !os.IsNotExist(err) {
		t.Fatal("last-suspect dedupe budget not dropped with the latch")
	}
	if !strings.Contains(readFile(t, d.State.LogFile), "STATE-EXIT") {
		t.Fatal("STATE-EXIT transition not logged")
	}

	// An absent latch is a no-op, never an error.
	d.StateExit("testx")
}

func TestReadState(t *testing.T) {
	d := newStateDeps(t)

	// Absent collapses to "" — distinct from a real "0" value.
	if got := d.ReadState("last-rvc"); got != "" {
		t.Fatalf("absent ReadState=%q want empty", got)
	}

	if err := os.WriteFile(filepath.Join(d.State.Dir, "last-rvc"),
		[]byte("  12345 \n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := d.ReadState("last-rvc"); got != "12345" {
		t.Fatalf("ReadState=%q want trimmed 12345", got)
	}

	// The empty-vs-zero distinction the frozen-rv check needs.
	if err := os.WriteFile(filepath.Join(d.State.Dir, "last-prvc"),
		[]byte("\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := d.ReadState("last-prvc"); got != "" {
		t.Fatalf("empty-line file ReadState=%q want empty", got)
	}
}

func TestWriteState(t *testing.T) {
	d := newStateDeps(t)

	d.WriteState("oomloop-shielded", "")
	b, err := os.ReadFile(filepath.Join(d.State.Dir, "oomloop-shielded"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "\n" {
		t.Fatalf("WriteState wrote %q want a bare newline", b)
	}

	d.WriteState("named", "payload")
	b, err = os.ReadFile(filepath.Join(d.State.Dir, "named"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "payload\n" {
		t.Fatalf("WriteState wrote %q want payload\\n", b)
	}

	// A write failure degrades to a warn — the state dir naming an
	// existing FILE makes every mkdir/write fail.
	blocked := filepath.Join(filepath.Dir(d.State.Dir), "blocked")
	if err := os.WriteFile(blocked, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	d2 := newStateDeps(t)
	d2.State.Dir = blocked
	d2.WriteState("oomloop-shielded", "x") // must not panic
}
