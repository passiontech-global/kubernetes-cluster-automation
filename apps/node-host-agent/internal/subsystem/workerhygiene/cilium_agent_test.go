// cilium_agent_test.go — check 32 cilium-agent healthz kill.
package workerhygiene

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestCiliumDownKillsAgent(t *testing.T) {
	e := fixture(t)
	e.mkCiliumTask(t, 9300)
	e.probes[defaultCiliumHealthzURL] = errors.New("refused")
	latch := filepath.Join(e.state, "state-cilium-agent-down")

	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("latch missing on first healthz fail: %v", err)
	}
	if len(e.kills) != 0 {
		t.Fatal("agent killed before ConsecNeeded")
	}
	e.h.Cycle(context.Background())
	if len(e.kills) != 1 || e.kills[0].pid != 9300 || e.kills[0].sig != syscall.SIGKILL {
		t.Fatalf("agent not SIGKILLed, kills=%v", e.kills)
	}
	if _, err := os.Stat(filepath.Join(e.state, "last-cilium-restart")); err != nil {
		t.Fatal("cilium restart budget not spent")
	}
	if !strings.Contains(logLines(t, e), "killed cilium-agent container") {
		t.Fatalf("missing kill log:\n%s", logLines(t, e))
	}
}

func TestCiliumNoContainerClearsLatch(t *testing.T) {
	e := fixture(t)
	writeFile(t, filepath.Join(e.state, "state-cilium-agent-down"), "1\n")
	// No cilium-agent task dirs → node runs no cilium → stale latch
	// from a false positive must clear.
	e.h.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.state, "state-cilium-agent-down")); !os.IsNotExist(err) {
		t.Fatal("latch kept on a node without cilium")
	}
}
