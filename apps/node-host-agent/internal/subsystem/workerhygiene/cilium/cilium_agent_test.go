// cilium_agent_test.go — check 32 cilium-agent healthz kill.
package cilium_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestCiliumDownKillsAgent(t *testing.T) {
	e := fixture(t)
	e.MkCiliumTask(t, 9300)
	e.Probes[wdeps.DefaultCiliumHealthzURL] = errors.New("refused")
	latch := filepath.Join(e.StateDir, "state-cilium-agent-down")

	e.H.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("latch missing on first healthz fail: %v", err)
	}
	if len(e.Kills) != 0 {
		t.Fatal("agent killed before ConsecNeeded")
	}
	e.H.Cycle(context.Background())
	if len(e.Kills) != 1 || e.Kills[0].PID != 9300 || e.Kills[0].Sig != syscall.SIGKILL {
		t.Fatalf("agent not SIGKILLed, kills=%v", e.Kills)
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "last-cilium-restart")); err != nil {
		t.Fatal("cilium restart budget not spent")
	}
	if !strings.Contains(e.LogLines(t), "killed cilium-agent container") {
		t.Fatalf("missing kill log:\n%s", e.LogLines(t))
	}
}

func TestCiliumNoContainerClearsLatch(t *testing.T) {
	e := fixture(t)
	wdepstest.WriteFile(t, filepath.Join(e.StateDir, "state-cilium-agent-down"), "1\n")
	// No cilium-agent task dirs → node runs no cilium → stale latch
	// from a false positive must clear.
	e.H.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.StateDir, "state-cilium-agent-down")); !os.IsNotExist(err) {
		t.Fatal("latch kept on a node without cilium")
	}
}
