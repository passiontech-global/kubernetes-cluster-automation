// cilium_init_test.go — check 35 reserved:init endpoint-stuck kill.
package cilium_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/cilium"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

func TestCiliumInitStuckKills(t *testing.T) {
	e := fixture(t)
	e.MkCiliumTask(t, 9400)
	e.UnixBody = []byte(`[{"id":1,"status":{"identity":{"labels":["reserved:init"]}}}]`)
	latch := filepath.Join(e.StateDir, "state-cilium-init-stuck")

	e.H.Cycle(context.Background())
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("init-stuck latch on first cycle")
	}
	e.H.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("init-stuck latch missing: %v", err)
	}
	if len(e.Kills) != 1 || e.Kills[0].PID != 9400 {
		t.Fatalf("cilium-agent not killed for init-stuck, kills=%v", e.Kills)
	}
}

func TestCiliumInitStuckTransientNoKill(t *testing.T) {
	e := fixture(t)
	e.MkCiliumTask(t, 9401)
	e.UnixBody = []byte(`reserved:init`)
	e.H.Cycle(context.Background())
	// Endpoint resolves before the second cycle — transient, reset.
	e.UnixBody = []byte(`[]`)
	e.H.Cycle(context.Background())
	if len(e.Kills) != 0 {
		t.Fatal("transient init endpoint killed the agent")
	}
	if wdepstest.Check[*cilium.CiliumInitCheck](e.H, wdeps.CheckCiliumInit).Fails != 0 {
		t.Fatalf("counter=%d want 0 after recovery", wdepstest.Check[*cilium.CiliumInitCheck](e.H, wdeps.CheckCiliumInit).Fails)
	}
}

func TestCiliumInitStuckInconclusiveKeepsCounter(t *testing.T) {
	e := fixture(t)
	e.MkCiliumTask(t, 9402)
	e.UnixBody = []byte(`reserved:init`)
	e.H.Cycle(context.Background())
	if wdepstest.Check[*cilium.CiliumInitCheck](e.H, wdeps.CheckCiliumInit).Fails != 1 {
		t.Fatalf("counter=%d want 1", wdepstest.Check[*cilium.CiliumInitCheck](e.H, wdeps.CheckCiliumInit).Fails)
	}
	// Endpoint list fails → inconclusive: counter kept, not reset.
	e.UnixErr = errors.New("socket dead")
	e.H.Cycle(context.Background())
	if wdepstest.Check[*cilium.CiliumInitCheck](e.H, wdeps.CheckCiliumInit).Fails != 1 {
		t.Fatalf("counter=%d want 1 (inconclusive keeps)", wdepstest.Check[*cilium.CiliumInitCheck](e.H, wdeps.CheckCiliumInit).Fails)
	}
}

// --- Run gates and remedy tails (bare CycleEnv rounds) ---

func initCycle(apiok bool) *wdeps.CycleEnv {
	return &wdeps.CycleEnv{APIOK: apiok, WorkerActive: true}
}

// TestCiliumInitGatedAndUnreachable: the k0sworker gate stands the
// check down; an unreadable task root aborts with the streak kept.
func TestCiliumInitGatedAndUnreachable(t *testing.T) {
	// Worker gate down → no socket read at all.
	e := fixture(t)
	e.H.Cfg.Seams.Cilium.UnixGet = func(context.Context, string, string) ([]byte, error) {
		t.Error("endpoint query ran with the worker gate down")
		return nil, nil
	}
	wdepstest.Check[*cilium.CiliumInitCheck](e.H, wdeps.CheckCiliumInit).
		Run(context.Background(), &wdeps.CycleEnv{})

	// ctr unreachable → inconclusive abort, evidence kept.
	e = fixture(t)
	e.MkCiliumTask(t, 9420)
	e.H.Cfg.CtrTaskRoot = filepath.Join(e.CtrDir, "gone")
	e.UnixBody = []byte(`reserved:init`)
	c := wdepstest.Check[*cilium.CiliumInitCheck](e.H, wdeps.CheckCiliumInit)
	c.Fails = 1
	c.Run(context.Background(), initCycle(true))
	if c.Fails != 1 {
		t.Fatalf("Fails=%d want 1 after the unreachable-root abort", c.Fails)
	}
}

// TestCiliumInitNoTasksResets: no cilium-agent container → nothing to
// wedge, the streak clears.
func TestCiliumInitNoTasksResets(t *testing.T) {
	e := fixture(t)
	e.UnixBody = []byte(`reserved:init`)
	c := wdepstest.Check[*cilium.CiliumInitCheck](e.H, wdeps.CheckCiliumInit)
	c.Fails = 5
	c.Run(context.Background(), initCycle(true))
	if c.Fails != 5 {
		t.Fatalf("Fails=%d want 5 — the no-agent branch stands down without clearing evidence", c.Fails)
	}
}

// TestCiliumInitRemedyGates: the SIGKILL tail is gated by the API,
// the node-overloaded latch and the shared restart budget — each
// skip is logged with its own reason, the latch still arms for NPD.
func TestCiliumInitRemedyGates(t *testing.T) {
	// API unreachable — the restarted agent could not resync.
	e := fixture(t)
	e.MkCiliumTask(t, 9421)
	e.UnixBody = []byte(`reserved:init`)
	c := wdepstest.Check[*cilium.CiliumInitCheck](e.H, wdeps.CheckCiliumInit)
	c.Run(context.Background(), initCycle(false))
	c.Run(context.Background(), initCycle(false))
	if len(e.Kills) != 0 || c.Fails != 2 {
		t.Fatalf("kills=%v fails=%d want 0 kills and the streak kept", e.Kills, c.Fails)
	}
	if !strings.Contains(e.LogLines(t), "API unreachable — skip kill") {
		t.Fatalf("missing API-gate line:\n%s", e.LogLines(t))
	}

	// Node overloaded — the restart gate holds.
	e = fixture(t)
	e.MkCiliumTask(t, 9422)
	e.UnixBody = []byte(`reserved:init`)
	e.H.State.Enter(latchdefs.LatchNodeOverloaded, "")
	c = wdepstest.Check[*cilium.CiliumInitCheck](e.H, wdeps.CheckCiliumInit)
	c.Run(context.Background(), initCycle(true))
	c.Run(context.Background(), initCycle(true))
	if len(e.Kills) != 0 {
		t.Fatalf("kills=%v under node-overloaded", e.Kills)
	}
	if !strings.Contains(e.LogLines(t), "node overloaded — skip kill") {
		t.Fatalf("missing overload line:\n%s", e.LogLines(t))
	}

	// Restart cooldown — the shared budget bounds the kill.
	e = fixture(t)
	e.MkCiliumTask(t, 9423)
	e.UnixBody = []byte(`reserved:init`)
	e.H.State.RateSpend("last-cilium-restart")
	c = wdepstest.Check[*cilium.CiliumInitCheck](e.H, wdeps.CheckCiliumInit)
	c.Run(context.Background(), initCycle(true))
	c.Run(context.Background(), initCycle(true))
	if len(e.Kills) != 0 {
		t.Fatalf("kills=%v inside the restart cooldown", e.Kills)
	}
	if !strings.Contains(e.LogLines(t), "restart cooldown — skip kill") {
		t.Fatalf("missing cooldown line:\n%s", e.LogLines(t))
	}
	if !e.H.State.Exists(latchdefs.LatchCiliumInitStuck) {
		t.Fatal("init-stuck latch must arm even when every kill gate skips")
	}
}

// TestCiliumInitDeadTaskNoKill: a task dir whose init is gone gives
// the remedy nothing to signal — the suspect line replaces the kill.
func TestCiliumInitDeadTaskNoKill(t *testing.T) {
	e := fixture(t)
	e.MkTask(t, wdepstest.UIDC, "cilium-agent", 9424) // pid never live
	e.UnixBody = []byte(`reserved:init`)
	c := wdepstest.Check[*cilium.CiliumInitCheck](e.H, wdeps.CheckCiliumInit)
	c.Run(context.Background(), initCycle(true))
	c.Run(context.Background(), initCycle(true))
	if len(e.Kills) != 0 {
		t.Fatalf("kills=%v against a dead task", e.Kills)
	}
	if !strings.Contains(e.LogLines(t), "no running task to kill") {
		t.Fatalf("missing no-kill line:\n%s", e.LogLines(t))
	}
}
