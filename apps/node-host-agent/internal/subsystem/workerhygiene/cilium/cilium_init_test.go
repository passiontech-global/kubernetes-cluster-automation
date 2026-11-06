// cilium_init_test.go — check 35 reserved:init endpoint-stuck kill.
package cilium_test

import (
	"context"
	"errors"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/cilium"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
	"os"
	"path/filepath"
	"testing"
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
