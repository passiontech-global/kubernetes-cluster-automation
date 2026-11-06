// cilium_init_test.go — check 35 reserved:init endpoint-stuck kill.
package workerhygiene

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCiliumInitStuckKills(t *testing.T) {
	e := fixture(t)
	e.mkCiliumTask(t, 9400)
	e.unixBody = []byte(`[{"id":1,"status":{"identity":{"labels":["reserved:init"]}}}]`)
	latch := filepath.Join(e.state, "state-cilium-init-stuck")

	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("init-stuck latch on first cycle")
	}
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("init-stuck latch missing: %v", err)
	}
	if len(e.kills) != 1 || e.kills[0].pid != 9400 {
		t.Fatalf("cilium-agent not killed for init-stuck, kills=%v", e.kills)
	}
}

func TestCiliumInitStuckTransientNoKill(t *testing.T) {
	e := fixture(t)
	e.mkCiliumTask(t, 9401)
	e.unixBody = []byte(`reserved:init`)
	e.h.Cycle(context.Background())
	// Endpoint resolves before the second cycle — transient, reset.
	e.unixBody = []byte(`[]`)
	e.h.Cycle(context.Background())
	if len(e.kills) != 0 {
		t.Fatal("transient init endpoint killed the agent")
	}
	if e.h.CiliumInitFails != 0 {
		t.Fatalf("counter=%d want 0 after recovery", e.h.CiliumInitFails)
	}
}

func TestCiliumInitStuckInconclusiveKeepsCounter(t *testing.T) {
	e := fixture(t)
	e.mkCiliumTask(t, 9402)
	e.unixBody = []byte(`reserved:init`)
	e.h.Cycle(context.Background())
	if e.h.CiliumInitFails != 1 {
		t.Fatalf("counter=%d want 1", e.h.CiliumInitFails)
	}
	// Endpoint list fails → inconclusive: counter kept, not reset.
	e.unixErr = errors.New("socket dead")
	e.h.Cycle(context.Background())
	if e.h.CiliumInitFails != 1 {
		t.Fatalf("counter=%d want 1 (inconclusive keeps)", e.h.CiliumInitFails)
	}
}
