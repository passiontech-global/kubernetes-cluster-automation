// cilium_envoy_test.go — B1 cilium-envoy readiness kill +
// agent/envoy coupled restart.
package workerhygiene

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// --- B1: cilium-envoy ---

// mkCiliumContainer registers a cilium container task dir named
// like the container (cilium-agent / cilium-envoy) with a live pid.
func mkCiliumContainer(t *testing.T, e *env, name string, pid int) {
	t.Helper()
	d := filepath.Join(e.ctr, "id-"+name)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := `{"labels":{"io.kubernetes.container.name":"` + name + `"}}`
	if err := os.WriteFile(filepath.Join(d, "config.json"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "init.pid"), []byte(strconv.Itoa(pid)), 0o644); err != nil {
		t.Fatal(err)
	}
	e.live[pid] = true
}

func TestCiliumEnvoyUnreadyKillAfterConsec(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	mkCiliumContainer(t, e, "cilium-envoy", 555)
	e.status["http://127.0.0.1:9964/ready"] = 503
	for i := 0; i < 2; i++ {
		e.h.Cycle(context.Background())
	}
	if !e.h.State.Exists("cilium-envoy-down") {
		t.Fatal("state-cilium-envoy-down should latch after 2 unready cycles")
	}
	found := false
	for _, k := range e.kills {
		if k.pid == 555 && k.sig == syscall.SIGKILL {
			found = true
		}
	}
	if !found {
		t.Fatal("envoy pid should be SIGKILLed after ConsecNeeded unready cycles")
	}
}

func TestCiliumEnvoyKilledWithAgent(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	mkCiliumContainer(t, e, "cilium-agent", 444)
	mkCiliumContainer(t, e, "cilium-envoy", 555)
	e.probes["http://127.0.0.1:9879/healthz"] = errors.New("down")
	for i := 0; i < 2; i++ {
		e.h.Cycle(context.Background())
	}
	killed := map[int]bool{}
	for _, k := range e.kills {
		if k.sig == syscall.SIGKILL {
			killed[k.pid] = true
		}
	}
	if !killed[444] || !killed[555] {
		t.Fatalf("agent kill must restart envoy too; kills=%v", e.kills)
	}
}
