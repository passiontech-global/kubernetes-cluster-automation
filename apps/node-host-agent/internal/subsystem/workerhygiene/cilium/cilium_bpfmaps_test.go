// cilium_bpfmaps_test.go — the mesh-net-guards BPF map-pressure probe
// riding inside CiliumCheck: ParseCiliumBPFMaps wire-shape table,
// the pressure latch/clear over the agent socket, and the healthz
// check's gate tails (API down, node overloaded, dead task).
package cilium_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/cilium"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// TestParseCiliumBPFMapsShapes pins the /v1/map wire-shape tolerance:
// name OR path-carried names, used as number OR cache/entries array
// length, capacity under several keys, nested collections, and the
// skip rules (non-critical maps, no readable pair, max<=0, garbage).
func TestParseCiliumBPFMapsShapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want map[string][2]int64
	}{
		{
			name: "name+used+max",
			body: `[{"name":"cilium_ct4_global","used":900,"max":1000}]`,
			want: map[string][2]int64{"cilium_ct4_global": {900, 1000}},
		},
		{
			name: "path basename + entries array",
			body: `[{"path":"/sys/fs/bpf/tc/globals/cilium_snat_v4_external",` +
				`"entries":[{"a":1},{"b":2},{"c":3}],"size":1000}]`,
			want: map[string][2]int64{"cilium_snat_v4_external": {3, 1000}},
		},
		{
			name: "cache array length is the used count",
			body: `[{"name":"cilium_lxc","cache":[{},{},{},{}],"maxSize":500}]`,
			want: map[string][2]int64{"cilium_lxc": {4, 500}},
		},
		{
			name: "count key + capacity key",
			body: `[{"name":"cilium_lb4_services_v2","count":80,"capacity":100}]`,
			want: map[string][2]int64{"cilium_lb4_services_v2": {80, 100}},
		},
		{
			name: "nested under maps + max-size dash key",
			body: `{"maps":[{"name":"cilium_ct_any4_global","used":950,` +
				`"max-size":1000}]}`,
			want: map[string][2]int64{"cilium_ct_any4_global": {950, 1000}},
		},
		{
			name: "non-critical map skipped",
			body: `[{"name":"cilium_ipv4_frag_datagrams","used":9999,"max":10}]`,
			want: map[string][2]int64{},
		},
		{
			name: "critical map without a usable pair skipped",
			body: `[{"name":"cilium_ct4_global","used":900},{"name":"cilium_lxc","max":10}]`,
			want: map[string][2]int64{},
		},
		{
			name: "zero capacity skipped",
			body: `[{"name":"cilium_ct4_global","used":1,"max":0}]`,
			want: map[string][2]int64{},
		},
		{
			name: "garbage body → nil",
			body: `not json`,
			want: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := cilium.ParseCiliumBPFMaps([]byte(tc.body))
			if len(got) != len(tc.want) {
				t.Fatalf("ParseCiliumBPFMaps=%v want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Fatalf("map %s = %v want %v", k, got[k], v)
				}
			}
		})
	}
}

// TestCiliumCheckBPFMapsLatchAndClear: on a green healthz the map
// probe rides the same socket — a critical map at/over the high
// ratio latches state-cilium-bpf-map-pressure, an under-ratio map
// clears it, and an unreadable socket is inconclusive (latch kept).
func TestCiliumCheckBPFMapsLatchAndClear(t *testing.T) {
	e := fixture(t)
	e.MkCiliumTask(t, 9310)
	c := wdepstest.Check[*cilium.CiliumCheck](e.H, wdeps.CheckCilium)
	cycle := &wdeps.CycleEnv{WorkerActive: true}
	latch := filepath.Join(e.StateDir, "state-cilium-bpf-map-pressure")
	over := []byte(`[{"name":"cilium_ct4_global","used":9500,"max":10000}]`)
	under := []byte(`[{"name":"cilium_ct4_global","used":10,"max":10000}]`)

	e.UnixBody = over
	c.Run(context.Background(), cycle)
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("pressure latch missing after an over-ratio map: %v", err)
	}

	// Socket unreadable → inconclusive: neither entered nor cleared.
	e.H.Cfg.Seams.Cilium.UnixGet = func(context.Context, string, string) ([]byte, error) {
		return nil, errors.New("socket gone")
	}
	e.UnixBody = under
	c.Run(context.Background(), cycle)
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("inconclusive probe must leave the latch untouched")
	}
	if !strings.Contains(e.LogLines(t), "map query on") {
		t.Fatalf("missing inconclusive suspect line:\n%s", e.LogLines(t))
	}

	// A readable under-ratio map clears the latch — restore the
	// fixture's path-aware socket stub (Bind re-reads UnixBody/
	// UnixErr live, so the under-ratio body still serves).
	e.Bind(e.H.Deps)
	c.Run(context.Background(), cycle)
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("pressure latch not cleared by an under-ratio map")
	}
}

// TestCiliumGatedWhenWorkerDown: the k0sworker head gate stands the
// whole check down — no task walk, no probe.
func TestCiliumGatedWhenWorkerDown(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Seams.Probe.ProbeHTTP = func(context.Context, string, time.Duration) error {
		t.Error("healthz probe ran with the worker gate down")
		return nil
	}
	wdepstest.Check[*cilium.CiliumCheck](e.H, wdeps.CheckCilium).
		Run(context.Background(), &wdeps.CycleEnv{WorkerActive: false})
}

// TestCiliumTaskRootUnreachableAborts: an unreadable ctr root makes
// the agent-container verdict inconclusive — abort, keep everything.
func TestCiliumTaskRootUnreachableAborts(t *testing.T) {
	e := fixture(t)
	e.MkCiliumTask(t, 9311)
	e.H.Cfg.CtrTaskRoot = filepath.Join(e.CtrDir, "gone")
	e.Probes[wdeps.DefaultCiliumHealthzURL] = errors.New("refused")
	wdepstest.Check[*cilium.CiliumCheck](e.H, wdeps.CheckCilium).
		Run(context.Background(), &wdeps.CycleEnv{WorkerActive: true})
	if len(e.Kills) != 0 {
		t.Fatalf("kills=%v on an inconclusive round", e.Kills)
	}
	if !strings.Contains(e.LogLines(t), "cilium checks inconclusive") {
		t.Fatalf("missing inconclusive line:\n%s", e.LogLines(t))
	}
}

// TestCiliumAPIUnreachableSkipsKill: healthz down but the API is dead
// — the restarted agent could not resync, so the kill is deferred.
func TestCiliumAPIUnreachableSkipsKill(t *testing.T) {
	e := fixture(t)
	e.MkCiliumTask(t, 9312)
	e.Probes[wdeps.DefaultCiliumHealthzURL] = errors.New("refused")
	c := wdepstest.Check[*cilium.CiliumCheck](e.H, wdeps.CheckCilium)
	cycle := &wdeps.CycleEnv{WorkerActive: true}
	c.Run(context.Background(), cycle)
	c.Run(context.Background(), cycle)
	if len(e.Kills) != 0 {
		t.Fatalf("kills=%v with the API unreachable", e.Kills)
	}
	if !strings.Contains(e.LogLines(t), "API unreachable — skip kill") {
		t.Fatalf("missing API-gate line:\n%s", e.LogLines(t))
	}
}

// TestCiliumNodeOverloadedSkipsKill: the node-overloaded latch gates
// the restart — the latch still arms for NPD, the agent stays up.
func TestCiliumNodeOverloadedSkipsKill(t *testing.T) {
	e := fixture(t)
	e.MkCiliumTask(t, 9313)
	e.Probes[wdeps.DefaultCiliumHealthzURL] = errors.New("refused")
	e.H.State.Enter(latchdefs.LatchNodeOverloaded, "")
	c := wdepstest.Check[*cilium.CiliumCheck](e.H, wdeps.CheckCilium)
	cycle := &wdeps.CycleEnv{APIOK: true, WorkerActive: true}
	c.Run(context.Background(), cycle)
	c.Run(context.Background(), cycle)
	if len(e.Kills) != 0 {
		t.Fatalf("kills=%v under node-overloaded", e.Kills)
	}
	if !strings.Contains(e.LogLines(t), "check 2/2") {
		t.Fatalf("streak not visible in the log:\n%s", e.LogLines(t))
	}
}

// TestCiliumDeadTaskLogsNoKill: a task dir whose init is gone gives
// the kill nothing to signal — the suspect line replaces the ACTION.
func TestCiliumDeadTaskLogsNoKill(t *testing.T) {
	e := fixture(t)
	e.MkTask(t, wdepstest.UIDC, "cilium-agent", 9314) // pid never registered live
	e.Probes[wdeps.DefaultCiliumHealthzURL] = errors.New("refused")
	c := wdepstest.Check[*cilium.CiliumCheck](e.H, wdeps.CheckCilium)
	cycle := &wdeps.CycleEnv{APIOK: true, WorkerActive: true}
	c.Run(context.Background(), cycle)
	c.Run(context.Background(), cycle)
	if len(e.Kills) != 0 {
		t.Fatalf("kills=%v against a dead task", e.Kills)
	}
	if !strings.Contains(e.LogLines(t), "no running task to kill") {
		t.Fatalf("missing no-kill line:\n%s", e.LogLines(t))
	}
}

// TestCiliumAgentKillFailureLogged: a failing signal delivery must
// not read as a successful restart — the suspect line arms instead.
func TestCiliumAgentKillFailureLogged(t *testing.T) {
	e := fixture(t)
	e.MkCiliumTask(t, 9315)
	e.Probes[wdeps.DefaultCiliumHealthzURL] = errors.New("refused")
	e.H.Cfg.Seams.Host.KillFn = func(pid int, sig syscall.Signal) error {
		if sig == syscall.SIGKILL {
			return errors.New("permission denied")
		}
		return nil
	}
	c := wdepstest.Check[*cilium.CiliumCheck](e.H, wdeps.CheckCilium)
	cycle := &wdeps.CycleEnv{APIOK: true, WorkerActive: true}
	c.Run(context.Background(), cycle)
	c.Run(context.Background(), cycle)
	log := e.LogLines(t)
	if !strings.Contains(log, "kill cilium-agent pid=9315 failed: permission denied") ||
		!strings.Contains(log, "no running task to kill") {
		t.Fatalf("missing kill-failure evidence:\n%s", log)
	}
}
