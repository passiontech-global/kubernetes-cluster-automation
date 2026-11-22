// cilium_bpfmaps_test.go — the mesh-net-guards BPF map-pressure probe
// riding inside CiliumCheck: ParseCiliumBPFMaps wire-shape table,
// the pressure latch/clear over the agent socket, and the healthz
// check's gate tails (API down, node overloaded, dead task).
package cilium_test

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

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
			name: "cache before name + precedence",
			body: `[{"cache":[{},{"x":[1,2]}],"count":10,"used":900.0,"maxSize":1200,"name":"cilium_ct4_global"}]`,
			want: map[string][2]int64{"cilium_ct4_global": {900, 1200}},
		},
		{
			name: "numeric entries precedence over cache array",
			body: `[{"name":"cilium_lxc","entries":42,"cache":[{},{}],"capacity":100}]`,
			want: map[string][2]int64{"cilium_lxc": {42, 100}},
		},
		{
			name: "nested dynamicMaps and staticMaps",
			body: `{"dynamicMaps":[{"name":"cilium_ct4_global","used":5,"max":10}],"staticMaps":{"inner":[{"name":"cilium_lxc","used":7,"size":14}]}}`,
			want: map[string][2]int64{"cilium_ct4_global": {5, 10}, "cilium_lxc": {7, 14}},
		},
		{
			name: "empty array returns non-nil empty map",
			body: `[]`,
			want: map[string][2]int64{},
		},
		{
			name: "empty object returns non-nil empty map",
			body: `{}`,
			want: map[string][2]int64{},
		},
		{
			name: "empty body → nil",
			body: ``,
			want: nil,
		},
		{
			name: "trailing garbage → nil",
			body: `[] trailing`,
			want: nil,
		},
		{
			name: "garbage body → nil",
			body: `not json`,
			want: nil,
		},
		{
			name: "huge float 1e20 saturates to MaxInt64",
			body: `[{"name":"cilium_ct4_global","used":1e20,"max":1000}]`,
			want: map[string][2]int64{"cilium_ct4_global": {math.MaxInt64, 1000}},
		},
		{
			name: "exact 2^63 float boundary saturates to MaxInt64",
			body: `[{"name":"cilium_ct4_global","used":9223372036854775808.0,"max":1000}]`,
			want: map[string][2]int64{"cilium_ct4_global": {math.MaxInt64, 1000}},
		},
		{
			name: "huge negative float -1e20 saturates to MinInt64",
			body: `[{"name":"cilium_ct4_global","used":-1e20,"max":1000}]`,
			want: map[string][2]int64{"cilium_ct4_global": {math.MinInt64, 1000}},
		},
		{
			name: "float64 overflow max=1e309 → nil",
			body: `[{"name":"cilium_ct4_global","used":10,"max":1e309}]`,
			want: nil,
		},
		{
			name: "float64 overflow used=1e309 → nil",
			body: `[{"name":"cilium_ct4_global","used":1e309,"max":1000}]`,
			want: nil,
		},
		{
			name: "float64 overflow in array → nil",
			body: `[1e309]`,
			want: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := cilium.ParseCiliumBPFMaps([]byte(tc.body))
			if (got == nil) != (tc.want == nil) {
				t.Fatalf("ParseCiliumBPFMaps nil=%v, want nil=%v (got=%v)", got == nil, tc.want == nil, got)
			}
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

// TestCiliumCheckBPFMapsCorruptJSONAbortsPreservingLatch verifies that
// unparseable/truncated /v1/map JSON aborts without clearing
// LatchCiliumBPFMapPressure, while valid empty payloads ("[]"/"{}")
// still exit the latch cleanly.
func TestCiliumCheckBPFMapsCorruptJSONAbortsPreservingLatch(t *testing.T) {
	e := fixture(t)
	e.MkCiliumTask(t, 9316)
	c := wdepstest.Check[*cilium.CiliumCheck](e.H, wdeps.CheckCilium)
	cycle := &wdeps.CycleEnv{WorkerActive: true}
	ctx := context.Background()

	over := []byte(`[{"name":"cilium_ct4_global","used":9500,"max":10000}]`)
	e.UnixBody = over
	c.Run(ctx, cycle)
	if !e.H.State.Exists(latchdefs.LatchCiliumBPFMapPressure) {
		t.Fatal("setup: LatchCiliumBPFMapPressure not armed")
	}
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCiliumBPF, "ok")); got != 1 {
		t.Fatalf("setup ok cycles=%v want 1", got)
	}

	// Truncated/corrupt JSON -> abort, keep latch, no STATE-EXIT.
	e.UnixBody = []byte(`[{"name":"cilium_ct4_global",`)
	c.Run(ctx, cycle)
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCiliumBPF, "abort")); got != 1 {
		t.Fatalf("abort cycles=%v want 1 on corrupt /v1/map JSON", got)
	}
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCiliumBPF, "ok")); got != 1 {
		t.Fatalf("ok cycles=%v want 1 (corrupt JSON must not emit ok)", got)
	}
	if !e.H.State.Exists(latchdefs.LatchCiliumBPFMapPressure) {
		t.Fatal("LatchCiliumBPFMapPressure falsely exited on corrupt /v1/map JSON")
	}
	if strings.Contains(e.LogLines(t), "STATE-EXIT: cilium-bpf-map-pressure") {
		t.Fatalf("unexpected STATE-EXIT on corrupt JSON:\n%s", e.LogLines(t))
	}
	if !strings.Contains(e.LogLines(t), "unparseable JSON") {
		t.Fatalf("missing inconclusive log line:\n%s", e.LogLines(t))
	}

	// Valid empty array "[]" -> exits latch cleanly.
	e.UnixBody = []byte(`[]`)
	c.Run(ctx, cycle)
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCiliumBPF, "ok")); got != 2 {
		t.Fatalf("ok cycles=%v want 2 on []", got)
	}
	if e.H.State.Exists(latchdefs.LatchCiliumBPFMapPressure) {
		t.Fatal("valid [] /v1/map payload should exit LatchCiliumBPFMapPressure")
	}

	// Re-arm and verify valid empty object "{}" also exits latch cleanly.
	e.UnixBody = over
	c.Run(ctx, cycle)
	if !e.H.State.Exists(latchdefs.LatchCiliumBPFMapPressure) {
		t.Fatal("re-arm failed")
	}
	e.UnixBody = []byte(`{}`)
	c.Run(ctx, cycle)
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCiliumBPF, "ok")); got != 4 {
		t.Fatalf("ok cycles=%v want 4 on {}", got)
	}
	if e.H.State.Exists(latchdefs.LatchCiliumBPFMapPressure) {
		t.Fatal("valid {} /v1/map payload should exit LatchCiliumBPFMapPressure")
	}
}

// TestCiliumCheckBPFMapsHugeFloatPreservesLatch verifies that huge
// JSON float counts (>= 2^63, e.g. 1e20) saturate positively rather
// than wrapping to MinInt64 and falsely clearing LatchCiliumBPFMapPressure,
// and that float64-overflowing numbers (1e309) abort without clearing.
func TestCiliumCheckBPFMapsHugeFloatPreservesLatch(t *testing.T) {
	e := fixture(t)
	e.MkCiliumTask(t, 9317)
	c := wdepstest.Check[*cilium.CiliumCheck](e.H, wdeps.CheckCilium)
	cycle := &wdeps.CycleEnv{WorkerActive: true}
	ctx := context.Background()

	e.UnixBody = []byte(`[{"name":"cilium_ct4_global","used":9500,"max":10000}]`)
	c.Run(ctx, cycle)
	if !e.H.State.Exists(latchdefs.LatchCiliumBPFMapPressure) {
		t.Fatal("setup: LatchCiliumBPFMapPressure not armed")
	}

	e.UnixBody = []byte(`[{"name":"cilium_ct4_global","used":1e20,"max":1000}]`)
	c.Run(ctx, cycle)
	if !e.H.State.Exists(latchdefs.LatchCiliumBPFMapPressure) {
		t.Fatal("used=1e20, max=1000 falsely cleared LatchCiliumBPFMapPressure")
	}
	if strings.Contains(e.LogLines(t), "STATE-EXIT: cilium-bpf-map-pressure") {
		t.Fatalf("unexpected STATE-EXIT on used=1e20:\n%s", e.LogLines(t))
	}

	e.UnixBody = []byte(`[{"name":"cilium_ct4_global","used":10,"max":1e309}]`)
	c.Run(ctx, cycle)
	if !e.H.State.Exists(latchdefs.LatchCiliumBPFMapPressure) {
		t.Fatal("max=1e309 falsely cleared LatchCiliumBPFMapPressure")
	}
	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCiliumBPF, "abort")); got != 1 {
		t.Fatalf("abort cycles=%v want 1 on max=1e309", got)
	}
}

var sinkBPFMaps map[string][2]int64

func BenchmarkParseCiliumBPFMaps(b *testing.B) {
	var sb strings.Builder
	sb.WriteString(`[{"name":"cilium_ct4_global","max":65536,"cache":[`)
	for i := range 5000 {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `{"key":"k%d","value":"v%d"}`, i, i)
	}
	sb.WriteString(`]},{"name":"cilium_lxc","used":120,"max":1024}]`)
	body := []byte(sb.String())

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		sinkBPFMaps = cilium.ParseCiliumBPFMaps(body)
	}
}
