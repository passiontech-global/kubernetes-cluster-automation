// cycle_test.go — Cycle verdict behavior: wedge/gap/dead drains,
// the fresh-backend fence, drain re-apply, VIP companions, static
// merges, staged drain, and probe-side vs apiserver-side verdicts.
package apiprober

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func TestFrozenWedgeDisables(t *testing.T) {
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	// hub1: rv_cache frozen at 100 while rv_now advances — wedge.
	// Cycle 1 sets the baseline, cycles 2-3 accumulate frozen.
	bad.set(100, 200)
	good.set(500, 500)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}

	if !hasCmd(ha.commands(), "disable server kube_apiserver/hub1") {
		t.Fatalf("no disable command sent, cmds=%v", ha.commands())
	}
	if got := promtest.ToFloat64(p.enabled.WithLabelValues("hub1")); got != 0 {
		t.Fatalf("enabled{hub1}=%v want 0", got)
	}
	if got := promtest.ToFloat64(p.enabled.WithLabelValues("hub2")); got != 1 {
		t.Fatalf("enabled{hub2}=%v want 1", got)
	}
	if got := promtest.ToFloat64(p.actions.WithLabelValues("hub1", "disable")); got != 1 {
		t.Fatalf("actions disable=%v want 1", got)
	}
}

func TestGapWedgeDisables(t *testing.T) {
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	// gap = 5000 - 1000 = 4000 > GapMin(1000), cache still advancing.
	bad.set(1000, 5000)
	good.set(100, 100)
	p.Cycle(context.Background())
	bad.set(1100, 5200) // still >1000 gap
	good.set(110, 110)
	p.Cycle(context.Background()) // fail #2 → disable

	if !hasCmd(ha.commands(), "disable server kube_apiserver/hub1") {
		t.Fatalf("no disable for gap wedge, cmds=%v", ha.commands())
	}
}

func TestQueryFailDeadDisables(t *testing.T) {
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	bad.setFail(true)
	good.set(50, 50)
	p.Cycle(context.Background())
	p.Cycle(context.Background()) // qfail #2 → DEAD → disable

	if !hasCmd(ha.commands(), "disable server kube_apiserver/hub1") {
		t.Fatalf("no disable for dead backend, cmds=%v", ha.commands())
	}
	if got := promtest.ToFloat64(p.probeFailures.WithLabelValues("hub1", "query")); got < 2 {
		t.Fatalf("query probe failures=%v want >=2", got)
	}
}

func TestFenceKeepsLastUsableBackend(t *testing.T) {
	bad1 := newAPIStub(t)
	bad2 := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad1.addr()},
		[2]string{"hub2", bad2.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	// Phase 1: hub1 wedges while hub2 is fresh → hub1 drains.
	bad1.set(100, 200)
	bad2.set(50, 50)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if !hasCmd(ha.commands(), "disable server kube_apiserver/hub1") {
		t.Fatalf("hub1 not drained, cmds=%v", ha.commands())
	}

	// Phase 2: hub2 wedges too while hub1 is still wedged+drained —
	// no fresh backend remains → fence keeps hub2 serving.
	bad2.set(300, 400)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if hasCmd(ha.commands(), "disable server kube_apiserver/hub2") {
		t.Fatalf("last usable backend disabled: %v", ha.commands())
	}
	if got := promtest.ToFloat64(p.actions.WithLabelValues("hub2", "fence_skip")); got < 1 {
		t.Fatalf("fence_skip=%v want >=1", got)
	}
}

func TestSimultaneousWedgeDrainsNothing(t *testing.T) {
	// Both backends wedge in the same cycles → fresh=0 → neither is
	// drained (the shell fence semantics: disabling any backend when
	// nothing fresh remains only takes the VIP down with it).
	bad1 := newAPIStub(t)
	bad2 := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad1.addr()},
		[2]string{"hub2", bad2.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	bad1.set(100, 200)
	bad2.set(300, 400)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if hasCmd(ha.commands(), "disable server") {
		t.Fatalf("backend disabled with no fresh peer: %v", ha.commands())
	}
}

func TestTCPUnreachableSkipped(t *testing.T) {
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeEnforce, map[string]bool{bad.addr(): false})
	bad.set(100, 200) // would wedge — but TCP down wins
	good.set(50, 50)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}

	if hasCmd(ha.commands(), "disable server kube_apiserver/hub1") {
		t.Fatalf("unreachable backend got disabled: %v", ha.commands())
	}
	if got := promtest.ToFloat64(p.probeFailures.WithLabelValues("hub1", "tcp")); got != 3 {
		t.Fatalf("tcp probe failures=%v want 3", got)
	}
}

func TestRecoveryReEnables(t *testing.T) {
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	bad.set(100, 200)
	good.set(50, 50)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	} // → drained

	// Backend recovers: cache advancing again + gap small.
	for i := 0; i < 3; i++ { // RecoverCycles
		bad.set(300+int64(i), 300)
		p.Cycle(context.Background())
	}

	if !hasCmd(ha.commands(), "enable server kube_apiserver/hub1") {
		t.Fatalf("no enable after recovery, cmds=%v", ha.commands())
	}
	// The enabled gauge reflects the next cycle's `show stat` status
	// (the cycle that issues enable still sees MAINT).
	bad.set(400, 300)
	p.Cycle(context.Background())
	if got := promtest.ToFloat64(p.enabled.WithLabelValues("hub1")); got != 1 {
		t.Fatalf("enabled{hub1}=%v want 1 after recovery", got)
	}
}

func TestDryRunTakesNoAction(t *testing.T) {
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeDryRun, nil)

	bad.set(100, 200)
	good.set(50, 50)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}

	for _, c := range ha.commands() {
		if !strings.HasPrefix(c, "show stat") {
			t.Fatalf("dry-run issued socket action: %v", ha.commands())
		}
	}
	if got := promtest.ToFloat64(p.actions.WithLabelValues("hub1", "dryrun_disable")); got != 1 {
		t.Fatalf("dryrun_disable=%v want 1", got)
	}
}

func TestRVGapMetric(t *testing.T) {
	b := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", b.addr()},
		[2]string{"hub2", "127.0.0.1:1"},
	)
	p := fixture(t, ha, ModeDryRun, map[string]bool{"127.0.0.1:1": false})
	b.set(100, 900)
	p.Cycle(context.Background())
	if got := promtest.ToFloat64(p.rvGap.WithLabelValues("hub1")); got != 800 {
		t.Fatalf("rvGap=%v want 800", got)
	}
}

func TestVIPBackendFollowsDirectControllerState(t *testing.T) {
	ctrl1 := newAPIStub(t)
	ctrl2 := newAPIStub(t)
	// api_datahub_lb is a VIP entry (suffix "_lb") — its address is not a
	// valid HTTP server, verifying it is never directly probed for RV gap.
	ha := newFakeHAProxy(t,
		[2]string{"api_datahub_ctrl", ctrl1.addr()},
		[2]string{"api_datahub_lb", "127.0.0.1:1"},
		[2]string{"api_contabo_ctrl", ctrl2.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	// Phase 1: ctrl2 wedges while ctrl1 stays fresh → both ctrl2 and
	// api_datahub_lb are disabled.
	ctrl1.set(500, 500)
	ctrl2.set(100, 3000)
	for i := 0; i < 2; i++ {
		p.Cycle(context.Background())
	}
	if !hasCmd(ha.commands(), "disable server kube_apiserver/api_contabo_ctrl") {
		t.Fatalf("expected api_contabo_ctrl disable, cmds=%v", ha.commands())
	}
	if !hasCmd(ha.commands(), "disable server kube_apiserver/api_datahub_lb") {
		t.Fatalf("expected api_datahub_lb disable alongside wedged ctrl, cmds=%v", ha.commands())
	}
	if got := promtest.ToFloat64(p.enabled.WithLabelValues("api_datahub_lb")); got != 0 {
		t.Fatalf("enabled{api_datahub_lb}=%v want 0", got)
	}

	// Phase 2: ctrl2 recovers for RecoverCycles (3) → both ctrl2 and
	// api_datahub_lb are re-enabled.
	ctrl2.set(500, 500)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if !hasCmd(ha.commands(), "enable server kube_apiserver/api_contabo_ctrl") {
		t.Fatalf("expected api_contabo_ctrl enable, cmds=%v", ha.commands())
	}
	if !hasCmd(ha.commands(), "enable server kube_apiserver/api_datahub_lb") {
		t.Fatalf("expected api_datahub_lb enable after ctrl recovery, cmds=%v", ha.commands())
	}
	p.Cycle(context.Background())
	if got := promtest.ToFloat64(p.enabled.WithLabelValues("api_datahub_lb")); got != 1 {
		t.Fatalf("enabled{api_datahub_lb}=%v want 1", got)
	}
}

func countCmd(cmds []string, want string) int {
	n := 0
	for _, c := range cmds {
		if c == want {
			n++
		}
	}
	return n
}

func TestReApplyDisableAfterHAProxyRestart(t *testing.T) {
	// HAProxy restart forgets runtime disables — a backend we marked
	// drained that shows UP again in `show stat` must get the disable
	// re-applied, not be treated as newly stale.
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	bad.set(100, 200)
	good.set(50, 50)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if countCmd(ha.commands(), "disable server kube_apiserver/hub1") != 1 {
		t.Fatalf("expected 1 disable, cmds=%v", ha.commands())
	}

	// Simulate the restart: HAProxy reports hub1 UP again while the
	// prober's in-memory drained flag persists.
	ha.mu.Lock()
	ha.disabled["hub1"] = false
	ha.mu.Unlock()
	p.Cycle(context.Background())

	if got := countCmd(ha.commands(), "disable server kube_apiserver/hub1"); got != 2 {
		t.Fatalf("re-applied disable count=%d want 2, cmds=%v", got, ha.commands())
	}
}

func TestEnableFailureKeepsDrained(t *testing.T) {
	// If `enable server` is rejected on the socket, the backend must
	// stay marked drained — clearing the flag would forget the wedge.
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	bad.set(100, 200)
	good.set(50, 50)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if !p.states["hub1"].drained {
		t.Fatal("hub1 not marked drained after wedge")
	}

	ha.mu.Lock()
	ha.failReply = map[string]string{"enable server": "No such server\n"}
	ha.mu.Unlock()
	for i := 0; i < 4; i++ { // >= RecoverCycles
		bad.set(300+int64(i), 300)
		p.Cycle(context.Background())
	}

	if !hasCmd(ha.commands(), "enable server kube_apiserver/hub1") {
		t.Fatalf("enable was never attempted, cmds=%v", ha.commands())
	}
	if !p.states["hub1"].drained {
		t.Fatal("drained flag cleared despite failed enable")
	}
	if got := promtest.ToFloat64(p.actions.WithLabelValues("hub1", "enable")); got != 0 {
		t.Fatalf("actions enable=%v want 0 (all enables failed)", got)
	}
	if got := promtest.ToFloat64(p.enabled.WithLabelValues("hub1")); got != 0 {
		t.Fatalf("enabled{hub1}=%v want 0", got)
	}
}

func TestExternalMaintBackendRecoversToEnable(t *testing.T) {
	// Backend found already MAINT (manual drain or agent restart lost
	// the drained flag): fresh probes still accumulate ok-cycles and
	// re-enable it after RecoverCycles.
	fresh1 := newAPIStub(t)
	fresh2 := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", fresh1.addr()},
		[2]string{"hub2", fresh2.addr()},
	)
	ha.disabled["hub1"] = true // externally drained → MAINT in show stat
	p := fixture(t, ha, ModeEnforce, nil)

	fresh1.set(50, 50)
	fresh2.set(60, 60)
	for i := 0; i < 3; i++ { // RecoverCycles
		p.Cycle(context.Background())
	}

	if !hasCmd(ha.commands(), "enable server kube_apiserver/hub1") {
		t.Fatalf("no enable for MAINT backend, cmds=%v", ha.commands())
	}
	if got := promtest.ToFloat64(p.actions.WithLabelValues("hub1", "enable")); got != 1 {
		t.Fatalf("actions enable=%v want 1", got)
	}
}

func TestVIPKeptWhenNoFreshController(t *testing.T) {
	// sig14b least-bad: a wedged sole controller must NOT drag the VIP
	// down — with fresh==0 the VIP is the only remaining path.
	ctrl := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"api_datahub_ctrl", ctrl.addr()},
		[2]string{"api_datahub_lb", "127.0.0.1:1"},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	ctrl.set(100, 200) // frozen wedge
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}

	if hasCmd(ha.commands(), "disable server kube_apiserver/api_datahub_lb") {
		t.Fatalf("VIP disabled with no fresh controller: %v", ha.commands())
	}
	if got := promtest.ToFloat64(p.enabled.WithLabelValues("api_datahub_lb")); got != 1 {
		t.Fatalf("enabled{api_datahub_lb}=%v want 1 (least-bad)", got)
	}
}

func TestVIPMaintReEnabledWhenControllersHealthy(t *testing.T) {
	// A VIP found in MAINT while all direct controllers are healthy
	// gets re-enabled — same reconcile path as external drains.
	ctrl := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"api_datahub_ctrl", ctrl.addr()},
		[2]string{"api_datahub_lb", "127.0.0.1:1"},
	)
	ha.disabled["api_datahub_lb"] = true
	p := fixture(t, ha, ModeEnforce, nil)

	ctrl.set(50, 50)
	p.Cycle(context.Background())

	if !hasCmd(ha.commands(), "enable server kube_apiserver/api_datahub_lb") {
		t.Fatalf("no enable for healthy VIP, cmds=%v", ha.commands())
	}
}

func TestCycleReturnsOnCancelledCtx(t *testing.T) {
	// Discover succeeds, then the backend loop bails on ctx.Err() —
	// the per-backend check, not a discover failure. The pipeDial
	// seam ignores ctx so `show stat` still answers.
	ha := newFakeHAProxy(t, [2]string{"hub1", "127.0.0.1:1"})
	p := fixture(t, ha, ModeDryRun, nil)
	p.cfg.DialSocket = pipeDial(ha.statCSV())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.Cycle(ctx)

	if got := promtest.ToFloat64(p.cycles.WithLabelValues("ok")); got != 1 {
		t.Fatalf("cycles ok=%v want 1 (discover completed)", got)
	}
}

func TestDryRunEnableOnRecovery(t *testing.T) {
	// Dry-run recovery: a MAINT backend with RecoverCycles fresh
	// probes logs "would enable" without touching the socket.
	fresh1 := newAPIStub(t)
	fresh2 := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", fresh1.addr()},
		[2]string{"hub2", fresh2.addr()},
	)
	ha.disabled["hub1"] = true // externally drained
	p := fixture(t, ha, ModeDryRun, nil)

	fresh1.set(50, 50)
	fresh2.set(60, 60)
	for i := 0; i < 3; i++ { // RecoverCycles
		p.Cycle(context.Background())
	}

	if got := promtest.ToFloat64(p.actions.WithLabelValues("hub1", "dryrun_enable")); got < 1 {
		t.Fatalf("dryrun_enable=%v want >=1", got)
	}
	for _, c := range ha.commands() {
		if !strings.HasPrefix(c, "show stat") {
			t.Fatalf("dry-run issued socket action: %v", ha.commands())
		}
	}
}

func TestEnableAfterHAProxyRestartCountsFresh(t *testing.T) {
	// Backend we drained shows UP again (HAProxy restart forgot the
	// disable) AND its probes recover: the successful enable path
	// counts the backend fresh again.
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	bad.set(100, 200)
	good.set(50, 50)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if !p.states["hub1"].drained {
		t.Fatal("hub1 not drained after wedge")
	}

	// HAProxy restart forgets the runtime disable → hub1 reports UP
	// again; its probes recover at the same time.
	ha.mu.Lock()
	ha.disabled["hub1"] = false
	ha.mu.Unlock()
	for i := 0; i < 3; i++ {
		bad.set(300+int64(i), 300)
		p.Cycle(context.Background())
	}

	if got := promtest.ToFloat64(p.actions.WithLabelValues("hub1", "enable")); got != 1 {
		t.Fatalf("actions enable=%v want 1", got)
	}
	if p.states["hub1"].drained {
		t.Fatal("drained flag still set after successful enable")
	}
}

func TestDrainDisableFailureLeavesUndrained(t *testing.T) {
	// A wedged backend whose `disable server` is rejected stays
	// un-drained — the guard must not record an action that never
	// happened.
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	ha.failReply = map[string]string{"disable server": "socket read only\n"}
	p := fixture(t, ha, ModeEnforce, nil)

	bad.set(100, 200)
	good.set(50, 50)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}

	if !hasCmd(ha.commands(), "disable server kube_apiserver/hub1") {
		t.Fatalf("disable never attempted, cmds=%v", ha.commands())
	}
	if p.states["hub1"].drained {
		t.Fatal("drained flag set despite failed disable")
	}
	if got := promtest.ToFloat64(p.actions.WithLabelValues("hub1", "disable")); got != 0 {
		t.Fatalf("actions disable=%v want 0 (all disables failed)", got)
	}
}

func TestReApplyDisableFailure(t *testing.T) {
	// Drained backend shows UP again after a HAProxy restart while
	// still wedged → re-apply is attempted; when the socket rejects
	// it, the error branch is taken and drained stays set.
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	bad.set(100, 200)
	good.set(50, 50)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if countCmd(ha.commands(), "disable server kube_apiserver/hub1") != 1 {
		t.Fatalf("expected 1 disable, cmds=%v", ha.commands())
	}

	// HAProxy restart forgets the disable AND the socket now rejects
	// further disables; the backend is still wedged → re-apply fails.
	ha.mu.Lock()
	ha.disabled["hub1"] = false
	ha.failReply = map[string]string{"disable server": "permission denied\n"}
	ha.mu.Unlock()
	p.Cycle(context.Background())

	if got := countCmd(ha.commands(), "disable server kube_apiserver/hub1"); got != 2 {
		t.Fatalf("re-apply attempts=%d want 2, cmds=%v", got, ha.commands())
	}
	if !p.states["hub1"].drained {
		t.Fatal("drained flag cleared despite failed re-apply")
	}
	if got := promtest.ToFloat64(p.actions.WithLabelValues("hub1", "disable")); got != 1 {
		t.Fatalf("actions disable=%v want 1 (re-apply failed)", got)
	}
}

func TestVIPDisableFailureLeavesUPEnabled(t *testing.T) {
	// A wedged controller triggers a VIP disable, but the socket
	// rejects it — the VIP must keep serving (enabled stays 1).
	ctrl1 := newAPIStub(t)
	ctrl2 := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"api_datahub_ctrl", ctrl1.addr()},
		[2]string{"api_datahub_lb", "127.0.0.1:1"},
		[2]string{"api_contabo_ctrl", ctrl2.addr()},
	)
	ha.failReply = map[string]string{"disable server": "permission denied\n"}
	p := fixture(t, ha, ModeEnforce, nil)

	ctrl1.set(500, 500)
	ctrl2.set(100, 3000)
	for i := 0; i < 2; i++ {
		p.Cycle(context.Background())
	}

	if !hasCmd(ha.commands(), "disable server kube_apiserver/api_datahub_lb") {
		t.Fatalf("VIP disable never attempted, cmds=%v", ha.commands())
	}
	if got := promtest.ToFloat64(p.actions.WithLabelValues("api_datahub_lb", "disable")); got != 0 {
		t.Fatalf("VIP actions disable=%v want 0 (disable failed)", got)
	}
	if got := promtest.ToFloat64(p.enabled.WithLabelValues("api_datahub_lb")); got != 1 {
		t.Fatalf("enabled{api_datahub_lb}=%v want 1 (still serving)", got)
	}
	if p.states["api_datahub_lb"].drained {
		t.Fatal("VIP drained flag set despite failed disable")
	}
}

func TestVIPEnableFailure(t *testing.T) {
	// A MAINT VIP with healthy controllers gets an enable attempt;
	// when the socket rejects it the VIP stays MAINT — no action
	// recorded, flag unchanged.
	ctrl := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"api_datahub_ctrl", ctrl.addr()},
		[2]string{"api_datahub_lb", "127.0.0.1:1"},
	)
	ha.disabled["api_datahub_lb"] = true
	ha.failReply = map[string]string{"enable server": "permission denied\n"}
	p := fixture(t, ha, ModeEnforce, nil)

	ctrl.set(50, 50)
	p.Cycle(context.Background())

	if !hasCmd(ha.commands(), "enable server kube_apiserver/api_datahub_lb") {
		t.Fatalf("VIP enable never attempted, cmds=%v", ha.commands())
	}
	if got := promtest.ToFloat64(p.actions.WithLabelValues("api_datahub_lb", "enable")); got != 0 {
		t.Fatalf("VIP actions enable=%v want 0 (enable failed)", got)
	}
	if got := promtest.ToFloat64(p.enabled.WithLabelValues("api_datahub_lb")); got != 0 {
		t.Fatalf("enabled{api_datahub_lb}=%v want 0 (still MAINT)", got)
	}
}

func TestVIPDryRunTransitions(t *testing.T) {
	// Dry-run VIP transitions: wedge → dryrun_disable (which marks
	// drained in memory), recovery → dryrun_enable. No real socket
	// action is ever issued.
	ctrl1 := newAPIStub(t)
	ctrl2 := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"api_datahub_ctrl", ctrl1.addr()},
		[2]string{"api_datahub_lb", "127.0.0.1:1"},
		[2]string{"api_contabo_ctrl", ctrl2.addr()},
	)
	p := fixture(t, ha, ModeDryRun, nil)

	ctrl1.set(500, 500)
	ctrl2.set(100, 3000)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if got := promtest.ToFloat64(p.actions.WithLabelValues("api_datahub_lb", "dryrun_disable")); got != 1 {
		t.Fatalf("VIP dryrun_disable=%v want 1", got)
	}

	// Controllers healthy again → the (in-memory) drained VIP is
	// re-enabled in dry-run terms.
	ctrl2.set(500, 500)
	for i := 0; i < 4; i++ { // RecoverCycles=3 for the direct ctrl
		p.Cycle(context.Background())
	}
	if got := promtest.ToFloat64(p.actions.WithLabelValues("api_datahub_lb", "dryrun_enable")); got != 1 {
		t.Fatalf("VIP dryrun_enable=%v want 1", got)
	}
	for _, c := range ha.commands() {
		if !strings.HasPrefix(c, "show stat") {
			t.Fatalf("dry-run issued socket action: %v", ha.commands())
		}
	}
}

func TestCompanionBackendsReceiveActions(t *testing.T) {
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	ha.failReply = map[string]string{
		"disable server konn_back/hub1": "No such server konn_back/hub1\n",
	}
	p := fixtureExt(t, ha, ModeEnforce, nil, func(c *Config) {
		c.CompanionBackends = []string{"konn_back"}
	})

	// Frozen wedge on hub1 for FrozenCycles.
	bad.set(100, 200)
	good.set(500, 500)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}

	cmds := ha.commands()
	if !hasCmd(cmds, "disable server kube_apiserver/hub1") {
		t.Fatalf("primary backend disable missing, cmds=%v", cmds)
	}
	if !hasCmd(cmds, "disable server konn_back/hub1") {
		t.Fatalf("companion backend disable missing, cmds=%v", cmds)
	}
	// "No such server" on the companion is a no-op — the action
	// still counted as a disable, not an error path.
	if got := promtest.ToFloat64(p.actions.WithLabelValues("hub1", "disable")); got != 1 {
		t.Fatalf("actions disable=%v want 1", got)
	}
}

func TestCompanionErrorDoesNotBlockDrain(t *testing.T) {
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	// Companion returns a REAL error (not "No such server") — the
	// primary already drained; the error surfaces in the log only.
	ha.failReply = map[string]string{
		"disable server konn_back/hub1": "permission denied for socket\n",
	}
	p := fixtureExt(t, ha, ModeEnforce, nil, func(c *Config) {
		c.CompanionBackends = []string{"konn_back"}
	})
	bad.set(100, 200)
	good.set(500, 500)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if !hasCmd(ha.commands(), "disable server kube_apiserver/hub1") {
		t.Fatalf("primary disable missing, cmds=%v", ha.commands())
	}
	// Primary disable succeeded → drained flag set.
	if !p.states["hub1"].drained {
		t.Fatal("hub1 not drained despite companion error")
	}
}

func TestStaticBackendsMergedAndDrained(t *testing.T) {
	bad := newAPIStub(t)
	good := newAPIStub(t)
	// HAProxy knows only hub2; hub1 comes from StaticBackends (the
	// api-backend-guard.conf API_BACKENDS model).
	ha := newFakeHAProxy(t, [2]string{"hub2", good.addr()})
	wdir := t.TempDir()
	p := fixtureExt(t, ha, ModeEnforce, nil, func(c *Config) {
		c.WatchdogStateDir = wdir
		c.StaticBackends = []StaticBackend{
			{Name: "hub1", Addr: bad.addr()},
		}
	})

	bad.set(100, 200) // frozen wedge
	good.set(500, 500)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}

	if !hasCmd(ha.commands(), "disable server kube_apiserver/hub1") {
		t.Fatalf("static backend disable missing, cmds=%v", ha.commands())
	}
	if got := promtest.ToFloat64(p.backendCount); got != 2 {
		t.Fatalf("backendCount=%v want 2 (static merged)", got)
	}
	// The stale latch is written for the static backend too — module
	// 06's upstream gate reads it by dashed IP.
	dashed := strings.ReplaceAll(strings.Split(bad.addr(), ":")[0], ".", "-")
	if _, err := os.Stat(wdir + "/state-apiserver-backend-stale-" + dashed); err != nil {
		t.Fatalf("stale latch missing for static backend: %v", err)
	}
}

func TestStagedDrainSpendsFreshPerDisable(t *testing.T) {
	// fresh=1 with 2 wedged backends: the first disable decrements
	// fresh (shell `fresh=$((fresh - 1))` parity), so the second
	// wedge hits the fence — staged drain, not drain-all.
	good := newAPIStub(t)
	bad1 := newAPIStub(t)
	bad2 := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", good.addr()},
		[2]string{"hub2", bad1.addr()},
		[2]string{"hub3", bad2.addr()},
	)
	p := fixtureExt(t, ha, ModeEnforce, nil, nil)
	good.set(50, 50)
	bad1.set(100, 200)
	bad2.set(100, 200)
	// Three cycles: cycle 1 seeds prevCache, frozen reaches
	// FrozenCycles on cycle 3 → ONE drain round — and the per-cycle
	// budget allows exactly `fresh` disables.
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	disables := 0
	for _, c := range ha.commands() {
		if strings.HasPrefix(c, "disable server") {
			disables++
		}
	}
	if disables != 1 {
		t.Fatalf("disables=%d want 1 (staged drain), cmds=%v", disables, ha.commands())
	}
	if got := promtest.ToFloat64(p.actions.WithLabelValues("hub3", "fence_skip")); got < 1 {
		t.Fatalf("hub3 fence_skip=%v want >=1", got)
	}
}

func TestCycleStaticsClearedAfterCycle(t *testing.T) {
	// cycleStatics is a Cycle-scoped snapshot by contract: outside
	// Cycle it must be nil so staticAddr resolves FRESH via
	// statics() (direct discover calls in tests rely on it). A
	// snapshot left behind would serve the last cycle's conf to
	// out-of-Cycle callers forever.
	confPath := filepath.Join(t.TempDir(), "node-watchdog.conf")
	writeConf := func(s string) {
		testutil.WriteFile(t, confPath, s)
	}
	writeConf("API_BACKENDS=\"old=10.0.0.9:6443\"\n")

	ha := newFakeHAProxy(t, [2]string{"hub1", "10.0.0.1:6443"})
	// TCP preflight fails for every backend → the cycle completes
	// without real apiserver probes (query timeouts would make the
	// test wait on the wall clock).
	p := fixture(t, ha, ModeDryRun,
		map[string]bool{"10.0.0.1:6443": false, "10.0.0.9:6443": false})
	p.cfg.WatchdogSrc = watchdogconf.NewReloader(confPath, nil)

	p.Cycle(context.Background())
	if p.cycleStatics != nil {
		t.Fatal("cycleStatics retained a stale snapshot after Cycle")
	}
	// A conf edit after the cycle must resolve NOW — serving the
	// cycle's snapshot is exactly the staleness the clear prevents.
	writeConf("API_BACKENDS=\"new=10.0.0.8:6443\"\n")
	if got := p.staticAddr("new"); got != "10.0.0.8:6443" {
		t.Fatalf("staticAddr(new)=%q want 10.0.0.8:6443 — stale snapshot served", got)
	}
	if got := p.staticAddr("old"); got != "" {
		t.Fatalf("staticAddr(old)=%q want \"\" — conf edit not re-read", got)
	}

	// Early-return path: a missing socket gates the cycle BEFORE
	// discover — the defer must still drop the snapshot.
	p2, err := New(Config{
		SocketPath:  filepath.Join(t.TempDir(), "absent.sock"),
		BackendName: "kube_apiserver",
		Mode:        ModeDryRun,
		HTTPClient:  newAPIStub(t).srv.Client(),
	}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	p2.Cycle(context.Background())
	if p2.cycleStatics != nil {
		t.Fatal("cycleStatics retained a stale snapshot after a gated cycle")
	}
}

func TestAddrKeyedStaticDoesNotDuplicateDiscoveredBackend(t *testing.T) {
	// The reported incident: API_BACKENDS on workers carries bare
	// apiserver_probe_backends addrs ("147.93.159.255:6443") while
	// api-local-lb serves the same addrs under svnames
	// (api_contabo_ctrl). The bare entry must collapse onto the
	// discovered row — never a second probe identity, and the drain
	// must use the HAProxy svname.
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"api_contabo_ctrl", bad.addr()},
		[2]string{"api_datahub_ctrl", good.addr()},
	)
	p := fixtureExt(t, ha, ModeEnforce, nil, func(c *Config) {
		c.StaticBackends = []StaticBackend{
			{Name: bad.addr(), Addr: bad.addr()},   // bare ip:port
			{Name: good.addr(), Addr: good.addr()}, // bare ip:port
		}
	})

	bad.set(100, 200) // frozen wedge
	good.set(500, 500)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}

	if !hasCmd(ha.commands(), "disable server kube_apiserver/api_contabo_ctrl") {
		t.Fatalf("disable must use the HAProxy svname, cmds=%v", ha.commands())
	}
	addrCmd := "disable server kube_apiserver/" + bad.addr()
	if hasCmd(ha.commands(), addrCmd) {
		t.Fatalf("disable issued under the addr key %q — 'No such server' bug, cmds=%v",
			bad.addr(), ha.commands())
	}
	if _, ok := p.states[bad.addr()]; ok {
		t.Fatal("addr-keyed phantom backend got its own probe state")
	}
	if got := promtest.ToFloat64(p.backendCount); got != 2 {
		t.Fatalf("backendCount=%v want 2 (addr-keyed static deduped)", got)
	}
}

func TestStaticOnlyBackendMissingServerDrainOnce(t *testing.T) {
	// A static-only backend (API_BACKENDS entry absent from every
	// HAProxy backend) going stale: the primary replies "No such
	// server" — the expected no-op — so the drain is recorded once
	// and NOT retried as an error every cycle.
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t, [2]string{"hub2", good.addr()})
	ha.failReply = map[string]string{
		"disable server kube_apiserver/ghost": "No such server.\n",
		"enable server kube_apiserver/ghost":  "No such server.\n",
	}
	p := fixtureExt(t, ha, ModeEnforce, nil, func(c *Config) {
		c.StaticBackends = []StaticBackend{{Name: "ghost", Addr: bad.addr()}}
	})

	bad.set(100, 200) // frozen wedge
	good.set(500, 500)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if !hasCmd(ha.commands(), "disable server kube_apiserver/ghost") {
		t.Fatalf("disable never attempted, cmds=%v", ha.commands())
	}
	if !p.states["ghost"].drained {
		t.Fatal("ghost not marked drained — tolerated 'No such server' must not block the drain record")
	}
	if got := promtest.ToFloat64(p.actions.WithLabelValues("ghost", "disable")); got != 1 {
		t.Fatalf("actions disable=%v want 1", got)
	}

	// Still wedged for several more cycles — the missing-server
	// drain must not retry/spam the socket every round.
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if got := countCmd(ha.commands(), "disable server kube_apiserver/ghost"); got != 1 {
		t.Fatalf("disable re-issued %d times for an absent server, cmds=%v",
			got, ha.commands())
	}

	// Recovery: the tolerated "No such server" enable clears the
	// drained flag the same way.
	for i := 0; i < 3; i++ {
		bad.set(300+int64(i), 300)
		p.Cycle(context.Background())
	}
	if p.states["ghost"].drained {
		t.Fatal("drained flag not cleared after tolerated enable")
	}
}

func TestProbeSideFailuresDoNotMarkDead(t *testing.T) {
	// 401 on BOTH probe paths: every failure is probe-side — the
	// backend is inconclusive, never qfails toward DEAD, never
	// drains, never latches the stale file (the incident shape).
	bad := newAPIStubOn(t, "127.0.0.2:0") // distinct dashed-IP latch name
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	wdir := t.TempDir()
	p := fixtureExt(t, ha, ModeEnforce, nil, func(c *Config) {
		c.WatchdogStateDir = wdir
	})

	bad.setStatus(http.StatusUnauthorized, http.StatusUnauthorized)
	good.set(50, 50)
	for i := 0; i < 4; i++ {
		p.Cycle(context.Background())
	}

	if hasCmd(ha.commands(), "disable server kube_apiserver/hub1") {
		t.Fatalf("probe-side failures drained a backend: %v", ha.commands())
	}
	st := p.states["hub1"]
	if st.qfail != 0 || st.drained {
		t.Fatalf("probe-side failures touched the DEAD path: qfail=%d drained=%v",
			st.qfail, st.drained)
	}
	if got := promtest.ToFloat64(
		p.probeFailures.WithLabelValues("hub1", "probe_error")); got != 4 {
		t.Fatalf("probe_error=%v want 4", got)
	}
	if got := promtest.ToFloat64(
		p.probeFailures.WithLabelValues("hub1", "query")); got != 0 {
		t.Fatalf("query=%v want 0 — probe-side faults are not apiserver evidence", got)
	}
	if _, err := os.Stat(filepath.Join(wdir,
		"state-apiserver-backend-stale-127-0-0-2")); !os.IsNotExist(err) {
		t.Fatalf("stale latch written for a probe-side outage: %v", err)
	}
	if got := promtest.ToFloat64(p.enabled.WithLabelValues("hub2")); got != 1 {
		t.Fatalf("enabled{hub2}=%v want 1 — healthy backend unaffected", got)
	}
}

func TestMixedFailurePrefersApiserverSide(t *testing.T) {
	// cache path 401 (probe-side) + live path 503 (apiserver-side):
	// the apiserver-side failure is real evidence — qfail still
	// accumulates toward DEAD exactly like a plain query failure.
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	bad.setStatus(http.StatusUnauthorized, http.StatusServiceUnavailable)
	good.set(50, 50)
	p.Cycle(context.Background())
	p.Cycle(context.Background()) // qfail #2 → DEAD → disable

	if !hasCmd(ha.commands(), "disable server kube_apiserver/hub1") {
		t.Fatalf("no disable for apiserver-side failure, cmds=%v", ha.commands())
	}
	if got := promtest.ToFloat64(
		p.probeFailures.WithLabelValues("hub1", "query")); got < 2 {
		t.Fatalf("query=%v want >=2", got)
	}
	if got := promtest.ToFloat64(
		p.probeFailures.WithLabelValues("hub1", "probe_error")); got != 0 {
		t.Fatalf("probe_error=%v want 0 — mixed failure is apiserver evidence", got)
	}
}

func TestProbeErrorBackendIsNotFreshForFence(t *testing.T) {
	// A probe-side-erroring backend can neither prove itself fresh
	// nor be declared dead — so it must NOT supply the "fresh
	// backend" the drain fence needs: hub2 stays wedged AND
	// protected while hub1's credential is broken (fresh=0 → FENCE).
	broken := newAPIStub(t)
	wedged := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", broken.addr()},
		[2]string{"hub2", wedged.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	broken.setStatus(http.StatusUnauthorized, http.StatusUnauthorized)
	wedged.set(100, 100000) // rv gap >> GapMin(1000) → stale
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	for _, name := range []string{"hub1", "hub2"} {
		if hasCmd(ha.commands(), "disable server kube_apiserver/"+name) {
			t.Fatalf("disable issued for %s: %v", name, ha.commands())
		}
	}
	if got := promtest.ToFloat64(
		p.actions.WithLabelValues("hub2", "fence_skip")); got < 1 {
		t.Fatalf("fence_skip=%v want >=1 — wedged backend kept, no fresh backend", got)
	}
}

func TestTokenRotationSelfHeals(t *testing.T) {
	// Production credential path (no injected client): the token
	// file is re-read on EVERY query, so a credential rotated on
	// disk self-heals on the next cycle without an agent restart —
	// the api-lb-vm shape where hubsync re-pushes
	// /etc/api-backend-guard/token.
	stub := newAPIStub(t)
	stub.setToken("good-token")
	stub.set(50, 50)
	ha := newFakeHAProxy(t, [2]string{"hub1", stub.addr()})
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("stale-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{
		SocketPath:    ha.sockPath,
		BackendName:   "kube_apiserver",
		Mode:          ModeEnforce,
		GapMin:        1000,
		FailCycles:    2,
		FrozenCycles:  2,
		RecoverCycles: 3,
		TokenFile:     tokenFile,
		InsecureTLS:   true,
		// Point the conf overlay at a file that never exists — this
		// test owns TokenFile; a stray real /etc conf must not win.
		GuardSrc: NewGuardReloader(
			filepath.Join(dir, "absent.conf"), GuardDefaults{}),
		TCPCheck: func(context.Context, string) error { return nil },
	}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}

	// Stale credential → 401 → probe_error, never DEAD.
	p.Cycle(context.Background())
	if got := promtest.ToFloat64(
		p.probeFailures.WithLabelValues("hub1", "probe_error")); got != 1 {
		t.Fatalf("probe_error=%v want 1", got)
	}
	st := p.states["hub1"]
	if st.qfail != 0 || st.probeErr == "" {
		t.Fatalf("stale credential should be inconclusive: qfail=%d probeErr=%q",
			st.qfail, st.probeErr)
	}

	// Rotate the credential file — picked up on the very next probe.
	if err := os.WriteFile(tokenFile, []byte("good-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p.Cycle(context.Background())
	if st.probeErr != "" {
		t.Fatal("probeErr latch not cleared after credential healed")
	}
	if st.ok != 1 || st.qfail != 0 {
		t.Fatalf("healed backend state ok=%d qfail=%d want 1/0", st.ok, st.qfail)
	}
	if got := promtest.ToFloat64(p.enabled.WithLabelValues("hub1")); got != 1 {
		t.Fatalf("enabled=%v want 1 after credential rotation", got)
	}
	if got := promtest.ToFloat64(
		p.probeFailures.WithLabelValues("hub1", "probe_error")); got != 1 {
		t.Fatalf("probe_error=%v want 1 — healed cycle counted no error", got)
	}
}

func TestProbeErrLoggedOncePerStateChange(t *testing.T) {
	// The PROBE-ERR Warn is edge-latched on the failure-class pair —
	// a persistent credential outage logs once, not once per cycle;
	// recovery and re-entry log once each.
	buf := captureSlog(t)
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	bad.setStatus(http.StatusUnauthorized, http.StatusUnauthorized)
	good.set(50, 50)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	logs := buf.String()
	if n := strings.Count(logs, "PROBE-ERR"); n != 1 {
		t.Fatalf("PROBE-ERR lines=%d want 1 (edge latch):\n%s", n, logs)
	}
	if !strings.Contains(logs, `cacheErr="auth: HTTP 401`) {
		t.Fatalf("PROBE-ERR line missing the concrete failure class:\n%s", logs)
	}

	// Recovery — one informational transition line.
	bad.setStatus(0, 0)
	bad.set(50, 50)
	p.Cycle(context.Background())
	logs = buf.String()
	if n := strings.Count(logs, "probe-side errors cleared"); n != 1 {
		t.Fatalf("cleared lines=%d want 1:\n%s", n, logs)
	}
	if n := strings.Count(logs, "PROBE-ERR"); n != 1 {
		t.Fatalf("PROBE-ERR lines=%d want 1 after recovery:\n%s", n, logs)
	}

	// Re-entering the same failure logs again (new state-change).
	bad.setStatus(http.StatusUnauthorized, http.StatusUnauthorized)
	p.Cycle(context.Background())
	if n := strings.Count(buf.String(), "PROBE-ERR"); n != 2 {
		t.Fatalf("PROBE-ERR lines=%d want 2 after re-entry:\n%s", n, buf.String())
	}
}

func TestDEADLogCarriesErrorDetail(t *testing.T) {
	// The DEAD line — the line that logged "API queries failing" for
	// 12.5h with no detail — now carries the concrete per-path
	// failure class + error.
	buf := captureSlog(t)
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	bad.setStatus(http.StatusServiceUnavailable, http.StatusServiceUnavailable)
	good.set(50, 50)
	p.Cycle(context.Background())
	p.Cycle(context.Background()) // qfail #2 → DEAD

	logs := buf.String()
	if !strings.Contains(logs, "DEAD: API queries failing") {
		t.Fatalf("DEAD line missing:\n%s", logs)
	}
	for _, want := range []string{
		`cacheErr="http_status: HTTP 503`, `liveErr="http_status: HTTP 503`,
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("DEAD line missing %q:\n%s", want, logs)
		}
	}
}
