package apiprober

import (
	"context"
	"strings"
	"testing"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"
)

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
