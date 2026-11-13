package apiprober

import (
	"context"
	"strings"
	"testing"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"
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
