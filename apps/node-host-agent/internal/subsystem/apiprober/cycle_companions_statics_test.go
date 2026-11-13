package apiprober

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

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
