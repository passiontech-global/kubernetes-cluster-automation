package subframe

import (
	"os"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostctx"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// TestFromDepsSplicesFields: FromDeps is the one-line splice every
// ConfigFromEnv collapses into — every dep-consumed Base field must
// land; Interval/ProcRoot stay out (they are env knobs, not deps).
func TestFromDepsSplicesFields(t *testing.T) {
	wd := &watchdogconf.Config{NebulaNet: "interdc"}
	wdSrc := watchdogconf.NewReloader("", nil)
	sysd := systemd.New(systemd.Config{HostRoot: "/"})
	clk := timex.NewCell(func() time.Time { return time.Unix(0, 0) })
	d := hostctx.Deps{
		WatchdogStateDir: "/var/lib/node-watchdog",
		WatchdogLogFile:  "/var/log/node-watchdog.log",
		HostRoot:         "/host",
		Systemd:          sysd,
		Watchdog:         wd,
		WatchdogSrc:      wdSrc,
		Clock:            clk,
	}

	b := FromDeps(d)
	if b.WatchdogStateDir != d.WatchdogStateDir ||
		b.WatchdogLogFile != d.WatchdogLogFile ||
		b.HostRoot != d.HostRoot ||
		b.Systemd != sysd ||
		b.Watchdog != wd ||
		b.WatchdogSrc != wdSrc ||
		b.Clock != clk {
		t.Fatalf("FromDeps splice mismatch: %+v", b)
	}
}

// TestStoreAtPackageFunc: the single hoststate.New call shape — dir/
// logFile carried, nil clock falls back to system time, and a cell
// clock binds the POINTER (a post-New Clock.Set is observed).
func TestStoreAtPackageFunc(t *testing.T) {
	fixed := time.Unix(1700000000, 0)
	clk := timex.NewCell(func() time.Time { return fixed })

	s := StoreAt("/var/lib/node-watchdog", "/var/log/wd.log", clk, nil)
	if s.Dir != "/var/lib/node-watchdog" || s.LogFile != "/var/log/wd.log" {
		t.Fatalf("store fields = %q/%q", s.Dir, s.LogFile)
	}
	if !s.Now().Equal(fixed) {
		t.Fatalf("store now = %v want the cell's %v", s.Now(), fixed)
	}
	// The method value binds the cell pointer — Set after New is seen.
	later := fixed.Add(time.Hour)
	clk.Set(func() time.Time { return later })
	if !s.Now().Equal(later) {
		t.Fatalf("post-New Set not observed: %v want %v", s.Now(), later)
	}

	// nil clock → hoststate falls back to system time (never nil panics).
	if snil := StoreAt("", "", nil, nil); snil.Now().IsZero() {
		t.Fatal("nil-clock store has no Now")
	}
}

// TestBaseStoreMethods: Base.Store reads the Base's own
// WatchdogStateDir/WatchdogLogFile pair; Base.StoreAt overrides the
// pair but keeps Base.Clock — the kinedb/hostconfig private-dir
// shape.
func TestBaseStoreMethods(t *testing.T) {
	clk := timex.NewCell(nil)
	b := &Base{
		WatchdogStateDir: "/var/lib/node-watchdog",
		WatchdogLogFile:  "/var/log/wd.log",
		Clock:            clk,
	}

	s := b.Store(nil)
	if s.Dir != b.WatchdogStateDir || s.LogFile != b.WatchdogLogFile {
		t.Fatalf("Store fields = %q/%q", s.Dir, s.LogFile)
	}
	if s.Now().Sub(time.Now()) > time.Minute {
		t.Fatalf("Store clock not Base.Clock: %v", s.Now())
	}

	priv := b.StoreAt("/var/lib/kinedb-guard", "", nil)
	if priv.Dir != "/var/lib/kinedb-guard" || priv.LogFile != "" {
		t.Fatalf("StoreAt fields = %q/%q", priv.Dir, priv.LogFile)
	}
	if priv.Now().Sub(time.Now()) > time.Minute {
		t.Fatalf("StoreAt clock not Base.Clock: %v", priv.Now())
	}
}

// TestRegisterAllRollsBackOnFailure: a mid-set registration failure
// must unregister the collectors that landed, so a retried New does
// not hit duplicate-registration; nil reg is a documented no-op.
func TestRegisterAllRollsBackOnFailure(t *testing.T) {
	if err := RegisterAll(nil, prometheus.NewCounter(prometheus.CounterOpts{Name: "x"})); err != nil {
		t.Fatalf("nil reg must be a no-op, got %v", err)
	}

	reg := prometheus.NewRegistry()
	c1 := prometheus.NewCounter(prometheus.CounterOpts{Name: "sub_ok_total"})
	c2 := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sub_cycles_total",
	}, []string{"check"})
	if err := RegisterAll(reg, c1, c2); err != nil {
		t.Fatalf("fresh set must register clean: %v", err)
	}
	if n := promtest.CollectAndCount(c1, "sub_ok_total"); n != 1 {
		t.Fatalf("c1 collected %d series want 1", n)
	}

	// A duplicate INSIDE one call: the first lands, the second fails,
	// and the rollback must have unregistered the one that landed (a
	// re-register then succeeds instead of hitting
	// AlreadyRegisteredError).
	reg2 := prometheus.NewRegistry()
	c3 := prometheus.NewCounter(prometheus.CounterOpts{Name: "sub_retry_total"})
	if err := RegisterAll(reg2, c3, c3); err == nil {
		t.Fatal("duplicate registration must fail")
	}
	if err := reg2.Register(c3); err != nil {
		t.Fatalf("c3 not rolled back after failure: %v", err)
	}

	// The failed call must not unwind collectors from EARLIER calls —
	// c2 (registered by the first RegisterAll) stays live.
	if err := reg.Register(c2); err == nil {
		t.Fatal("c2 should still be registered on reg from the first call")
	}
}

// TestCountersShape: the conventional cycles/actions pair — names,
// help strings and label dims are the scrape contract.
func TestCountersShape(t *testing.T) {
	cycles, actions := Counters("probe",
		"probe cycles", "probe actions")

	if got := promtest.CollectAndCount(cycles, "node_host_agent_probe_cycles_total"); got != 0 {
		t.Fatalf("fresh cycles family has %d series, want 0", got)
	}
	cycles.WithLabelValues("journald", "ok").Inc()
	cycles.WithLabelValues("journald", "fail").Inc()
	if got := promtest.CollectAndCount(cycles, "node_host_agent_probe_cycles_total"); got != 2 {
		t.Fatalf("cycles series = %d want 2", got)
	}
	if got := promtest.ToFloat64(cycles.WithLabelValues("journald", "ok")); got != 1 {
		t.Fatalf("cycles{journald,ok} = %v want 1", got)
	}

	actions.WithLabelValues("journald", "restart").Inc()
	if got := promtest.ToFloat64(actions.WithLabelValues("journald", "restart")); got != 1 {
		t.Fatalf("actions{journald,restart} = %v want 1", got)
	}
	if got := promtest.CollectAndCount(actions, "node_host_agent_probe_actions_total"); got != 1 {
		t.Fatalf("actions series = %d want 1", got)
	}
}

// TestBeginCycle: nil conf → every check runs (pre-conf contract);
// a set conf → sigOn mirrors SignalEnabled; a wired WatchdogSrc
// refreshes b.Watchdog so conf rewrites land next cycle.
func TestBeginCycle(t *testing.T) {
	// Nil conf + nil src: sigOn is unconditionally true.
	b := &Base{}
	wd, sigOn := b.BeginCycle()
	if wd != nil {
		t.Fatal("nil Watchdog must come back nil")
	}
	if !sigOn("anything") {
		t.Fatal("nil conf → every check runs")
	}

	// Static conf (no src): the kill switch mirrors SignalEnabled.
	b = &Base{Watchdog: &watchdogconf.Config{
		Disabled: map[string]bool{"overlay-egress": true},
	}}
	wd, sigOn = b.BeginCycle()
	if wd != b.Watchdog {
		t.Fatal("BeginCycle must return the held conf")
	}
	if sigOn("OVERLAY_EGRESS") {
		t.Fatal("disabled signal must read off")
	}
	if !sigOn("journald") {
		t.Fatal("unset signal must read on")
	}

	// WatchdogSrc: conf refreshed from the reloader on every cycle —
	// hostconfig rewrites the file mid-run and the flip lands.
	confFile := t.TempDir() + "/node-watchdog.conf"
	writeConf := func(content string) {
		t.Helper()
		if err := os.WriteFile(confFile, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeConf("WD_SIG_OVERLAY_EGRESS=off\n")
	b = &Base{WatchdogSrc: watchdogconf.NewReloader(confFile, nil)}
	wd, sigOn = b.BeginCycle()
	if wd == nil {
		t.Fatal("reloader refresh must install a conf")
	}
	if sigOn("OVERLAY_EGRESS") {
		t.Fatal("conf flip must reach sigOn via the reloader")
	}
	writeConf("# signal back on\n")
	if _, sigOn = b.BeginCycle(); !sigOn("OVERLAY_EGRESS") {
		t.Fatal("second refresh must see the rewritten conf")
	}
}
