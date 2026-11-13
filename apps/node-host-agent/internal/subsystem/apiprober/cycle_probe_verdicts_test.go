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
)

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
	if st.ok != 0 || st.qfail != 0 {
		t.Fatalf("healed backend state ok=%d qfail=%d want 0/0 — ok only counts while a recovery verdict is in flight", st.ok, st.qfail)
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

// A probe-side fault (auth reject) withholds the verdict; when the
// SAME backend later fails apiserver-side, the withheld probeErr
// must clear and real evidence start counting (qfail, query split).
func TestProbeSideErrorsClearOnApiserverSideFault(t *testing.T) {
	stub := newAPIStub(t)
	ha := newFakeHAProxy(t, [2]string{"hub1", stub.addr()})
	p := fixture(t, ha, ModeEnforce, nil)

	// Cycle 1: 401 on both paths — credential fault, verdict withheld.
	stub.setStatus(http.StatusUnauthorized, http.StatusUnauthorized)
	p.Cycle(context.Background())
	if p.states["hub1"].probeErr == "" {
		t.Fatal("probe-side fault did not latch probeErr")
	}
	if got := promtest.ToFloat64(p.probeFailures.WithLabelValues("hub1", "probe_error")); got != 1 {
		t.Fatalf("probe_error=%v want 1", got)
	}

	// Cycle 2: the cache answers but the consistent read 503s —
	// apiserver evidence at last: probeErr clears, qfail starts.
	stub.setStatus(0, http.StatusServiceUnavailable)
	buf := captureSlog(t)
	p.Cycle(context.Background())
	if p.states["hub1"].probeErr != "" {
		t.Fatalf("probeErr not cleared on apiserver-side fault: %q",
			p.states["hub1"].probeErr)
	}
	if !strings.Contains(buf.String(), "probe-side errors cleared") {
		t.Fatalf("clear transition not logged:\n%s", buf.String())
	}
	if got := promtest.ToFloat64(p.probeFailures.WithLabelValues("hub1", "query")); got != 1 {
		t.Fatalf("query failures=%v want 1", got)
	}
	// qfail 1 < FailCycles(2) — no drain yet.
	if got := countCmd(ha.commands(), "disable server kube_apiserver/hub1"); got != 0 {
		t.Fatalf("premature disable (%d), cmds=%v", got, ha.commands())
	}
}

// reapplyDrains: a drained backend that HAProxy forgot while the
// whole fleet is probe-side down (fresh == 0, drained backend NOT
// stale) must NOT be re-disabled — the last-standing fence covers
// the re-apply pass too, not just the drain phase.
func TestReapplyDrainsFencedWhenNoFreshBackend(t *testing.T) {
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	p := fixture(t, ha, ModeEnforce, nil)

	// Drain hub1 (query-dead), hub2 stays fresh.
	bad.setFail(true)
	good.set(50, 50)
	p.Cycle(context.Background())
	p.Cycle(context.Background())
	if !p.states["hub1"].drained {
		t.Fatal("hub1 not drained")
	}

	// HAProxy forgets the disable (restart), and BOTH backends go
	// probe-side down: hub1 is drained but inconclusive (not stale),
	// fresh == 0 → the fence holds the re-apply.
	ha.mu.Lock()
	ha.disabled["hub1"] = false
	ha.mu.Unlock()
	bad.setStatus(http.StatusUnauthorized, http.StatusUnauthorized)
	good.setStatus(http.StatusUnauthorized, http.StatusUnauthorized)
	p.Cycle(context.Background())

	if got := countCmd(ha.commands(), "disable server kube_apiserver/hub1"); got != 1 {
		t.Fatalf("fenced re-apply re-disabled (%d disables), cmds=%v", got, ha.commands())
	}
	if !p.states["hub1"].drained {
		t.Fatal("drained flag lost")
	}
}

// The non-stale re-apply pass (drained backend, HAProxy forgot it,
// other backends fresh) issues the disable — and a socket rejection
// there is logged, drained kept, actions untouched.
func TestReapplyDrainsErrorKeepsDrained(t *testing.T) {
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
	p.Cycle(context.Background())
	if countCmd(ha.commands(), "disable server kube_apiserver/hub1") != 1 {
		t.Fatalf("expected 1 drain disable, cmds=%v", ha.commands())
	}

	// HAProxy forgets the disable and now rejects re-disables; hub1
	// goes probe-side down (inconclusive → NOT stale → reapplyDrains
	// owns the pass) while hub2 stays fresh (no fence).
	ha.mu.Lock()
	ha.disabled["hub1"] = false
	ha.failReply = map[string]string{
		"disable server kube_apiserver/hub1": "permission denied\n",
	}
	ha.mu.Unlock()
	bad.setStatus(http.StatusUnauthorized, http.StatusUnauthorized)
	buf := captureSlog(t)
	p.Cycle(context.Background())

	if !strings.Contains(buf.String(), "re-apply disable failed") {
		t.Fatalf("re-apply error not logged:\n%s", buf.String())
	}
	if !p.states["hub1"].drained {
		t.Fatal("drained flag cleared despite failed re-apply")
	}
	if got := promtest.ToFloat64(p.actions.WithLabelValues("hub1", "disable")); got != 1 {
		t.Fatalf("actions disable=%v want 1 (re-apply failed)", got)
	}
}
