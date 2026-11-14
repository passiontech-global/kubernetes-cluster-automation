package nethealth

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/nethealth/nebula"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// nebulaWD is a minimal nebula-active watchdog config for the MTU
// blackhole check.
func nebulaWD() *watchdogconf.Config {
	return &watchdogconf.Config{
		OverlayActive:       "nebula",
		NebulaNet:           "interdc",
		NebulaDev:           "neb1",
		OverlayProbeTargets: []string{"10.128.0.2"},
	}
}

func mtuEnv(t *testing.T) *env {
	t.Helper()
	e := fixture(t, nebulaWD())
	e.sd.On("is-enabled nebula@interdc", "enabled\n")
	e.sd.On("is-active nebula@interdc", "active\n")
	return e
}

func TestNebulaMTUBlackholeLatch(t *testing.T) {
	e := mtuEnv(t)
	n := e.n
	ctx := context.Background()
	st := n.mtuState()
	// Small ping OK, DF ping fails → 3 consecutive → latch + clamp.
	e.pingOK["10.128.0.2|false"] = true
	e.host.FailOn("-M do -s 1252", errCmdFail)
	for i := 0; i < nebula.MTUBlackholeNeeded; i++ {
		n.checkNebulaMTUBlackhole(ctx, st)
	}
	if _, err := os.Stat(filepath.Join(e.state,
		"state-nebula-mtu-blackhole")); err != nil {
		t.Fatal("nebula-mtu-blackhole latch missing after 3 DF fails")
	}
	// MSS clamp attempted on neb1 (iptables -C fails → -A runs).
	if !e.host.Ran("clamp-mss-to-pmtu") {
		t.Fatal("MSS clamp not attempted")
	}
	// DF ping succeeding clears the latch — and REMOVES the clamp
	// rule it installed (a left-behind TCPMSS keeps forcing PMTU MSS
	// on healthy overlay flows forever).
	e.host.On("-C POSTROUTING -o neb1", "ok\n") // rule present → -D runs
	e.host.Clear("-M do -s 1252")
	n.checkNebulaMTUBlackhole(ctx, st)
	if _, err := os.Stat(filepath.Join(e.state,
		"state-nebula-mtu-blackhole")); !os.IsNotExist(err) {
		t.Fatal("latch not cleared after DF ping recovers")
	}
	if !e.host.Ran("-D POSTROUTING -o neb1") {
		t.Fatal("MSS clamp rule not removed on recovery")
	}
	if strings.Contains(logLines(t, e), "MSS unclamp failed") {
		t.Fatalf("unclamp failed:\n%s", logLines(t, e))
	}
}

// TestNebulaMTUBlackholeRecoveryUnclampsCiliumWG: the blackhole
// remediation clamps cilium_wg0 alongside the overlay dev
// (maybeClampNebulaMSS) — recovery must remove BOTH rules, or the
// double-encapsulation path keeps forcing clamp-mss-to-pmtu forever
// after the fault cleared. The cilium_wg0 rule here came from the
// blackhole path (wgClampKnown false — the MTU invariant never fired
// in this fixture).
func TestNebulaMTUBlackholeRecoveryUnclampsCiliumWG(t *testing.T) {
	e := mtuEnv(t)
	n := e.n
	ctx := context.Background()
	st := n.mtuState()
	e.pingOK["10.128.0.2|false"] = true
	e.host.FailOn("-M do -s 1252", errCmdFail)
	// The fake answers "rule already present" by default — make the
	// -C probes fail so the latch phase actually INSTALLS (-A) on
	// both devs, like a host without the rules.
	e.host.FailOn("-C POSTROUTING", errCmdFail)
	for range nebula.MTUBlackholeNeeded {
		n.checkNebulaMTUBlackhole(ctx, st)
	}
	if _, err := os.Stat(filepath.Join(e.state,
		"state-nebula-mtu-blackhole")); err != nil {
		t.Fatal("latch missing after DF fails")
	}
	// The blackhole clamp covered BOTH devs.
	if !e.host.Ran("-A POSTROUTING -o neb1") ||
		!e.host.Ran("-A POSTROUTING -o cilium_wg0") {
		t.Fatal("blackhole clamp did not cover neb1 + cilium_wg0")
	}

	// Recovery with the invariant bit unset: both rules go.
	st.Mu.Lock()
	st.WGClampKnown = false
	st.Mu.Unlock()
	e.host.On("-C POSTROUTING -o neb1", "ok\n")       // rule present → -D
	e.host.On("-C POSTROUTING -o cilium_wg0", "ok\n") // rule present → -D
	e.host.Clear("-M do -s 1252")
	n.checkNebulaMTUBlackhole(ctx, st)
	if _, err := os.Stat(filepath.Join(e.state,
		"state-nebula-mtu-blackhole")); !os.IsNotExist(err) {
		t.Fatal("latch not cleared after DF ping recovers")
	}
	if !e.host.Ran("-D POSTROUTING -o neb1") {
		t.Fatal("neb1 clamp rule not removed on recovery")
	}
	if !e.host.Ran("-D POSTROUTING -o cilium_wg0") {
		t.Fatal("cilium_wg0 clamp rule not removed on blackhole recovery")
	}
}

// TestNebulaMTUBlackholeRecoveryKeepsInvariantClamp: when
// wgClampKnown is set the cilium_wg0 rule belongs to the MTU
// invariant (config drift that outlives the blackhole episode) —
// recovery unclamps the overlay dev ONLY and must not fork iptables
// against cilium_wg0 (the invariant re-installs the rule next probe
// cycle anyway).
func TestNebulaMTUBlackholeRecoveryKeepsInvariantClamp(t *testing.T) {
	e := mtuEnv(t)
	n := e.n
	ctx := context.Background()
	st := n.mtuState()
	e.pingOK["10.128.0.2|false"] = true
	e.host.FailOn("-M do -s 1252", errCmdFail)
	e.host.FailOn("-C POSTROUTING", errCmdFail)
	for range nebula.MTUBlackholeNeeded {
		n.checkNebulaMTUBlackhole(ctx, st)
	}
	if !e.host.Ran("-A POSTROUTING -o cilium_wg0") {
		t.Fatal("blackhole clamp did not cover cilium_wg0")
	}

	st.Mu.Lock()
	st.WGClampKnown = true // the invariant owns the cilium_wg0 rule
	st.Mu.Unlock()
	e.host.On("-C POSTROUTING -o neb1", "ok\n")
	e.host.ClearLog()
	e.host.Clear("-M do -s 1252")
	n.checkNebulaMTUBlackhole(ctx, st)
	if e.host.Ran("cilium_wg0") {
		t.Fatal("recovery touched the invariant-owned cilium_wg0 rule")
	}
	if !e.host.Ran("-D POSTROUTING -o neb1") {
		t.Fatal("neb1 clamp rule not removed on recovery")
	}
}

func TestNebulaMTUBlackholeNeedsSmallOK(t *testing.T) {
	e := mtuEnv(t)
	n := e.n
	ctx := context.Background()
	st := n.mtuState()
	// NO small ping → total overlay failure is NOT a PMTU latch.
	for i := 0; i < nebula.MTUBlackholeNeeded+1; i++ {
		n.checkNebulaMTUBlackhole(ctx, st)
	}
	if _, err := os.Stat(filepath.Join(e.state,
		"state-nebula-mtu-blackhole")); !os.IsNotExist(err) {
		t.Fatal("latch set with no alive peer — wrong verdict")
	}
	// Overlay not active → gated out entirely.
	n.cfg.Watchdog.OverlayActive = "tinc"
	n.checkNebulaMTUBlackhole(ctx, st)
	if e.host.Ran("-M do") {
		t.Fatal("DF probe ran while overlay=tinc")
	}
}

func TestNebulaMTUMetric(t *testing.T) {
	e := mtuEnv(t)
	n := e.n
	st := n.mtuState()
	dir := t.TempDir()
	n.cfg.TextfileDir = dir
	n.writeMTUBHMetric(st)
	b, err := os.ReadFile(filepath.Join(dir, "node-agent-nebula-mtu.prom"))
	if err != nil {
		t.Fatalf("metric file missing: %v", err)
	}
	if !strings.Contains(string(b),
		"node_agent_nebula_mtu_blackhole 0") {
		t.Fatalf("metric wrong:\n%s", b)
	}
	// Latch → gauge flips to 1.
	n.state.Enter("nebula-mtu-blackhole", "test")
	n.writeMTUBHMetric(st)
	b, _ = os.ReadFile(filepath.Join(dir, "node-agent-nebula-mtu.prom"))
	if !strings.Contains(string(b),
		"node_agent_nebula_mtu_blackhole 1") {
		t.Fatalf("metric not latched:\n%s", b)
	}
}

// ciliumSysfsMTU renders Host sysfs MTU files for the invariant check.
func ciliumSysfsMTU(t *testing.T, mtus map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for dev, mtu := range mtus {
		path := filepath.Join(root, "sys", "class", "net", dev, "mtu")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(mtu+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// The cilium_wg0 MTU invariant is config-drift enforcement,
// not a blackhole symptom — it must run EVERY probe cycle, including
// when neb1 is fully healthy (DF ping passes → no latch, no
// maybeClampNebulaMSS). A cilium_wg0 sized against the underlay
// (1420 > nebula 1300−80) must be caught + MSS-clamped here, not only
// after the blackhole latches.
func TestCiliumWGMTUInvariantOnHealthyOverlay(t *testing.T) {
	e := mtuEnv(t)
	n := e.n
	ctx := context.Background()
	st := n.mtuState()
	n.cfg.HostRoot = ciliumSysfsMTU(t, map[string]string{
		"neb1":       "1300",
		"cilium_wg0": "1420",
	})
	// Healthy overlay: small ping answers AND DF ping passes — no
	// blackhole, no clamp via maybeClampNebulaMSS.
	e.pingOK["10.128.0.2|false"] = true
	n.checkNebulaMTUBlackhole(ctx, st)
	if _, err := os.Stat(filepath.Join(e.state,
		"state-nebula-mtu-blackhole")); !os.IsNotExist(err) {
		t.Fatal("latch set on healthy DF ping")
	}
	if !e.host.Ran("-o cilium_wg0") {
		t.Fatal("cilium_wg0 invariant not enforced on a healthy overlay — MSS clamp missing")
	}
}

// Compliant control: cilium_wg0 within the invariant (1200 <= 1300−80)
// must NOT trigger a clamp on the healthy-overlay path.
func TestCiliumWGMTUInvariantCompliantNoClamp(t *testing.T) {
	e := mtuEnv(t)
	n := e.n
	ctx := context.Background()
	st := n.mtuState()
	n.cfg.HostRoot = ciliumSysfsMTU(t, map[string]string{
		"neb1":       "1300",
		"cilium_wg0": "1200",
	})
	e.pingOK["10.128.0.2|false"] = true
	n.checkNebulaMTUBlackhole(ctx, st)
	if e.host.Ran("-o cilium_wg0") {
		t.Fatal("clamp fired although cilium_wg0 satisfies the MTU invariant")
	}
}

// --- prober loop ---

// The prober loop ticks on the nethealth Interval, probes every 5th
// invocation, and writes the gauge EVERY invocation; an unset
// Interval falls back to the module default instead of a zero
// ticker.
func TestMTUProbeLoopTicksAndDefaults(t *testing.T) {
	dir := t.TempDir()
	e := mtuEnv(t)
	n := e.n
	n.cfg.TextfileDir = dir
	st := n.mtuState()
	n.cfg.Interval = 5 * time.Millisecond // fast ticks
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		n.mtuProbeLoop(ctx, st)
	}()
	waitForCond(t, 2*time.Second, func() bool {
		st.Mu.Lock()
		defer st.Mu.Unlock()
		return st.Cycle >= 6
	})
	cancel()
	<-done
	st.Mu.Lock()
	probed := st.Cycle >= 5 // cycle 5 is the first %5==0 tick
	st.Mu.Unlock()
	if !probed {
		t.Fatalf("no probe tick reached within %d cycles", st.Cycle)
	}
	if _, err := os.Stat(filepath.Join(dir, "node-agent-nebula-mtu.prom")); err != nil {
		t.Fatalf("gauge not written on off-invocations: %v", err)
	}

	// Zero Interval → the module default keeps the ticker sane; the
	// up-front invocation still counts as cycle #1 and writes the
	// gauge.
	e2 := mtuEnv(t)
	e2.n.cfg.Interval = 0
	st2 := e2.n.mtuState()
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		e2.n.mtuProbeLoop(ctx2, st2)
	}()
	// The up-front invocation is cycle #1 even on the 2m default.
	waitForCond(t, 2*time.Second, func() bool {
		st2.Mu.Lock()
		defer st2.Mu.Unlock()
		return st2.Cycle >= 1
	})
	cancel2()
	<-done2
	st2.Mu.Lock()
	defer st2.Mu.Unlock()
	if st2.Cycle != 1 {
		t.Fatalf("up-front invocation not counted: cycle=%d", st2.Cycle)
	}
}

// The MSS clamp rate limit: the first latch spends the 30m budget,
// immediate re-invocations are no-ops (no extra iptables forks), and
// the clamp falls back to the neb1 default dev name when the conf
// carries none. A FAILED -A must NOT spend the budget — the next
// tick retries immediately while flows still blackhole.
func TestMaybeClampNebulaMSSRateLimitAndFailure(t *testing.T) {
	e := mtuEnv(t)
	n := e.n
	ctx := context.Background()
	st := n.mtuState()
	// Rule absent (-C fails) and -A failing: clamp fails, budget not
	// spent.
	e.host.FailOn("-C POSTROUTING", errCmdFail)
	e.host.FailOn("-A POSTROUTING", errCmdFail)
	n.maybeClampNebulaMSS(ctx, n.cfg.Watchdog, st)
	if !strings.Contains(logLines(t, e), "MSS clamp failed on neb1") {
		t.Fatalf("missing clamp-failure log:\n%s", logLines(t, e))
	}
	st.Mu.Lock()
	spent := !st.LastClamp.IsZero()
	st.Mu.Unlock()
	if spent {
		t.Fatal("clamp budget spent on a failed iptables run")
	}
	// Now let the -A succeed: budget spent, both devs clamped
	// (NebulaDev=neb1 here; the empty-dev default is covered below).
	e.host.Clear("-A POSTROUTING")
	n.maybeClampNebulaMSS(ctx, n.cfg.Watchdog, st)
	st.Mu.Lock()
	spent = !st.LastClamp.IsZero()
	st.Mu.Unlock()
	if !spent {
		t.Fatal("clamp budget not spent on a delivered clamp")
	}
	e.host.ClearLog()
	n.maybeClampNebulaMSS(ctx, n.cfg.Watchdog, st) // inside 30m window
	if e.host.Ran("iptables") {
		t.Fatalf("clamp re-forked inside the 30m rate limit: %v", e.host.Cmds())
	}
}

// An empty NebulaDev falls back to the neb1 script constant —
// neither an empty iptables -o nor a panic.
func TestMaybeClampNebulaMSSEmptyDev(t *testing.T) {
	e := mtuEnv(t)
	n := e.n
	ctx := context.Background()
	wd := &watchdogconf.Config{} // no NebulaDev
	n.maybeClampNebulaMSS(ctx, wd, n.mtuState())
	if !e.host.Ran("-o neb1") {
		t.Fatalf("clamp did not target the neb1 default dev: %v", e.host.Cmds())
	}
}

// unclampMSSOn: a rule the -C probe cannot confirm is a silent
// no-op; a confirmed rule whose -D fails is logged and leaves the
// mss_unclamp metric alone.
func TestUnclampMSSPaths(t *testing.T) {
	e := mtuEnv(t)
	n := e.n
	ctx := context.Background()
	// Rule absent/uncheckable → no-op (fixture fake answers -C with
	// success by default; force failure).
	e.host.FailOn("-C POSTROUTING -o neb1", errCmdFail)
	e.host.ClearLog()
	n.UnclampMSSOn(ctx, "neb1")
	if e.host.Ran("-D POSTROUTING") {
		t.Fatal("unclamp -D ran without a confirmed rule")
	}
	// Rule present, delete fails → logged, no metric.
	e.host.On("-C POSTROUTING -o neb1", "ok\n")
	e.host.FailOn("-D POSTROUTING -o neb1", errCmdFail)
	n.UnclampMSSOn(ctx, "neb1")
	if !strings.Contains(logLines(t, e), "MSS unclamp failed on neb1") {
		t.Fatalf("missing unclamp-failure log:\n%s", logLines(t, e))
	}
	if got := promtest.ToFloat64(n.actions.WithLabelValues(
		nebula.MTUCheckName, "mss_unclamp")); got != 0 {
		t.Fatalf("mss_unclamp metric=%v want 0 on failed delete", got)
	}
	// Successful delete → metric + ACTION line.
	e.host.On("-D POSTROUTING -o neb1", "")
	e.host.ClearLog()
	n.UnclampMSSOn(ctx, "neb1")
	if got := promtest.ToFloat64(n.actions.WithLabelValues(
		nebula.MTUCheckName, "mss_unclamp")); got != 1 {
		t.Fatalf("mss_unclamp metric=%v want 1", got)
	}
	if !strings.Contains(logLines(t, e),
		"removed the TCP MSS clamp on neb1") {
		t.Fatalf("missing unclamp ACTION line:\n%s", logLines(t, e))
	}
}

// sysfsMTU parses the interface MTU; junk content is an error, not
// a zero MTU that would satisfy the invariant.
func TestSysfsMTUParsing(t *testing.T) {
	e := mtuEnv(t)
	root := t.TempDir()
	e.n.cfg.HostRoot = root
	if _, err := e.n.SysfsMTU("absent0"); err == nil {
		t.Fatal("missing dev MTU read succeeded")
	}
	path := filepath.Join(root, "sys", "class", "net", "junk0", "mtu")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not-a-number\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := e.n.SysfsMTU("junk0"); err == nil {
		t.Fatal("garbage MTU parsed without error")
	}
}

// The invariant needs BOTH MTUs: a cilium_wg0 with a readable MTU
// but an unreadable nebula dev MTU must not clamp on a half-read
// comparison.
func TestCiliumWGMTUInvariantMissingNebMTU(t *testing.T) {
	e := mtuEnv(t)
	n := e.n
	ctx := context.Background()
	st := n.mtuState()
	n.cfg.HostRoot = ciliumSysfsMTU(t, map[string]string{
		"cilium_wg0": "1420", // violating — but neb1 MTU unreadable
	})
	n.CheckCiliumWGMTUInvariant(ctx, "neb1", st)
	if e.host.Ran("-o cilium_wg0") {
		t.Fatal("clamp decided on a half-read invariant")
	}
	st.Mu.Lock()
	known := st.WGClampKnown
	st.Mu.Unlock()
	if known {
		t.Fatal("wgClampKnown set without a complete invariant check")
	}
}

// A violating cilium_wg0 whose clamp exec fails warns and keeps
// wgClampKnown unset — the next probe cycle retries the clamp.
func TestCiliumWGMTUInvariantClampFailureRetries(t *testing.T) {
	e := mtuEnv(t)
	n := e.n
	ctx := context.Background()
	st := n.mtuState()
	n.cfg.HostRoot = ciliumSysfsMTU(t, map[string]string{
		"neb1":       "1300",
		"cilium_wg0": "1420",
	})
	e.host.FailOn("-C POSTROUTING -o cilium_wg0", errCmdFail)
	e.host.FailOn("-A POSTROUTING -o cilium_wg0", errCmdFail)
	n.CheckCiliumWGMTUInvariant(ctx, "neb1", st)
	if !strings.Contains(logLines(t, e), "cilium_wg0 MSS clamp failed") {
		t.Fatalf("missing invariant clamp-failure warn:\n%s", logLines(t, e))
	}
	st.Mu.Lock()
	known := st.WGClampKnown
	st.Mu.Unlock()
	if known {
		t.Fatal("wgClampKnown set although the clamp never landed")
	}
	// And the healthy DF ping still passes below (overlay unaffected).
	e.pingOK["10.128.0.2|false"] = true
	n.checkNebulaMTUBlackhole(ctx, st)
	if _, err := os.Stat(filepath.Join(e.state,
		"state-nebula-mtu-blackhole")); !os.IsNotExist(err) {
		t.Fatal("blackhole latched without a DF failure")
	}
}

// The textfile gauge degrades silently when the directory cannot be
// created or the write fails — the probe loop must survive a broken
// node-exporter mount.
func TestMTUMetricWriteFailuresDegrade(t *testing.T) {
	e := mtuEnv(t)
	n := e.n
	st := n.mtuState()
	// A FILE squatting the textfile dir path → MkdirAll fails.
	blocker := filepath.Join(t.TempDir(), "textfile")
	testutil.WriteFile(t, blocker, "not a dir\n")
	n.cfg.TextfileDir = blocker
	n.writeMTUBHMetric(st) // mkdir fails → debug log, return

	// A read-only dir → promfile.Write fails after mkdir succeeds.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	st.Mu.Lock()
	st.LastGauge = "" // force the write attempt
	st.Mu.Unlock()
	n.cfg.TextfileDir = dir
	n.writeMTUBHMetric(st)
	if _, err := os.Stat(filepath.Join(dir, "node-agent-nebula-mtu.prom")); !os.IsNotExist(err) {
		t.Fatal("metric file appeared despite a failed write")
	}
}
