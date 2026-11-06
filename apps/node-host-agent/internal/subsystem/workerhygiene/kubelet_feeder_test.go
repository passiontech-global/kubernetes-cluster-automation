// kubelet_feeder_test.go — T15 systemd-watchdog kubelet feeder:
// 15s healthz ticks, Gate-0 re-probe, G1-G5 remediate gates,
// activation flips, and the API backend port defaulting.
package workerhygiene

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

// TestWithDefaultAPIPort covers the backend port defaulting — the
// trailing-colon form ("1.2.3.4:") previously passed through into a
// malformed URL that failed every /livez probe silently.
func TestWithDefaultAPIPort(t *testing.T) {
	for in, want := range map[string]string{
		"1.2.3.4":      "1.2.3.4:6443",
		"1.2.3.4:":     "1.2.3.4:6443",
		"1.2.3.4:7443": "1.2.3.4:7443",
		"[::1]:6443":   "[::1]:6443",
		"[::1]:":       "[::1]:6443",
	} {
		if got := withDefaultAPIPort(in); got != want {
			t.Fatalf("withDefaultAPIPort(%q)=%q want %q", in, got, want)
		}
	}
}

// --- T15: kubelet watchdog feeder + remediate gates ---

// feedTicks runs n feeder ticks synchronously (the 15s loop body).
func feedTicks(e *env, n int) {
	for i := 0; i < n; i++ {
		e.h.kubeletFeedTick(context.Background())
	}
}

func TestKubeletFeederFailThenRestart(t *testing.T) {
	e := fixture(t)
	// Happy path: :10248 dead, all gates pass (uptime absent →
	// fail-open, k0sworker settled, no overload latch, API fallback
	// livez unconfigured → probe map default nil = alive).
	e.sdReply["restart k0sworker.service"] = ""
	e.sdReply["reset-failed k0sworker.service"] = ""

	feedTicks(e, defaultKubeletWdMaxFail-1)
	if e.h.KubeletWdFails != defaultKubeletWdMaxFail-1 {
		t.Fatalf("fails=%d want %d", e.h.KubeletWdFails, defaultKubeletWdMaxFail-1)
	}
	if e.sdRan("restart k0sworker") {
		t.Fatal("restart before MaxFail consecutive fails")
	}
	feedTicks(e, 1) // 4th fail → gates → act
	if e.h.KubeletWdFails != 0 {
		t.Fatalf("fails=%d want 0 (re-armed after remediate)", e.h.KubeletWdFails)
	}
	if !e.sdRan("reset-failed k0sworker.service") {
		t.Fatalf("reset-failed not issued, cmds=%v", e.sdcmds)
	}
	if !e.sdRan("restart k0sworker.service") {
		t.Fatalf("k0sworker restart not issued, cmds=%v", e.sdcmds)
	}
	if _, err := os.Stat(filepath.Join(e.state, "last-restart")); err != nil {
		t.Fatal("last-restart budget not spent")
	}
	if !strings.Contains(logLines(t, e),
		"ACTION: restarting k0sworker (reason=systemd-watchdog-kubelet-healthz-60s") {
		t.Fatalf("missing NPD ACTION contract line:\n%s", logLines(t, e))
	}
}

func TestKubeletFeederProbeOKResetsFailsAndClearsLatch(t *testing.T) {
	e := fixture(t)
	latch := filepath.Join(e.state, "state-kubelet-healthz-down")
	writeFile(t, latch, "1\n")
	feedTicks(e, 2)
	if e.h.KubeletWdFails != 2 {
		t.Fatalf("fails=%d want 2", e.h.KubeletWdFails)
	}
	e.bodyOK[e.h.Cfg.Kubelet.WdProbeURL] = true
	e.h.kubeletFeedTick(context.Background())
	if e.h.KubeletWdFails != 0 {
		t.Fatalf("fails=%d want 0 after probe OK", e.h.KubeletWdFails)
	}
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("healthz-down latch kept after probe OK")
	}
	if !strings.Contains(logLines(t, e), "STATE-EXIT: kubelet-healthz-down") {
		t.Fatalf("missing STATE-EXIT log:\n%s", logLines(t, e))
	}
}

func TestKubeletFeederGateUptime(t *testing.T) {
	e := fixture(t)
	writeFile(t, filepath.Join(e.proc, "uptime"), "600.5 0\n") // <1200s
	// Gate-0 re-probe runs before every gate: 4 failed ticks + 2
	// failed re-probes before G1 is even evaluated.
	var probes int
	e.h.Cfg.Seams.ProbeBodyOK = func(_ context.Context, _ string, _ time.Duration) bool {
		probes++
		return false
	}
	feedTicks(e, defaultKubeletWdMaxFail)
	if e.sdRan("restart k0sworker") {
		t.Fatal("restart under uptime gate")
	}
	if probes != defaultKubeletWdMaxFail+2 {
		t.Fatalf("probe calls=%d want %d (4 ticks + 2 re-probes)",
			probes, defaultKubeletWdMaxFail+2)
	}
	if !strings.Contains(logLines(t, e), "SKIP(G1-uptime)") {
		t.Fatalf("missing G1 log:\n%s", logLines(t, e))
	}
}

func TestKubeletFeederGateSettle(t *testing.T) {
	e := fixture(t)
	// k0sworker restarted a minute ago — kubelet may still be initing
	// (uptimeµs - 60s → age 60s < 180s settle window).
	e.sdReply["ActiveEnterTimestampMonotonic --value k0sworker.service"] = "7140500000\n"
	feedTicks(e, defaultKubeletWdMaxFail)
	if e.sdRan("restart k0sworker") {
		t.Fatal("restart inside the 180s settle window")
	}
	if !strings.Contains(logLines(t, e), "SKIP(G2-settle)") {
		t.Fatalf("missing G2 log:\n%s", logLines(t, e))
	}
}

func TestKubeletFeederGateOverload(t *testing.T) {
	e := fixture(t)
	writeFile(t, filepath.Join(e.state, "state-node-overloaded"), "1\n")
	feedTicks(e, defaultKubeletWdMaxFail)
	if e.sdRan("restart k0sworker") {
		t.Fatal("restart under node-overloaded")
	}
	if !strings.Contains(logLines(t, e), "SKIP(G3-overload)") {
		t.Fatalf("missing G3 log:\n%s", logLines(t, e))
	}
}

func TestKubeletFeederGateAPIServer(t *testing.T) {
	e := fixture(t)
	// No backends configured → fallback api-local-lb livez is probed;
	// dead → node isolated → no restart.
	e.probes[e.h.Cfg.Kubelet.APIFallbackURL] = errors.New("refused")
	feedTicks(e, defaultKubeletWdMaxFail)
	if e.sdRan("restart k0sworker") {
		t.Fatal("restart while API unreachable")
	}
	if !strings.Contains(logLines(t, e), "SKIP(G4-apiserver)") {
		t.Fatalf("missing G4 log:\n%s", logLines(t, e))
	}
}

// TestKubeletFeederGateAPIServerNon200StillLive: the G4 verdict is
// listener-liveness, not health — an apiserver or api-local-lb
// answering ANY HTTP code (503/401/403) means the node is NOT
// isolated and remediation must proceed (curl -sk parity: the probe
// used to demand 2xx and read a degraded endpoint as "unreachable").
func TestKubeletFeederGateAPIServerNon200StillLive(t *testing.T) {
	e := fixture(t)
	e.status[e.h.Cfg.Kubelet.APIFallbackURL] = 503
	e.sdReply["restart k0sworker.service"] = ""
	e.sdReply["reset-failed k0sworker.service"] = ""
	feedTicks(e, defaultKubeletWdMaxFail)
	if strings.Contains(logLines(t, e), "SKIP(G4-apiserver)") {
		t.Fatalf("G4 skipped on a 503 answer — listener is alive:\n%s",
			logLines(t, e))
	}
	if !e.sdRan("restart k0sworker.service") {
		t.Fatal("remediation blocked although /livez answered 503")
	}
}

func TestKubeletFeederGateAPIServerConfiguredBackends(t *testing.T) {
	e := fixture(t)
	// Configured API_BACKENDS are probed (ports preserved); the
	// fallback URL must NOT be consulted — kill it and keep one
	// backend alive.
	e.h.Cfg.Watchdog = &watchdogconf.Config{
		Disabled: map[string]bool{},
		APIBackends: []watchdogconf.APIBackend{
			{Name: "ctrl1", Addr: "10.0.0.9:6443"},
			{Name: "ctrl2", Addr: "10.0.0.10:6443"},
		},
	}
	e.probes["https://10.0.0.9:6443/livez"] = errors.New("refused")
	// 10.0.0.10 unconfigured → probe map default nil = alive.
	e.probes[e.h.Cfg.Kubelet.APIFallbackURL] = errors.New("refused")
	e.sdReply["restart k0sworker.service"] = ""
	feedTicks(e, defaultKubeletWdMaxFail)
	if !e.sdRan("restart k0sworker.service") {
		t.Fatal("restart blocked although a configured backend is live")
	}
}

func TestKubeletFeederGateRateLimitLatches(t *testing.T) {
	e := fixture(t)
	// Budget spent moments ago → G5 skips and escalates via the latch.
	writeFile(t, filepath.Join(e.state, "last-restart"),
		fmt.Sprintf("%d\n", e.now.Unix()))
	latch := filepath.Join(e.state, "state-kubelet-healthz-down")
	feedTicks(e, defaultKubeletWdMaxFail)
	if e.sdRan("restart k0sworker") {
		t.Fatal("restart inside 30m cooldown")
	}
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("kubelet-healthz-down latch missing (NHC escalation): %v", err)
	}
	if !strings.Contains(logLines(t, e), "SKIP(G5-ratelimit)") {
		t.Fatalf("missing G5 log:\n%s", logLines(t, e))
	}
	if strings.Contains(logLines(t, e), "ACTION: restarting k0sworker") {
		t.Fatal("ACTION logged inside cooldown")
	}
	// A recovered kubelet clears the escalation latch again.
	e.bodyOK[e.h.Cfg.Kubelet.WdProbeURL] = true
	e.h.kubeletFeedTick(context.Background())
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch kept after kubelet recovered")
	}
}

func TestKubeletFeederStandsDownWhenWorkerInactive(t *testing.T) {
	e := fixture(t)
	// PartOf=k0sworker.service parity: an intentionally stopped unit
	// must not accumulate probe fails toward a restart — and a stale
	// healthz-down latch must clear too, else NHC→SNR reboots a
	// deliberately-stopped node.
	latch := filepath.Join(e.state, "state-kubelet-healthz-down")
	writeFile(t, latch, "1\n")
	e.sdReply["systemctl is-active k0sworker.service"] = "inactive\n"
	feedTicks(e, defaultKubeletWdMaxFail+1)
	if e.h.KubeletWdFails != 0 {
		t.Fatalf("fails=%d want 0 while k0sworker inactive", e.h.KubeletWdFails)
	}
	if e.sdRan("restart k0sworker") {
		t.Fatal("restart while k0sworker intentionally down")
	}
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("healthz-down latch kept while k0sworker intentionally stopped")
	}
}

func TestKubeletFeederActivation(t *testing.T) {
	e := fixture(t)
	if !e.h.kubeletFeederActive() {
		t.Fatal("feeder inactive on a default worker node (unit file present)")
	}
	// Off the worker list and no unit file → inactive.
	if err := os.Remove(e.unit); err != nil {
		t.Fatal(err)
	}
	if e.h.kubeletFeederActive() {
		t.Fatal("feeder active without unit file and without host listing")
	}
	// Listed in systemd_watchdog_hosts → active regardless of the
	// unit file (the shell install gate).
	e.h.Cfg.Kubelet.WatchdogHosts = []string{"node-x", "node-a"}
	if !e.h.kubeletFeederActive() {
		t.Fatal("feeder inactive although node is listed")
	}
	// WD_SIG_KUBELET_WATCHDOG=off kills it even when listed.
	e.h.Cfg.Watchdog = &watchdogconf.Config{
		Disabled: map[string]bool{"kubelet-watchdog": true},
	}
	if e.h.kubeletFeederActive() {
		t.Fatal("feeder active with WD_SIG kill switch off")
	}
	e.h.Cfg.Watchdog = nil
	e.h.Cfg.Kubelet.WatchdogHosts = nil
	if e.h.kubeletFeederActive() {
		t.Fatal("feeder active without unit file and unlisted")
	}
}

func TestKubeletFeederLoopStopsOnCancel(t *testing.T) {
	e := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.h.runKubeletFeeder(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runKubeletFeeder did not return after cancel")
	}
}

// --- remediate Gate-0 re-probe + feeder activation edges ---

func TestKubeletRemediateReprobeSelfCorrects(t *testing.T) {
	e := fixture(t)
	// Shell Gate-1 parity: after 4 failed ticks the remediate pass
	// re-probes :10248 twice ~3s apart before any gate. One "ok" —
	// the streak was a CPU-steal probe timeout — self-corrects: no
	// gates, no restart, fail streak and latch dropped.
	latch := filepath.Join(e.state, "state-kubelet-healthz-down")
	writeFile(t, latch, "1\n") // leftover from an earlier episode
	var probes int
	e.h.Cfg.Seams.ProbeBodyOK = func(_ context.Context, _ string, _ time.Duration) bool {
		probes++
		return probes > defaultKubeletWdMaxFail // ticks 1..4 fail, re-probe 1 OK
	}
	feedTicks(e, defaultKubeletWdMaxFail)
	if e.sdRan("restart k0sworker") {
		t.Fatal("restart despite re-probe self-correct (steal blip kills kubelets)")
	}
	if e.h.KubeletWdFails != 0 {
		t.Fatalf("fails=%d want 0 after re-probe ok", e.h.KubeletWdFails)
	}
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("healthz-down latch kept after re-probe ok")
	}
	if !strings.Contains(logLines(t, e), "SKIP(G0-reprobe)") {
		t.Fatalf("missing G0 log:\n%s", logLines(t, e))
	}
	// One "ok" exits early — exactly one re-probe call, not two.
	if probes != defaultKubeletWdMaxFail+1 {
		t.Fatalf("probes=%d want %d (4 ticks + 1 re-probe)", probes, defaultKubeletWdMaxFail+1)
	}
}

func TestKubeletRemediateReprobeSecondProbeOK(t *testing.T) {
	e := fixture(t)
	// First re-probe fails, second answers — still self-corrects.
	var probes int
	e.h.Cfg.Seams.ProbeBodyOK = func(_ context.Context, _ string, _ time.Duration) bool {
		probes++
		return probes > defaultKubeletWdMaxFail+1
	}
	feedTicks(e, defaultKubeletWdMaxFail)
	if e.sdRan("restart k0sworker") {
		t.Fatal("restart although the second re-probe answered")
	}
	if probes != defaultKubeletWdMaxFail+2 {
		t.Fatalf("probes=%d want %d (4 ticks + 2 re-probes)", probes, defaultKubeletWdMaxFail+2)
	}
}

func TestKubeletFeederReactivationResetsFails(t *testing.T) {
	e := fixture(t)
	// No "start" log while the feeder never activates — the goroutine
	// runs fleet-wide but logs only on an actual activation flip.
	if strings.Contains(logLines(t, e), "kubelet-feeder: start") {
		t.Fatal("start log before any tick")
	}
	// Two failed ticks while active, then deactivation.
	feedTicks(e, 2)
	if e.h.KubeletWdFails != 2 {
		t.Fatalf("setup fails=%d want 2", e.h.KubeletWdFails)
	}
	if err := os.Remove(e.unit); err != nil {
		t.Fatal(err)
	}
	e.h.kubeletFeedTick(context.Background()) // inactive tick — fails persist
	if e.h.KubeletWdFails != 2 {
		t.Fatalf("fails=%d want 2 kept while inactive", e.h.KubeletWdFails)
	}
	// Re-activation (unit file reappears) must drop the stale streak
	// before it can reach MaxFail — and logs exactly one "start" per
	// activation (the first active tick + this flip).
	e.bodyOK[e.h.Cfg.Kubelet.WdProbeURL] = true
	writeFile(t, e.unit, "[Service]\nExecStart=/usr/bin/k0s worker --node-ip=10.1.2.3\n")
	e.h.kubeletFeedTick(context.Background())
	if e.h.KubeletWdFails != 0 {
		t.Fatalf("fails=%d want 0 on re-activation", e.h.KubeletWdFails)
	}
	if got := strings.Count(logLines(t, e), "kubelet-feeder: start"); got != 2 {
		t.Fatalf("start logs=%d want 2 (one per activation)", got)
	}
	if !strings.Contains(logLines(t, e), "dropping 2 stale fails") {
		t.Fatalf("missing stale-fails log:\n%s", logLines(t, e))
	}
}
