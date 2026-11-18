// argocd_agent_spin_test.go — coverage for the argocd-agent-spin
// check (argocd-agent-spin): the log-spin predicate, the CPU channel, the
// FirstSeenLedger persistence window and the gated pod delete.
package gitops

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// argocd-agent-spin — argocd-agent-spin
// ---------------------------------------------------------------------------

// spinLogBody renders the log body nErr repeated stream errors with
// an optional successful-reconnect line appended after them.
func spinLogBody(nErr int, reconnectAfter bool) string {
	return spinLogBodyAt(nErr, reconnectAfter,
		time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC))
}

// spinLogBodyAt renders the same body with caller-chosen line
// timestamps — Run-level tests need stamps newer than the check's
// frozen `base` or the freshness gate (correctly) reads the tail as
// stale on the second sweep.
func spinLogBodyAt(nErr int, reconnectAfter bool, ts time.Time) string {
	var b strings.Builder
	stamp := ts.UTC().Format(time.RFC3339)
	for range nErr {
		b.WriteString(stamp + " err agent agent.go:88 Error receiving from stream: rpc error: code = Unknown desc = stream.Recv failed: transport is closing\n")
	}
	if reconnectAfter {
		b.WriteString(ts.Add(time.Minute).UTC().Format(time.RFC3339) +
			" info agent stream.go:41 connected to remote argocd — stream established\n")
	}
	return b.String()
}

// TestScanAgentSpinLines pins the pure predicate: >=15 unresolved
// error lines spin; a successful reconnect AFTER the last error does
// not; errors recovered before later reconnects are history.
func TestScanAgentSpinLines(t *testing.T) {
	errs, rec, _, _ := scanAgentSpinLines(strings.NewReader(spinLogBody(15, false)), time.Time{}, false)
	if errs != 15 || rec {
		t.Fatalf("15 unresolved errors = %d,%v — want spin", errs, rec)
	}
	errs, _, _, _ = scanAgentSpinLines(strings.NewReader(spinLogBody(14, false)), time.Time{}, false)
	if errs >= 15 {
		t.Fatalf("14 errors must stay under the threshold, got %d", errs)
	}
	_, rec, _, _ = scanAgentSpinLines(strings.NewReader(spinLogBody(30, true)), time.Time{}, false)
	if !rec {
		t.Fatal("reconnect AFTER the last error must disarm the log channel")
	}
	// Reconnect BEFORE the errors — the loop resumed after it, spin.
	body := "connected to remote argocd\n" + spinLogBody(15, false)
	errs, rec, _, _ = scanAgentSpinLines(strings.NewReader(body), time.Time{}, false)
	if errs != 15 || rec {
		t.Fatalf("errors after the reconnect must spin: %d,%v", errs, rec)
	}
}

// agentPod builds a Running argocd-agent-agent pod created at created.
func agentPod(name string, created time.Time) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:         "argocd",
			Name:              name,
			CreationTimestamp: metav1.NewTime(created),
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

// agentLogReactor answers pod log reads with body (the fake GetLogs
// action carries no pod name — the cfLogReactor precedent).
func agentLogReactor(body string) ktesting.ReactionFunc {
	return func(a ktesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() != "log" {
			return false, nil, nil
		}
		return true, &runtime.Unknown{Raw: []byte(body)}, nil
	}
}

// agentLogLiveReactor re-renders the spin body on EVERY log read —
// stamps advance with the real clock, like a live spinning agent
// that keeps writing error lines. A static body reads as recovered
// under the scan-boundary freshness gate: its stamps never advance
// past the previous sweep's streamNewest, so the next scan counts
// zero fresh errors (correct dedup of the overlapping tail).
// agentLiveCall serializes the per-call stamp offset across EVERY
// agentLogLiveReactor instance — a test that swaps reactors
// mid-run (fail → revive) must still produce stamps strictly newer
// than the boundary the previous instance's scan stored.
var agentLiveCall atomic.Int64

func agentLogLiveReactor(nErr int, reconnectAfter bool) ktesting.ReactionFunc {
	return func(a ktesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() != "log" {
			return false, nil, nil
		}
		// RFC3339 stamps carry only SECOND precision — two sweeps
		// inside one real second would render identical stamps and
		// read as "no fresh errors". The shared per-call offset
		// keeps the stream's stamps strictly increasing like a
		// live spinner's, across reactor swaps too.
		n := agentLiveCall.Add(1)
		return true, &runtime.Unknown{Raw: []byte(
			spinLogBodyAt(nErr, reconnectAfter,
				time.Now().Add(time.Duration(n)*time.Second)))}, nil
	}
}

// A spinning pod whose log channel carries the unresolved signature
// persists through the 10m window, then the pod is deleted; the too-
// young sibling survives untouched (its own logs never matter — the
// age gate skips it before the log read).
func TestArgoCDAgentSpinDeletesAfterWindow(t *testing.T) {
	base := time.Now()
	spinning := agentPod("argocd-agent-agent-7f9c", base.Add(-30*time.Minute))
	young := agentPod("argocd-agent-agent-new00", base.Add(-time.Minute))
	cs := fake.NewSimpleClientset(spinning, young)
	cs.PrependReactor("get", "pods", agentLogLiveReactor(20, false))
	p := probetest.NewCheckProber(cs, testutil.NewDynamicClient(),
		NewArgoCDAgentSpinCheck)
	probetest.FreezeNow(p.Deps, base)
	chk := probetest.MustCheck[*argoCDAgentSpinCheck](t, p)

	// First sighting stamps the ledger — detection only, no delete.
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); res.Pass {
		t.Fatalf("spinning agent must FAIL: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("argocd").Get(ctx, spinning.Name, metav1.GetOptions{}); err != nil {
		t.Fatalf("first sighting must not delete yet: %v", err)
	}

	// Past the window the sustained signature deletes the pod.
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); res.Pass {
		t.Fatalf("sustained spin must FAIL: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("argocd").Get(ctx, spinning.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("sustained spin pod was not deleted")
	}
	if _, err := cs.CoreV1().Pods("argocd").Get(ctx, young.Name, metav1.GetOptions{}); err != nil {
		t.Fatalf("young pod deleted before the age gate: %v", err)
	}
}

// agentLogFailReactor answers pod log reads with err — the log
// channel unavailable, inconclusive never clean.
func agentLogFailReactor(err error) ktesting.ReactionFunc {
	return func(a ktesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() != "log" {
			return false, nil, nil
		}
		return true, nil, err
	}
}

// Inconclusive sweeps (cpu + log channels both unavailable) must
// carry the pod's first-seen entry through the keep-set — Prune may
// not wipe a clock the sweep could not re-evaluate, or a
// flaky-evidence spin never reaches argocdAgentWindow and never
// heals.
func TestArgoCDAgentSpinInconclusiveSweepKeepsSeen(t *testing.T) {
	base := time.Now()
	pod := agentPod("argocd-agent-agent-flaky", base.Add(-time.Hour))
	cs := fake.NewSimpleClientset(pod)
	cs.PrependReactor("get", "pods", agentLogLiveReactor(20, false))
	p := probetest.NewCheckProber(cs, testutil.NewDynamicClient(),
		NewArgoCDAgentSpinCheck)
	probetest.FreezeNow(p.Deps, base)
	chk := probetest.MustCheck[*argoCDAgentSpinCheck](t, p)

	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); res.Pass {
		t.Fatalf("first spin sighting must FAIL: %+v", res)
	}
	// The log channel dies for one sweep (the cpu channel is already
	// dead — no prometheus endpoint wired): inconclusive, not clean.
	cs.PrependReactor("get", "pods",
		agentLogFailReactor(errors.New("kubelet log read boom")))
	_ = chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	// The log channel revives past the window: the sustained spin
	// deletes the pod on the preserved clock.
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	cs.PrependReactor("get", "pods", agentLogLiveReactor(20, false))
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	if _, err := cs.CoreV1().Pods("argocd").Get(ctx, pod.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("flaky-evidence spin pod was not deleted — the inconclusive sweep wiped the first-seen clock")
	}
}

// A log signature the agent already recovered from (reconnect AFTER
// the last error) never deletes — and a quiet log keeps the check
// green.
func TestArgoCDAgentSpinRecoveredLogsPass(t *testing.T) {
	base := time.Now()
	pod := agentPod("argocd-agent-agent-recovered", base.Add(-time.Hour))
	cs := fake.NewSimpleClientset(pod)
	cs.PrependReactor("get", "pods", agentLogReactor(spinLogBodyAt(30, true, base.Add(30*time.Minute))))
	p := probetest.NewCheckProber(cs, testutil.NewDynamicClient(),
		NewArgoCDAgentSpinCheck)
	probetest.FreezeNow(p.Deps, base)
	chk := probetest.MustCheck[*argoCDAgentSpinCheck](t, p)

	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("recovered stream errors must pass: %+v", res)
	}
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("recovered stream errors must pass past the window: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("argocd").Get(ctx, pod.Name, metav1.GetOptions{}); err != nil {
		t.Fatalf("recovered pod deleted: %v", err)
	}
}

// cpuSpin is pure: the pod-matched series above argocdAgentCPU (0.5,
// strictly) is spin; the exact boundary, a series for another pod and
// an empty channel are not.
func TestArgoCDAgentSpinCPUPredicate(t *testing.T) {
	pod := agentPod("argocd-agent-agent-7f9c", time.Now().Add(-time.Hour))
	for _, tc := range []struct {
		name   string
		series []promq.Sample
		want   bool
	}{
		{"above threshold", []promq.Sample{
			{Metric: map[string]string{"pod": pod.Name}, Value: 0.6}}, true},
		{"exactly at threshold is not spin", []promq.Sample{
			{Metric: map[string]string{"pod": pod.Name}, Value: 0.5}}, false},
		{"other pod's series", []promq.Sample{
			{Metric: map[string]string{"pod": "argocd-agent-agent-other"}, Value: 2}}, false},
		{"no series", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := probetest.NewCheckProber(fake.NewSimpleClientset(),
				testutil.NewDynamicClient(), NewArgoCDAgentSpinCheck)
			chk := probetest.MustCheck[*argoCDAgentSpinCheck](t, p)
			if got := chk.cpuSpin(tc.series, pod); got != tc.want {
				t.Fatalf("cpuSpin = %v, want %v", got, tc.want)
			}
		})
	}
}

// Guard-branch skips: pods without the argocd-agent-agent- prefix,
// pods already terminating and non-Running pods are never tracked —
// the FirstSeenLedger stays empty and the check passes.
func TestArgoCDAgentSpinGuardBranchesSkip(t *testing.T) {
	base := time.Now()
	cs := fake.NewSimpleClientset(
		func() *corev1.Pod {
			p := agentPod("argocd-server-abc", base.Add(-time.Hour))
			return p
		}(),
		func() *corev1.Pod {
			p := agentPod("argocd-agent-agent-gone", base.Add(-time.Hour))
			now := metav1.NewTime(base)
			p.DeletionTimestamp = &now
			return p
		}(),
		func() *corev1.Pod {
			p := agentPod("argocd-agent-agent-pend", base.Add(-time.Hour))
			p.Status.Phase = corev1.PodPending
			return p
		}())
	cs.PrependReactor("get", "pods", agentLogReactor(spinLogBodyAt(50, false, base.Add(30*time.Minute))))
	p := probetest.NewCheckProber(cs, testutil.NewDynamicClient(),
		NewArgoCDAgentSpinCheck)
	probetest.FreezeNow(p.Deps, base)
	chk := probetest.MustCheck[*argoCDAgentSpinCheck](t, p)

	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("unqualified pods must pass: %+v", res)
	}
	if keys := probetest.LedgerKeys(&chk.seen); len(keys) != 0 {
		t.Fatalf("unqualified pods were tracked: %v", keys)
	}
}

// The 30m per-controller delete cooldown: after a delivered delete,
// a same-named replacement pod showing the same spin signature is
// detected but NOT re-deleted inside argocdAgentCool — the heals
// ledger suppresses the bounce.
func TestArgoCDAgentSpinDeleteCooldown(t *testing.T) {
	base := time.Now()
	testutil.CleanupMetric(t, argocdAgentSpinGauge,
		"argocd", "argocd-agent-agent-7f9c", "logs")
	pod := agentPod("argocd-agent-agent-7f9c", base.Add(-30*time.Minute))
	cs := fake.NewSimpleClientset(pod)
	cs.PrependReactor("get", "pods", agentLogLiveReactor(20, false))
	p := probetest.NewCheckProber(cs, testutil.NewDynamicClient(),
		NewArgoCDAgentSpinCheck)
	probetest.FreezeNow(p.Deps, base)
	chk := probetest.MustCheck[*argoCDAgentSpinCheck](t, p)

	// Detection at t0, delivered delete at t0+11m (past the window).
	chk.Run(probetest.SweepCtx(ctx, chk.Deps))
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); res.Pass {
		t.Fatalf("sustained spin must FAIL: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("argocd").Get(ctx, pod.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("original pod was not deleted past the window")
	}

	// Replacement pod (same controller key) spins again 9m later —
	// inside the 30m cooldown: detected, but not re-deleted.
	probetest.FreezeNow(p.Deps, base.Add(20*time.Minute))
	repl := agentPod("argocd-agent-agent-7f9c", base.Add(19*time.Minute))
	if _, err := cs.CoreV1().Pods("argocd").Create(ctx, repl, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create replacement: %v", err)
	}
	// The sweep may PASS here (the gauge series is already 1 and
	// re-emitting dedupes) — what matters is that the spin is still
	// detected and the replacement is NOT bounced inside the cooldown.
	if m := probetest.FindMetric(t, "node_automation_argocd_agent_spin",
		map[string]string{"namespace": "argocd",
			"pod": repl.Name, "reason": "logs"}); m == nil || m.GetGauge().GetValue() != 1 {
		t.Fatal("replacement spin not detected")
	}
	if _, err := cs.CoreV1().Pods("argocd").Get(ctx, repl.Name, metav1.GetOptions{}); err != nil {
		t.Fatal("replacement bounced inside the 30m cooldown")
	}

	// Past the cooldown the replacement is fair game again.
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute+argocdAgentCool+11*time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); res.Pass {
		t.Fatalf("sustained spin past cooldown must FAIL: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("argocd").Get(ctx, repl.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("replacement not deleted after the cooldown expired")
	}
}

// The scan boundary must survive a sweep where the CPU channel
// answered instead of the log channel — the pod is still a
// candidate, only this sweep's channel choice differed. The old
// code deleted logScanAt for every pod not log-scanned that sweep,
// so the next log read bootstrapped fresh and re-counted the whole
// overlapping 15m tail (stale errors re-flagging as new).
func TestArgoCDAgentSpinLogBoundarySurvivesCPUChannel(t *testing.T) {
	base := time.Now()
	pod := agentPod("argocd-agent-agent-flap", base.Add(-time.Hour))
	cs := fake.NewSimpleClientset(pod)

	// The prom responder flips hot/quiet per sweep: quiet → the
	// log channel runs; hot → cpuSpin wins and the log fetch is
	// skipped entirely.
	var hot atomic.Bool
	srv, _ := probetest.PromTestServer(t,
		func(string) []probetest.PromTestSample {
			if !hot.Load() {
				return nil
			}
			return []probetest.PromTestSample{{
				Labels: map[string]string{"pod": pod.Name},
				Value:  2.0, // > argocdAgentCPU
			}}
		})

	// Every sweep reads the SAME tail — error stamps fixed at the
	// sweep-1 boundary. Only the FIRST scan may count them; later
	// scans must see zero fresh errors (overlapping-tail dedup).
	stamp := base.UTC().Format(time.RFC3339)
	body := strings.Repeat(stamp+
		" err agent agent.go:88 Error receiving from stream: "+
		"rpc error: code = Unknown desc = stream.Recv failed: "+
		"transport is closing\n", 20)
	cs.PrependReactor("get", "pods", agentLogReactor(body))
	p := probetest.NewCheckProber(cs, testutil.NewDynamicClient(),
		NewArgoCDAgentSpinCheck)
	p.Deps.Cfg.HTTPContent.URL = srv.URL
	p.Deps.HTTPClient = srv.Client()
	probetest.FreezeNow(p.Deps, base)
	chk := probetest.MustCheck[*argoCDAgentSpinCheck](t, p)
	key := "argocd/" + pod.Name

	// Sweep 1 — cpu quiet → log channel scans; boundary = the
	// tail's newest stamp; first sighting, no delete.
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); res.Pass {
		t.Fatalf("first spin sighting must FAIL: %+v", res)
	}
	if _, ok := chk.logScanAt[key]; !ok {
		t.Fatal("sweep 1 left no log-scan boundary")
	}

	// Sweep 2 — cpu answers hot → cpuSpin wins, log channel
	// skipped. The boundary MUST survive: dropping it would make
	// the next log read re-count the whole stale tail.
	hot.Store(true)
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); res.Pass {
		t.Fatalf("cpu-channel spin must FAIL: %+v", res)
	}
	if _, ok := chk.logScanAt[key]; !ok {
		t.Fatal("cpu-answered sweep dropped the log-scan boundary")
	}

	// Sweep 3 — cpu quiet again → the log channel re-reads the
	// SAME tail. Every error stamp equals the stored boundary →
	// zero FRESH errors → no spin, no delete past the window.
	hot.Store(false)
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	if res := chk.Run(probetest.SweepCtx(ctx, chk.Deps)); !res.Pass {
		t.Fatalf("stale-only tail re-flagged after a cpu-answered sweep: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("argocd").Get(ctx, pod.Name,
		metav1.GetOptions{}); err != nil {
		t.Fatalf("stale tail must not delete the pod: %v", err)
	}
}

// The freshOnly predicate leg: with a previous scan boundary, only
// error lines stamped AFTER it count toward the spin threshold —
// and streamNewestTS reports the newest stamp on ANY line (the
// boundary the caller stores), not just matching ones.
func TestScanAgentSpinLinesFreshBoundary(t *testing.T) {
	boundary := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	stale := spinLogBodyAt(20, false, boundary.Add(-time.Hour))
	fresh := spinLogBodyAt(20, false, boundary.Add(time.Minute))

	// Mixed tail: 20 stale + 20 fresh errors → only the 20 fresh
	// count; both clocks land on the fresh stamp.
	errs, rec, newestErr, streamNewest := scanAgentSpinLines(
		strings.NewReader(stale+fresh), boundary, true)
	if errs != 20 || rec {
		t.Fatalf("freshOnly counted %d errs (recovered=%v) — want 20 fresh only", errs, rec)
	}
	if !newestErr.Equal(boundary.Add(time.Minute)) {
		t.Fatalf("newestErr = %v, want the fresh stamp", newestErr)
	}
	if !streamNewest.Equal(boundary.Add(time.Minute)) {
		t.Fatalf("streamNewest = %v, want the newest stamp on ANY line", streamNewest)
	}

	// All-stale tail → zero counted errors.
	errs, _, _, _ = scanAgentSpinLines(
		strings.NewReader(stale), boundary, true)
	if errs != 0 {
		t.Fatalf("stale-only tail counted %d errors — overlapping-window dedup broken", errs)
	}

	// No boundary (first scan) → the whole window counts.
	errs, _, _, _ = scanAgentSpinLines(
		strings.NewReader(stale+fresh), time.Time{}, false)
	if errs != 40 {
		t.Fatalf("first scan counted %d — want the full window (40)", errs)
	}

	// An error line with NO parseable stamp counts as fresh —
	// fail toward alerting, never toward silence.
	errs, _, _, _ = scanAgentSpinLines(strings.NewReader(
		"err agent agent.go:88 Error receiving from stream: transport is closing\n"),
		boundary, true)
	if errs != 1 {
		t.Fatalf("unparseable-stamp error counted %d — want 1 (fresh)", errs)
	}
}
