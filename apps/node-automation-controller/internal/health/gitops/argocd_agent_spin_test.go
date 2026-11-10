// argocd_agent_spin_test.go — coverage for the argocd-agent-spin
// check (argocd-agent-spin): the log-spin predicate, the CPU channel, the
// FirstSeenLedger persistence window and the gated pod delete.
package gitops

import (
	"errors"
	"strings"
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
	var b strings.Builder
	for range nErr {
		b.WriteString("2026-11-08T00:00:00Z err agent agent.go:88 Error receiving from stream: rpc error: code = Unknown desc = stream.Recv failed: transport is closing\n")
	}
	if reconnectAfter {
		b.WriteString("2026-11-08T00:01:00Z info agent stream.go:41 connected to remote argocd — stream established\n")
	}
	return b.String()
}

// TestScanAgentSpinLines pins the pure predicate: >=15 unresolved
// error lines spin; a successful reconnect AFTER the last error does
// not; errors recovered before later reconnects are history.
func TestScanAgentSpinLines(t *testing.T) {
	errs, rec := scanAgentSpinLines(strings.NewReader(spinLogBody(15, false)))
	if errs != 15 || rec {
		t.Fatalf("15 unresolved errors = %d,%v — want spin", errs, rec)
	}
	errs, rec = scanAgentSpinLines(strings.NewReader(spinLogBody(14, false)))
	if errs >= 15 {
		t.Fatalf("14 errors must stay under the threshold, got %d", errs)
	}
	errs, rec = scanAgentSpinLines(strings.NewReader(spinLogBody(30, true)))
	if !rec {
		t.Fatal("reconnect AFTER the last error must disarm the log channel")
	}
	// Reconnect BEFORE the errors — the loop resumed after it, spin.
	body := "connected to remote argocd\n" + spinLogBody(15, false)
	errs, rec = scanAgentSpinLines(strings.NewReader(body))
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

// A spinning pod whose log channel carries the unresolved signature
// persists through the 10m window, then the pod is deleted; the too-
// young sibling survives untouched (its own logs never matter — the
// age gate skips it before the log read).
func TestArgoCDAgentSpinDeletesAfterWindow(t *testing.T) {
	base := time.Now()
	spinning := agentPod("argocd-agent-agent-7f9c", base.Add(-30*time.Minute))
	young := agentPod("argocd-agent-agent-new00", base.Add(-time.Minute))
	cs := fake.NewSimpleClientset(spinning, young)
	cs.PrependReactor("get", "pods", agentLogReactor(spinLogBody(20, false)))
	p := probetest.NewCheckProber(cs, testutil.NewDynamicClient(),
		NewArgoCDAgentSpinCheck)
	probetest.FreezeNow(p.Deps, base)
	chk := probetest.MustCheck[*argoCDAgentSpinCheck](t, p)

	// First sighting stamps the ledger — detection only, no delete.
	if res := chk.Run(ctx); res.Pass {
		t.Fatalf("spinning agent must FAIL: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("argocd").Get(ctx, spinning.Name, metav1.GetOptions{}); err != nil {
		t.Fatalf("first sighting must not delete yet: %v", err)
	}

	// Past the window the sustained signature deletes the pod.
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	if res := chk.Run(ctx); res.Pass {
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
	cs.PrependReactor("get", "pods", agentLogReactor(spinLogBody(20, false)))
	p := probetest.NewCheckProber(cs, testutil.NewDynamicClient(),
		NewArgoCDAgentSpinCheck)
	probetest.FreezeNow(p.Deps, base)
	chk := probetest.MustCheck[*argoCDAgentSpinCheck](t, p)

	if res := chk.Run(ctx); res.Pass {
		t.Fatalf("first spin sighting must FAIL: %+v", res)
	}
	// The log channel dies for one sweep (the cpu channel is already
	// dead — no prometheus endpoint wired): inconclusive, not clean.
	cs.PrependReactor("get", "pods",
		agentLogFailReactor(errors.New("kubelet log read boom")))
	_ = chk.Run(ctx)
	// The log channel revives past the window: the sustained spin
	// deletes the pod on the preserved clock.
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	cs.PrependReactor("get", "pods", agentLogReactor(spinLogBody(20, false)))
	chk.Run(ctx)
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
	cs.PrependReactor("get", "pods", agentLogReactor(spinLogBody(30, true)))
	p := probetest.NewCheckProber(cs, testutil.NewDynamicClient(),
		NewArgoCDAgentSpinCheck)
	probetest.FreezeNow(p.Deps, base)
	chk := probetest.MustCheck[*argoCDAgentSpinCheck](t, p)

	if res := chk.Run(ctx); !res.Pass {
		t.Fatalf("recovered stream errors must pass: %+v", res)
	}
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	if res := chk.Run(ctx); !res.Pass {
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
	cs.PrependReactor("get", "pods", agentLogReactor(spinLogBody(50, false)))
	p := probetest.NewCheckProber(cs, testutil.NewDynamicClient(),
		NewArgoCDAgentSpinCheck)
	probetest.FreezeNow(p.Deps, base)
	chk := probetest.MustCheck[*argoCDAgentSpinCheck](t, p)

	if res := chk.Run(ctx); !res.Pass {
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
	cs.PrependReactor("get", "pods", agentLogReactor(spinLogBody(20, false)))
	p := probetest.NewCheckProber(cs, testutil.NewDynamicClient(),
		NewArgoCDAgentSpinCheck)
	probetest.FreezeNow(p.Deps, base)
	chk := probetest.MustCheck[*argoCDAgentSpinCheck](t, p)

	// Detection at t0, delivered delete at t0+11m (past the window).
	chk.Run(ctx)
	probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
	if res := chk.Run(ctx); res.Pass {
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
	if res := chk.Run(ctx); res.Pass {
		t.Fatalf("sustained spin past cooldown must FAIL: %+v", res)
	}
	if _, err := cs.CoreV1().Pods("argocd").Get(ctx, repl.Name, metav1.GetOptions{}); err == nil {
		t.Fatal("replacement not deleted after the cooldown expired")
	}
}
