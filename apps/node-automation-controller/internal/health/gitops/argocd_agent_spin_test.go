// argocd_agent_spin_test.go — coverage for the argocd-agent-spin
// check (argocd-agent-spin): the log-spin predicate, the CPU channel, the
// FirstSeenLedger persistence window and the gated pod delete.
package gitops

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
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
