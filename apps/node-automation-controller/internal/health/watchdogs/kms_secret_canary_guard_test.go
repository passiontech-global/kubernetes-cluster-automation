// kms_secret_canary_guard_test.go — unit tests for kms-secret-canary-guard.
package watchdogs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

func kmsCanaryTestProber(t *testing.T, cs *fake.Clientset, now time.Time) *probetest.Prober {
	t.Helper()
	t.Cleanup(kmsCanaryUnhealthyGauge.Reset)
	p := probetest.NewCheckProber(cs, nil, NewKMSCanaryGuardCheck)
	probetest.FreezeNow(p.Deps, now)
	return p
}

func TestKMSSecretCanaryGuard(t *testing.T) {
	now := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)

	t.Run("healthy round-trip creates and updates canary Secret and honors interval rate-limiting", func(t *testing.T) {
		t.Setenv("NODE_AUTOMATION_KMS_CANARY_NAMESPACE", "node-ops")
		t.Setenv("NODE_AUTOMATION_KMS_CANARY_INTERVAL", "5m")

		cs := fake.NewSimpleClientset()
		var secretWrites int
		cs.PrependReactor("create", "secrets", func(action ktesting.Action) (bool, runtime.Object, error) {
			secretWrites++
			return false, nil, nil
		})
		cs.PrependReactor("update", "secrets", func(action ktesting.Action) (bool, runtime.Object, error) {
			secretWrites++
			return false, nil, nil
		})

		p := kmsCanaryTestProber(t, cs, now)
		chk := probetest.MustCheck[*kmsCanaryCheck](t, p)

		// First sweep writes + reads canary Secret.
		sctx1 := probetest.SweepCtx(context.Background(), chk.Deps)
		res1 := chk.Run(sctx1)
		probetest.VerifySweep(sctx1)
		if !res1.Pass || secretWrites != 1 {
			t.Fatalf("expected PASS and 1 write on first run, got res=%+v writes=%d", res1, secretWrites)
		}

		// Second sweep 2m later must skip write/read due to 5m interval.
		probetest.FreezeNow(p.Deps, now.Add(2*time.Minute))
		sctx2 := probetest.SweepCtx(context.Background(), chk.Deps)
		res2 := chk.Run(sctx2)
		probetest.VerifySweep(sctx2)
		if !res2.Pass || secretWrites != 1 {
			t.Fatalf("expected rate-limited skip (writes still 1), got res=%+v writes=%d", res2, secretWrites)
		}

		// Third sweep at +5m performs a fresh Update + quorum Get.
		probetest.FreezeNow(p.Deps, now.Add(5*time.Minute))
		sctx3 := probetest.SweepCtx(context.Background(), chk.Deps)
		res3 := chk.Run(sctx3)
		probetest.VerifySweep(sctx3)
		if !res3.Pass || secretWrites != 2 {
			t.Fatalf("expected fresh update at +5m (writes=2), got res=%+v writes=%d", res3, secretWrites)
		}
	})

	t.Run("403 Forbidden gracefully skips without alert or Infra error", func(t *testing.T) {
		t.Setenv("NODE_AUTOMATION_KMS_CANARY_NAMESPACE", "")
		t.Setenv("POD_NAMESPACE", "custom-ops")

		cs := fake.NewSimpleClientset()
		cs.PrependReactor("get", "secrets", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, kmsCanarySecretName, errors.New("forbidden"))
		})

		p := kmsCanaryTestProber(t, cs, now)
		chk := probetest.MustCheck[*kmsCanaryCheck](t, p)
		if chk.canaryNS != "custom-ops" {
			t.Fatalf("expected POD_NAMESPACE fallback custom-ops, got %q", chk.canaryNS)
		}

		sctx := probetest.SweepCtx(context.Background(), chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if !res.Pass || res.Infra != nil {
			t.Fatalf("expected graceful PASS on 403 Forbidden, got %+v", res)
		}
	})

	t.Run("500 KMS decrypt error triggers bounded namespace LIST Secrets isolation and pinpoints broken namespace", func(t *testing.T) {
		t.Setenv("NODE_AUTOMATION_KMS_CANARY_NAMESPACE", "node-ops")
		t.Setenv("NODE_AUTOMATION_KMS_CANARY_INTERVAL", "5m")

		objs := []runtime.Object{
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "node-ops"}, Status: corev1.NamespaceStatus{Phase: corev1.NamespaceActive}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "healthy-ns"}, Status: corev1.NamespaceStatus{Phase: corev1.NamespaceActive}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "broken-kms-ns"}, Status: corev1.NamespaceStatus{Phase: corev1.NamespaceActive}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "terminating-ns"}, Status: corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating}},
		}
		cs := fake.NewSimpleClientset(objs...)

		// Simulate 500 InternalError on canary Get AND on LIST Secrets in broken-kms-ns.
		cs.PrependReactor("get", "secrets", func(action ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewInternalError(fmt.Errorf("unable to transform Secret from storage: kms decrypt failed"))
		})
		var isolatedNamespaces []string
		cs.PrependReactor("list", "secrets", func(action ktesting.Action) (bool, runtime.Object, error) {
			la := action.(ktesting.ListAction)
			isolatedNamespaces = append(isolatedNamespaces, la.GetNamespace())
			if la.GetNamespace() == "broken-kms-ns" {
				return true, nil, apierrors.NewInternalError(fmt.Errorf("kms key unavailable during decrypt"))
			}
			return true, &corev1.SecretList{}, nil
		})

		p := kmsCanaryTestProber(t, cs, now)
		chk := probetest.MustCheck[*kmsCanaryCheck](t, p)

		sctx := probetest.SweepCtx(context.Background(), chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)

		if res.Pass {
			t.Fatalf("expected FAIL on KMS 500 error, got %+v", res)
		}
		if !strings.Contains(res.Why, "broken-kms-ns") || !strings.Contains(res.Why, kmsCanaryReasonDecrypt) {
			t.Fatalf("expected broken-kms-ns pinpointed in Why, got %q", res.Why)
		}
		if m := probetest.FindMetric(t, "node_automation_kms_secret_canary_unhealthy", map[string]string{
			"namespace": "broken-kms-ns", "reason": kmsCanaryReasonNS500,
		}); m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("expected namespace_secret_list_500=1 for broken-kms-ns, got %v", m)
		}
		if m := probetest.FindMetric(t, "node_automation_kms_secret_canary_unhealthy", map[string]string{
			"namespace": "healthy-ns", "reason": kmsCanaryReasonNS500,
		}); m != nil {
			t.Fatalf("healthy-ns must not be flagged: %v", m)
		}
		if len(isolatedNamespaces) != 3 { // node-ops, healthy-ns, broken-kms-ns (terminating skipped)
			t.Fatalf("expected 3 active namespaces isolated, got %d (%v)", len(isolatedNamespaces), isolatedNamespaces)
		}

		evs, _ := cs.EventsV1().Events("node-ops").List(context.Background(), metav1.ListOptions{})
		if len(evs.Items) != 1 || evs.Items[0].Reason != kmsCanaryEventReason ||
			!strings.Contains(evs.Items[0].Note, "broken-kms-ns") {
			t.Fatalf("expected KMSSecretCanaryFailed event naming broken-kms-ns, got %+v", evs.Items)
		}

		// Rate-limited second run within interval carries held findings without hitting API again.
		probetest.FreezeNow(p.Deps, now.Add(time.Minute))
		sctx2 := probetest.SweepCtx(context.Background(), chk.Deps)
		res2 := chk.Run(sctx2)
		probetest.VerifySweep(sctx2)
		if res2.Pass || !strings.Contains(res2.Why, "broken-kms-ns") || len(isolatedNamespaces) != 3 {
			t.Fatalf("expected carried failure during rate-limit without extra LISTs, got res=%+v lists=%d", res2, len(isolatedNamespaces))
		}
	})
}
