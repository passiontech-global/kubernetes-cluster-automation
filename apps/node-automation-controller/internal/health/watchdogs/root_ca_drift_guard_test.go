// root_ca_drift_guard_test.go — unit tests for root-ca-drift-guard.
package watchdogs

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
)

func rootCATestProber(t *testing.T, cs *fake.Clientset, now time.Time) *probetest.Prober {
	t.Helper()
	t.Cleanup(rootCADriftGauge.Reset)
	p := probetest.NewCheckProber(cs, nil, NewRootCADriftGuardCheck)
	probetest.FreezeNow(p.Deps, now)
	return p
}

func rootCANamespace(name string, phase corev1.NamespacePhase, age time.Duration, now time.Time) *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			CreationTimestamp: metav1.NewTime(now.Add(-age)),
		},
		Status: corev1.NamespaceStatus{Phase: phase},
	}
}

func rootCAConfigMap(ns, ca string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      rootCAConfigMapName,
		},
		Data: map[string]string{"ca.crt": ca},
	}
}

func TestRootCADriftGuard(t *testing.T) {
	now := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	const refCA = "-----BEGIN CERTIFICATE-----\nVALIDCA\n-----END CERTIFICATE-----\n"

	t.Run("all active namespaces matching trimmed ca.crt pass", func(t *testing.T) {
		objs := []runtime.Object{
			rootCANamespace("kube-system", corev1.NamespaceActive, time.Hour, now),
			rootCANamespace("apps", corev1.NamespaceActive, time.Hour, now),
			rootCANamespace("db", corev1.NamespaceActive, time.Hour, now),
			rootCAConfigMap("kube-system", refCA),
			rootCAConfigMap("apps", "  "+refCA+"\n"),
			rootCAConfigMap("db", refCA),
			// Unrelated ConfigMap in fake clientset must be ignored.
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "other-cm"}},
		}

		cs := fake.NewSimpleClientset(objs...)
		p := rootCATestProber(t, cs, now)
		chk := probetest.MustCheck[*rootCADriftCheck](t, p)

		sctx := probetest.SweepCtx(context.Background(), chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if !res.Pass {
			t.Fatalf("expected PASS when all active namespaces match, got %+v", res)
		}
	})

	t.Run("missing CM in old ns flagged, brand-new ns skipped, SHA mismatch flagged, terminating ns skipped", func(t *testing.T) {
		objs := []runtime.Object{
			rootCANamespace("kube-system", corev1.NamespaceActive, time.Hour, now),
			rootCANamespace("old-missing", corev1.NamespaceActive, 5*time.Minute, now),
			rootCANamespace("brand-new", corev1.NamespaceActive, 30*time.Second, now.Add(rootCAMissingMinAge)),
			rootCANamespace("drifted", corev1.NamespaceActive, time.Hour, now),
			rootCANamespace("empty-ca", corev1.NamespaceActive, time.Hour, now),
			rootCANamespace("dying-ns", corev1.NamespaceTerminating, time.Hour, now),
			rootCAConfigMap("kube-system", refCA),
			rootCAConfigMap("drifted", "-----BEGIN CERTIFICATE-----\nSTALECA\n-----END CERTIFICATE-----"),
			rootCAConfigMap("empty-ca", "   "),
		}

		cs := fake.NewSimpleClientset(objs...)
		p := rootCATestProber(t, cs, now)
		chk := probetest.MustCheck[*rootCADriftCheck](t, p)

		sctx := probetest.SweepCtx(context.Background(), chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)

		if res.Pass {
			t.Fatalf("expected FAIL on missing namespace, got %+v", res)
		}
		if !strings.Contains(res.Why, "old-missing (missing)") {
			t.Fatalf("expected old-missing in Why, got %q", res.Why)
		}
		// hash_mismatch & empty must arm inside 2m window to avoid mid-rotation false alarms.
		if strings.Contains(res.Why, "drifted") || strings.Contains(res.Why, "empty-ca") {
			t.Fatalf("drifted/empty-ca must arm inside 2m persistence window, got %q", res.Why)
		}
		if strings.Contains(res.Why, "brand-new") {
			t.Fatalf("brand-new namespace (<2m) must not be flagged: %q", res.Why)
		}
		if strings.Contains(res.Why, "dying-ns") {
			t.Fatalf("Terminating namespace must not be flagged: %q", res.Why)
		}

		// Advance past 2m persistence window: drifted and empty-ca now flag.
		probetest.FreezeNow(p.Deps, now.Add(rootCAMissingMinAge+time.Second))
		sctx2 := probetest.SweepCtx(context.Background(), chk.Deps)
		res2 := chk.Run(sctx2)
		probetest.VerifySweep(sctx2)

		if res2.Pass {
			t.Fatalf("expected FAIL after 2m window, got %+v", res2)
		}
		if !strings.Contains(res2.Why, "old-missing (missing)") {
			t.Fatalf("expected old-missing in Why, got %q", res2.Why)
		}
		if !strings.Contains(res2.Why, "drifted (sha256=") {
			t.Fatalf("expected drifted sha256 mismatch in Why, got %q", res2.Why)
		}
		if !strings.Contains(res2.Why, "empty-ca (empty ca.crt)") {
			t.Fatalf("expected empty-ca in Why, got %q", res2.Why)
		}
		if strings.Contains(res2.Why, "brand-new") {
			t.Fatalf("brand-new namespace (<2m) must not be flagged: %q", res2.Why)
		}
		if strings.Contains(res2.Why, "dying-ns") {
			t.Fatalf("Terminating namespace must not be flagged: %q", res2.Why)
		}

		for _, tc := range []struct {
			ns, reason string
		}{
			{"old-missing", rootCAReasonMissing},
			{"drifted", rootCAReasonMismatch},
			{"empty-ca", rootCAReasonEmpty},
		} {
			if m := probetest.FindMetric(t, "node_automation_root_ca_drift", map[string]string{
				"namespace": tc.ns, "reason": tc.reason,
			}); m == nil || m.GetGauge().GetValue() != 1 {
				t.Fatalf("expected gauge=1 for %s/%s, got %v", tc.ns, tc.reason, m)
			}
		}

		evs, _ := cs.EventsV1().Events("old-missing").List(context.Background(), metav1.ListOptions{})
		if len(evs.Items) != 1 || evs.Items[0].Reason != rootCAEventReason {
			t.Fatalf("expected 1 RootCADrift Warning Event in old-missing, got %+v", evs.Items)
		}
	})

	t.Run("mid-rotation hash mismatch that recovers before 2m never flags", func(t *testing.T) {
		objs := []runtime.Object{
			rootCANamespace("kube-system", corev1.NamespaceActive, time.Hour, now),
			rootCANamespace("rotating", corev1.NamespaceActive, time.Hour, now),
			rootCAConfigMap("kube-system", refCA),
			rootCAConfigMap("rotating", "-----BEGIN CERTIFICATE-----\nOLD\n-----END CERTIFICATE-----"),
		}
		cs := fake.NewSimpleClientset(objs...)
		p := rootCATestProber(t, cs, now)
		chk := probetest.MustCheck[*rootCADriftCheck](t, p)

		sctx := probetest.SweepCtx(context.Background(), chk.Deps)
		if res := chk.Run(sctx); !res.Pass {
			t.Fatalf("mid-rotation mismatch must pass inside 2m window: %+v", res)
		}

		// ConfigMap converges before 2m -> rotation completes quietly.
		_, _ = cs.CoreV1().ConfigMaps("rotating").Update(context.Background(), rootCAConfigMap("rotating", refCA), metav1.UpdateOptions{})
		probetest.FreezeNow(p.Deps, now.Add(time.Minute))
		if res := chk.Run(probetest.SweepCtx(context.Background(), chk.Deps)); !res.Pass {
			t.Fatalf("converged namespace must pass: %+v", res)
		}
	})

	t.Run("missing kube-system/kube-root-ca.crt gracefully skips and passes", func(t *testing.T) {
		cs := fake.NewSimpleClientset(rootCANamespace("apps", corev1.NamespaceActive, time.Hour, now))
		p := rootCATestProber(t, cs, now)
		chk := probetest.MustCheck[*rootCADriftCheck](t, p)

		sctx := probetest.SweepCtx(context.Background(), chk.Deps)
		res := chk.Run(sctx)
		probetest.VerifySweep(sctx)
		if !res.Pass || res.Infra != nil {
			t.Fatalf("expected graceful PASS when kube-system/kube-root-ca.crt absent, got %+v", res)
		}
	})
}
