package nodehealth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

func zoneGrayTestWorker(name, zone string, ready bool, extraConds ...corev1.NodeCondition) *corev1.Node {
	readyStatus := corev1.ConditionTrue
	if !ready {
		readyStatus = corev1.ConditionFalse
	}
	conds := []corev1.NodeCondition{{Type: corev1.NodeReady, Status: readyStatus}}
	conds = append(conds, extraConds...)
	labels := map[string]string{}
	if zone != "" {
		labels[corev1.LabelTopologyZone] = zone
	}
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Status:     corev1.NodeStatus{Conditions: conds},
	}
}

func zoneGrayTestCP(name, zone string) *corev1.Node {
	n := zoneGrayTestWorker(name, zone, false)
	n.Labels["node-role.kubernetes.io/control-plane"] = ""
	return n
}

func TestZoneGrayFailureGuardDetectionAndHoldoff(t *testing.T) {
	t.Run("fewer than 2 zones skipped gracefully", func(t *testing.T) {
		w1 := zoneGrayTestWorker("w1", "az-a", false)
		w2 := zoneGrayTestWorker("w2", "az-a", false)
		cs := fake.NewSimpleClientset(w1, w2)
		p := probetest.NewCheckProber(cs, nil, NewZoneGrayFailureGuardCheck)
		chk := probetest.MustCheck[*zoneGrayFailureGuardCheck](t, p)

		res := probetest.RunCheck(ctx, chk.Deps, chk)
		if !res.Pass || res.Infra != nil {
			t.Fatalf("expected PASS on single-zone cluster, got %+v", res)
		}
	})

	t.Run("below 50 percent degraded ratio in zone skipped", func(t *testing.T) {
		// az-a has 1/3 degraded (33% < 50%); az-b & az-c healthy.
		nodes := []corev1.Node{
			*zoneGrayTestWorker("a1", "az-a", false),
			*zoneGrayTestWorker("a2", "az-a", true),
			*zoneGrayTestWorker("a3", "az-a", true),
			*zoneGrayTestWorker("b1", "az-b", true),
			*zoneGrayTestWorker("c1", "az-c", true),
		}
		cs := fake.NewSimpleClientset(&nodes[0], &nodes[1], &nodes[2], &nodes[3], &nodes[4])
		p := probetest.NewCheckProber(cs, nil, NewZoneGrayFailureGuardCheck)
		base := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*zoneGrayFailureGuardCheck](t, p)

		_ = probetest.RunCheck(ctx, chk.Deps, chk)
		probetest.FreezeNow(p.Deps, base.Add(15*time.Minute))
		res := probetest.RunCheck(ctx, chk.Deps, chk)
		if !res.Pass {
			t.Fatalf("expected PASS when degraded ratio < 50%%, got %+v", res)
		}
	})

	t.Run("holdoff below 10m passes, >=10m triggers alert and Warning event", func(t *testing.T) {
		// az-a has 2/2 degraded (DiskSlowIO + CoreDNSUpstreamDegraded), az-b & az-c healthy.
		a1 := zoneGrayTestWorker("a1", "az-a", true, corev1.NodeCondition{
			Type: corev1.NodeConditionType(nodecond.DiskSlowIO), Status: corev1.ConditionTrue,
		})
		a2 := zoneGrayTestWorker("a2", "az-a", true, corev1.NodeCondition{
			Type: corev1.NodeConditionType("CoreDNSUpstreamDegraded"), Status: corev1.ConditionTrue,
		})
		b1 := zoneGrayTestWorker("b1", "az-b", true)
		c1 := zoneGrayTestWorker("c1", "az-c", true)

		cs := fake.NewSimpleClientset(a1, a2, b1, c1)
		p := probetest.NewCheckProber(cs, nil, NewZoneGrayFailureGuardCheck)
		base := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*zoneGrayFailureGuardCheck](t, p)

		// t=0: first seen -> PASS.
		if res := probetest.RunCheck(ctx, chk.Deps, chk); !res.Pass {
			t.Fatalf("t=0 expected PASS during holdoff, got %+v", res)
		}
		// t=9m: still inside 10m holdoff -> PASS.
		probetest.FreezeNow(p.Deps, base.Add(9*time.Minute))
		if res := probetest.RunCheck(ctx, chk.Deps, chk); !res.Pass {
			t.Fatalf("t=9m expected PASS during holdoff, got %+v", res)
		}
		// t=10m: sustained -> FAIL + ZoneGrayFailureDetected Warning event.
		probetest.FreezeNow(p.Deps, base.Add(10*time.Minute))
		res := probetest.RunCheck(ctx, chk.Deps, chk)
		if res.Pass {
			t.Fatal("t=10m expected FAIL for sustained zone gray failure")
		}
		if !strings.Contains(res.Why, "az-a (2/2 workers degraded)") {
			t.Fatalf("unexpected Why: %s", res.Why)
		}
		if m := probetest.FindMetric(t, "node_automation_zone_gray_failure", map[string]string{"zone": "az-a"}); m == nil || m.GetGauge().GetValue() != 1 {
			t.Fatalf("expected zone_gray_failure=1 for az-a, got %v", m)
		}
		evs, _ := cs.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
		if len(evs.Items) != 1 || evs.Items[0].Reason != zoneGrayEventReason {
			t.Fatalf("expected 1 ZoneGrayFailureDetected event, got %+v", evs.Items)
		}
	})

	t.Run("fewer than 2 healthy zones remaining does NOT trigger zone gray-failure", func(t *testing.T) {
		// 3 zones, but 2 zones degraded -> only 1 healthy zone (<2) -> fleet issue, not zone gray-failure.
		a1 := zoneGrayTestWorker("a1", "az-a", false)
		b1 := zoneGrayTestWorker("b1", "az-b", false)
		c1 := zoneGrayTestWorker("c1", "az-c", true)

		cs := fake.NewSimpleClientset(a1, b1, c1)
		p := probetest.NewCheckProber(cs, nil, NewZoneGrayFailureGuardCheck)
		base := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*zoneGrayFailureGuardCheck](t, p)

		_ = probetest.RunCheck(ctx, chk.Deps, chk)
		probetest.FreezeNow(p.Deps, base.Add(15*time.Minute))
		res := probetest.RunCheck(ctx, chk.Deps, chk)
		if !res.Pass {
			t.Fatalf("expected PASS when <2 healthy zones exist, got %+v", res)
		}
	})

	t.Run("PromQL per-node error correlation and CrashLoop pod ratio", func(t *testing.T) {
		// a1 degraded via PromQL error sample, a2 degraded via 2/2 CrashLoop pods.
		a1 := zoneGrayTestWorker("a1", "az-a", true)
		a2 := zoneGrayTestWorker("a2", "az-a", true)
		b1 := zoneGrayTestWorker("b1", "az-b", true)
		c1 := zoneGrayTestWorker("c1", "az-c", true)

		p1 := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "p1"},
			Spec:       corev1.PodSpec{NodeName: "a2"},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				ContainerStatuses: []corev1.ContainerStatus{{
					Name:  "c",
					State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
				}},
			},
		}
		p2 := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "p2"},
			Spec:       corev1.PodSpec{NodeName: "a2"},
			Status:     corev1.PodStatus{Phase: corev1.PodPending},
		}

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"node":"a1"},"value":[1700000000,"5.2"]}]}}`))
		}))
		defer srv.Close()

		cs := fake.NewSimpleClientset(a1, a2, b1, c1, p1, p2)
		p := probetest.NewCheckProber(cs, nil, NewZoneGrayFailureGuardCheck)
		p.Cfg.HTTPContent.URL = srv.URL + "/health"
		base := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*zoneGrayFailureGuardCheck](t, p)

		_ = probetest.RunCheck(ctx, chk.Deps, chk)
		probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
		res := probetest.RunCheck(ctx, chk.Deps, chk)
		if res.Pass || !strings.Contains(res.Why, "az-a (2/2 workers degraded)") {
			t.Fatalf("expected az-a degraded via PromQL + pod ratio, got %+v", res)
		}
	})
}

func TestZoneGrayFailureGuardSheddingAndRecovery(t *testing.T) {
	t.Run("opt-in shedding taints workers ONLY (never CP), enforces max-1-zone cap, auto-untaints after 15m recovery", func(t *testing.T) {
		t.Setenv("NODE_AUTOMATION_ZONE_GRAY_SHED_ENABLED", "true")

		cpA := zoneGrayTestCP("cp-a", "az-a")
		a1 := zoneGrayTestWorker("a1", "az-a", true, corev1.NodeCondition{
			Type: corev1.NodeConditionType(nodecond.NebulaSlowpath), Status: corev1.ConditionTrue,
		})
		a2 := zoneGrayTestWorker("a2", "az-a", false)
		b1 := zoneGrayTestWorker("b1", "az-b", true)
		c1 := zoneGrayTestWorker("c1", "az-c", true)

		cs := fake.NewSimpleClientset(cpA, a1, a2, b1, c1)
		p := probetest.NewCheckProber(cs, nil, NewZoneGrayFailureGuardCheck)
		base := time.Date(2026, 11, 25, 13, 0, 0, 0, time.UTC)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*zoneGrayFailureGuardCheck](t, p)

		_ = probetest.RunCheck(ctx, chk.Deps, chk)
		probetest.FreezeNow(p.Deps, base.Add(10*time.Minute))
		res := probetest.RunCheck(ctx, chk.Deps, chk)
		if res.Pass {
			t.Fatal("expected FAIL at t=10m")
		}

		// Control plane must NEVER be tainted; workers in az-a MUST be tainted PreferNoSchedule.
		gotCP, _ := cs.CoreV1().Nodes().Get(ctx, "cp-a", metav1.GetOptions{})
		if kube.HasTaint(gotCP.Spec.Taints, zoneGrayTaintKey) {
			t.Fatal("control-plane node must NEVER receive zone-gray-failure taint")
		}
		for _, wName := range []string{"a1", "a2"} {
			gotW, _ := cs.CoreV1().Nodes().Get(ctx, wName, metav1.GetOptions{})
			if !kube.HasTaint(gotW.Spec.Taints, zoneGrayTaintKey) {
				t.Fatalf("expected worker %s in az-a to carry taint %s", wName, zoneGrayTaintKey)
			}
			for _, tt := range gotW.Spec.Taints {
				if tt.Key == zoneGrayTaintKey && tt.Effect != corev1.TaintEffectPreferNoSchedule {
					t.Fatalf("expected PreferNoSchedule effect, got %s", tt.Effect)
				}
			}
		}

		// Now add az-d healthy and degrade az-b: max-1-zone cap must block shedding az-b while az-a is tainted!
		d1 := zoneGrayTestWorker("d1", "az-d", true)
		_, _ = cs.CoreV1().Nodes().Create(ctx, d1, metav1.CreateOptions{})
		gotB1, _ := cs.CoreV1().Nodes().Get(ctx, "b1", metav1.GetOptions{})
		gotB1.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionFalse}}
		_, _ = cs.CoreV1().Nodes().UpdateStatus(ctx, gotB1, metav1.UpdateOptions{})

		probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
		_ = probetest.RunCheck(ctx, chk.Deps, chk)
		probetest.FreezeNow(p.Deps, base.Add(22*time.Minute))
		_ = probetest.RunCheck(ctx, chk.Deps, chk)

		gotB1, _ = cs.CoreV1().Nodes().Get(ctx, "b1", metav1.GetOptions{})
		if kube.HasTaint(gotB1.Spec.Taints, zoneGrayTaintKey) {
			t.Fatal("max-1-zone cap must prevent shedding az-b while az-a is still tainted")
		}

		// Recover az-a workers and disable SHED_ENABLED -> auto-untaint MUST still recover after 15m!
		t.Setenv("NODE_AUTOMATION_ZONE_GRAY_SHED_ENABLED", "false")
		chk2 := NewZoneGrayFailureGuardCheck(p.Deps).(*zoneGrayFailureGuardCheck)
		// Carry over az-a recovery test on a check with shedEnabled=false.
		for _, wName := range []string{"a1", "a2"} {
			gotW, _ := cs.CoreV1().Nodes().Get(ctx, wName, metav1.GetOptions{})
			gotW.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}
			_, _ = cs.CoreV1().Nodes().UpdateStatus(ctx, gotW, metav1.UpdateOptions{})
		}
		// Restore b1 healthy too.
		gotB1.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}
		_, _ = cs.CoreV1().Nodes().UpdateStatus(ctx, gotB1, metav1.UpdateOptions{})

		recoverBase := base.Add(30 * time.Minute)
		probetest.FreezeNow(p.Deps, recoverBase)
		_ = probetest.RunCheck(ctx, chk2.Deps, chk2)

		// At +14m, taint must still remain.
		probetest.FreezeNow(p.Deps, recoverBase.Add(14*time.Minute))
		_ = probetest.RunCheck(ctx, chk2.Deps, chk2)
		gotA1, _ := cs.CoreV1().Nodes().Get(ctx, "a1", metav1.GetOptions{})
		if !kube.HasTaint(gotA1.Spec.Taints, zoneGrayTaintKey) {
			t.Fatal("taint should remain before 15m recovery duration")
		}

		// At +15m, taint MUST be removed even with SHED_ENABLED=false.
		probetest.FreezeNow(p.Deps, recoverBase.Add(15*time.Minute))
		res = probetest.RunCheck(ctx, chk2.Deps, chk2)
		if !res.Pass {
			t.Fatalf("expected PASS after recovery, got %+v", res)
		}
		for _, wName := range []string{"a1", "a2"} {
			gotW, _ := cs.CoreV1().Nodes().Get(ctx, wName, metav1.GetOptions{})
			if kube.HasTaint(gotW.Spec.Taints, zoneGrayTaintKey) {
				t.Fatalf("expected taint removed from %s after >=15m recovery", wName)
			}
		}
	})

	t.Run("shedding blocked when cluster has fewer than 3 zones", func(t *testing.T) {
		t.Setenv("NODE_AUTOMATION_ZONE_GRAY_SHED_ENABLED", "true")

		// Only 2 zones (az-a degraded, az-b healthy) -> alert allowed? Wait: <2 healthy zones
		// won't even alert, and even if 2 healthy zones were somehow counted, <3 zones blocks shedding.
		a1 := zoneGrayTestWorker("a1", "az-a", false)
		b1 := zoneGrayTestWorker("b1", "az-b", true)
		cs := fake.NewSimpleClientset(a1, b1)
		p := probetest.NewCheckProber(cs, nil, NewZoneGrayFailureGuardCheck)
		base := time.Date(2026, 11, 25, 14, 0, 0, 0, time.UTC)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*zoneGrayFailureGuardCheck](t, p)

		_ = probetest.RunCheck(ctx, chk.Deps, chk)
		probetest.FreezeNow(p.Deps, base.Add(15*time.Minute))
		_ = probetest.RunCheck(ctx, chk.Deps, chk)

		gotA1, _ := cs.CoreV1().Nodes().Get(ctx, "a1", metav1.GetOptions{})
		if kube.HasTaint(gotA1.Spec.Taints, zoneGrayTaintKey) {
			t.Fatal("2-zone cluster must NEVER shed a zone")
		}
	})

	t.Run("taint-only control-plane node excluded and unrelated worker taints preserved", func(t *testing.T) {
		t.Setenv("NODE_AUTOMATION_ZONE_GRAY_SHED_ENABLED", "true")

		// Control-plane identified by taint only (no node-role label).
		cpTaintOnly := zoneGrayTestWorker("cp-taint", "az-a", false)
		cpTaintOnly.Spec.Taints = []corev1.Taint{{
			Key:    "node-role.kubernetes.io/control-plane",
			Effect: corev1.TaintEffectNoSchedule,
		}}
		a1 := zoneGrayTestWorker("a1", "az-a", false)
		a1.Spec.Taints = []corev1.Taint{{Key: "dedicated", Value: "gpu", Effect: corev1.TaintEffectNoSchedule}}
		b1 := zoneGrayTestWorker("b1", "az-b", true)
		c1 := zoneGrayTestWorker("c1", "az-c", true)

		cs := fake.NewSimpleClientset(cpTaintOnly, a1, b1, c1)
		p := probetest.NewCheckProber(cs, nil, NewZoneGrayFailureGuardCheck)
		base := time.Date(2026, 11, 25, 15, 0, 0, 0, time.UTC)
		probetest.FreezeNow(p.Deps, base)
		chk := probetest.MustCheck[*zoneGrayFailureGuardCheck](t, p)

		_ = probetest.RunCheck(ctx, chk.Deps, chk)
		probetest.FreezeNow(p.Deps, base.Add(10*time.Minute))
		_ = probetest.RunCheck(ctx, chk.Deps, chk)

		gotCP, _ := cs.CoreV1().Nodes().Get(ctx, "cp-taint", metav1.GetOptions{})
		if kube.HasTaint(gotCP.Spec.Taints, zoneGrayTaintKey) {
			t.Fatal("taint-only control-plane node must NEVER receive zone-gray-failure taint")
		}
		gotA1, _ := cs.CoreV1().Nodes().Get(ctx, "a1", metav1.GetOptions{})
		if !kube.HasTaint(gotA1.Spec.Taints, zoneGrayTaintKey) || !kube.HasTaint(gotA1.Spec.Taints, "dedicated") {
			t.Fatalf("expected both dedicated and zone-gray-failure taints on a1, got %+v", gotA1.Spec.Taints)
		}

		// Recover a1 and verify dedicated taint remains after zone-gray-failure untaints.
		gotA1.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}
		_, _ = cs.CoreV1().Nodes().UpdateStatus(ctx, gotA1, metav1.UpdateOptions{})
		probetest.FreezeNow(p.Deps, base.Add(11*time.Minute))
		_ = probetest.RunCheck(ctx, chk.Deps, chk)
		probetest.FreezeNow(p.Deps, base.Add(27*time.Minute))
		_ = probetest.RunCheck(ctx, chk.Deps, chk)

		gotA1, _ = cs.CoreV1().Nodes().Get(ctx, "a1", metav1.GetOptions{})
		if kube.HasTaint(gotA1.Spec.Taints, zoneGrayTaintKey) || !kube.HasTaint(gotA1.Spec.Taints, "dedicated") {
			t.Fatalf("expected zone-gray-failure removed while preserving dedicated taint, got %+v", gotA1.Spec.Taints)
		}
	})
}
