// maintenancestamper_test.go — the runnable's contract: the FIRST
// convergence pass runs immediately on Start (leader acquisition
// must not wait a full 30s interval to stamp a maintenance window
// that opened during failover), and the stamp timestamp rides the
// injected shared.Clock seam.
package main

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// cordonedStampNode builds a node inside the 2h stamp horizon —
// spec.unschedulable plus a fresh unschedulable taint — so
// StampMaintenanceTargets resolves it as a target.
func cordonedStampNode(name string, taintAt time.Time) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.NodeSpec{
			Unschedulable: true,
			Taints: []corev1.Taint{{
				Key:       kube.UnschedulableTaintKey,
				TimeAdded: &metav1.Time{Time: taintAt},
			}},
		},
	}
}

// Start must run stamp() BEFORE the first ticker wait: a maintenance
// window that opened while this replica was standby has to converge
// on leader acquisition, not up to 30s later. The test cancels the
// moment the first node patch lands — if Start waited for the
// ticker, no patch would ever arrive inside the deadline.
func TestMaintenanceStamperStampsImmediately(t *testing.T) {
	now := time.Now()
	cs := fake.NewSimpleClientset(cordonedStampNode("w1", now.Add(-time.Minute)))
	patched := make(chan struct{})
	var once sync.Once
	cs.PrependReactor("patch", "nodes",
		func(ktesting.Action) (bool, runtime.Object, error) {
			once.Do(func() { close(patched) })
			return false, nil, nil
		})

	r := &maintenanceStamperRunnable{cs: cs, dyn: nil, now: shared.SystemClock}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Start(ctx) }()

	select {
	case <-patched:
		// First pass converged without waiting for the ticker.
	case <-time.After(10 * time.Second):
		t.Fatal("no stamp within 10s — Start waited for the first tick")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after ctx cancel")
	}
}

// The stamp timestamp rides the runnable's clock seam — a pinned
// `now` must land in the annotation as now+TTL, proving stamp()
// reads r.now.Now() and not time.Now.
func TestMaintenanceStamperUsesClock(t *testing.T) {
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	cs := fake.NewSimpleClientset(cordonedStampNode("w1", base.Add(-time.Minute)))

	var payloads [][]byte
	cs.PrependReactor("patch", "nodes",
		func(action ktesting.Action) (bool, runtime.Object, error) {
			if pa, ok := action.(ktesting.PatchAction); ok {
				payloads = append(payloads, pa.GetPatch())
			}
			return false, nil, nil
		})

	r := &maintenanceStamperRunnable{
		cs:  cs,
		dyn: nil,
		now: func() time.Time { return base },
	}
	r.stamp(context.Background())

	if len(payloads) == 0 {
		t.Fatal("stamp pass issued no node patch")
	}
	var doc struct {
		Metadata struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(payloads[0], &doc); err != nil {
		t.Fatalf("patch payload not merge-patch JSON: %v", err)
	}
	stamp, ok := doc.Metadata.Annotations[nodecond.AnnoClusterMaintenanceUntil]
	if !ok || stamp == "" {
		t.Fatalf("patch carries no maintenance stamp: %s", payloads[0])
	}
	ts, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		t.Fatalf("stamp %q not RFC3339: %v", stamp, err)
	}
	want := base.Add(15 * time.Minute)
	if ts.Sub(want).Abs() > time.Minute {
		t.Fatalf("stamp = %v, want ~%v (pinned clock + TTL)", ts, want)
	}
}
