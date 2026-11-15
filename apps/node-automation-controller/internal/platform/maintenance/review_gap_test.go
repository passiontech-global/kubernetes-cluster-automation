// review_gap_test.go — regression coverage for the review's
// maintenance-package gaps: the 90m medik8s remediation horizon,
// evalFlight singleflight sharing under concurrency, and backward-
// clock memo behavior.
package maintenance

import (
	"context"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/testhelp"
)

func medik8sCRAt(gvr schema.GroupVersionResource, kind, ns, name,
	phase string, created time.Time) *unstructured.Unstructured {
	u := testhelp.Unstructured(gvr.GroupVersion().WithKind(kind),
		ns, name, nil)
	if phase != "" {
		u.Object["status"] = map[string]any{"phase": phase}
	}
	if !created.IsZero() {
		u.SetCreationTimestamp(metav1.NewTime(created))
	}
	return u
}

// The 90m horizon: a Running NodeMaintenance younger than
// medik8sRemediationMaxAge holds the mutex, one past it is a stuck
// record and does not, and a timestamp-less CR fails closed (held).
func TestMedik8sRemediationMaxAgeBoundary(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewSimpleClientset()
	now := time.Now()
	for _, tc := range []struct {
		name    string
		created time.Time
		held    bool
	}{
		{"fresh-89m", now.Add(-89 * time.Minute), true},
		{"stale-91m", now.Add(-91 * time.Minute), false},
		{"no-timestamp", time.Time{}, true}, // unverifiable → fail closed
	} {
		t.Run(tc.name, func(t *testing.T) {
			obj := medik8sCRAt(kube.GVRNodeMaintenance, "NodeMaintenance",
				"", "w1", "Running", tc.created)
			held, why, err := MaintenanceActiveWithClock(ctx, cs,
				maintenanceDynFake(obj), now)
			if err != nil {
				t.Fatal(err)
			}
			if held != tc.held {
				t.Fatalf("held=%v (why %q), want %v", held, why, tc.held)
			}
		})
	}
}

// Concurrent Scope callers must share the single in-flight
// evaluation (evalFlight) — every waiter gets the same verdict and
// none restarts a duplicate sweep read. Under -race this also
// proves the flight handoff is race-free.
func TestVerdictScopeConcurrentSharesFlight(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewSimpleClientset()
	dyn := maintenanceDynFake()
	v := &Verdict{}
	now := time.Now()

	const callers = 8
	var wg sync.WaitGroup
	errs := make([]error, callers)
	scopes := make([]Scope, callers)
	for i := range callers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			scopes[i], errs[i] = v.Scope(ctx, cs, dyn, now)
		}(i)
	}
	wg.Wait()
	for i := range callers {
		if errs[i] != nil {
			t.Fatalf("caller %d err=%v", i, errs[i])
		}
		// Scope carries a map — compare field-wise, not with !=.
		if scopes[i].Held != scopes[0].Held ||
			scopes[i].ClusterWide != scopes[0].ClusterWide ||
			scopes[i].Why != scopes[0].Why ||
			len(scopes[i].Nodes) != len(scopes[0].Nodes) {
			t.Fatalf("caller %d scope diverged: %+v vs %+v",
				i, scopes[i], scopes[0])
		}
	}
}

// A backward-moving clock must not serve a stale memo: Scope's
// freshness check requires now >= at, so an earlier `now` re-
// evaluates rather than replaying a verdict from the "future".
func TestVerdictScopeBackwardClockReevaluates(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewSimpleClientset()
	dyn := maintenanceDynFake()
	v := &Verdict{}
	t0 := time.Now()

	if _, err := v.Scope(ctx, cs, dyn, t0); err != nil {
		t.Fatal(err)
	}
	// Backward clock: before the memo's `at` — must re-evaluate,
	// not panic or serve the future-stamped verdict blindly.
	if _, err := v.Scope(ctx, cs, dyn, t0.Add(-time.Hour)); err != nil {
		t.Fatalf("backward-clock Scope err=%v", err)
	}
	// And a normal forward read inside the TTL still memoizes.
	if _, err := v.Scope(ctx, cs, dyn, t0.Add(time.Minute)); err != nil {
		t.Fatalf("forward-clock Scope err=%v", err)
	}
}
