// coord_test.go — the L1↔L3 coordination protocol: cached
// Cluster→Node verdicts, nodes/status + pod stamp writes, and the
// fail-open HoldLocalAction contract (hold only inside a previously
// CONFIRMED maintenance window; unverifiable state otherwise fails
// open so a dead apiserver cannot freeze L1 self-heal).
package nodecoord

import (
	"context"
	"errors"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

func TestMaintenanceActiveStamp(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	var gets int
	c := &Coord{
		Now: func() time.Time { return now },
		GetAnnos: func(context.Context) (map[string]string, error) {
			gets++
			return map[string]string{
				nodecond.AnnoClusterMaintenanceUntil: now.Add(10 * time.Minute).Format(time.RFC3339),
			}, nil
		},
	}
	v, err := c.Maintenance(context.Background())
	if err != nil || !v.Active {
		t.Fatalf("verdict = %+v err=%v, want active", v, err)
	}
	// Second call inside CacheTTL must not re-read.
	if _, err := c.Maintenance(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gets != 1 {
		t.Fatalf("gets = %d, want 1 (cache)", gets)
	}
	if !c.HoldLocalAction(context.Background()) {
		t.Fatal("HoldLocalAction false during active maintenance")
	}
}

func TestMaintenanceExpiredStamp(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	c := &Coord{
		Now: func() time.Time { return now },
		GetAnnos: func(context.Context) (map[string]string, error) {
			return map[string]string{
				nodecond.AnnoClusterMaintenanceUntil: now.Add(-time.Minute).Format(time.RFC3339),
			}, nil
		},
	}
	v, err := c.Maintenance(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v.Active || v.MaintenanceUntil.IsZero() {
		t.Fatalf("verdict = %+v, want inactive with parsed stamp", v)
	}
	if c.HoldLocalAction(context.Background()) {
		t.Fatal("HoldLocalAction true on expired stamp")
	}
}

func TestMaintenanceKuredLock(t *testing.T) {
	c := &Coord{
		GetAnnos: func(context.Context) (map[string]string, error) {
			return map[string]string{kuredLockAnno: "node-3"}, nil
		},
	}
	v, err := c.Maintenance(context.Background())
	if err != nil || !v.Active || !v.KuredLocked {
		t.Fatalf("verdict = %+v err=%v, want kured-locked active", v, err)
	}
}

// TestHoldLocalActionFailsOpenOnError is the RBAC contract: a
// controller VM with no Node object (404) or a dead apiserver must
// NOT freeze L1 self-heal — HoldLocalAction returns false when no
// previously confirmed maintenance window is still open.
func TestHoldLocalActionFailsOpenOnError(t *testing.T) {
	notFound := apierrors.NewNotFound(
		schema.GroupResource{Resource: "nodes"}, "ctrl-vm")
	for name, err := range map[string]error{
		"404":     notFound,
		"connref": errors.New("connection refused"),
	} {
		c := &Coord{
			GetAnnos: func(context.Context) (map[string]string, error) {
				return nil, err
			},
		}
		if c.HoldLocalAction(context.Background()) {
			t.Fatalf("%s: HoldLocalAction must fail open with no confirmed window", name)
		}
	}
}

// TestHoldLocalActionHoldsInsideConfirmedWindow: once a verdict
// confirmed a live MaintenanceUntil, an API failure keeps holding
// while now < until — a drain verified moments ago survives an
// apiserver blip — and fails open once the window lapses.
func TestHoldLocalActionHoldsInsideConfirmedWindow(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	until := now.Add(10 * time.Minute)
	fail := false
	c := &Coord{
		Now: func() time.Time { return now },
		GetAnnos: func(context.Context) (map[string]string, error) {
			if fail {
				return nil, errors.New("apiserver gone")
			}
			return map[string]string{
				nodecond.AnnoClusterMaintenanceUntil: until.Format(time.RFC3339),
			}, nil
		},
	}
	if !c.HoldLocalAction(context.Background()) {
		t.Fatal("want hold during confirmed window")
	}
	// API dies mid-window → still holds (confirmed window open).
	fail = true
	c.Now = func() time.Time { return now.Add(5 * time.Minute) }
	// Expire the read cache so the error path is exercised.
	c.cachedAt = now.Add(-2 * CacheTTL)
	if !c.HoldLocalAction(context.Background()) {
		t.Fatal("want hold inside confirmed window despite API error")
	}
	// Window lapses → fail open.
	c.Now = func() time.Time { return until.Add(time.Minute) }
	c.cachedAt = now.Add(-2 * CacheTTL)
	if c.HoldLocalAction(context.Background()) {
		t.Fatal("want fail-open after confirmed window lapses")
	}
}

// TestHoldLocalActionKuredSurvivesFlap: a SUCCESSFULLY READ kured
// drain lock keeps holding through kuredLockTTL of apiserver
// failure — a brief flap must not drop the drain hold — then fails
// open. And a cached FALSE verdict is never promoted to a hold by
// the error itself (fresh evidence wins over the cache).
func TestHoldLocalActionKuredSurvivesFlap(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	fail := false
	c := &Coord{
		Now: func() time.Time { return t0 },
		GetAnnos: func(context.Context) (map[string]string, error) {
			if fail {
				return nil, errors.New("apiserver gone")
			}
			return map[string]string{kuredLockAnno: "node-3"}, nil
		},
	}
	if !c.HoldLocalAction(context.Background()) {
		t.Fatal("want hold on confirmed kured lock")
	}
	// API dies 10s later — inside kuredLockTTL the confirmed lock
	// still holds (cachedAt is forced stale so the error path runs).
	fail = true
	c.Now = func() time.Time { return t0.Add(10 * time.Second) }
	c.cachedAt = t0.Add(-2 * CacheTTL)
	if !c.HoldLocalAction(context.Background()) {
		t.Fatal("want hold through flap inside kuredLockTTL")
	}
	// Past the TTL the unverifiable lock drops → fail open (no
	// maintenance window was ever confirmed).
	c.Now = func() time.Time { return t0.Add(2 * kuredLockTTL) }
	c.cachedAt = t0.Add(-2 * CacheTTL)
	if c.HoldLocalAction(context.Background()) {
		t.Fatal("want fail-open after kuredLockTTL of API failure")
	}
}

// TestMaintenanceErrorKeepsCachedFalse: the stale-while-error path
// must not overwrite a cached FALSE verdict with Active=true — an
// API error is not evidence of a hold.
func TestMaintenanceErrorKeepsCachedFalse(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	fail := false
	c := &Coord{
		Now: func() time.Time { return t0 },
		GetAnnos: func(context.Context) (map[string]string, error) {
			if fail {
				return nil, errors.New("apiserver gone")
			}
			return map[string]string{}, nil // no maintenance evidence
		},
	}
	if _, err := c.Maintenance(context.Background()); err != nil {
		t.Fatal(err)
	}
	fail = true
	c.Now = func() time.Time { return t0.Add(time.Minute) }
	c.cachedAt = t0.Add(-2 * CacheTTL)
	v, err := c.Maintenance(context.Background())
	if err == nil {
		t.Fatal("want the API error surfaced")
	}
	if v.Active {
		t.Fatalf("cached FALSE verdict promoted to Active on error: %+v", v)
	}
}

func TestStamps(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	var conds []StatusCondition
	var podAnno map[string]string
	var podNS, podName string
	c := &Coord{
		Now: func() time.Time { return now },
		PatchNodeStatus: func(_ context.Context, cond StatusCondition) error {
			conds = append(conds, cond)
			return nil
		},
		PatchPodAnno: func(_ context.Context, ns, name string, annos map[string]string) error {
			podNS, podName, podAnno = ns, name, annos
			return nil
		},
	}
	if err := c.StampLocalRemediation(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(conds) != 1 || conds[0].Type != nodecond.CondLocalRemediation ||
		conds[0].Status != "True" {
		t.Fatalf("remediation condition = %+v", conds)
	}
	if err := c.StampPodHealed(context.Background(), "kube-system", "coredns-abc"); err != nil {
		t.Fatal(err)
	}
	if podNS != "kube-system" || podName != "coredns-abc" {
		t.Fatalf("pod stamp target = %s/%s", podNS, podName)
	}
	if podAnno[nodecond.AnnoLastPodHealedAt] != now.UTC().Format(time.RFC3339) {
		t.Fatalf("healed stamp = %q", podAnno[nodecond.AnnoLastPodHealedAt])
	}
	// StampPodHealed must ALSO refresh the condition heartbeat.
	if len(conds) != 2 {
		t.Fatalf("conditions = %d, want 2 (remediation + healed heartbeat)", len(conds))
	}
}

// TestStampPodHealedPodPatchFailsStillStampsCondition: a missing
// pod (already gone) must not suppress the nodes/status refresh.
func TestStampPodHealedPodPatchFailsStillStampsCondition(t *testing.T) {
	var conds int
	notFound := apierrors.NewNotFound(
		schema.GroupResource{Resource: "pods"}, "gone")
	c := &Coord{
		PatchNodeStatus: func(context.Context, StatusCondition) error {
			conds++
			return nil
		},
		PatchPodAnno: func(context.Context, string, string, map[string]string) error {
			return notFound
		},
	}
	if err := c.StampPodHealed(context.Background(), "ns", "gone"); err != nil {
		t.Fatalf("404 pod patch must be silent, got %v", err)
	}
	if conds != 1 {
		t.Fatalf("condition stamps = %d, want 1", conds)
	}
}

// TestStampLocalRemediationIgnoresNode404: a standalone controller
// VM has no Node object — the status patch 404s and must be silent.
func TestStampLocalRemediationIgnoresNode404(t *testing.T) {
	notFound := apierrors.NewNotFound(
		schema.GroupResource{Resource: "nodes"}, "ctrl-vm")
	c := &Coord{
		PatchNodeStatus: func(context.Context, StatusCondition) error {
			return notFound
		},
	}
	if err := c.StampLocalRemediation(context.Background()); err != nil {
		t.Fatalf("404 node status patch must be silent, got %v", err)
	}
}

func TestStampNilSeam(t *testing.T) {
	c := &Coord{}
	if err := c.StampPodHealed(context.Background(), "ns", "p"); err == nil {
		t.Fatal("expected nil-seam error")
	}
}
