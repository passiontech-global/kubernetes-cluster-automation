// coord_test.go — the L1↔L3 coordination protocol: cached
// Cluster→Node verdicts, nodes/status + pod stamp writes, and the
// two maintenance gates: HoldLocalAction fails CLOSED on API
// errors (404 alone fails open — destructive heals must never run
// mid-drain) while HoldEmergencyHeal fails OPEN and holds only on
// positively-known maintenance.
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
			return map[string]string{nodecond.KuredLockAnno: "node-3"}, nil
		},
	}
	v, err := c.Maintenance(context.Background())
	if err != nil || !v.Active || !v.KuredLocked {
		t.Fatalf("verdict = %+v err=%v, want kured-locked active", v, err)
	}
}

// TestHoldLocalActionFailClosedOnError is the destructive-heal
// contract: a node WITH a Node object whose annotation read fails
// for any non-404 reason (network, timeout, 5xx) must HOLD —
// deleting pvc-* state or evicting pods mid-drain is unrecoverable.
// Only the 404 (standalone controller VM, no Node object) fails
// open, because maintenance is unverifiable there by construction.
func TestHoldLocalActionFailClosedOnError(t *testing.T) {
	notFound := apierrors.NewNotFound(
		schema.GroupResource{Resource: "nodes"}, "ctrl-vm")
	for name, tc := range map[string]struct {
		err  error
		want bool
	}{
		"404":       {notFound, false},
		"connref":   {errors.New("connection refused"), true},
		"deadline":  {context.DeadlineExceeded, true},
		"forbidden": {apierrors.NewForbidden(schema.GroupResource{Resource: "nodes"}, "n", errors.New("rbac")), true},
		"unavail":   {apierrors.NewServiceUnavailable("apiserver gone"), true},
	} {
		c := &Coord{
			GetAnnos: func(context.Context) (map[string]string, error) {
				return nil, tc.err
			},
		}
		if got := c.HoldLocalAction(context.Background()); got != tc.want {
			t.Fatalf("%s: HoldLocalAction = %v, want %v", name, got, tc.want)
		}
	}
}

// TestHoldEmergencyHealFailsOpenOnError: the self-heal gate must
// never freeze controller/CNI recovery on an unreachable apiserver
// — with no positively-known maintenance it returns false.
func TestHoldEmergencyHealFailsOpenOnError(t *testing.T) {
	c := &Coord{
		GetAnnos: func(context.Context) (map[string]string, error) {
			return nil, errors.New("apiserver gone")
		},
	}
	if c.HoldEmergencyHeal(context.Background()) {
		t.Fatal("HoldEmergencyHeal must fail open with no confirmed state")
	}
}

// TestHoldEmergencyHealHoldsInsideConfirmedWindow: once a verdict
// confirmed a live MaintenanceUntil, an API failure keeps holding
// while now < lastMaintUntil — and fails open once the window
// lapses (unlike HoldLocalAction, which holds on ANY error).
func TestHoldEmergencyHealHoldsInsideConfirmedWindow(t *testing.T) {
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
	if !c.HoldEmergencyHeal(context.Background()) {
		t.Fatal("want hold during confirmed window")
	}
	// API dies mid-window → still holds (confirmed window open).
	fail = true
	c.Now = func() time.Time { return now.Add(5 * time.Minute) }
	// Expire the read cache so the error path is exercised.
	c.cachedAt = now.Add(-2 * CacheTTL)
	if !c.HoldEmergencyHeal(context.Background()) {
		t.Fatal("want hold inside confirmed window despite API error")
	}
	// Window lapses → fail open.
	c.Now = func() time.Time { return until.Add(time.Minute) }
	c.cachedAt = now.Add(-2 * CacheTTL)
	if c.HoldEmergencyHeal(context.Background()) {
		t.Fatal("want fail-open after confirmed window lapses")
	}
}

// TestHoldEmergencyHealKuredSurvivesFlap: a SUCCESSFULLY READ kured
// drain lock keeps holding HoldEmergencyHeal through kuredHealTTL
// (10m) of apiserver failure — a kured drain legitimately runs for
// minutes — then fails open.
func TestHoldEmergencyHealKuredSurvivesFlap(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	fail := false
	c := &Coord{
		Now: func() time.Time { return t0 },
		GetAnnos: func(context.Context) (map[string]string, error) {
			if fail {
				return nil, errors.New("apiserver gone")
			}
			return map[string]string{nodecond.KuredLockAnno: "node-3"}, nil
		},
	}
	if !c.HoldEmergencyHeal(context.Background()) {
		t.Fatal("want hold on confirmed kured lock")
	}
	// API dies 5m later — inside kuredHealTTL the confirmed lock
	// still holds (cachedAt is forced stale so the error path runs).
	fail = true
	c.Now = func() time.Time { return t0.Add(5 * time.Minute) }
	c.cachedAt = t0.Add(-2 * CacheTTL)
	if !c.HoldEmergencyHeal(context.Background()) {
		t.Fatal("want hold through flap inside kuredHealTTL")
	}
	// Past the 10m window the unverifiable lock drops → fail open.
	c.Now = func() time.Time { return t0.Add(kuredHealTTL + time.Minute) }
	c.cachedAt = t0.Add(-2 * CacheTTL)
	if c.HoldEmergencyHeal(context.Background()) {
		t.Fatal("want fail-open after kuredHealTTL of API failure")
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
