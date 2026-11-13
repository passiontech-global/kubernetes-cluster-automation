// unlock_gate_test.go — the unlock gates: the 24h cooldown alert,
// cooldown expiry, the 30m first-seen window, recovery pruning, the
// ledger prune, the crash-loop skip and the persisted
// last-helm-unlock stamp.
package helmreleaseunlocker

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kfake "k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// An HR that is stuck again inside the 24h cooldown: the previous
// unlock did not fix it → alert (IncError), no action.
func TestHelmReleaseUnlockerCooldownAlert(t *testing.T) {
	hr := hrObj("apps", "myapp", "v2")
	hrReady(hr, "False", "another operation is in progress")

	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v1", "myapp", 1, "deployed"),
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v2", "myapp", 2, "pending-upgrade"))
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")
	u.pending.unlocked.Stamp("apps/myapp", time.Now().Add(-time.Hour)) // unlocked 1h ago

	before := testutil.ReconcileErrorCount(t, "helmrelease-unlocker")
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("secret deleted inside the 24h cooldown")
	}
	if got := hrAnnotation(t, dyn, helmReleaseGVRs[0], "apps", "myapp", fluxReconcileAnno); got != "" {
		t.Fatal("HR annotated inside the 24h cooldown")
	}
	if got := testutil.ReconcileErrorCount(t, "helmrelease-unlocker"); got != before+1 {
		t.Fatalf("cooldown alert did not IncError: got %v, want %v", got, before+1)
	}
}

// Cooldown expired (>24h) → a fresh unlock IS allowed.
func TestHelmReleaseUnlockerCooldownExpired(t *testing.T) {
	hr := hrObj("apps", "myapp", "v2")
	hrReady(hr, "False", "another operation is in progress")

	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v1", "myapp", 1, "deployed"),
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v2", "myapp", 2, "pending-rollback"))
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")
	u.pending.unlocked.Stamp("apps/myapp", time.Now().Add(-25*time.Hour))

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("pending secret not deleted after cooldown expiry")
	}
}

// helm-controller CrashLoopBackOff → warn + skip the whole run:
// without a working controller the unlock cannot converge.
func TestHelmReleaseUnlockerCrashLoopSkip(t *testing.T) {
	hr := hrObj("apps", "myapp", "v2")
	hrReady(hr, "False", "another operation is in progress")

	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v1", "myapp", 1, "deployed"),
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v2", "myapp", 2, "pending-upgrade"),
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "helm-controller-abc",
				Namespace: "flux-system",
				Labels:    map[string]string{"app.kubernetes.io/name": "helm-controller"},
			},
			Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
				Name:  "manager",
				State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
			}}},
		})
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("secret deleted while helm-controller is crashlooping")
	}
}

// The 30m first-seen gate: a fresh "in progress" must be tracked but
// never acted on until the window elapses.
func TestHelmReleaseUnlockerFirstSeenGate(t *testing.T) {
	hr := hrObj("apps", "myapp", "v2")
	hrReady(hr, "False", "another operation is in progress")

	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v1", "myapp", 1, "deployed"),
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v2", "myapp", 2, "pending-upgrade"))
	u := newUnlocker(cs, dyn, 0, "")

	// First run: records first-seen, must NOT act.
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := u.pending.firstSeen.Seen("apps/myapp", time.Now()); !ok {
		t.Fatal("stuck HR not tracked in firstSeen")
	}
	if !secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("acted before the 30m window elapsed")
	}

	// Second run inside the window: still no action.
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("acted before the 30m window elapsed (2nd tick)")
	}

	// Window elapsed → act. Forget+Observe re-seeds the first-seen
	// stamp unconditionally (Observe alone only stamps absent keys).
	u.pending.firstSeen.Forget("apps/myapp")
	u.pending.firstSeen.Observe("apps/myapp", time.Now().Add(-helmStuckThreshold-time.Minute))
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("pending secret not deleted after the 30m window")
	}
}

// Recovery prunes the first-seen marker so a later stall re-arms.
func TestHelmReleaseUnlockerRecoveryPrunesFirstSeen(t *testing.T) {
	hr := hrObj("apps", "myapp", "v2")
	hrReady(hr, "False", "another operation is in progress")

	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset()
	u := newUnlocker(cs, dyn, 0, "")

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := u.pending.firstSeen.Seen("apps/myapp", time.Now()); !ok {
		t.Fatal("stuck HR not tracked")
	}

	// HR reconciled fine — message cleared.
	hrReady(hr, "True", "Reconciliation finished")
	if _, err := dyn.Resource(helmReleaseGVRs[0]).Namespace("apps").
		Update(ctx, hr, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := u.pending.firstSeen.Seen("apps/myapp", time.Now()); ok {
		t.Fatal("recovered HR not pruned from firstSeen")
	}
}

// The unlock ledger prunes entries whose HelmRelease vanished or whose
// stamp aged past the 24h cooldown, and keeps a live HR still inside it.
func TestHelmReleaseUnlockerPrunesUnlockedLedger(t *testing.T) {
	live := hrObj("apps", "myapp", "v2")
	hrReady(live, "True", "Reconciliation finished")
	old := hrObj("apps", "oldrel", "v2")
	hrReady(old, "True", "Reconciliation finished")
	dyn := newDynFake(live, old)
	u := newUnlocker(kfake.NewSimpleClientset(), dyn, 0, "")
	u.pending.unlocked.Stamp("apps/myapp", time.Now()) // live HR inside cooldown → keep
	u.pending.unlocked.Stamp("apps/gone", time.Now())  // HR vanished → prune
	// Live HR past the cooldown → pruned by age, not absence.
	u.pending.unlocked.Stamp("apps/oldrel", time.Now().Add(-helmUnlockCooldown-time.Minute))

	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := u.pending.unlocked.Entries()["apps/gone"]; ok {
		t.Fatal("unlocked entry for a deleted HR not pruned")
	}
	if _, ok := u.pending.unlocked.Entries()["apps/oldrel"]; ok {
		t.Fatal("live HR's unlocked entry past the cooldown not pruned")
	}
	if _, ok := u.pending.unlocked.Entries()["apps/myapp"]; !ok {
		t.Fatal("live HR inside the cooldown lost its unlock-ledger entry")
	}
}

// The persisted passiontech.dev/last-helm-unlock stamp IS the cooldown: with
// an empty in-RAM ledger (post-restart) an HR still inside 24h is
// alerted, not re-unlocked.
func TestHelmReleaseUnlockerPersistedCooldown(t *testing.T) {
	hr := hrObj("apps", "myapp", "v2")
	hrReady(hr, "False", "another operation is in progress")
	hr.SetAnnotations(map[string]string{
		helmLastUnlockAnno: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	})
	dyn := newDynFake(hr)
	cs := kfake.NewSimpleClientset(
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v1", "myapp", 1, "deployed"),
		helmRelSecret("apps", "sh.helm.release.v1.myapp.v2", "myapp", 2, "pending-upgrade"))
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")

	before := testutil.ReconcileErrorCount(t, "helmrelease-unlocker")
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !secretExists(t, cs, "apps", "sh.helm.release.v1.myapp.v2") {
		t.Fatal("secret deleted inside the persisted 24h cooldown")
	}
	if got := testutil.ReconcileErrorCount(t, "helmrelease-unlocker"); got != before+1 {
		t.Fatalf("persisted-cooldown alert did not IncError: got %v, want %v", got, before+1)
	}
}

// A successful unlock stamps BOTH reconcile.fluxcd.io/requestedAt and
// passiontech.dev/last-helm-unlock on the HR.
func TestHelmReleaseUnlockerStampsLastUnlockAnnotation(t *testing.T) {
	dyn, secrets := stuckHRFixture()
	cs := kfake.NewSimpleClientset(secrets...)
	u := newUnlocker(cs, dyn, time.Hour, "apps/myapp")
	if err := u.run(ctx); err != nil {
		t.Fatal(err)
	}
	got := hrAnnotation(t, dyn, helmReleaseGVRs[0], "apps", "myapp", helmLastUnlockAnno)
	if got == "" {
		t.Fatal("passiontech.dev/last-helm-unlock not persisted on unlock")
	}
	if _, err := time.Parse(time.RFC3339, got); err != nil {
		t.Fatalf("last-helm-unlock %q is not RFC3339: %v", got, err)
	}
}
