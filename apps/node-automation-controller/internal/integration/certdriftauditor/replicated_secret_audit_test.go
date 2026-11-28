// replicated_secret_audit_test.go — coverage for the
// kubernetes-replicator resync heal (replicator-cert-drift):
// forceReplicationResync strips the replicated-from-version
// annotation so the replicator copies the source fresh — rate-limited
// per destination, counted on failure, stamped only on delivery.
package certdriftauditor

import (
	"bytes"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

var (
	resyncRef = replicatedSecretRef{
		namespace: "app", name: "dest-tls", source: "ca/ca-src"}
	resyncKey = replicationMetricKey{
		namespace: "app", name: "dest-tls", source: "ca/ca-src"}
)

// The strip is the whole heal: the destination loses its
// replicated-from-version annotation so kubernetes-replicator copies
// the source fresh next pass, and the cooldown is stamped on the
// DELIVERED patch only.
func TestForceReplicationResyncStrips(t *testing.T) {
	cs := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "app", Name: "dest-tls",
			Annotations: map[string]string{
				replicatedFromVersionAnno: "42"},
		},
	})
	now := time.Now()
	a := newCertDriftAuditor(cs, nil, now)
	a.forceReplicationResync(ctx, resyncRef, resyncKey)

	s, err := cs.CoreV1().Secrets("app").Get(ctx, "dest-tls", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Annotations[replicatedFromVersionAnno]; ok {
		t.Fatal("replicated-from-version annotation survived the strip — the resync never lands")
	}
	if _, ok := a.resyncHeals.Last(replStreakKey(resyncKey)); !ok {
		t.Fatal("delivered strip did not stamp the resync cooldown")
	}
}

// A destination inside the cooldown window is skipped BEFORE the
// patch is attempted — the in-RAM ledger bounds the heal to once
// per hour per destination.
func TestForceReplicationResyncCooldownSkips(t *testing.T) {
	cs := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "app", Name: "dest-tls",
			Annotations: map[string]string{
				replicatedFromVersionAnno: "42"},
		},
	})
	patches := 0
	cs.PrependReactor("patch", "secrets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			patches++
			return false, nil, nil
		})
	now := time.Now()
	a := newCertDriftAuditor(cs, nil, now)
	a.resyncHeals.Stamp(replStreakKey(resyncKey), now.Add(-time.Minute))
	a.forceReplicationResync(ctx, resyncRef, resyncKey)
	if patches != 0 {
		t.Fatalf("patched %d times inside the cooldown, want 0", patches)
	}
}

// A failed patch is counted and NOT stamped — the next sweep must
// retry rather than sit out the hour with a drifted copy.
func TestForceReplicationResyncPatchError(t *testing.T) {
	cs := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "app", Name: "dest-tls",
			Annotations: map[string]string{
				replicatedFromVersionAnno: "42"},
		},
	})
	cs.PrependReactor("patch", "secrets",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
	now := time.Now()
	a := newCertDriftAuditor(cs, nil, now)
	a.queue = "cert-drift-auditor"
	before := testutil.QueueErrorCount(t, "cert-drift-auditor")
	a.forceReplicationResync(ctx, resyncRef, resyncKey)

	if _, ok := a.resyncHeals.Last(replStreakKey(resyncKey)); ok {
		t.Fatal("failed patch stamped the cooldown — the drift is masked for an hour")
	}
	if got := testutil.QueueErrorCount(t, "cert-drift-auditor") - before; got != 1 {
		t.Fatalf("queue errors delta = %v, want 1", got)
	}
}

// Persistent drift across 4 sweeps escalates from replicated-from-version
// stripping (scan 2) to direct merge-patch sync of tls.crt/tls.key/ca.crt
// from the source Secret (scan 4), and clears the drift gauge on scan 5.
func TestReplicatedDriftEscalatesToDirectSyncAfterFourScans(t *testing.T) {
	testutil.CleanupMetric(t, metrics.ReplicatedSecretDrift, "app", "dest-tls", "default/src-tls")

	src := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "src-tls"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": []byte("NEW-CERT"),
			"tls.key": []byte("NEW-KEY"),
			"ca.crt":  []byte("NEW-CA"),
		},
	}
	dest := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "app", Name: "dest-tls",
			Annotations: map[string]string{
				replicatedFromAnno:        "default/src-tls",
				replicatedFromVersionAnno: "11",
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": []byte("OLD-CERT"),
			"tls.key": []byte("OLD-KEY"),
		},
	}
	cs := fake.NewSimpleClientset(src, dest)
	a := newCertDriftAuditor(cs, cdaDyn(), time.Now())

	// Scan 1: mid-sync grace — no gauge, no patch.
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ := cs.CoreV1().Secrets("app").Get(ctx, "dest-tls", metav1.GetOptions{})
	if _, ok := got.Annotations[replicatedFromVersionAnno]; !ok {
		t.Fatal("scan 1 stripped replicated-from-version too early")
	}

	// Scan 2: drift latches, strips replicated-from-version, data still old.
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ = cs.CoreV1().Secrets("app").Get(ctx, "dest-tls", metav1.GetOptions{})
	if _, ok := got.Annotations[replicatedFromVersionAnno]; ok {
		t.Fatal("scan 2 did not strip replicated-from-version")
	}
	if !bytes.Equal(got.Data["tls.crt"], []byte("OLD-CERT")) {
		t.Fatalf("scan 2 direct-synced too early: tls.crt=%q", got.Data["tls.crt"])
	}

	// Scan 3: still below replicationDirectSyncScans (4) — no direct sync yet.
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ = cs.CoreV1().Secrets("app").Get(ctx, "dest-tls", metav1.GetOptions{})
	if !bytes.Equal(got.Data["tls.crt"], []byte("OLD-CERT")) {
		t.Fatalf("scan 3 direct-synced too early: tls.crt=%q", got.Data["tls.crt"])
	}

	// Scan 4: escalates to direct fallback sync.
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ = cs.CoreV1().Secrets("app").Get(ctx, "dest-tls", metav1.GetOptions{})
	if !bytes.Equal(got.Data["tls.crt"], []byte("NEW-CERT")) ||
		!bytes.Equal(got.Data["tls.key"], []byte("NEW-KEY")) ||
		!bytes.Equal(got.Data["ca.crt"], []byte("NEW-CA")) {
		t.Fatalf("scan 4 did not direct-sync source data: got=%v", got.Data)
	}
	if _, ok := a.directSyncHeals.Last("app/dest-tls/default/src-tls"); !ok {
		t.Fatal("directSyncHeals cooldown was not stamped")
	}

	// Scan 5: destination now matches source — streak resets and gauge drops.
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := driftGauge("app", "dest-tls", "default/src-tls"); got != 0 {
		t.Fatalf("drift gauge after convergence = %v, want 0", got)
	}
}

func TestDirectSyncReplicatedSecretCooldownDisabledAndError(t *testing.T) {
	t.Run("cooldown skips patch", func(t *testing.T) {
		cs := fake.NewSimpleClientset(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "dest-tls"},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{"tls.crt": []byte("OLD")},
		})
		patches := 0
		cs.PrependReactor("patch", "secrets", func(ktesting.Action) (bool, runtime.Object, error) {
			patches++
			return false, nil, nil
		})
		now := time.Now()
		a := newCertDriftAuditor(cs, nil, now)
		a.directSyncHeals.Stamp(replStreakKey(resyncKey), now.Add(-10*time.Minute))
		a.directSyncReplicatedSecret(ctx, resyncRef, resyncKey, &corev1.Secret{
			Data: map[string][]byte{"tls.crt": []byte("NEW")},
		})
		if patches != 0 {
			t.Fatalf("patched %d times inside cooldown, want 0", patches)
		}
	})

	t.Run("disabled flag skips direct sync at scan 4", func(t *testing.T) {
		testutil.CleanupMetric(t, metrics.ReplicatedSecretDrift, "app", "dest-tls", "default/src-tls")
		src := replicatedSecret("default", "src-tls", "", "NEW")
		dest := replicatedSecret("app", "dest-tls", "default/src-tls", "OLD")
		cs := fake.NewSimpleClientset(src, dest)
		a := newCertDriftAuditor(cs, cdaDyn(), time.Now())
		a.disableReplicatedDirectSync = true

		for range 4 {
			if err := a.run(ctx); err != nil {
				t.Fatal(err)
			}
		}
		got, _ := cs.CoreV1().Secrets("app").Get(ctx, "dest-tls", metav1.GetOptions{})
		if !bytes.Equal(got.Data["tls.crt"], []byte("OLD")) {
			t.Fatalf("direct sync patched despite disableReplicatedDirectSync=true: %q", got.Data["tls.crt"])
		}
	})

	t.Run("patch error counts queue error and does not stamp cooldown", func(t *testing.T) {
		cs := fake.NewSimpleClientset(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "dest-tls"},
		})
		cs.PrependReactor("patch", "secrets", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("api down")
		})
		a := newCertDriftAuditor(cs, nil, time.Now())
		a.queue = "cert-drift-auditor"
		before := testutil.QueueErrorCount(t, "cert-drift-auditor")
		a.directSyncReplicatedSecret(ctx, resyncRef, resyncKey, &corev1.Secret{
			Data: map[string][]byte{"tls.crt": []byte("NEW")},
		})
		if _, ok := a.directSyncHeals.Last(replStreakKey(resyncKey)); ok {
			t.Fatal("failed patch stamped directSyncHeals cooldown")
		}
		if got := testutil.QueueErrorCount(t, "cert-drift-auditor") - before; got != 1 {
			t.Fatalf("queue errors delta = %v, want 1", got)
		}
	})
}

func TestReplicateToMissingTargetsDetection(t *testing.T) {
	testutil.CleanupMetric(t, metrics.ReplicatedSecretDrift, "ns-present", "wildcard-tls", "default/wildcard-tls")
	testutil.CleanupMetric(t, metrics.ReplicatedSecretDrift, "ns-missing", "wildcard-tls", "default/wildcard-tls")
	testutil.CleanupMetric(t, metrics.ReplicatedSecretDrift, "ns-term", "wildcard-tls", "default/wildcard-tls")
	testutil.CleanupMetric(t, metrics.ReplicatedSecretDrift, "ns-absent", "wildcard-tls", "default/wildcard-tls")

	src := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default", Name: "wildcard-tls",
			Annotations: map[string]string{
				replicateToAnno: "ns-present, ns-missing, ns-missing, ns-term, ns-absent, default, .*, ns-[a-z]+",
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{"tls.crt": []byte("CERT")},
	}
	presentCopy := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns-present", Name: "wildcard-tls",
			Annotations: map[string]string{replicatedFromAnno: "default/wildcard-tls"},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{"tls.crt": []byte("CERT")},
	}
	nsDefault := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Status: corev1.NamespaceStatus{Phase: corev1.NamespaceActive}}
	nsPresent := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns-present"}, Status: corev1.NamespaceStatus{Phase: corev1.NamespaceActive}}
	nsMissing := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns-missing"}, Status: corev1.NamespaceStatus{Phase: corev1.NamespaceActive}}
	nsTerm := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns-term"}, Status: corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating}}

	cs := fake.NewSimpleClientset(src, presentCopy, nsDefault, nsPresent, nsMissing, nsTerm)
	a := newCertDriftAuditor(cs, cdaDyn(), time.Now())

	// Scan 1: below replicationDriftScans threshold.
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := driftGauge("ns-missing", "wildcard-tls", "default/wildcard-tls"); got != 0 {
		t.Fatalf("missing target gauge after 1 scan = %v, want 0", got)
	}

	// Scan 2: missing active literal target latches 1; present/terminating/absent/regex stay 0.
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := driftGauge("ns-missing", "wildcard-tls", "default/wildcard-tls"); got != 1 {
		t.Fatalf("missing target gauge after 2 scans = %v, want 1", got)
	}
	if got := driftGauge("ns-present", "wildcard-tls", "default/wildcard-tls"); got != 0 {
		t.Fatalf("present target gauge = %v, want 0", got)
	}
	if got := driftGauge("ns-term", "wildcard-tls", "default/wildcard-tls"); got != 0 {
		t.Fatalf("terminating target gauge = %v, want 0", got)
	}
	if got := driftGauge("ns-absent", "wildcard-tls", "default/wildcard-tls"); got != 0 {
		t.Fatalf("non-existent target gauge = %v, want 0", got)
	}

	// Creating the target Secret clears the series on the next scan.
	if _, err := cs.CoreV1().Secrets("ns-missing").Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns-missing", Name: "wildcard-tls"},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": []byte("CERT")},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := a.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := driftGauge("ns-missing", "wildcard-tls", "default/wildcard-tls"); got != 0 {
		t.Fatalf("target gauge did not clear after secret created: %v", got)
	}

	// Namespace list errors carry forward previously-emitted drift series
	// and preserve streaks without failing run().
	cs.PrependReactor("list", "namespaces", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("namespaces list unavailable")
	})
	// Re-arm ns-missing drift (delete the secret we just created and run 2 scans without reactor).
	cs.ReactionChain = cs.ReactionChain[1:]
	if err := cs.CoreV1().Secrets("ns-missing").Delete(ctx, "wildcard-tls", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := a.run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if got := driftGauge("ns-missing", "wildcard-tls", "default/wildcard-tls"); got != 1 {
		t.Fatalf("pre-outage missing target gauge = %v, want 1", got)
	}
	cs.PrependReactor("list", "namespaces", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("namespaces list unavailable")
	})
	if err := a.run(ctx); err != nil {
		t.Fatalf("namespaces list error broke run(): %v", err)
	}
	if got := driftGauge("ns-missing", "wildcard-tls", "default/wildcard-tls"); got != 1 {
		t.Fatalf("namespaces list error pruned active drift gauge = %v, want 1 (carried forward)", got)
	}
	if got := a.replicationMismatch.Count("ns-missing/wildcard-tls/default/wildcard-tls"); got < 2 {
		t.Fatalf("namespaces list error wiped replicationMismatch streak = %d, want >=2", got)
	}
}
