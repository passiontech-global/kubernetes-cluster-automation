// replicated_secret_audit_test.go — coverage for the
// kubernetes-replicator resync heal (replicator-cert-drift):
// forceReplicationResync strips the replicated-from-version
// annotation so the replicator copies the source fresh — rate-limited
// per destination, counted on failure, stamped only on delivery.
package certdriftauditor

import (
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

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
