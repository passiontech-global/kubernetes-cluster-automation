// snapshot_verify_test.go — the post-sweep half of the mutation
// guard: VerifySweepSnapshotUnmutated re-checks every loaded memo's
// fingerprint after the checks finish (catching in-place writes
// that landed AFTER a memo's last read — invisible to the per-get
// guard), and PodNodes filters sweep-tombstoned pods on every read
// rather than serving a frozen first-read map.
package probefw

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// A clean sweep verifies silently — every loaded memo's fingerprint
// still matches its load-time state.
func TestVerifySweepSnapshotUnmutatedClean(t *testing.T) {
	EnableSnapshotVerify()
	cs := fake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "ns", Name: "p", UID: "u1"}})
	d := &Deps{CS: cs}
	sctx := WithSweepSnapshot(t.Context())

	if _, err := d.AllPods(sctx); err != nil {
		t.Fatal(err)
	}
	if _, err := d.PodNodes(sctx); err != nil {
		t.Fatal(err)
	}
	// Must not panic.
	VerifySweepSnapshotUnmutated(sctx)
}

// The gap the post-sweep verify closes: a census object mutated in
// place AFTER its memo's last read escapes every per-get check —
// the sweep's final checks never re-read it. VerifySweepSnapshot
// Unmutated re-fingerprints every loaded memo and panics on the
// first drift, same contract as the per-read guard.
func TestVerifySweepSnapshotUnmutatedCatchesLateMutation(t *testing.T) {
	EnableSnapshotVerify()
	cs := fake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "ns", Name: "p", UID: "u1"}})
	d := &Deps{CS: cs}
	sctx := WithSweepSnapshot(t.Context())

	pods, err := d.AllPods(sctx)
	if err != nil {
		t.Fatal(err)
	}
	// In-place write through the shared census slice — the exact
	// bug class the overlay exists to eliminate. No further census
	// read happens, so the per-get guard never fires.
	pods[0].Spec.NodeName = "mutated-node"

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("VerifySweepSnapshotUnmutated missed an in-place " +
				"census mutation after the memo's last read")
		}
	}()
	VerifySweepSnapshotUnmutated(sctx)
}

// Outside a sweep ctx the verify is a no-op — each census call
// already saw fresh data, there is nothing memoized to check.
func TestVerifySweepSnapshotUnmutatedNoSnapshot(t *testing.T) {
	EnableSnapshotVerify()
	VerifySweepSnapshotUnmutated(t.Context()) // must not panic
}

// PodNodes filters tombstoned pods on EVERY read: the memoized
// placement map is built once, but a pod deleted mid-sweep via the
// O(1) MarkPodDeleted path (which deliberately does NOT invalidate
// the derived join) must drop out of every later PodNodes call.
func TestPodNodesExcludesTombstonedPods(t *testing.T) {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns", Name: "web-0", UID: "u-del"},
		Spec: corev1.PodSpec{NodeName: "w1"},
	}
	q := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns", Name: "web-1", UID: "u-live"},
		Spec: corev1.PodSpec{NodeName: "w2"},
	}
	d := &Deps{CS: fake.NewSimpleClientset(p, q)}
	sctx := WithSweepSnapshot(t.Context())

	m, err := d.PodNodes(sctx)
	if err != nil {
		t.Fatal(err)
	}
	if m["ns/web-0"] != "w1" || m["ns/web-1"] != "w2" {
		t.Fatalf("initial PodNodes = %v", m)
	}

	// Tombstone web-0 mid-sweep — the memoized map still holds its
	// entry, but every later read must filter it out.
	kube.MarkPodDeleted(sctx, "u-del")
	m, err = d.PodNodes(sctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m["ns/web-0"]; ok {
		t.Fatalf("tombstoned pod still placed: %v", m)
	}
	if m["ns/web-1"] != "w2" {
		t.Fatalf("live pod lost its placement: %v", m)
	}
	// AllPods agrees — the tombstone hides it from the census too.
	pods, err := d.AllPods(sctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, pod := range pods {
		if pod.Name == "web-0" {
			t.Fatal("AllPods returned a tombstoned pod")
		}
	}
}
