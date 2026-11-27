// superseded_secret_prune_test.go — the kine-bloat-guard superseded
// helm release secret pruner: cap, oldest-excess selection and the
// highest-version protection.
package helmreleaseunlocker

import (
	"strconv"
	"testing"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kfake "k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
)

// ---------------------------------------------------------------------------
// kine-bloat-guard — superseded helm release secret pruner
// ---------------------------------------------------------------------------

// A release with more than maxSupersededSecrets superseded secrets
// loses the OLDEST excess — deployed/pending/failed secrets and the
// highest-version secret are never touched, and each delivered delete
// bumps HelmSecretsPrunedTotal{namespace}.
func TestHelmReleaseUnlockerPrunesSupersededSecrets(t *testing.T) {
	var objs []runtime.Object
	// 12 superseded revisions v1..v12 for release myrel.
	for v := 1; v <= 12; v++ {
		objs = append(objs, helmRelSecret("apps",
			"sh.helm.release.v1.myrel.v"+strconv.Itoa(v), "myrel", v, "superseded"))
	}
	// Live-state secrets that must survive: deployed v13 (also the
	// highest version), pending-upgrade v14, failed v15.
	objs = append(objs,
		helmRelSecret("apps", "sh.helm.release.v1.myrel.v13", "myrel", 13, "deployed"),
		helmRelSecret("apps", "sh.helm.release.v1.myrel.v14", "myrel", 14, "pending-upgrade"),
		helmRelSecret("apps", "sh.helm.release.v1.myrel.v15", "myrel", 15, "failed"),
		// A second release under the cap — untouched.
		helmRelSecret("apps", "sh.helm.release.v1.small.v1", "small", 1, "superseded"),
		helmRelSecret("apps", "sh.helm.release.v1.small.v2", "small", 2, "superseded"),
		// Not a helm release secret — ignored entirely.
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "plain",
			Labels: map[string]string{"owner": "helm", "name": "myrel",
				"status": "superseded", "version": "1"}},
			Type: corev1.SecretTypeOpaque},
	)
	cs := kfake.NewSimpleClientset(objs...)
	dyn := newDynFake()
	u := newUnlocker(cs, dyn, 0, "")

	before := promtestutil.ToFloat64(
		metrics.HelmSecretsPrunedTotal.WithLabelValues("apps"))
	if err := u.pruneSupersededSecrets(ctx); err != nil {
		t.Fatal(err)
	}
	after := promtestutil.ToFloat64(
		metrics.HelmSecretsPrunedTotal.WithLabelValues("apps"))
	if got := after - before; got != 2 {
		t.Fatalf("pruned counter delta = %v, want 2 (12 superseded - cap 10)", got)
	}
	// Oldest two superseded gone.
	for _, v := range []int{1, 2} {
		if secretExists(t, cs, "apps",
			"sh.helm.release.v1.myrel.v"+strconv.Itoa(v)) {
			t.Fatalf("superseded v%d must be pruned", v)
		}
	}
	// The remaining 10 superseded + all live-state secrets survive.
	for v := 3; v <= 15; v++ {
		if !secretExists(t, cs, "apps",
			"sh.helm.release.v1.myrel.v"+strconv.Itoa(v)) {
			t.Fatalf("secret v%d must survive", v)
		}
	}
	for _, s := range []string{
		"sh.helm.release.v1.small.v1", "sh.helm.release.v1.small.v2", "plain"} {
		if !secretExists(t, cs, "apps", s) {
			t.Fatalf("%s must survive", s)
		}
	}
}

// A release at exactly the cap is a no-op — and the highest-version
// secret is protected even when it is itself superseded.
func TestHelmReleaseUnlockerPrunerKeepsHighestAndCap(t *testing.T) {
	var objs []runtime.Object
	// Exactly 10 superseded — at the cap, nothing pruned.
	for v := 1; v <= 10; v++ {
		objs = append(objs, helmRelSecret("apps",
			"sh.helm.release.v1.cap.v"+strconv.Itoa(v), "cap", v, "superseded"))
	}
	// 11 superseded where the NEWEST is itself superseded — the
	// highest-version secret must survive even though it is a
	// prune candidate by status.
	for v := 1; v <= 11; v++ {
		objs = append(objs, helmRelSecret("apps",
			"sh.helm.release.v1.top.v"+strconv.Itoa(v), "top", v, "superseded"))
	}
	cs := kfake.NewSimpleClientset(objs...)
	u := newUnlocker(cs, newDynFake(), 0, "")
	if err := u.pruneSupersededSecrets(ctx); err != nil {
		t.Fatal(err)
	}
	for v := 1; v <= 10; v++ {
		if !secretExists(t, cs, "apps",
			"sh.helm.release.v1.cap.v"+strconv.Itoa(v)) {
			t.Fatalf("at-cap release lost v%d", v)
		}
	}
	// top: 11 superseded, cap 10 → delete 1 oldest (v1); v11 is the
	// highest version and stays even though superseded.
	if secretExists(t, cs, "apps", "sh.helm.release.v1.top.v1") {
		t.Fatal("oldest superseded of over-cap release must be pruned")
	}
	for v := 2; v <= 11; v++ {
		if !secretExists(t, cs, "apps",
			"sh.helm.release.v1.top.v"+strconv.Itoa(v)) {
			t.Fatalf("top release lost v%d", v)
		}
	}
}

// Large (>=512 KiB serialized JSON, incl. 420 KiB raw after base64) superseded
// secrets tighten down to 0 when a deployed revision exists, and stale failed
// revisions strictly older than deployed are pruned too.
func TestHelmReleaseUnlockerPrunesLargeSupersededAndOldFailed(t *testing.T) {
	raw420KiB := make([]byte, 420*1024)
	mkBig := func(rel string, v int, status string) *corev1.Secret {
		s := helmRelSecret("apps", "sh.helm.release.v1."+rel+".v"+strconv.Itoa(v), rel, v, status)
		s.Data = map[string][]byte{"release": raw420KiB}
		return s
	}

	cs := kfake.NewSimpleClientset(
		mkBig("big", 1, "failed"),
		mkBig("big", 2, "superseded"),
		mkBig("big", 3, "superseded"),
		mkBig("big", 4, "deployed"),
		mkBig("big", 5, "failed"),
		// Failed initial install (no deployed revision): must survive.
		helmRelSecret("apps", "sh.helm.release.v1.initfail.v1", "initfail", 1, "failed"),
	)
	u := newUnlocker(cs, newDynFake(), 0, "")
	if err := u.pruneSupersededSecrets(ctx); err != nil {
		t.Fatal(err)
	}
	for _, pruned := range []string{
		"sh.helm.release.v1.big.v1",
		"sh.helm.release.v1.big.v2",
		"sh.helm.release.v1.big.v3",
	} {
		if secretExists(t, cs, "apps", pruned) {
			t.Fatalf("%s must be pruned", pruned)
		}
	}
	for _, keep := range []string{
		"sh.helm.release.v1.big.v4",
		"sh.helm.release.v1.big.v5",
		"sh.helm.release.v1.initfail.v1",
	} {
		if !secretExists(t, cs, "apps", keep) {
			t.Fatalf("%s must survive", keep)
		}
	}
}
