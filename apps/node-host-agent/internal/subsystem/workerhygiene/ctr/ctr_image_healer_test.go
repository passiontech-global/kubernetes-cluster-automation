package ctr_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8stesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/ctr"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// --- check: ctr-image-healer (37) ---

// recordImageRm points the single Seams.Ctr.Exec seam at a recorder
// for `images rm --sync <ref>` calls (the argv the RmImage method
// builds — the ref is the last element). Other ctr execs pass
// through quietly.
func recordImageRm(e *env, removed *[]string) {
	e.H.Cfg.Seams.Ctr.Exec = func(_ context.Context, argv ...string) error {
		if slices.Contains(argv, "--sync") {
			*removed = append(*removed, argv[len(argv)-1])
		}
		return nil
	}
}

// waitingPod builds a Pending pod on node-a whose single container is
// stuck Waiting with the given reason/message/image — 37 evidence.
// imageID is the CRI repoDigest record (e.g.
// docker.io/library/nginx@sha256:…) kubelet reports alongside Image —
// the healer removes both records.
func waitingPod(name, ns, uid, image, imageID, reason, msg string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns, UID: types.UID(uid),
		},
		Spec: corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{
			Phase: corev1.PodPending,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:    "app",
				Image:   image,
				ImageID: imageID,
				State: corev1.ContainerState{
					Waiting: &corev1.ContainerStateWaiting{Reason: reason, Message: msg},
				},
			}},
		},
	}
}

func TestCtrImageHealerRemovesCorruptedImage(t *testing.T) {
	e := fixture(t)
	var removed []string
	recordImageRm(e, &removed)
	p := waitingPod("stuck-pull", "default", wdepstest.UIDA, "registry.local/app:v1",
		"registry.local/app@sha256:f00dcafe",
		"ImagePullBackOff",
		`rpc error: code = Unknown desc = failed to pull and unpack image: `+
			`content digest sha256:abc123def456: not found`)
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	// One corrupted container → two store records (tag + repoDigest).
	want := []string{"registry.local/app:v1", "registry.local/app@sha256:f00dcafe"}
	if !slices.Equal(removed, want) {
		t.Fatalf("removed=%v want %v", removed, want)
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "last-ctr-image-rm")); err != nil {
		t.Fatal("last-ctr-image-rm budget not spent")
	}
	if !strings.Contains(e.LogLines(t),
		"ACTION: removed corrupted image registry.local/app:v1") {
		t.Fatalf("missing NPD ACTION contract line:\n%s", e.LogLines(t))
	}
}

func TestCtrImageHealerReasonAndMessageFilter(t *testing.T) {
	e := fixture(t)
	var removed []string
	recordImageRm(e, &removed)
	mk := func(name, uid, image, imageID, reason, msg string) {
		p := waitingPod(name, "default", uid, image, imageID, reason, msg)
		if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	// Wrong reason — a plain CrashLoopBackOff with the corrupt text is
	// a runtime crash, not a store-corruption signal.
	mk("crashloop", wdepstest.UIDA, "registry.local/app:v1", "registry.local/app@sha256:f00d",
		"CrashLoopBackOff", "content digest sha256:abc123: not found")
	// Right reason, unrelated message — a quota deny is not a
	// corrupted layer.
	mk("quota-deny", wdepstest.UIDB, "registry.local/app:v1", "registry.local/app@sha256:f00d",
		"ErrImagePull", "pull rate limit exceeded")
	// Right reason + matching message but no image recorded — nothing
	// to remove.
	mk("no-image", wdepstest.UIDC, "", "",
		"ImagePullBackOff", "content digest sha256:abc123: not found")
	// A pod on another node must be ignored entirely.
	other := waitingPod("other-node", "default", wdepstest.UIDD, "registry.local/app:v1",
		"registry.local/app@sha256:f00d",
		"CreateContainerError", "failed to extract layer")
	other.Spec.NodeName = "node-b"
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), other, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if len(removed) != 0 {
		t.Fatalf("removed=%v want none (reason/message/node filters)", removed)
	}
	if _, err := os.Stat(filepath.Join(e.StateDir, "last-ctr-image-rm")); !os.IsNotExist(err) {
		t.Fatal("budget spent with nothing to remove")
	}
}

func TestCtrImageHealerAllSignatures(t *testing.T) {
	e := fixture(t)
	var removed []string
	recordImageRm(e, &removed)
	mk := func(name, uid, image, imageID, reason, msg string) {
		p := waitingPod(name, "default", uid, image, imageID, reason, msg)
		if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	mk("extract", wdepstest.UIDA, "img/extract:1", "docker.io/img/extract@sha256:e1e1",
		"CreateContainerError", "failed to extract layer sha256:abc: unexpected EOF")
	mk("snapshot", wdepstest.UIDB, "img/snapshot:2", "docker.io/img/snapshot@sha256:52",
		"ErrImagePull", "parent snapshot sha256:def456 does not exist")
	mk("digest", wdepstest.UIDC, "img/digest:3", "docker.io/img/digest@sha256:d363",
		"CreateContainerError", "content digest sha256:789abc: not found")
	e.H.Cycle(context.Background())
	// Each corrupted container removes its tag record AND its
	// repoDigest record → 2 refs per pod.
	want := []string{
		"docker.io/img/digest:3", "docker.io/img/digest@sha256:d363",
		"docker.io/img/extract:1", "docker.io/img/extract@sha256:e1e1",
		"docker.io/img/snapshot:2", "docker.io/img/snapshot@sha256:52",
	}
	if !slices.Equal(removed, want) {
		t.Fatalf("removed=%v want %v (tag+digest per corrupted image)", removed, want)
	}
}

func TestCtrImageHealerDedupesAndRateLimits(t *testing.T) {
	e := fixture(t)
	var removed []string
	recordImageRm(e, &removed)
	msg := "content digest sha256:aaa111: not found"
	for i, uid := range []string{wdepstest.UIDA, wdepstest.UIDB} {
		p := waitingPod(fmt.Sprintf("dup-%d", i), "default", uid,
			"registry.local/app:v1", "registry.local/app@sha256:aaa111",
			"ImagePullBackOff", msg)
		if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	e.H.Cycle(context.Background())
	if len(removed) != 2 {
		t.Fatalf("removed=%v want 2 (tag+digest deduped across pods)", removed)
	}
	// Second cycle: evidence unchanged but the 15m budget is spent.
	e.H.Cycle(context.Background())
	if len(removed) != 2 {
		t.Fatalf("removed=%v want 2 (15m cooldown blocks the repeat)", removed)
	}
	if !strings.Contains(e.LogLines(t), "in rm cooldown (<15m)") {
		t.Fatalf("missing cooldown suspect line:\n%s", e.LogLines(t))
	}
	// Budget aged out → the next cycle may rm again.
	e.Now = e.Now.Add(16 * time.Minute)
	e.H.Cycle(context.Background())
	if len(removed) != 4 {
		t.Fatalf("removed=%v want 4 after cooldown expired", removed)
	}
}

func TestCtrImageHealerRmErrorKeepsGoing(t *testing.T) {
	e := fixture(t)
	e.H.Cfg.Seams.Ctr.Exec = func(_ context.Context, argv ...string) error {
		if slices.Contains(argv, "--sync") &&
			argv[len(argv)-1] == "docker.io/library/bad:1" {
			return errors.New("ctr exploded")
		}
		return nil
	}
	mk := func(name, uid, image, imageID string) {
		p := waitingPod(name, "default", uid, image, imageID, "CreateContainerError",
			"failed to extract layer sha256:x")
		if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	mk("a", wdepstest.UIDA, "bad:1", "docker.io/library/bad@sha256:b1")
	mk("b", wdepstest.UIDB, "good:2", "docker.io/library/good@sha256:62")
	e.H.Cycle(context.Background())
	if !strings.Contains(e.LogLines(t),
		"ctr image rm docker.io/library/bad:1 failed: ctr exploded") {
		t.Fatalf("missing rm-failure log:\n%s", e.LogLines(t))
	}
	if !strings.Contains(e.LogLines(t),
		"ACTION: removed corrupted image docker.io/library/good:2") {
		t.Fatalf("one rm failure must not block the next image:\n%s", e.LogLines(t))
	}
}

func TestCtrImageHealerDefaultSeamUsesSystemdExec(t *testing.T) {
	e := fixture(t)
	// Bind stubs Seams.Ctr.Exec — restore the production default's
	// shape (a full-argv passthrough onto Systemd.Exec) so the rm
	// argv lands on the systemd fake, which answers any `ctr
	// images rm` with success.
	e.H.Cfg.Seams.Ctr.Exec = func(ctx context.Context, argv ...string) error {
		_, err := e.H.Cfg.Systemd.Exec(ctx, argv[0], argv[1:]...)
		return err
	}
	e.SDReply["images rm"] = ""
	p := waitingPod("stuck", "default", wdepstest.UIDA, "registry.local/app:v1",
		"registry.local/app@sha256:feed",
		"ImagePullBackOff", "content digest sha256:abc123: not found")
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if !e.SDRan("k0s ctr --namespace k8s.io images rm --sync registry.local/app:v1") {
		t.Fatalf("RmImage did not exec ctr images rm, cmds=%v", e.SDCmds)
	}
	if !e.SDRan("k0s ctr --namespace k8s.io images rm --sync registry.local/app@sha256:feed") {
		t.Fatalf("RmImage did not exec ctr images rm on the repoDigest, cmds=%v", e.SDCmds)
	}
}

func TestCtrImageHealerAPIFailNoAction(t *testing.T) {
	e := fixture(t)
	var removed []string
	recordImageRm(e, &removed)
	e.CS.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver flake")
	})
	e.H.Cycle(context.Background())
	if len(removed) != 0 {
		t.Fatal("image rm fired on an inconclusive (API-failed) cycle")
	}
	if got := e.H.Cycles.WithLabelValues(wdeps.CheckCtrImages, "abort"); testutil.ToFloat64(got) != 1 {
		t.Fatalf("abort=%v want 1", testutil.ToFloat64(got))
	}
}

// TestNormalizeCRIImageName pins the docker reference convention the
// CRI plugin applies at pull time — `ctr images rm` matches store
// names verbatim, so every spec must be canonicalized first.
func TestNormalizeCRIImageName(t *testing.T) {
	cases := []struct{ in, want string }{
		// Short dockerhub names → docker.io/library/.
		{"nginx:1.25", "docker.io/library/nginx:1.25"},
		{"nginx", "docker.io/library/nginx"},
		{"docker.io/nginx:1.25", "docker.io/library/nginx:1.25"},
		// Org path → docker.io/org/, no library insertion.
		{"org/app:1.0", "docker.io/org/app:1.0"},
		{"docker.io/org/app:1.0", "docker.io/org/app:1.0"},
		// Private registries pass through untouched — '.'/':'/
		// "localhost" mark the first segment as a domain, and
		// library/ is a docker.io-only convention.
		{"registry.local/app:v1", "registry.local/app:v1"},
		{"registry.local:5000/team/app:v2", "registry.local:5000/team/app:v2"},
		{"localhost/app:1", "localhost/app:1"},
		{"localhost:5000/app:1", "localhost:5000/app:1"},
		// Digest refs canonicalize to name@sha256:… — the tag is
		// dropped, a registry port is not.
		{"nginx:1.25@sha256:abc", "docker.io/library/nginx@sha256:abc"},
		{"nginx@sha256:abc", "docker.io/library/nginx@sha256:abc"},
		{"registry.local/app:v1@sha256:abc", "registry.local/app@sha256:abc"},
		{"localhost:5000/app@sha256:abc", "localhost:5000/app@sha256:abc"},
		// Already-canonical refs are idempotent.
		{"docker.io/library/nginx:1.25", "docker.io/library/nginx:1.25"},
		{"docker.io/library/nginx@sha256:abc", "docker.io/library/nginx@sha256:abc"},
	}
	for _, c := range cases {
		if got := ctr.NormalizeCRIImageName(c.in); got != c.want {
			t.Errorf("ctr.NormalizeCRIImageName(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

// The whole point of the fix: a short dockerhub spec must reach
// Ctr.RmImage as the canonical docker.io/library/… ref, and the
// repoDigest record goes with it.
func TestCtrImageHealerNormalizesDockerHubShortName(t *testing.T) {
	e := fixture(t)
	var removed []string
	recordImageRm(e, &removed)
	p := waitingPod("stuck-pull", "default", wdepstest.UIDA, "nginx:1.25",
		"docker.io/library/nginx@sha256:beef",
		"ImagePullBackOff", "content digest sha256:abc123: not found")
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	want := []string{"docker.io/library/nginx:1.25", "docker.io/library/nginx@sha256:beef"}
	if !slices.Equal(removed, want) {
		t.Fatalf("removed=%v want %v", removed, want)
	}
}

// Spec and ImageID naming the same canonical digest ref must produce
// ONE rm — the image store holds a single record for it.
func TestCtrImageHealerDigestRefDedupes(t *testing.T) {
	e := fixture(t)
	var removed []string
	recordImageRm(e, &removed)
	p := waitingPod("stuck-pull", "default", wdepstest.UIDA, "nginx@sha256:beef",
		"docker.io/library/nginx@sha256:beef",
		"CreateContainerError", "failed to extract layer sha256:abc")
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	want := []string{"docker.io/library/nginx@sha256:beef"}
	if !slices.Equal(removed, want) {
		t.Fatalf("removed=%v want %v (spec+ImageID same ref → single rm)", removed, want)
	}
}

// name:tag@digest spec → the tag is stripped, digest wins.
func TestCtrImageHealerTagPlusDigestStripsTag(t *testing.T) {
	e := fixture(t)
	var removed []string
	recordImageRm(e, &removed)
	p := waitingPod("stuck-pull", "default", wdepstest.UIDA, "nginx:1.25@sha256:beef",
		"docker.io/library/nginx@sha256:beef",
		"ImagePullBackOff", "content digest sha256:abc123: not found")
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	want := []string{"docker.io/library/nginx@sha256:beef"}
	if !slices.Equal(removed, want) {
		t.Fatalf("removed=%v want %v (tag+digest → digest only)", removed, want)
	}
}

// Private-registry refs (with port, multi-segment path) must reach
// Ctr.RmImage byte-for-byte unchanged — no docker.io/library rewrite.
func TestCtrImageHealerPrivateRegistryUntouched(t *testing.T) {
	e := fixture(t)
	var removed []string
	recordImageRm(e, &removed)
	p := waitingPod("stuck-pull", "default", wdepstest.UIDA,
		"registry.local:5000/team/app:v2", "registry.local:5000/team/app@sha256:cafe",
		"ErrImagePull", "parent snapshot sha256:def456 does not exist")
	if _, err := e.CS.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	want := []string{
		"registry.local:5000/team/app:v2",
		"registry.local:5000/team/app@sha256:cafe",
	}
	if !slices.Equal(removed, want) {
		t.Fatalf("removed=%v want %v", removed, want)
	}
}

// Corrupted-on-disk-layer signatures at run/start time — the
// waiting reasons kubelet reports for a container that started and
// then died on the corrupt layer (RunContainerError/StartError).
func TestCtrImageHealerCorruptLayerSignatures(t *testing.T) {
	e := fixture(t)
	var removed []string
	recordImageRm(e, &removed)
	for i, tc := range []struct {
		reason, msg string
	}{
		{"RunContainerError", "failed to mount /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/9/fs: structure needs cleaning"},
		{"StartError", "failed to create shim task: OCI runtime create failed: input/output error"},
		{"RunContainerError", "error while loading shared libraries: libc.so.6: file too short"},
	} {
		p := waitingPod("stuck-"+strconv.Itoa(i), "default", wdepstest.UIDA[:8]+strconv.Itoa(i),
			"registry.local/app:v"+strconv.Itoa(i), "",
			tc.reason, tc.msg)
		if _, err := e.CS.CoreV1().Pods("default").Create(
			context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	e.H.Cycle(context.Background())
	if len(removed) != 3 {
		t.Fatalf("removed=%v want 3 (all on-disk-corrupt signatures)", removed)
	}
}

// The exec-format class is once-per-image: a 0-byte truncated
// binary heals on repull, but a wrong-arch image repulls the same
// un-runnable ref — the ref may be deleted at most ONCE, even after
// the 15m rm budget ages out. Other signatures stay unlimited.
func TestCtrImageHealerExecFormatOncePerImage(t *testing.T) {
	e := fixture(t)
	var removed []string
	recordImageRm(e, &removed)
	p := waitingPod("wrongarch", "default", wdepstest.UIDA, "app:v1",
		"registry.local/app@sha256:beef",
		"StartError", "exec /bin/app: exec format error")
	if _, err := e.CS.CoreV1().Pods("default").Create(
		context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	if len(removed) != 2 {
		t.Fatalf("removed=%v want 2 (tag + digest refs once)", removed)
	}
	// Budget ages out but the refs are healed — a persistent
	// wrong-arch image must never loop-delete.
	e.Now = e.Now.Add(16 * time.Minute)
	e.H.Cycle(context.Background())
	if len(removed) != 2 {
		t.Fatalf("removed=%v want 2 (exec-format refs deleted at most once)", removed)
	}
	e.Now = e.Now.Add(16 * time.Minute)
	e.H.Cycle(context.Background())
	if len(removed) != 2 {
		t.Fatalf("removed=%v want 2 (still healed)", removed)
	}
}

// A DIFFERENT image with an exec-format failure still gets its own
// single heal — the ledger is per-ref.
func TestCtrImageHealerExecFormatPerRef(t *testing.T) {
	e := fixture(t)
	var removed []string
	recordImageRm(e, &removed)
	for i, img := range []string{"bad-a:1", "bad-b:2"} {
		p := waitingPod("w"+strconv.Itoa(i), "default",
			wdepstest.UIDA[:8]+strconv.Itoa(i), img, "",
			"StartError", "exec format error")
		if _, err := e.CS.CoreV1().Pods("default").Create(
			context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	e.H.Cycle(context.Background())
	if len(removed) != 2 {
		t.Fatalf("removed=%v want 2 (each ref healed once)", removed)
	}
	// A pod reporting exec-format AND a different corrupt signature
	// on the same cycle keeps the once-guard on the exec refs while
	// the other signature still re-deletes after cooldown.
	e.Now = e.Now.Add(16 * time.Minute)
	p := waitingPod("mixed", "default", wdepstest.UIDC, "dirty:3", "",
		"CreateContainerError", "failed to extract layer sha256:zz")
	if _, err := e.CS.CoreV1().Pods("default").Create(
		context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.H.Cycle(context.Background())
	want := []string{"bad-a:1", "bad-b:2", "docker.io/library/dirty:3"}
	if len(removed) != 3 {
		t.Fatalf("removed=%v want %v (only the new non-exec ref re-deleted)", removed, want)
	}
}
