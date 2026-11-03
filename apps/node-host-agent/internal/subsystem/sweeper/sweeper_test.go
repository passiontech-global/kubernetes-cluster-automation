package sweeper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const pvcUUID = "pvc-12345678-90ab-cdef-1234-567890abcdef"

// fixture builds a sweeper rooted at t.TempDir() with a writable fake
// mounts file, an injected statfs, and the given fake clientset.
func fixture(t *testing.T, client *fake.Clientset) (*Sweeper, string, string) {
	t.Helper()
	base := t.TempDir()
	mountsFile := filepath.Join(t.TempDir(), "mounts")
	if err := os.WriteFile(mountsFile, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{
		BaseDir:    base,
		MinAge:     time.Hour,
		MaxDelete:  10,
		MountsFile: mountsFile,
		Client:     client,
		nowFn:      time.Now,
		statfsFn:   func(string) (uint64, error) { return 0, errors.New("no fs in test") },
	}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	return s, base, mountsFile
}

// mkPVC creates a pvc-* dir under base, aged `age` via Chtimes.
func mkPVC(t *testing.T, base, name string, age time.Duration) string {
	t.Helper()
	dir := filepath.Join(base, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-age)
	if err := os.Chtimes(dir, old, old); err != nil {
		t.Fatal(err)
	}
	return dir
}

func mkPV(name, phase string, reclaim corev1.PersistentVolumeReclaimPolicy,
	claimNS, claimName string) *corev1.PersistentVolume {
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeReclaimPolicy: reclaim,
		},
		Status: corev1.PersistentVolumeStatus{
			Phase: corev1.PersistentVolumePhase(phase),
		},
	}
	if claimNS != "" || claimName != "" {
		pv.Spec.ClaimRef = &corev1.ObjectReference{Namespace: claimNS, Name: claimName}
	}
	return pv
}

func skipCount(t *testing.T, s *Sweeper, reason string) float64 {
	t.Helper()
	return testutil.ToFloat64(s.skips.WithLabelValues(reason))
}

func TestSweepOrphanDirDeleted(t *testing.T) {
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	s, base, _ := fixture(t, fake.NewSimpleClientset(other))
	dir := mkPVC(t, base, pvcUUID, 2*time.Hour)

	s.Sweep(context.Background())

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("orphan dir still present: %v", err)
	}
	if got := testutil.ToFloat64(s.dirsDeleted); got != 1 {
		t.Fatalf("dirsDeleted=%v want 1", got)
	}
	if got := testutil.ToFloat64(s.cycles.WithLabelValues("ok")); got != 1 {
		t.Fatalf("cycles ok=%v want 1", got)
	}
}

func TestAbortWhenPVListEmptyAndDirsExist(t *testing.T) {
	s, base, _ := fixture(t, fake.NewSimpleClientset())
	dir := mkPVC(t, base, pvcUUID, 2*time.Hour)

	s.Sweep(context.Background())

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("dir removed despite empty pvlist abort: %v", err)
	}
	if got := testutil.ToFloat64(s.cycles.WithLabelValues("abort")); got != 1 {
		t.Fatalf("cycles abort=%v want 1", got)
	}
}

func TestAbortOnPVListError(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "persistentvolumes",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("apiserver down")
		})
	s, base, _ := fixture(t, cs)
	dir := mkPVC(t, base, pvcUUID, 2*time.Hour)

	s.Sweep(context.Background())

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("dir removed despite list error abort: %v", err)
	}
	if got := testutil.ToFloat64(s.cycles.WithLabelValues("abort")); got != 1 {
		t.Fatalf("cycles abort=%v want 1", got)
	}
}

func TestSkipNameMismatch(t *testing.T) {
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	s, base, _ := fixture(t, fake.NewSimpleClientset(other))
	dir := mkPVC(t, base, "pvc-not-a-uuid", 2*time.Hour)

	s.Sweep(context.Background())

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("non-uuid dir removed: %v", err)
	}
	if got := skipCount(t, s, skipNameMismatch); got != 1 {
		t.Fatalf("name_mismatch skips=%v want 1", got)
	}
}

func TestSkipTooYoung(t *testing.T) {
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	s, base, _ := fixture(t, fake.NewSimpleClientset(other))
	dir := mkPVC(t, base, pvcUUID, 10*time.Minute) // younger than 60m MinAge

	s.Sweep(context.Background())

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("young dir removed: %v", err)
	}
	if got := skipCount(t, s, skipTooYoung); got != 1 {
		t.Fatalf("too_young skips=%v want 1", got)
	}
}

func TestSkipPVStillBound(t *testing.T) {
	pv := mkPV(pvcUUID, "Bound", corev1.PersistentVolumeReclaimDelete, "", "")
	s, base, _ := fixture(t, fake.NewSimpleClientset(pv))
	dir := mkPVC(t, base, pvcUUID, 2*time.Hour)

	s.Sweep(context.Background())

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("dir removed while PV Bound: %v", err)
	}
	if got := skipCount(t, s, skipPVInUse); got != 1 {
		t.Fatalf("pv_in_use skips=%v want 1", got)
	}
}

func TestReleasedPVClaimRefGoneDeletesPVAndDir(t *testing.T) {
	pv := mkPV(pvcUUID, "Released", corev1.PersistentVolumeReclaimDelete, "app", "data")
	pv.Finalizers = []string{"kubernetes.io/pv-protection"}
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	cs := fake.NewSimpleClientset(pv, other)
	s, base, _ := fixture(t, cs)
	dir := mkPVC(t, base, pvcUUID, 2*time.Hour)

	s.Sweep(context.Background())

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("dir still present after Released+Delete PV cleanup: %v", err)
	}
	if _, err := cs.CoreV1().PersistentVolumes().
		Get(context.Background(), pvcUUID, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("PV still present: %v", err)
	}
}

func TestReleasedPVClaimRefExistsSkips(t *testing.T) {
	pv := mkPV(pvcUUID, "Released", corev1.PersistentVolumeReclaimDelete, "app", "data")
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "data"},
	}
	cs := fake.NewSimpleClientset(pv, pvc)
	s, base, _ := fixture(t, cs)
	dir := mkPVC(t, base, pvcUUID, 2*time.Hour)

	s.Sweep(context.Background())

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("dir removed while claimRef PVC exists: %v", err)
	}
	if got := skipCount(t, s, skipClaimRefUnclear); got != 1 {
		t.Fatalf("claimref_unclear skips=%v want 1", got)
	}
}

func TestReleasedPVClaimRefGetErrorSkips(t *testing.T) {
	pv := mkPV(pvcUUID, "Released", corev1.PersistentVolumeReclaimDelete, "app", "data")
	cs := fake.NewSimpleClientset(pv)
	cs.PrependReactor("get", "persistentvolumeclaims",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewServiceUnavailable("api degraded")
		})
	s, base, _ := fixture(t, cs)
	dir := mkPVC(t, base, pvcUUID, 2*time.Hour)

	s.Sweep(context.Background())

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("dir removed on ambiguous claimRef error: %v", err)
	}
	if got := skipCount(t, s, skipClaimRefUnclear); got != 1 {
		t.Fatalf("claimref_unclear skips=%v want 1", got)
	}
}

func TestReGetNonNotFoundErrorSkips(t *testing.T) {
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	cs := fake.NewSimpleClientset(other)
	cs.PrependReactor("get", "persistentvolumes",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewInternalError(errors.New("etcd slow"))
		})
	s, base, _ := fixture(t, cs)
	dir := mkPVC(t, base, pvcUUID, 2*time.Hour)

	s.Sweep(context.Background())

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("dir removed despite ambiguous re-GET error: %v", err)
	}
	if got := skipCount(t, s, skipPVGetError); got != 1 {
		t.Fatalf("pv_get_error skips=%v want 1", got)
	}
}

func TestMountInsideDirSkips(t *testing.T) {
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	s, base, mountsFile := fixture(t, fake.NewSimpleClientset(other))
	dir := mkPVC(t, base, pvcUUID, 2*time.Hour)
	// Host mount table shows a mount inside the candidate dir.
	mounts := "overlay " + dir + "/rootfs overlay rw 0 0\n" +
		"proc /proc proc rw 0 0\n"
	if err := os.WriteFile(mountsFile, []byte(mounts), 0o644); err != nil {
		t.Fatal(err)
	}

	s.Sweep(context.Background())

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("dir removed despite mount inside: %v", err)
	}
	if got := skipCount(t, s, skipMounted); got != 1 {
		t.Fatalf("mounted skips=%v want 1", got)
	}
}

func TestMountAtDirSkips(t *testing.T) {
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	s, base, mountsFile := fixture(t, fake.NewSimpleClientset(other))
	dir := mkPVC(t, base, pvcUUID, 2*time.Hour)
	mounts := "tmpfs " + dir + " tmpfs rw 0 0\n"
	if err := os.WriteFile(mountsFile, []byte(mounts), 0o644); err != nil {
		t.Fatal(err)
	}

	s.Sweep(context.Background())
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("dir removed despite mount at dir: %v", err)
	}
}

func TestMaxDeleteCap(t *testing.T) {
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	s, base, _ := fixture(t, fake.NewSimpleClientset(other))
	s.cfg.MaxDelete = 2
	var dirs []string
	for i := 0; i < 4; i++ {
		name := "pvc-12345678-90ab-cdef-1234-567890abcd" + string(rune('0'+i)) + "f"
		dirs = append(dirs, mkPVC(t, base, name, 2*time.Hour))
	}

	s.Sweep(context.Background())

	remaining := 0
	for _, d := range dirs {
		if _, err := os.Stat(d); err == nil {
			remaining++
		}
	}
	if remaining != 2 {
		t.Fatalf("remaining=%d want 2 (MAX_DELETE=2)", remaining)
	}
	if got := testutil.ToFloat64(s.dirsDeleted); got != 2 {
		t.Fatalf("dirsDeleted=%v want 2", got)
	}
}

func TestUnescapeMountField(t *testing.T) {
	got := unescapeMountField(`/var/lib/dir\040with\011esc\012seq\134x`)
	want := "/var/lib/dir with\tesc\nseq\\x"
	if got != want {
		t.Fatalf("unescapeMountField=%q want %q", got, want)
	}
}

func TestName(t *testing.T) {
	s, _, _ := fixture(t, fake.NewSimpleClientset())
	if s.Name() != "sweeper" {
		t.Fatalf("Name()=%q want %q", s.Name(), "sweeper")
	}
}

func TestApplyDefaults(t *testing.T) {
	// Trailing slashes must be trimmed — they would defeat the
	// mount-boundary string compare in mountedInside.
	s, err := New(Config{BaseDir: "/var/openebs/local/"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.BaseDir != "/var/openebs/local" {
		t.Fatalf("BaseDir=%q want trailing slash trimmed", s.cfg.BaseDir)
	}

	s, err = New(Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.MinAge != defaultMinAge || s.cfg.MaxDelete != defaultMaxDelete ||
		s.cfg.Interval != defaultInterval || s.cfg.MountsFile != defaultMountsFile ||
		s.cfg.RequestTimeout != defaultRequestTimeout {
		t.Fatalf("defaults not applied: %+v", s.cfg)
	}
	if s.cfg.statfsFn == nil || s.cfg.nowFn == nil {
		t.Fatal("statfsFn/nowFn seams not defaulted")
	}
}

func TestOrDash(t *testing.T) {
	if got := orDash(""); got != "?" {
		t.Fatalf("orDash(\"\")=%q want \"?\"", got)
	}
	if got := orDash("x"); got != "x" {
		t.Fatalf("orDash(\"x\")=%q want \"x\"", got)
	}
}

func TestUsedBytes(t *testing.T) {
	if got, err := usedBytes(t.TempDir()); err != nil || got == 0 {
		t.Fatalf("usedBytes(tempdir)=%d, %v want >0, nil", got, err)
	}
	if _, err := usedBytes(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("usedBytes(absent) want error")
	}
}

func TestRunSweepsOnceThenStopsOnCancel(t *testing.T) {
	s, base, _ := fixture(t, fake.NewSimpleClientset())
	s.cfg.BaseDir = filepath.Join(base, "gone") // absent → cheap no-op sweep
	s.cfg.Interval = time.Hour                  // only the immediate sweep runs

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()

	// Wait for the first sweep to complete, then cancel — Run must
	// return promptly instead of waiting for the ticker.
	deadline := time.After(5 * time.Second)
	for testutil.ToFloat64(s.cycles.WithLabelValues("ok")) != 1 {
		select {
		case <-deadline:
			t.Fatal("first sweep never ran")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	cancel()
	select {
	case <-done:
	case <-deadline:
		t.Fatal("Run did not return after cancel")
	}
}

func TestSweepBaseDirAbsent(t *testing.T) {
	s, base, _ := fixture(t, fake.NewSimpleClientset())
	s.cfg.BaseDir = filepath.Join(base, "gone")

	s.Sweep(context.Background())

	if got := testutil.ToFloat64(s.cycles.WithLabelValues("ok")); got != 1 {
		t.Fatalf("cycles ok=%v want 1 (absent base dir is not an abort)", got)
	}
	if got := testutil.ToFloat64(s.cycles.WithLabelValues("abort")); got != 0 {
		t.Fatalf("cycles abort=%v want 0", got)
	}
}

func TestSweepBaseDirIsFile(t *testing.T) {
	s, base, _ := fixture(t, fake.NewSimpleClientset())
	f := filepath.Join(base, "not-a-dir")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.cfg.BaseDir = f

	s.Sweep(context.Background())

	if got := testutil.ToFloat64(s.cycles.WithLabelValues("ok")); got != 1 {
		t.Fatalf("cycles ok=%v want 1 (file-as-basedir is not an abort)", got)
	}
}

func TestListPVDirsError(t *testing.T) {
	s, base, _ := fixture(t, fake.NewSimpleClientset())
	f := filepath.Join(base, "not-a-dir")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.cfg.BaseDir = f
	if _, err := s.listPVDirs(); err == nil {
		t.Fatal("listPVDirs on a file want error")
	}
}

func TestAbortWhenBaseDirUnreadable(t *testing.T) {
	// BaseDir passes os.Stat+IsDir but ReadDir fails → fail-closed
	// abort. Requires a non-root euid for the chmod to bite.
	if os.Geteuid() == 0 {
		t.Skip("running as root — permission bits are not enforced")
	}
	s, base, _ := fixture(t, fake.NewSimpleClientset())
	if err := os.Chmod(base, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(base, 0o755) })

	s.Sweep(context.Background())

	if got := testutil.ToFloat64(s.cycles.WithLabelValues("abort")); got != 1 {
		t.Fatalf("cycles abort=%v want 1 (unreadable base dir)", got)
	}
}

func TestZeroDirsSkipsPVList(t *testing.T) {
	// No pvc-* candidates on disk → the whole-cluster PV List is
	// skipped entirely; the reactor fails the test if it ever runs.
	cs := fake.NewSimpleClientset()
	listed := 0
	cs.PrependReactor("list", "persistentvolumes",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			listed++
			return true, nil, errors.New("PV list must not be called")
		})
	s, base, _ := fixture(t, cs)
	// Non-candidates don't defeat the early return: a non-pvc dir and
	// a pvc-* FILE (dirs only, like the shell glob).
	if err := os.MkdirAll(filepath.Join(base, "quota.lock"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "pvc-not-a-dir"),
		[]byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	s.Sweep(context.Background())

	if listed != 0 {
		t.Fatalf("PV list calls=%d want 0 (no pvc-* dirs)", listed)
	}
	if got := testutil.ToFloat64(s.cycles.WithLabelValues("ok")); got != 1 {
		t.Fatalf("cycles ok=%v want 1", got)
	}
	if got := testutil.ToFloat64(s.cycles.WithLabelValues("abort")); got != 0 {
		t.Fatalf("cycles abort=%v want 0", got)
	}
	if got := testutil.ToFloat64(s.dirsExamined); got != 0 {
		t.Fatalf("dirsExamined=%v want 0", got)
	}
}

func TestStatfsErrorTolerated(t *testing.T) {
	// The fixture's statfsFn always errors — the sweep must still
	// delete orphans; statfs feeds logging/bytesFreed only.
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	s, base, _ := fixture(t, fake.NewSimpleClientset(other))
	dir := mkPVC(t, base, pvcUUID, 2*time.Hour)

	s.Sweep(context.Background())

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("dir present despite statfs error tolerance: %v", err)
	}
	if got := testutil.ToFloat64(s.cycles.WithLabelValues("ok")); got != 1 {
		t.Fatalf("cycles ok=%v want 1", got)
	}
}

func TestBytesFreedCounted(t *testing.T) {
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	s, base, _ := fixture(t, fake.NewSimpleClientset(other))
	dir := mkPVC(t, base, pvcUUID, 2*time.Hour)

	// statfs call order per cycle: uStart, u0 (pre-rm), u1 (post-rm),
	// uEnd. Return a smaller value from the third call on so the
	// post-rm measurement reports freed space.
	var calls int
	s.cfg.statfsFn = func(string) (uint64, error) {
		calls++
		if calls < 3 {
			return 1000, nil
		}
		return 500, nil
	}

	s.Sweep(context.Background())

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("dir still present: %v", err)
	}
	if got := testutil.ToFloat64(s.bytesFreed); got != 500 {
		t.Fatalf("bytesFreed=%v want 500", got)
	}
}

func TestMountsFileUnreadableSkips(t *testing.T) {
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	s, base, mountsFile := fixture(t, fake.NewSimpleClientset(other))
	dir := mkPVC(t, base, pvcUUID, 2*time.Hour)
	if err := os.Remove(mountsFile); err != nil {
		t.Fatal(err)
	}

	s.Sweep(context.Background())

	// An unreadable mount table fails closed — the dir stays.
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("dir removed despite unreadable mounts file: %v", err)
	}
	if got := skipCount(t, s, skipMountsUnread); got != 1 {
		t.Fatalf("mounts_unreadable skips=%v want 1", got)
	}
}

func TestReleasedPVPatchFailsSkips(t *testing.T) {
	pv := mkPV(pvcUUID, "Released", corev1.PersistentVolumeReclaimDelete, "", "")
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	cs := fake.NewSimpleClientset(pv, other)
	cs.PrependReactor("patch", "persistentvolumes",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewInternalError(errors.New("patch denied"))
		})
	s, base, _ := fixture(t, cs)
	dir := mkPVC(t, base, pvcUUID, 2*time.Hour)

	s.Sweep(context.Background())

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("dir removed despite patch failure: %v", err)
	}
	if got := skipCount(t, s, skipPVPatchFailed); got != 1 {
		t.Fatalf("pv_patch_failed skips=%v want 1", got)
	}
}

func TestReleasedPVDeleteFailsSkips(t *testing.T) {
	pv := mkPV(pvcUUID, "Released", corev1.PersistentVolumeReclaimDelete, "", "")
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	cs := fake.NewSimpleClientset(pv, other)
	cs.PrependReactor("delete", "persistentvolumes",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewInternalError(errors.New("delete denied"))
		})
	s, base, _ := fixture(t, cs)
	dir := mkPVC(t, base, pvcUUID, 2*time.Hour)

	s.Sweep(context.Background())

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("dir removed despite delete failure: %v", err)
	}
	if got := skipCount(t, s, skipPVDeleteFailed); got != 1 {
		t.Fatalf("pv_delete_failed skips=%v want 1", got)
	}
}

func TestReGetPVReturnsObjectSkips(t *testing.T) {
	// PV absent from the LIST but re-GET returns an object — the dir
	// must not be removed (fail closed on a reappearing PV).
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	cs := fake.NewSimpleClientset(other)
	cs.PrependReactor("get", "persistentvolumes",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, mkPV(pvcUUID, "Bound",
				corev1.PersistentVolumeReclaimDelete, "", ""), nil
		})
	s, base, _ := fixture(t, cs)
	dir := mkPVC(t, base, pvcUUID, 2*time.Hour)

	s.Sweep(context.Background())

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("dir removed despite re-GET returning PV: %v", err)
	}
	if got := skipCount(t, s, skipPVStillPresent); got != 1 {
		t.Fatalf("pv_still_present skips=%v want 1", got)
	}
}

func TestMountEscapedPathInsideDirSkips(t *testing.T) {
	// /proc/*/mounts octal-escapes spaces in mount points — the
	// unescape must happen before the boundary compare.
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	s, base, mountsFile := fixture(t, fake.NewSimpleClientset(other))
	spaceBase := filepath.Join(base, "my base")
	if err := os.MkdirAll(spaceBase, 0o755); err != nil {
		t.Fatal(err)
	}
	s.cfg.BaseDir = spaceBase
	dir := mkPVC(t, spaceBase, pvcUUID, 2*time.Hour)
	mounts := "overlay " + strings.ReplaceAll(dir+"/inner", " ", `\040`) +
		" overlay rw 0 0\n"
	if err := os.WriteFile(mountsFile, []byte(mounts), 0o644); err != nil {
		t.Fatal(err)
	}

	s.Sweep(context.Background())

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("dir removed despite escaped mount inside: %v", err)
	}
	if got := skipCount(t, s, skipMounted); got != 1 {
		t.Fatalf("mounted skips=%v want 1", got)
	}
}

func TestNewRegisterError(t *testing.T) {
	// A conflicting metric name in the registry makes New fail
	// instead of leaving half-registered collectors.
	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_sweeper_cycles_total",
	}))
	_, err := New(Config{Client: fake.NewSimpleClientset()}, reg)
	if err == nil || !strings.Contains(err.Error(), "register sweeper metrics") {
		t.Fatalf("New err=%v want 'register sweeper metrics'", err)
	}
}

func TestRunTicksSweepAgain(t *testing.T) {
	// The ticker branch: Interval small enough to fire within the
	// test deadline — cycles accumulate, then cancel stops Run.
	s, base, _ := fixture(t, fake.NewSimpleClientset())
	s.cfg.BaseDir = filepath.Join(base, "gone") // absent → cheap no-op sweep
	s.cfg.Interval = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()

	deadline := time.After(5 * time.Second)
	for testutil.ToFloat64(s.cycles.WithLabelValues("ok")) < 2 {
		select {
		case <-deadline:
			t.Fatal("ticker cycles never ran")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	cancel()
	select {
	case <-done:
	case <-deadline:
		t.Fatal("Run did not return after cancel")
	}
}

func TestSweepCtxCancelledInDirLoop(t *testing.T) {
	// A cancelled ctx aborts mid-loop BEFORE any dir is examined —
	// the per-dir ctx.Err() guard, distinct from an abort result.
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	s, base, _ := fixture(t, fake.NewSimpleClientset(other))
	dir := mkPVC(t, base, pvcUUID, 2*time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.Sweep(ctx)

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("dir removed on cancelled ctx: %v", err)
	}
	if got := testutil.ToFloat64(s.cycles.WithLabelValues("ok")); got != 0 {
		t.Fatalf("cycles ok=%v want 0 (bailed before cycle end)", got)
	}
	if got := testutil.ToFloat64(s.cycles.WithLabelValues("abort")); got != 0 {
		t.Fatalf("cycles abort=%v want 0", got)
	}
	if got := testutil.ToFloat64(s.dirsExamined); got != 0 {
		t.Fatalf("dirsExamined=%v want 0 (bailed in the dir loop)", got)
	}
}

func TestStatErrorOnChildDirSkips(t *testing.T) {
	// ReadDir needs r on the base dir; DirEntry.Info lstats the child
	// and needs x on it. A 0o400 base dir satisfies the first and
	// fails the second → skipStatError.
	if os.Geteuid() == 0 {
		t.Skip("running as root — permission bits are not enforced")
	}
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	s, base, _ := fixture(t, fake.NewSimpleClientset(other))
	dir := mkPVC(t, base, pvcUUID, 2*time.Hour)
	if err := os.Chmod(base, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(base, 0o755) })

	s.Sweep(context.Background())

	// Restore access before asserting the dir survived.
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("dir removed despite stat error: %v", err)
	}
	if got := skipCount(t, s, skipStatError); got != 1 {
		t.Fatalf("stat_error skips=%v want 1", got)
	}
}

func TestRemoveAllFailureWarns(t *testing.T) {
	// Removing the dir needs w on the base dir — a 0o555 base makes
	// the final rmdir fail → the WARN branch, and the cycle still
	// completes ok (rm failures are logged, not aborts).
	if os.Geteuid() == 0 {
		t.Skip("running as root — permission bits are not enforced")
	}
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	s, base, _ := fixture(t, fake.NewSimpleClientset(other))
	dir := mkPVC(t, base, pvcUUID, 2*time.Hour)
	if err := os.Chmod(base, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(base, 0o755) })

	s.Sweep(context.Background())

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("dir removed despite unwritable base dir: %v", err)
	}
	if got := testutil.ToFloat64(s.dirsDeleted); got != 0 {
		t.Fatalf("dirsDeleted=%v want 0 (rm failed)", got)
	}
	if got := testutil.ToFloat64(s.cycles.WithLabelValues("ok")); got != 1 {
		t.Fatalf("cycles ok=%v want 1 (rm failure is not an abort)", got)
	}
}
