package sweeper

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	nhatestutil "github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
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
		Clock:      timex.NewCell(time.Now),
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
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			UID:             types.UID("uid-" + name),
			ResourceVersion: "1",
		},
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
	s, base, _ := fixture(t, nhatestutil.FakeKube(other))
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
	s, base, _ := fixture(t, nhatestutil.FakeKube())
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
	cs := nhatestutil.FakeKube()
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
	s, base, _ := fixture(t, nhatestutil.FakeKube(other))
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
	s, base, _ := fixture(t, nhatestutil.FakeKube(other))
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
	s, base, _ := fixture(t, nhatestutil.FakeKube(pv))
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
	cs := nhatestutil.FakeKube(pv, other)
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
	cs := nhatestutil.FakeKube(pv, pvc)
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
	cs := nhatestutil.FakeKube(pv)
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
	cs := nhatestutil.FakeKube(other)
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
	s, base, mountsFile := fixture(t, nhatestutil.FakeKube(other))
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
	s, base, mountsFile := fixture(t, nhatestutil.FakeKube(other))
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

// The mounts snapshot is taken once per cycle — a mount appearing
// inside the candidate dir between the snapshot and the rm (a pod
// volume attaching mid-sweep) is invisible to it. The pre-rm
// re-read is the last belt: here the mount lands when the
// per-candidate PV re-GET runs, after the snapshot.
func TestMountAppearingMidSweepSkips(t *testing.T) {
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	cs := nhatestutil.FakeKube(other)
	s, base, mountsFile := fixture(t, cs)
	dir := mkPVC(t, base, pvcUUID, 2*time.Hour)
	cs.PrependReactor("get", "persistentvolumes",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			mounts := "tmpfs " + dir + " tmpfs rw 0 0\n"
			if err := os.WriteFile(mountsFile, []byte(mounts), 0o644); err != nil {
				return true, nil, err
			}
			return true, nil, apierrors.NewNotFound(
				corev1.Resource("persistentvolumes"), pvcUUID)
		})

	s.Sweep(context.Background())

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("dir removed despite mid-sweep mount: %v", err)
	}
	if got := skipCount(t, s, skipMounted); got != 1 {
		t.Fatalf("mounted skips=%v want 1 (fresh mount-table re-read)", got)
	}
}

// The pre-rm re-read is the last belt before the destructive rm —
// a table that was readable at the cycle-start snapshot but
// unreadable at rm time must fail closed too (skipMountsUnread),
// never fall through to os.RemoveAll on stale information.
func TestMountsUnreadableAtRmSkips(t *testing.T) {
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	cs := nhatestutil.FakeKube(other)
	s, base, mountsFile := fixture(t, cs)
	dir := mkPVC(t, base, pvcUUID, 2*time.Hour)
	// The snapshot read at cycle start succeeds; the mounts file is
	// gone by the time the orphan's re-GET runs — immediately before
	// the fresh pre-rm read.
	cs.PrependReactor("get", "persistentvolumes",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			if err := os.Remove(mountsFile); err != nil {
				return true, nil, err
			}
			return true, nil, apierrors.NewNotFound(
				corev1.Resource("persistentvolumes"), pvcUUID)
		})

	s.Sweep(context.Background())

	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("dir removed despite unreadable pre-rm mount table: %v", err)
	}
	if got := skipCount(t, s, skipMountsUnread); got != 1 {
		t.Fatalf("mounts_unreadable skips=%v want 1 (fresh re-read)", got)
	}
}

func TestMaxDeleteCap(t *testing.T) {
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	s, base, _ := fixture(t, nhatestutil.FakeKube(other))
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

// MaxDelete counts BOTH destructive ops — the Released-PV object
// delete AND the dir rm. With the cap at 1 a Released+Delete pair
// spends its whole budget on the PV object; the orphaned dir waits
// for next cycle instead of riding past the cap on the same op.
func TestMaxDeleteCountsPVObjectDelete(t *testing.T) {
	pv := mkPV(pvcUUID, "Released", corev1.PersistentVolumeReclaimDelete, "app", "data")
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	cs := nhatestutil.FakeKube(pv, other)
	s, base, _ := fixture(t, cs)
	s.cfg.MaxDelete = 1
	dir := mkPVC(t, base, pvcUUID, 2*time.Hour)

	s.Sweep(context.Background())

	if _, err := cs.CoreV1().PersistentVolumes().
		Get(context.Background(), pvcUUID, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("Released PV still present: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("dir removed past MAX_DELETE=1 (PV delete spent the slot): %v", err)
	}
	// Next cycle the PV is gone — the lone dir rm fits the budget.
	s.Sweep(context.Background())
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("orphan dir kept after budget-free cycle: %v", err)
	}
}

func TestUnescapeMountField(t *testing.T) {
	got := procfs.UnescapeMountPath(`/var/lib/dir\040with\011esc\012seq\134x`)
	want := "/var/lib/dir with\tesc\nseq\\x"
	if got != want {
		t.Fatalf("UnescapeMountPath=%q want %q", got, want)
	}
}

func TestName(t *testing.T) {
	s, _, _ := fixture(t, nhatestutil.FakeKube())
	if s.Name() != "sweeper" {
		t.Fatalf("Name()=%q want %q", s.Name(), "sweeper")
	}
}

func TestApplyDefaults(t *testing.T) {
	// Trailing slashes must be trimmed — they would defeat the
	// mount-boundary string compare in mountedInside.
	s, err := New(Config{
		BaseDir: "/var/openebs/local/",
		Client:  nhatestutil.FakeKube(),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.BaseDir != "/var/openebs/local" {
		t.Fatalf("BaseDir=%q want trailing slash trimmed", s.cfg.BaseDir)
	}

	s, err = New(Config{Client: nhatestutil.FakeKube()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.MinAge != defaultMinAge || s.cfg.MaxDelete != defaultMaxDelete ||
		s.cfg.Interval != defaultInterval || s.cfg.MountsFile != defaultMountsFile ||
		s.cfg.RequestTimeout != defaultRequestTimeout {
		t.Fatalf("defaults not applied: %+v", s.cfg)
	}
	if s.cfg.statfsFn == nil || s.cfg.Clock == nil {
		t.Fatal("statfsFn/Clock seams not defaulted")
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
	s, base, _ := fixture(t, nhatestutil.FakeKube())
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
	s, base, _ := fixture(t, nhatestutil.FakeKube())
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
	s, base, _ := fixture(t, nhatestutil.FakeKube())
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
	s, base, _ := fixture(t, nhatestutil.FakeKube())
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
	s, base, _ := fixture(t, nhatestutil.FakeKube())
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
	cs := nhatestutil.FakeKube()
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
	s, base, _ := fixture(t, nhatestutil.FakeKube(other))
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
	s, base, _ := fixture(t, nhatestutil.FakeKube(other))
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
	s, base, mountsFile := fixture(t, nhatestutil.FakeKube(other))
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
	pv := mkPV(pvcUUID, "Released", corev1.PersistentVolumeReclaimDelete, "app", "data")
	pv.Finalizers = []string{"kubernetes.io/pv-protection"}
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	cs := nhatestutil.FakeKube(pv, other)
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
	pv := mkPV(pvcUUID, "Released", corev1.PersistentVolumeReclaimDelete, "app", "data")
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	cs := nhatestutil.FakeKube(pv, other)
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
	cs := nhatestutil.FakeKube(other)
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
	s, base, mountsFile := fixture(t, nhatestutil.FakeKube(other))
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
	_, err := New(Config{Client: nhatestutil.FakeKube()}, reg)
	if err == nil || !strings.Contains(err.Error(), "register sweeper metrics") {
		t.Fatalf("New err=%v want 'register sweeper metrics'", err)
	}
}

func TestRunTicksSweepAgain(t *testing.T) {
	// The ticker branch: Interval small enough to fire within the
	// test deadline — cycles accumulate, then cancel stops Run.
	s, base, _ := fixture(t, nhatestutil.FakeKube())
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
	// the per-dir ctx.Err() guard records an abort cycle (and the
	// examined gauge) instead of returning uncounted.
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	s, base, _ := fixture(t, nhatestutil.FakeKube(other))
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
	if got := testutil.ToFloat64(s.cycles.WithLabelValues("abort")); got != 1 {
		t.Fatalf("cycles abort=%v want 1 (cancelled mid-loop counts as abort)", got)
	}
	if got := testutil.ToFloat64(s.dirsExamined); got != 0 {
		t.Fatalf("dirsExamined=%v want 0 (bailed in the dir loop)", got)
	}
}

func TestNewNilClientErrors(t *testing.T) {
	// A nil Client must fail at construction, not panic on the
	// first PV List.
	if _, err := New(Config{}, nil); err == nil {
		t.Fatal("New with nil Client want error")
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
	s, base, _ := fixture(t, nhatestutil.FakeKube(other))
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
	s, base, _ := fixture(t, nhatestutil.FakeKube(other))
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

func TestPVListUsesResourceVersionZeroAndGetsStayQuorum(t *testing.T) {
	pv := mkPV(pvcUUID, "Released", corev1.PersistentVolumeReclaimDelete, "app", "data")
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "", "")
	cs := nhatestutil.FakeKube(pv, other)
	s, base, _ := fixture(t, cs)
	dir := mkPVC(t, base, pvcUUID, 2*time.Hour)

	s.Sweep(context.Background())

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("Released+Delete orphan dir still present: %v", err)
	}

	var pvListOpts []metav1.ListOptions
	var pvcGetOpts []metav1.GetOptions
	var pvGetOpts []metav1.GetOptions
	var pvDeleteOpts []metav1.DeleteOptions
	for _, act := range cs.Actions() {
		switch a := act.(type) {
		case k8stesting.ListActionImpl:
			if a.GetResource().Resource == "persistentvolumes" {
				pvListOpts = append(pvListOpts, a.GetListOptions())
			}
		case k8stesting.GetActionImpl:
			switch a.GetResource().Resource {
			case "persistentvolumeclaims":
				pvcGetOpts = append(pvcGetOpts, a.GetGetOptions())
			case "persistentvolumes":
				pvGetOpts = append(pvGetOpts, a.GetGetOptions())
			}
		case k8stesting.DeleteActionImpl:
			if a.GetResource().Resource == "persistentvolumes" {
				pvDeleteOpts = append(pvDeleteOpts, a.GetDeleteOptions())
			}
		}
	}

	if len(pvListOpts) != 1 {
		t.Fatalf("PV list calls = %d, want 1", len(pvListOpts))
	}
	if pvListOpts[0].ResourceVersion != "0" || pvListOpts[0].Limit != 0 || pvListOpts[0].Continue != "" {
		t.Fatalf("PV ListOptions = %+v, want ResourceVersion=\"0\", Limit=0, Continue=\"\"", pvListOpts[0])
	}
	if len(pvcGetOpts) != 1 {
		t.Fatalf("PVC get calls = %d, want 1", len(pvcGetOpts))
	}
	if pvcGetOpts[0].ResourceVersion != "" {
		t.Fatalf("PVC GetOptions.ResourceVersion = %q, want \"\" (quorum)", pvcGetOpts[0].ResourceVersion)
	}
	// Two quorum PV Gets: one in releaseStalePV before Patch/Delete,
	// and one re-GET in pvGoneAndUnmounted before os.RemoveAll.
	if len(pvGetOpts) != 2 {
		t.Fatalf("PV get calls = %d, want 2", len(pvGetOpts))
	}
	for i, opts := range pvGetOpts {
		if opts.ResourceVersion != "" {
			t.Fatalf("PV GetOptions[%d].ResourceVersion = %q, want \"\" (quorum)", i, opts.ResourceVersion)
		}
	}
	if len(pvDeleteOpts) != 1 {
		t.Fatalf("PV delete calls = %d, want 1", len(pvDeleteOpts))
	}
	pre := pvDeleteOpts[0].Preconditions
	if pre == nil || pre.UID == nil || *pre.UID != pv.UID ||
		pre.ResourceVersion == nil || *pre.ResourceVersion != pv.ResourceVersion {
		t.Fatalf("PV Delete Preconditions = %+v, want UID=%q ResourceVersion=%q",
			pre, pv.UID, pv.ResourceVersion)
	}
}

// staleCacheFakeServer emulates a watch-cache (RV="0" List) lagging behind
// live etcd state while enforcing real Kubernetes JSONPatch test ops and
// Delete Preconditions (UID + ResourceVersion).
type staleCacheFakeServer struct {
	mu          sync.Mutex
	staleList   []corev1.PersistentVolume
	livePVs     map[string]*corev1.PersistentVolume
	livePVCs    map[string]*corev1.PersistentVolumeClaim
	onPVGet     func(live *corev1.PersistentVolume)
	deleteCalls []metav1.DeleteOptions
	patchedToRV string
}

func (f *staleCacheFakeServer) install(cs *fake.Clientset) {
	cs.PrependReactor("list", "persistentvolumes",
		func(act k8stesting.Action) (bool, runtime.Object, error) {
			la := act.(k8stesting.ListAction)
			if la.GetListRestrictions().Fields.Empty() && la.GetListRestrictions().Labels.Empty() {
				f.mu.Lock()
				items := make([]corev1.PersistentVolume, len(f.staleList))
				for i := range f.staleList {
					items[i] = *f.staleList[i].DeepCopy()
				}
				f.mu.Unlock()
				return true, &corev1.PersistentVolumeList{Items: items}, nil
			}
			return false, nil, nil
		})
	cs.PrependReactor("get", "persistentvolumes",
		func(act k8stesting.Action) (bool, runtime.Object, error) {
			ga := act.(k8stesting.GetAction)
			name := ga.GetName()
			f.mu.Lock()
			defer f.mu.Unlock()
			pv, ok := f.livePVs[name]
			if !ok {
				return true, nil, apierrors.NewNotFound(corev1.Resource("persistentvolumes"), name)
			}
			out := pv.DeepCopy()
			if f.onPVGet != nil {
				f.onPVGet(pv)
			}
			return true, out, nil
		})
	cs.PrependReactor("get", "persistentvolumeclaims",
		func(act k8stesting.Action) (bool, runtime.Object, error) {
			ga := act.(k8stesting.GetAction)
			key := ga.GetNamespace() + "/" + ga.GetName()
			f.mu.Lock()
			defer f.mu.Unlock()
			pvc, ok := f.livePVCs[key]
			if !ok {
				return true, nil, apierrors.NewNotFound(corev1.Resource("persistentvolumeclaims"), ga.GetName())
			}
			return true, pvc.DeepCopy(), nil
		})
	cs.PrependReactor("patch", "persistentvolumes",
		func(act k8stesting.Action) (bool, runtime.Object, error) {
			pa := act.(k8stesting.PatchAction)
			name := pa.GetName()
			f.mu.Lock()
			defer f.mu.Unlock()
			pv, ok := f.livePVs[name]
			if !ok {
				return true, nil, apierrors.NewNotFound(corev1.Resource("persistentvolumes"), name)
			}
			var ops []struct {
				Op    string `json:"op"`
				Path  string `json:"path"`
				Value any    `json:"value"`
			}
			if err := json.Unmarshal(pa.GetPatch(), &ops); err != nil {
				return true, nil, apierrors.NewBadRequest(err.Error())
			}
			for _, op := range ops {
				if op.Op == "test" {
					switch op.Path {
					case "/metadata/uid":
						if op.Value != string(pv.UID) {
							return true, nil, apierrors.NewConflict(corev1.Resource("persistentvolumes"), name, errors.New("uid mismatch"))
						}
					case "/metadata/resourceVersion":
						if op.Value != pv.ResourceVersion {
							return true, nil, apierrors.NewConflict(corev1.Resource("persistentvolumes"), name, errors.New("rv mismatch"))
						}
					}
				}
			}
			pv.Finalizers = nil
			if f.patchedToRV != "" {
				pv.ResourceVersion = f.patchedToRV
			}
			return true, pv.DeepCopy(), nil
		})
	cs.PrependReactor("delete", "persistentvolumes",
		func(act k8stesting.Action) (bool, runtime.Object, error) {
			da := act.(k8stesting.DeleteAction)
			name := da.GetName()
			opts := da.GetDeleteOptions()
			f.mu.Lock()
			defer f.mu.Unlock()
			f.deleteCalls = append(f.deleteCalls, opts)
			pv, ok := f.livePVs[name]
			if !ok {
				return true, nil, apierrors.NewNotFound(corev1.Resource("persistentvolumes"), name)
			}
			if opts.Preconditions != nil {
				if opts.Preconditions.UID != nil && *opts.Preconditions.UID != pv.UID {
					return true, nil, apierrors.NewConflict(corev1.Resource("persistentvolumes"), name, errors.New("uid precondition mismatch"))
				}
				if opts.Preconditions.ResourceVersion != nil && *opts.Preconditions.ResourceVersion != pv.ResourceVersion {
					return true, nil, apierrors.NewConflict(corev1.Resource("persistentvolumes"), name, errors.New("resourceVersion precondition mismatch"))
				}
			}
			delete(f.livePVs, name)
			return true, nil, nil
		})
}

func TestStaleRVZeroSameUIDPVProtected(t *testing.T) {
	const sameUID = types.UID("same-uid-1234")
	other := mkPV("pvc-aaaaaaaa-0000-0000-0000-000000000000", "Bound",
		corev1.PersistentVolumeReclaimDelete, "sys", "keep")

	t.Run("rebound_to_new_PVC_with_same_UID_no_finalizers", func(t *testing.T) {
		stalePV := mkPV(pvcUUID, "Released", corev1.PersistentVolumeReclaimDelete, "app", "old-data")
		stalePV.UID = sameUID
		stalePV.ResourceVersion = "10"
		stalePV.Finalizers = nil

		livePV := mkPV(pvcUUID, "Bound", corev1.PersistentVolumeReclaimDelete, "prod", "live-db")
		livePV.UID = sameUID
		livePV.ResourceVersion = "25"
		livePV.Finalizers = nil

		livePVC := &corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{Namespace: "prod", Name: "live-db"},
		}
		srv := &staleCacheFakeServer{
			staleList: []corev1.PersistentVolume{*stalePV, *other},
			livePVs:   map[string]*corev1.PersistentVolume{pvcUUID: livePV, other.Name: other},
			livePVCs:  map[string]*corev1.PersistentVolumeClaim{"prod/live-db": livePVC},
		}
		cs := nhatestutil.FakeKube()
		srv.install(cs)
		s, base, _ := fixture(t, cs)
		dir := mkPVC(t, base, pvcUUID, 2*time.Hour)

		s.Sweep(context.Background())

		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("live volume dir deleted despite rebound PV: %v", err)
		}
		srv.mu.Lock()
		_, pvAlive := srv.livePVs[pvcUUID]
		delCalls := len(srv.deleteCalls)
		srv.mu.Unlock()
		if !pvAlive {
			t.Fatal("live Bound PV was deleted")
		}
		if delCalls != 0 {
			t.Fatalf("PV delete calls = %d, want 0 (quorum PV.Get aborted before Delete)", delCalls)
		}
	})

	t.Run("reclaim_policy_changed_to_Retain_same_UID_no_finalizers", func(t *testing.T) {
		stalePV := mkPV(pvcUUID, "Released", corev1.PersistentVolumeReclaimDelete, "app", "old-data")
		stalePV.UID = sameUID
		stalePV.ResourceVersion = "10"
		stalePV.Finalizers = nil

		livePV := mkPV(pvcUUID, "Released", corev1.PersistentVolumeReclaimRetain, "app", "old-data")
		livePV.UID = sameUID
		livePV.ResourceVersion = "25"
		livePV.Finalizers = nil

		srv := &staleCacheFakeServer{
			staleList: []corev1.PersistentVolume{*stalePV, *other},
			livePVs:   map[string]*corev1.PersistentVolume{pvcUUID: livePV, other.Name: other},
			livePVCs:  map[string]*corev1.PersistentVolumeClaim{},
		}
		cs := nhatestutil.FakeKube()
		srv.install(cs)
		s, base, _ := fixture(t, cs)
		dir := mkPVC(t, base, pvcUUID, 2*time.Hour)

		s.Sweep(context.Background())

		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("volume dir deleted despite live Retain policy: %v", err)
		}
		srv.mu.Lock()
		_, pvAlive := srv.livePVs[pvcUUID]
		delCalls := len(srv.deleteCalls)
		srv.mu.Unlock()
		if !pvAlive {
			t.Fatal("live Retain PV was deleted")
		}
		if delCalls != 0 {
			t.Fatalf("PV delete calls = %d, want 0", delCalls)
		}
	})

	t.Run("toctou_race_after_quorum_PV_Get_blocked_by_RV_precondition", func(t *testing.T) {
		stalePV := mkPV(pvcUUID, "Released", corev1.PersistentVolumeReclaimDelete, "app", "old-data")
		stalePV.UID = sameUID
		stalePV.ResourceVersion = "10"
		stalePV.Finalizers = nil

		livePV := stalePV.DeepCopy()
		mutated := false
		srv := &staleCacheFakeServer{
			staleList: []corev1.PersistentVolume{*stalePV, *other},
			livePVs:   map[string]*corev1.PersistentVolume{pvcUUID: livePV, other.Name: other},
			livePVCs:  map[string]*corev1.PersistentVolumeClaim{},
			onPVGet: func(pv *corev1.PersistentVolume) {
				// Simulate PV being rebound/updated with the SAME UID immediately
				// after quorum PV.Get returned Released+Delete RV="10".
				if !mutated {
					mutated = true
					pv.Status.Phase = corev1.VolumeBound
					pv.ResourceVersion = "25"
					pv.Spec.ClaimRef = &corev1.ObjectReference{Namespace: "prod", Name: "live-db"}
				}
			},
		}
		cs := nhatestutil.FakeKube()
		srv.install(cs)
		s, base, _ := fixture(t, cs)
		dir := mkPVC(t, base, pvcUUID, 2*time.Hour)

		s.Sweep(context.Background())

		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("volume dir deleted after post-GET TOCTOU rebind: %v", err)
		}
		srv.mu.Lock()
		_, pvAlive := srv.livePVs[pvcUUID]
		delCalls := append([]metav1.DeleteOptions(nil), srv.deleteCalls...)
		srv.mu.Unlock()
		if !pvAlive {
			t.Fatal("live rebound PV was deleted despite ResourceVersion precondition")
		}
		if len(delCalls) != 1 || delCalls[0].Preconditions == nil ||
			delCalls[0].Preconditions.ResourceVersion == nil ||
			*delCalls[0].Preconditions.ResourceVersion != "10" {
			t.Fatalf("expected Delete with ResourceVersion=10 precondition, got %+v", delCalls)
		}
		if got := skipCount(t, s, skipPVDeleteFailed); got != 1 {
			t.Fatalf("pv_delete_failed skips = %v, want 1", got)
		}
	})

	t.Run("claimRef_cleared_or_changed_in_live_PV_skips", func(t *testing.T) {
		stalePV := mkPV(pvcUUID, "Released", corev1.PersistentVolumeReclaimDelete, "app", "old-data")
		stalePV.UID = sameUID
		stalePV.ResourceVersion = "10"
		stalePV.Spec.ClaimRef.UID = "pvc-uid-1"

		livePV := stalePV.DeepCopy()
		livePV.ResourceVersion = "12"
		livePV.Spec.ClaimRef = nil

		srv := &staleCacheFakeServer{
			staleList: []corev1.PersistentVolume{*stalePV, *other},
			livePVs:   map[string]*corev1.PersistentVolume{pvcUUID: livePV, other.Name: other},
			livePVCs:  map[string]*corev1.PersistentVolumeClaim{},
		}
		cs := nhatestutil.FakeKube()
		srv.install(cs)
		s, base, _ := fixture(t, cs)
		dir := mkPVC(t, base, pvcUUID, 2*time.Hour)

		s.Sweep(context.Background())

		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("dir deleted despite nil ClaimRef in live PV: %v", err)
		}
		if got := skipCount(t, s, skipClaimRefUnclear); got != 1 {
			t.Fatalf("claimref_unclear skips = %v, want 1", got)
		}
	})

	t.Run("happy_path_with_finalizers_uses_post_patch_RV", func(t *testing.T) {
		stalePV := mkPV(pvcUUID, "Released", corev1.PersistentVolumeReclaimDelete, "app", "old-data")
		stalePV.UID = sameUID
		stalePV.ResourceVersion = "10"
		stalePV.Finalizers = []string{"kubernetes.io/pv-protection"}

		livePV := stalePV.DeepCopy()
		srv := &staleCacheFakeServer{
			staleList:   []corev1.PersistentVolume{*stalePV, *other},
			livePVs:     map[string]*corev1.PersistentVolume{pvcUUID: livePV, other.Name: other},
			livePVCs:    map[string]*corev1.PersistentVolumeClaim{},
			patchedToRV: "11",
		}
		cs := nhatestutil.FakeKube()
		srv.install(cs)
		s, base, _ := fixture(t, cs)
		dir := mkPVC(t, base, pvcUUID, 2*time.Hour)

		s.Sweep(context.Background())

		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("orphan dir still present after happy-path cleanup with finalizers: %v", err)
		}
		srv.mu.Lock()
		_, pvAlive := srv.livePVs[pvcUUID]
		delCalls := append([]metav1.DeleteOptions(nil), srv.deleteCalls...)
		srv.mu.Unlock()
		if pvAlive {
			t.Fatal("PV still present after Delete")
		}
		if len(delCalls) != 1 || delCalls[0].Preconditions == nil ||
			delCalls[0].Preconditions.UID == nil || *delCalls[0].Preconditions.UID != sameUID ||
			delCalls[0].Preconditions.ResourceVersion == nil || *delCalls[0].Preconditions.ResourceVersion != "11" {
			t.Fatalf("Delete Preconditions = %+v, want UID=%q and post-patch RV=\"11\"", delCalls, sameUID)
		}
	})

	t.Run("happy_path_without_finalizers_uses_live_RV", func(t *testing.T) {
		stalePV := mkPV(pvcUUID, "Released", corev1.PersistentVolumeReclaimDelete, "app", "old-data")
		stalePV.UID = sameUID
		stalePV.ResourceVersion = "10"
		stalePV.Finalizers = nil

		livePV := stalePV.DeepCopy()
		livePV.ResourceVersion = "15" // benign live RV bump while still Released+Delete same ClaimRef
		srv := &staleCacheFakeServer{
			staleList: []corev1.PersistentVolume{*stalePV, *other},
			livePVs:   map[string]*corev1.PersistentVolume{pvcUUID: livePV, other.Name: other},
			livePVCs:  map[string]*corev1.PersistentVolumeClaim{},
		}
		cs := nhatestutil.FakeKube()
		srv.install(cs)
		s, base, _ := fixture(t, cs)
		dir := mkPVC(t, base, pvcUUID, 2*time.Hour)

		s.Sweep(context.Background())

		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("orphan dir still present after happy-path cleanup without finalizers: %v", err)
		}
		srv.mu.Lock()
		_, pvAlive := srv.livePVs[pvcUUID]
		delCalls := append([]metav1.DeleteOptions(nil), srv.deleteCalls...)
		srv.mu.Unlock()
		if pvAlive {
			t.Fatal("PV still present after Delete")
		}
		if len(delCalls) != 1 || delCalls[0].Preconditions == nil ||
			delCalls[0].Preconditions.UID == nil || *delCalls[0].Preconditions.UID != sameUID ||
			delCalls[0].Preconditions.ResourceVersion == nil || *delCalls[0].Preconditions.ResourceVersion != "15" {
			t.Fatalf("Delete Preconditions = %+v, want UID=%q and live RV=\"15\"", delCalls, sameUID)
		}
	})
}
