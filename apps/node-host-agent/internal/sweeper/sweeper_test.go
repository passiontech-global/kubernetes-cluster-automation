package sweeper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
