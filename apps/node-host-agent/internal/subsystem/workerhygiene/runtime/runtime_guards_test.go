// runtime_guards_test.go — guard tests: the subproc-oom
// living-dead subproc OOM detector, the sa-token-ttl SA-token TTL
// guard, the localpv-quota LocalPV quota enforcer, the run-tmpfs /run
// tmpfs guard and the kernel-pressure memory-compaction remedy.
package runtime_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/runtime"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// mkOOMScope lays down one kubepods pod slice with a container
// scope carrying memory.events + cgroup.procs (named mkOOMScope —
// the throttle test's mkPodSlice helper already owns that name).
func mkOOMScope(t *testing.T, e *env, uid, ctrID string, oomKill int64, pid1 int) string {
	t.Helper()
	podDir := filepath.Join(e.H.Cfg.Runtime.CgroupRoot, "kubepods.slice",
		"kubepods-burstable.slice",
		"kubepods-burstable-pod"+strings.ReplaceAll(uid, "-", "_")+".slice")
	scope := filepath.Join(podDir, "cri-containerd-"+ctrID+".scope")
	wdepstest.WriteFile(t, filepath.Join(scope, "memory.events"),
		fmt.Sprintf("low 0\nhigh 0\nmax 0\noom 0\noom_kill %d\n", oomKill))
	if pid1 > 0 {
		wdepstest.WriteFile(t, filepath.Join(scope, "cgroup.procs"),
			fmt.Sprintf("%d\n%d\n", pid1, pid1+1))
	}
	return scope
}

// --- subproc-oom: living-dead subprocess OOM detector ---

func TestSubprocOOMLivingDead(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default",
			UID: types.UID(wdepstest.UIDA)},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	e := fixture(t, pod)
	h := e.H
	ctx := context.Background()
	cg := t.TempDir()
	h.Cfg.Runtime.CgroupRoot = cg
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}
	chk := wdepstest.Check[*runtime.SubprocOOMCheck](h, wdeps.CheckSubprocOOM)

	scope := mkOOMScope(t, e, wdepstest.UIDA, "aaa111", 1, 4242)
	chk.Run(ctx, ce) // baseline — first sighting only
	// oom_kill advances with the SAME pid1 → pending verdict.
	wdepstest.WriteFile(t, filepath.Join(scope, "memory.events"), "oom_kill 2\n")
	chk.Run(ctx, ce)
	// 61s later, pid1 unchanged → living-dead event.
	e.Now = e.Now.Add(61 * time.Second)
	chk.Run(ctx, ce)
	evs, err := e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs.Items) != 1 || evs.Items[0].Reason != "ContainerSubprocessOOMKilled" {
		t.Fatalf("events=%+v want one ContainerSubprocessOOMKilled", evs.Items)
	}
	if h.ContainerSubprocessOOM != 1 {
		t.Fatalf("ContainerSubprocessOOM=%d want 1", h.ContainerSubprocessOOM)
	}
	// Same generation → no double-report next cycle.
	e.Now = e.Now.Add(61 * time.Second)
	chk.Run(ctx, ce)
	evs2, _ := e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
	if len(evs2.Items) != 1 {
		t.Fatalf("double-reported event: %d", len(evs2.Items))
	}
}

func TestSubprocOOMRealInitKillNoEvent(t *testing.T) {
	e := fixture(t)
	h := e.H
	ctx := context.Background()
	cg := t.TempDir()
	h.Cfg.Runtime.CgroupRoot = cg
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true}

	scope := mkOOMScope(t, e, wdepstest.UIDB, "bbb222", 0, 1000)
	chk := wdepstest.Check[*runtime.SubprocOOMCheck](h, wdeps.CheckSubprocOOM)
	chk.Run(ctx, ce)
	// Kill lands AND pid1 changes (container restarted) → no event.
	wdepstest.WriteFile(t, filepath.Join(scope, "memory.events"), "oom_kill 1\n")
	wdepstest.WriteFile(t, filepath.Join(scope, "cgroup.procs"), "2000\n")
	chk.Run(ctx, ce)
	e.Now = e.Now.Add(2 * time.Minute)
	chk.Run(ctx, ce)
	evs, _ := e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
	if len(evs.Items) != 0 {
		t.Fatalf("legit init-kill produced living-dead event: %+v", evs.Items)
	}
	// The detection counter must not have fired either — a pod-less
	// fixture only masks the false positive at event-create time.
	if h.ContainerSubprocessOOM != 0 {
		t.Fatalf("ContainerSubprocessOOM=%d want 0 for a legit init-kill restart",
			h.ContainerSubprocessOOM)
	}
	// Missing kubepods.slice root → abort, never panic.
	h.Cfg.Runtime.CgroupRoot = filepath.Join(cg, "nope")
	chk.Run(ctx, ce)
}

func TestSubprocOOMKillStormStillConfirms(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "storm", Namespace: "default",
			UID: types.UID(wdepstest.UIDA)},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	e := fixture(t, pod)
	h := e.H
	ctx := context.Background()
	h.Cfg.Runtime.CgroupRoot = t.TempDir()
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}
	chk := wdepstest.Check[*runtime.SubprocOOMCheck](h, wdeps.CheckSubprocOOM)

	scope := mkOOMScope(t, e, wdepstest.UIDA, "ccc333", 1, 4242)
	chk.Run(ctx, ce) // baseline — first sighting only
	// A subprocess kill lands EVERY cycle while pid1 survives —
	// pendingAt must stay armed from the FIRST kill so the verdict
	// still fires ~60s out, not be postponed forever.
	for i := int64(2); i <= 4; i++ {
		wdepstest.WriteFile(t, filepath.Join(scope, "memory.events"),
			fmt.Sprintf("oom_kill %d\n", i))
		chk.Run(ctx, ce)
		e.Now = e.Now.Add(31 * time.Second)
	}
	chk.Run(ctx, ce) // ~93s after the first kill
	evs, err := e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs.Items) != 1 || evs.Items[0].Reason != "ContainerSubprocessOOMKilled" {
		t.Fatalf("events=%+v want one ContainerSubprocessOOMKilled", evs.Items)
	}
	if h.ContainerSubprocessOOM != 1 {
		t.Fatalf("ContainerSubprocessOOM=%d want 1", h.ContainerSubprocessOOM)
	}
}

// --- sa-token-ttl: projected SA token TTL guard ---

// fakeJWT builds a syntactically-valid compact JWT carrying exp.
func fakeJWT(exp int64) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	pl := base64.RawURLEncoding.EncodeToString(
		[]byte(fmt.Sprintf(`{"exp":%d}`, exp)))
	return hdr + "." + pl + ".sig"
}

func TestSATokenTTLStalled(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api-client", Namespace: "default",
			UID: types.UID(wdepstest.UIDC)},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	e := fixture(t, pod)
	h := e.H
	ctx := context.Background()
	tokDir := filepath.Join(e.KubepodsDir, wdepstest.UIDC,
		"volumes", "kubernetes.io~projected", "kube-api-access-xyz")
	exp := e.Now.Add(120 * time.Second).Unix() // 120s < 600s floor
	wdepstest.WriteFile(t, filepath.Join(tokDir, "token"), fakeJWT(exp)+"\n")

	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}
	chk := wdepstest.Check[*runtime.SATokenTTLCheck](h, wdeps.CheckSATokenTTL)
	chk.Run(ctx, ce)
	if h.SATokenMinTTLSec != 120 {
		t.Fatalf("SATokenMinTTLSec=%v want 120", h.SATokenMinTTLSec)
	}
	evs, err := e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs.Items) != 1 || evs.Items[0].Reason != "SATokenRotationStalled" {
		t.Fatalf("events=%+v want one SATokenRotationStalled", evs.Items)
	}
	// The resync annotation was stamped.
	got, err := e.CS.CoreV1().Pods("default").Get(ctx, "api-client", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Annotations["passiontech.dev/token-resync-at"] == "" {
		t.Fatal("token-resync-at annotation missing after stall")
	}
	// Second cycle within the nudge cooldown → no second patch.
	patches := func() int {
		n := 0
		for _, a := range e.CS.Actions() {
			if a.GetVerb() == "patch" && a.GetResource().Resource == "pods" {
				n++
			}
		}
		return n
	}
	chk.Run(ctx, ce)
	if patches() != 1 {
		t.Fatalf("pod patches=%d want 1 (cooldown dedupe)", patches())
	}
}

func TestSATokenTTLHealthy(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "ok", Namespace: "default",
			UID: types.UID(wdepstest.UIDD)},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	e := fixture(t, pod)
	h := e.H
	ctx := context.Background()
	// Far-future token → min TTL only, no event/nudge.
	tokDir := filepath.Join(e.KubepodsDir, wdepstest.UIDD,
		"volumes", "kubernetes.io~projected", "kube-api-access-ok")
	exp := e.Now.Add(40 * time.Minute).Unix()
	wdepstest.WriteFile(t, filepath.Join(tokDir, "token"), fakeJWT(exp)+"\n")
	// Garbage token on another pod dir → skipped, never logged.
	badDir := filepath.Join(e.KubepodsDir, wdepstest.UIDE,
		"volumes", "kubernetes.io~projected", "v")
	wdepstest.WriteFile(t, filepath.Join(badDir, "token"), "not-a-jwt\n")

	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}
	wdepstest.Check[*runtime.SATokenTTLCheck](h, wdeps.CheckSATokenTTL).Run(ctx, ce)
	if h.SATokenMinTTLSec < 2300 || h.SATokenMinTTLSec > 2400 {
		t.Fatalf("SATokenMinTTLSec=%v want ~2400", h.SATokenMinTTLSec)
	}
	evs, _ := e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
	if len(evs.Items) != 0 {
		t.Fatalf("healthy token produced event: %+v", evs.Items)
	}
	if strings.Contains(e.LogLines(t), "not-a-jwt") {
		t.Fatal("token contents leaked into the log")
	}
}

// --- localpv-quota: LocalPV quota enforcer ---

func TestLocalPVQuotaThrottle(t *testing.T) {
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pvc-abc123"},
		Spec: corev1.PersistentVolumeSpec{
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse("1Gi"),
			},
		},
	}
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: "default"},
		Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: "pvc-abc123"},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "hog", Namespace: "default",
			UID: types.UID(wdepstest.UIDA)},
		Spec: corev1.PodSpec{
			NodeName: "node-a",
			Volumes: []corev1.Volume{{
				Name: "data",
				VolumeSource: corev1.VolumeSource{
					PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
						ClaimName: "data"},
				},
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	e := fixture(t, pv, pvc, pod)
	h := e.H
	ctx := context.Background()
	prov := t.TempDir()
	h.Cfg.Disk.LocalPVQuotaDir = prov
	pvcDir := filepath.Join(prov, "pvc-abc123")
	// 1.6Gi of data in a 1Gi PV (>1.5x).
	big := filepath.Join(pvcDir, "big.bin")
	if err := os.MkdirAll(pvcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	bf, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := bf.Truncate(1717986918); err != nil { // 1.6Gi > 1.5x the 1Gi PV
		t.Fatal(err)
	}
	_ = bf.Close()
	// A live task for the pod.
	e.Live[7777] = true
	e.MkTask(t, wdepstest.UIDA, "hog", 7777)
	e.DiskUsed = 0.85 // >80% node disk
	reniced := map[int]bool{}
	ioniced := map[int]bool{}
	h.Cfg.Seams.Host.ReniceFn = func(pid int) error { reniced[pid] = true; return nil }
	h.Cfg.Seams.Host.IoniceIdleFn = func(pid int) error { ioniced[pid] = true; return nil }
	// pod cgroup slice for the io.weight drop.
	cg := t.TempDir()
	h.Cfg.Runtime.CgroupRoot = cg
	podDir := filepath.Join(cg, "kubepods.slice", "kubepods-burstable.slice",
		"kubepods-burstable-pod"+strings.ReplaceAll(wdepstest.UIDA, "-", "_")+".slice")
	wdepstest.WriteFile(t, filepath.Join(podDir, "io.weight"), "100")

	tasks, _ := h.BuildTaskMap()
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true,
		Pods: []corev1.Pod{*pod},
		TasksOnce: func() (map[string][]wdeps.CtrTask, bool) {
			return tasks, true
		}}
	wdepstest.Check[*runtime.DiskBloatCheck](h, wdeps.CheckDiskBloat).Run(ctx, ce)
	if !reniced[7777] || !ioniced[7777] {
		t.Fatalf("tasks not deprioritized: renice=%v ionice=%v", reniced, ioniced)
	}
	if w, _ := os.ReadFile(filepath.Join(podDir, "io.weight")); string(w) != "1" {
		t.Fatalf("io.weight=%q want 1", w)
	}
	evs, _ := e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
	found := false
	for _, ev := range evs.Items {
		if ev.Reason == "LocalPVQuotaExceeded" {
			found = true
		}
	}
	if !found || h.LocalPVQuotaThrottled != 1 {
		t.Fatalf("LocalPVQuotaExceeded=%v throttled=%d", found, h.LocalPVQuotaThrottled)
	}
	// Below-pressure run must not re-throttle the ledger entry.
	e.DiskUsed = 0.50
	wdepstest.Check[*runtime.DiskBloatCheck](h, wdeps.CheckDiskBloat).Run(ctx, ce)
	if h.LocalPVQuotaThrottled != 1 {
		t.Fatalf("throttled=%d want 1 (ledger)", h.LocalPVQuotaThrottled)
	}
}

// TestLocalPVQuotaNoDirsSkipsAPI — no pvc-* dir under the scan
// roots → the cluster-wide PV/PVC lists never fire (sweeper parity).
func TestLocalPVQuotaNoDirsSkipsAPI(t *testing.T) {
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pvc-abc123"},
		Spec: corev1.PersistentVolumeSpec{
			Capacity: corev1.ResourceList{
				corev1.ResourceStorage: resource.MustParse("1Gi"),
			},
		},
	}
	e := fixture(t, pv)
	e.H.Cfg.Disk.LocalPVQuotaDir = t.TempDir() // empty root — no pvc-* dirs
	e.DiskUsed = 0.85
	lists := func() (pvN, pvcN int) {
		for _, a := range e.CS.Actions() {
			switch a.GetResource().Resource {
			case "persistentvolumes":
				if a.GetVerb() == "list" {
					pvN++
				}
			case "persistentvolumeclaims":
				if a.GetVerb() == "list" {
					pvcN++
				}
			}
		}
		return pvN, pvcN
	}
	e.H.Check(wdeps.CheckDiskBloat).Run(context.Background(),
		&wdeps.CycleEnv{WorkerActive: true, APIOK: true})
	if pvN, pvcN := lists(); pvN != 0 || pvcN != 0 {
		t.Fatalf("no-dir cycle issued API lists: pv=%d pvc=%d", pvN, pvcN)
	}

	// With a pvc-* candidate on disk the lists DO fire.
	if err := os.MkdirAll(
		filepath.Join(e.H.Cfg.Disk.LocalPVQuotaDir, "pvc-abc123"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.H.Check(wdeps.CheckDiskBloat).Run(context.Background(),
		&wdeps.CycleEnv{WorkerActive: true, APIOK: true})
	pvN, pvcN := lists()
	if pvN != 1 || pvcN != 1 {
		t.Fatalf("candidate cycle lists: pv=%d pvc=%d, want 1/1", pvN, pvcN)
	}
}

// --- run-tmpfs: /run tmpfs guard ---

func TestRunTmpfsGuard(t *testing.T) {
	e := fixture(t)
	h := e.H
	ctx := context.Background()
	runDir := t.TempDir()
	h.Cfg.Disk.HostRunDir = runDir
	// statfs seam per-path: /run reports 85% bytes; k0sdata stays low.
	h.Cfg.Seams.Host.StatfsFn = func(path string, st *unix.Statfs_t) error {
		st.Blocks = 100
		st.Files = 100
		st.Ffree = 50
		if path == runDir {
			st.Bavail = 15 // 85% used
		} else {
			st.Bavail = 100 - uint64(e.DiskUsed*100)
		}
		return nil
	}
	// Orphan .tmp files: one old, one fresh.
	old := filepath.Join(runDir, "orphan.tmp")
	fresh := filepath.Join(runDir, "fresh.tmp")
	wdepstest.WriteFile(t, old, "stale")
	wdepstest.WriteFile(t, fresh, "new")
	past := e.Now.Add(-3 * time.Hour)
	_ = os.Chtimes(old, past, past)

	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: false}
	wdepstest.Check[*runtime.DiskBloatCheck](h, wdeps.CheckDiskBloat).Run(ctx, ce)
	if h.RunTmpfsUsedRatio < 0.84 {
		t.Fatalf("RunTmpfsUsedRatio=%v want ~0.85", h.RunTmpfsUsedRatio)
	}
	if !e.SDRan("journalctl") || !e.SDRan("vacuum-size=16M") {
		t.Fatalf("journal vacuum not exec'd: %v", e.SDCmds)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("old orphan .tmp not removed")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatal("fresh .tmp removed")
	}
	if h.RunTmpfsCleanups != 1 {
		t.Fatalf("RunTmpfsCleanups=%d want 1", h.RunTmpfsCleanups)
	}
	// 15m cooldown: second cycle does not re-vacuum.
	nCmds := len(e.SDCmds)
	wdepstest.Check[*runtime.DiskBloatCheck](h, wdeps.CheckDiskBloat).Run(ctx, ce)
	if len(e.SDCmds) != nCmds {
		t.Fatal("vacuum re-ran inside the 15m budget")
	}
}

// --- kernel-pressure: page-alloc-failure → compact_memory ---

func TestPageAllocCompaction(t *testing.T) {
	e := fixture(t)
	h := e.H
	ctx := context.Background()
	target := filepath.Join(e.ProcDir, "sys", "vm", "compact_memory")
	wdepstest.WriteFile(t, target, "0\n")
	chk := wdepstest.Check[*runtime.HostOOMCheck](h, wdeps.CheckHostOOM)
	ce := &wdeps.CycleEnv{WorkerActive: true}
	// No latch → no write.
	chk.Run(ctx, ce)
	if b, _ := os.ReadFile(target); string(b) != "0\n" {
		t.Fatalf("compact_memory poked without latch: %q", b)
	}
	// Latch held → write 1 + counter + cooldown.
	h.State.Enter("page-alloc-failure", "order:4")
	chk.Run(ctx, ce)
	if b, _ := os.ReadFile(target); string(b) != "1" {
		t.Fatalf("compact_memory=%q want 1", b)
	}
	if h.MemoryCompactionRuns != 1 {
		t.Fatalf("MemoryCompactionRuns=%d want 1", h.MemoryCompactionRuns)
	}
	// Registry contract: the consumer Exits the latch after a
	// successful compact — a held latch would re-fire every 30m.
	if h.State.Exists("page-alloc-failure") {
		t.Fatal("page-alloc-failure latch still held after compact")
	}
	// Cooldown blocks the repeat.
	wdepstest.WriteFile(t, target, "0\n")
	chk.Run(ctx, ce)
	if b, _ := os.ReadFile(target); string(b) != "0\n" {
		t.Fatal("compact_memory re-poked inside the 30m budget")
	}
}

// TestSubprocOOMMemoryStatBreakdown — subproc-oom-breakdown: at living-dead
// confirmation the memory.stat of the same cgroup is folded into
// the event note ("mem_stat=anon=XMiB shmem=YMiB file=ZMiB") — a
// big shmem is the tmpfs/emptyDir{medium:Memory} fingerprint.
func TestSubprocOOMMemoryStatBreakdown(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "tmpfs", Namespace: "default",
			UID: types.UID(wdepstest.UIDA)},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	e := fixture(t, pod)
	h := e.H
	ctx := context.Background()
	h.Cfg.Runtime.CgroupRoot = t.TempDir()
	ce := &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: []corev1.Pod{*pod}}
	chk := wdepstest.Check[*runtime.SubprocOOMCheck](h, wdeps.CheckSubprocOOM)

	scope := mkOOMScope(t, e, wdepstest.UIDA, "mem111", 1, 4242)
	// 3.5 GiB anon, 1.2 GiB shmem, 0.1 GiB file (byte-exact MiB
	// rounding: 3758096384 → 3584, 1288490189 → 1229, 107374183 → 102).
	wdepstest.WriteFile(t, filepath.Join(scope, "memory.stat"),
		"anon 3758096384\nfile 107374183\nshmem 1288490189\nkernel 100\nsock 5\n")
	chk.Run(ctx, ce) // baseline
	wdepstest.WriteFile(t, filepath.Join(scope, "memory.events"), "oom_kill 2\n")
	chk.Run(ctx, ce)
	e.Now = e.Now.Add(61 * time.Second)
	chk.Run(ctx, ce)
	evs, err := e.CS.EventsV1().Events("default").List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs.Items) != 1 {
		t.Fatalf("events=%d want 1", len(evs.Items))
	}
	note := evs.Items[0].Note
	want := "mem_stat=anon=3584MiB shmem=1229MiB file=102MiB"
	if !strings.Contains(note, want) {
		t.Fatalf("event note missing breakdown %q:\n%s", want, note)
	}
	if !strings.Contains(e.LogLines(t), want) {
		t.Fatalf("log missing breakdown %q:\n%s", want, e.LogLines(t))
	}
}
