// Wave-9 tests — the kernel slab-leak guard + PSI evictor hardening
// (W9-KR3), the orphan /run/netns/cni-* reaper (W9-NM2), the
// containerd content-store prune (W9-NM4), and the cilium_wg0
// double-encapsulation MTU guard (W9-NM1 worker side).

package workerhygiene

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
)

// --- W9-KR3: kernel slab-leak guard ---

// writeMeminfoSlab writes a meminfo carrying MemTotal, MemAvailable
// and SUnreclaim (kB) — the three fields the slab guard + PSI check
// consume.
func writeMeminfoSlab(t *testing.T, e *env, availKB, totalKB, slabKB int) {
	t.Helper()
	writeFile(t, filepath.Join(e.proc, "meminfo"), fmt.Sprintf(
		"MemTotal: %d kB\nMemFree: %d kB\nMemAvailable: %d kB\nSUnreclaim: %d kB\n",
		totalKB, availKB, availKB, slabKB))
}

// writeThrashFilesSlab is writeThrashFiles plus an SUnreclaim line —
// PSI thrash AND a slab leak can coexist; the guard must still run.
func writeThrashFilesSlab(t *testing.T, e *env, avg60 float64,
	availKB, totalKB, slabKB int) {
	t.Helper()
	writeThrashFiles(t, e, avg60, availKB, totalKB)
	writeMeminfoSlab(t, e, availKB, totalKB, slabKB)
}

// procRSSProc registers a fake process whose cgroup attributes it to
// pod uid and whose VmRSS is rssKB — the PSI victim-ranking inputs.
func procRSSProc(t *testing.T, e *env, pid int, uid string, rssKB int) {
	t.Helper()
	d := filepath.Join(e.proc, strconv.Itoa(pid))
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	underscored := strings.ReplaceAll(uid, "-", "_")
	writeFile(t, filepath.Join(d, "cgroup"),
		"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod"+underscored+".slice\n")
	writeFile(t, filepath.Join(d, "status"),
		fmt.Sprintf("Name:\tc\nVmRSS:\t%d kB\n", rssKB))
}

// psiPod builds a Running pod on node-a for the eviction tests.
func psiPod(name, ns, uid string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns, UID: types.UID(uid)},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

// statefulOwner marks a pod as StatefulSet-owned for the victim
// tiering tests.
func statefulOwner(p *corev1.Pod, name string) *corev1.Pod {
	controller := true
	p.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "apps/v1", Kind: "StatefulSet",
		Name: name, Controller: &controller,
	}}
	return p
}

// TestKernelSlabLeakLatchesDropsCachesAndBudgets: SUnreclaim above
// 35% of MemTotal latches state-kernel-slab-leak, writes "2" to
// drop_caches once per hour (the rate budget), and the ACTION lines
// hit the watchdog log for nodereporter's event mapping.
func TestKernelSlabLeakLatchesDropsCachesAndBudgets(t *testing.T) {
	e := fixture(t)
	// 40% unreclaimable slab — above the 0.35 enter ratio. PSI is
	// absent (psiOK=false) but the guard must still evaluate.
	writeMeminfoSlab(t, e, 500000, 1000000, 400000)
	dropCaches := filepath.Join(e.proc, "sys", "vm", "drop_caches")
	writeFile(t, dropCaches, "")

	e.h.checkPSIThrash(context.Background(), nil, true, pidsOf(), true)
	if !e.h.state.Exists("kernel-slab-leak") {
		t.Fatal("no kernel-slab-leak latch at 40% SUnreclaim")
	}
	data, err := os.ReadFile(dropCaches)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "2" {
		t.Fatalf("drop_caches = %q, want \"2\"", string(data))
	}
	logs := logLines(t, e)
	if !strings.Contains(logs, "ACTION kernel-slab-leak: sunreclaim_ratio=") {
		t.Fatalf("missing latch-entry ACTION line:\n%s", logs)
	}
	if n := strings.Count(logs, "wrote 2 to sys/vm/drop_caches"); n != 1 {
		t.Fatalf("drop_caches writes = %d, want 1", n)
	}
	if _, err := os.Stat(filepath.Join(e.state, "last-slab-drop-caches")); err != nil {
		t.Fatal("last-slab-drop-caches budget not spent")
	}

	// Same-hour re-entry: the budget blocks a second write.
	e.h.checkPSIThrash(context.Background(), nil, true, pidsOf(), true)
	if n := strings.Count(logLines(t, e), "wrote 2 to sys/vm/drop_caches"); n != 1 {
		t.Fatalf("drop_caches writes inside the hour = %d, want 1", n)
	}
	// The latch mtime is refreshed while held (janitor-safe).
	if !e.h.state.Exists("kernel-slab-leak") {
		t.Fatal("latch dropped while still leaking")
	}

	// Past the 1h budget the write resumes.
	e.now = e.now.Add(61 * time.Minute)
	e.h.checkPSIThrash(context.Background(), nil, true, pidsOf(), true)
	if n := strings.Count(logLines(t, e), "wrote 2 to sys/vm/drop_caches"); n != 2 {
		t.Fatalf("drop_caches writes past the budget = %d, want 2", n)
	}

	// Below the 0.25 clear ratio the latch exits.
	writeMeminfoSlab(t, e, 500000, 1000000, 200000)
	e.h.checkPSIThrash(context.Background(), nil, true, pidsOf(), true)
	if e.h.state.Exists("kernel-slab-leak") {
		t.Fatal("kernel-slab-leak latch not cleared at 20% SUnreclaim")
	}
}

// TestKernelSlabLeakHysteresis: between the 0.25 clear and 0.35
// enter ratios the latch simply persists — no flapping on a ratio
// hovering near a threshold.
func TestKernelSlabLeakHysteresis(t *testing.T) {
	e := fixture(t)
	writeFile(t, filepath.Join(e.proc, "sys", "vm", "drop_caches"), "")

	// 0.30 is inside the band but was never entered → no latch.
	writeMeminfoSlab(t, e, 500000, 1000000, 300000)
	e.h.checkPSIThrash(context.Background(), nil, true, pidsOf(), true)
	if e.h.state.Exists("kernel-slab-leak") {
		t.Fatal("latch entered at 0.30 without crossing 0.35")
	}

	// Cross 0.35 → latch.
	writeMeminfoSlab(t, e, 500000, 1000000, 400000)
	e.h.checkPSIThrash(context.Background(), nil, true, pidsOf(), true)
	if !e.h.state.Exists("kernel-slab-leak") {
		t.Fatal("no latch at 0.40")
	}

	// Back into the band → still latched.
	writeMeminfoSlab(t, e, 500000, 1000000, 300000)
	e.h.checkPSIThrash(context.Background(), nil, true, pidsOf(), true)
	if !e.h.state.Exists("kernel-slab-leak") {
		t.Fatal("latch cleared inside the hysteresis band")
	}
}

// TestPSIThrashEvictSuppressedBySlabLeak: while kernel-slab-leak is
// latched the PSI evictor holds its latch but refuses to evict —
// a kernel slab leak is not a pod-size problem. Once the slab
// recovers the NEXT thrash cycle evicts normally.
func TestPSIThrashEvictSuppressedBySlabLeak(t *testing.T) {
	e := fixture(t)
	writeThrashFilesSlab(t, e, 30.0, 50000, 1000000, 400000)
	hog := psiPod("memhog", "app", uidA)
	pods := []corev1.Pod{*hog}
	procRSSProc(t, e, 5001, uidA, 900000)
	pids := pidsOf(5001)

	for i := 0; i < 2; i++ {
		e.h.checkPSIThrash(context.Background(), pods, true, pids, true)
	}
	if !e.h.state.Exists("psi-memory-thrash") {
		t.Fatal("no psi-memory-thrash latch")
	}
	if !e.h.state.Exists("kernel-slab-leak") {
		t.Fatal("no kernel-slab-leak latch")
	}
	if n := len(evictActions(e.cs)); n != 0 {
		t.Fatalf("evictions while slab-leaking = %v, want none", evictActions(e.cs))
	}
	if got := logLines(t, e); !strings.Contains(got,
		"pod evict suppressed - kernel-slab-leak latched") {
		t.Fatalf("missing suppression line:\n%s", got)
	}

	// Slab recovers → the evictor resumes on the next thrash cycle.
	writeThrashFilesSlab(t, e, 30.0, 50000, 1000000, 100000)
	e.h.checkPSIThrash(context.Background(), pods, true, pids, true)
	evs := evictActions(e.cs)
	if len(evs) != 1 || evs[0] != "memhog" {
		t.Fatalf("evictions after slab recovery = %v, want memhog", evs)
	}
}

// --- W9 victim-selection hardening ---

// thrashEnv lays down sustained PSI thrash + a healthy slab ratio.
func thrashEnv(t *testing.T, e *env) {
	t.Helper()
	writeThrashFilesSlab(t, e, 30.0, 50000, 1000000, 100000)
}

// drivePSI runs checkPSIThrash ConsecNeeded times so the latch +
// eviction path fire.
func drivePSI(t *testing.T, e *env, pods []corev1.Pod, pids func() []int) {
	t.Helper()
	for i := 0; i < e.h.cfg.ConsecNeeded; i++ {
		e.h.checkPSIThrash(context.Background(), pods, true, pids, true)
	}
}

// TestPSIEvictorRSSFloor: no pod at/above 512 MiB RSS → the latch
// holds but nothing is evicted — small pods are not worth the API
// churn while the thrash persists.
func TestPSIEvictorRSSFloor(t *testing.T) {
	e := fixture(t)
	thrashEnv(t, e)
	pods := []corev1.Pod{*psiPod("small", "app", uidA)}
	procRSSProc(t, e, 5001, uidA, 500000) // ~488 MiB < 512 MiB floor
	drivePSI(t, e, pods, pidsOf(5001))
	if !e.h.state.Exists("psi-memory-thrash") {
		t.Fatal("no psi-memory-thrash latch")
	}
	if n := len(evictActions(e.cs)); n != 0 {
		t.Fatalf("evictions below the RSS floor = %v", evictActions(e.cs))
	}
	// Exactly at the floor still counts.
	e2 := fixture(t)
	thrashEnv(t, e2)
	pods2 := []corev1.Pod{*psiPod("edge", "app", uidA)}
	procRSSProc(t, e2, 5001, uidA, minEvictRSSBytes/1024+1)
	drivePSI(t, e2, pods2, pidsOf(5001))
	if evs := evictActions(e2.cs); len(evs) != 1 || evs[0] != "edge" {
		t.Fatalf("evictions at the RSS floor = %v, want edge", evs)
	}
}

// TestPSIEvictorExcludedNamespaces: storage/CNI/flux namespaces are
// never victims even holding the most RSS; the eligible app pod is.
func TestPSIEvictorExcludedNamespaces(t *testing.T) {
	e := fixture(t)
	thrashEnv(t, e)
	pods := []corev1.Pod{
		*psiPod("csi-provisioner", "openebs", uidA),
		*psiPod("gotk-controller", "flux-system", uidB),
		*psiPod("workload", "app", uidC),
	}
	procRSSProc(t, e, 5001, uidA, 900000)
	procRSSProc(t, e, 5002, uidB, 800000)
	procRSSProc(t, e, 5003, uidC, 600000)
	drivePSI(t, e, pods, pidsOf(5001, 5002, 5003))
	evs := evictActions(e.cs)
	if len(evs) != 1 || evs[0] != "workload" {
		t.Fatalf("evictions = %v, want only workload", evs)
	}
}

// TestPSIEvictorOnlyProtectedPods: when EVERY pod above the floor is
// protected there is no victim — better a held latch than evicting
// the recovery path.
func TestPSIEvictorOnlyProtectedPods(t *testing.T) {
	e := fixture(t)
	thrashEnv(t, e)
	pods := []corev1.Pod{
		*psiPod("openebs-csi", "openebs", uidA),
		*psiPod("cert-manager", "cert-manager", uidB),
	}
	procRSSProc(t, e, 5001, uidA, 900000)
	procRSSProc(t, e, 5002, uidB, 800000)
	drivePSI(t, e, pods, pidsOf(5001, 5002))
	if !e.h.state.Exists("psi-memory-thrash") {
		t.Fatal("no psi-memory-thrash latch")
	}
	if n := len(evictActions(e.cs)); n != 0 {
		t.Fatalf("evictions with only protected pods = %v", evictActions(e.cs))
	}
}

// TestPSIEvictorCriticalPriorityClass: system-cluster-critical pods
// are untouchable regardless of RSS.
func TestPSIEvictorCriticalPriorityClass(t *testing.T) {
	e := fixture(t)
	thrashEnv(t, e)
	crit := psiPod("apiserver-sidecar", "app", uidA)
	crit.Spec.PriorityClassName = "system-cluster-critical"
	pods := []corev1.Pod{*crit}
	procRSSProc(t, e, 5001, uidA, 900000)
	drivePSI(t, e, pods, pidsOf(5001))
	if n := len(evictActions(e.cs)); n != 0 {
		t.Fatalf("evictions of a critical-priority pod = %v", evictActions(e.cs))
	}
}

// TestPSIEvictorTerminating: a pod already being deleted is not a
// victim — its memory is already on its way out.
func TestPSIEvictorTerminating(t *testing.T) {
	e := fixture(t)
	thrashEnv(t, e)
	pods := []corev1.Pod{*terminatingPod(e, "dying", "app", uidA, time.Minute)}
	procRSSProc(t, e, 5001, uidA, 900000)
	drivePSI(t, e, pods, pidsOf(5001))
	if n := len(evictActions(e.cs)); n != 0 {
		t.Fatalf("evictions of a terminating pod = %v", evictActions(e.cs))
	}
}

// TestPSIEvictorQoSTiering: a Guaranteed pod with MORE RSS loses to
// a Burstable pod above the floor — Guaranteed workloads are the
// fallback tier, evicted only when nothing preferred qualifies.
func TestPSIEvictorQoSTiering(t *testing.T) {
	e := fixture(t)
	thrashEnv(t, e)
	guaranteed := psiPod("guaranteed", "app", uidA)
	guaranteed.Status.QOSClass = corev1.PodQOSGuaranteed
	burstable := psiPod("burstable", "app", uidB)
	burstable.Status.QOSClass = corev1.PodQOSBurstable
	pods := []corev1.Pod{*guaranteed, *burstable}
	procRSSProc(t, e, 5001, uidA, 900000) // Guaranteed holds more
	procRSSProc(t, e, 5002, uidB, 600000)
	drivePSI(t, e, pods, pidsOf(5001, 5002))
	evs := evictActions(e.cs)
	if len(evs) != 1 || evs[0] != "burstable" {
		t.Fatalf("evictions = %v, want the Burstable pod (QoS tiering)", evs)
	}
}

// TestPSIEvictorGuaranteedFallback: with ONLY a Guaranteed pod above
// the floor it is still evicted — the fallback tier exists so the
// thrash does not end in a kernel OOM pick.
func TestPSIEvictorGuaranteedFallback(t *testing.T) {
	e := fixture(t)
	thrashEnv(t, e)
	guaranteed := psiPod("guaranteed", "app", uidA)
	guaranteed.Status.QOSClass = corev1.PodQOSGuaranteed
	pods := []corev1.Pod{*guaranteed}
	procRSSProc(t, e, 5001, uidA, 900000)
	drivePSI(t, e, pods, pidsOf(5001))
	if evs := evictActions(e.cs); len(evs) != 1 || evs[0] != "guaranteed" {
		t.Fatalf("evictions = %v, want the Guaranteed fallback victim", evs)
	}
}

// TestPSIEvictorStatefulSetDBQuorum: a StatefulSet-owned pod whose
// labels name a database/quorum workload is NEVER a victim — quorum
// loss costs far more than the memory it frees. A non-DB StatefulSet
// pod is only the fallback tier.
func TestPSIEvictorStatefulSetDBQuorum(t *testing.T) {
	e := fixture(t)
	thrashEnv(t, e)
	db := statefulOwner(psiPod("scylla-0", "scylla", uidA), "scylla")
	db.Labels = map[string]string{"app.kubernetes.io/name": "scylla"}
	plain := statefulOwner(psiPod("cache-0", "app", uidB), "cache")
	burstable := psiPod("workload", "app", uidC)
	pods := []corev1.Pod{*db, *plain, *burstable}
	procRSSProc(t, e, 5001, uidA, 950000) // DB pod holds the most
	procRSSProc(t, e, 5002, uidB, 800000) // StatefulSet non-DB
	procRSSProc(t, e, 5003, uidC, 600000)
	drivePSI(t, e, pods, pidsOf(5001, 5002, 5003))
	evs := evictActions(e.cs)
	if len(evs) != 1 || evs[0] != "workload" {
		t.Fatalf("evictions = %v, want workload (db-quorum + sts protected)", evs)
	}

	// Without the preferred-tier pod the non-DB StatefulSet pod is
	// the fallback victim — the DB pod still never competes.
	e2 := fixture(t)
	thrashEnv(t, e2)
	db2 := statefulOwner(psiPod("scylla-0", "scylla", uidA), "scylla")
	db2.Labels = map[string]string{"app.kubernetes.io/name": "scylla"}
	plain2 := statefulOwner(psiPod("cache-0", "app", uidB), "cache")
	pods2 := []corev1.Pod{*db2, *plain2}
	procRSSProc(t, e2, 5001, uidA, 950000)
	procRSSProc(t, e2, 5002, uidB, 800000)
	drivePSI(t, e2, pods2, pidsOf(5001, 5002))
	if evs := evictActions(e2.cs); len(evs) != 1 || evs[0] != "cache-0" {
		t.Fatalf("fallback evictions = %v, want cache-0 (db pod excluded)", evs)
	}
}

// TestPSIEvictorDBLabelWithoutStatefulSet: the quorum-label guard
// requires BOTH a StatefulSet owner AND a db label — a db label on
// a Deployment-owned pod does not exempt it (deployments reschedule
// freely; only StatefulSet identity pins the quorum member).
func TestPSIEvictorDBLabelWithoutStatefulSet(t *testing.T) {
	e := fixture(t)
	thrashEnv(t, e)
	labeled := psiPod("pg-0", "app", uidA)
	// carriesDBQuorumLabel WOULD match this — the missing piece is
	// the StatefulSet owner.
	labeled.Labels = map[string]string{"app": "postgresql"}
	pods := []corev1.Pod{*labeled}
	procRSSProc(t, e, 5001, uidA, 900000)
	drivePSI(t, e, pods, pidsOf(5001))
	if evs := evictActions(e.cs); len(evs) != 1 || evs[0] != "pg-0" {
		t.Fatalf("evictions = %v, want pg-0 (label alone does not exempt)", evs)
	}
}

// TestPSIEvictorEvictionAPIError: a refused eviction (PDB, webhook,
// RBAC) logs suspect and does NOT count the pod_evict action — the
// budget was already spent so the next cycle waits out the cooldown.
func TestPSIEvictorEvictionAPIError(t *testing.T) {
	e := fixture(t)
	thrashEnv(t, e)
	e.cs.PrependReactor("create", "pods",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("pods \"memhog\" is forbidden by pdb")
		})
	pods := []corev1.Pod{*psiPod("memhog", "app", uidA)}
	procRSSProc(t, e, 5001, uidA, 900000)
	drivePSI(t, e, pods, pidsOf(5001))
	if got := logLines(t, e); !strings.Contains(got,
		"evict app/memhog failed") {
		t.Fatalf("missing eviction-failure suspect line:\n%s", got)
	}
	if got := testutil.ToFloat64(
		e.h.actions.WithLabelValues(checkPSIThrash, "pod_evict")); got != 0 {
		t.Fatalf("pod_evict actions = %v, want 0 on API error", got)
	}
}

// --- W9-NM2: orphan CNI netns reaper ---

// netnsFixture points the reaper at a tempdir netns root inside the
// fixture's proc tree (same filesystem → hardlinks work for the
// live-process inode test).
func netnsFixture(t *testing.T, e *env) string {
	t.Helper()
	dir := filepath.Join(e.proc, "netns")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	e.h.cfg.Net.NetnsDir = dir
	return dir
}

// TestOrphanCNINetnsConfirmedThenReaped: an unreferenced cni-* file
// gets a cni-netns-seen-* marker on first sight; only after the
// 30m confirmation window does the reaper umount + remove it.
func TestOrphanCNINetnsConfirmedThenReaped(t *testing.T) {
	e := fixture(t)
	dir := netnsFixture(t, e)
	orphan := filepath.Join(dir, "cni-deadbeef")
	writeFile(t, orphan, "")
	// A non-cni file must never be touched.
	writeFile(t, filepath.Join(dir, "keepme"), "")
	e.sdReply["umount"] = ""

	e.h.checkOrphanCNINetns(context.Background(), pidsOf(), true)
	if _, err := os.Stat(filepath.Join(e.state, "cni-netns-seen-cni-deadbeef")); err != nil {
		t.Fatal("no confirmation marker on first sight")
	}
	if e.sdRan("umount") {
		t.Fatal("umount ran before the confirmation window")
	}
	if _, err := os.Stat(orphan); err != nil {
		t.Fatal("orphan file removed before confirmation")
	}

	// Inside the window: still no reap.
	e.now = e.now.Add(15 * time.Minute)
	e.h.checkOrphanCNINetns(context.Background(), pidsOf(), true)
	if e.sdRan("umount") {
		t.Fatal("umount inside the 30m window")
	}

	// Past the window: lazy umount + file removal + marker cleanup.
	e.now = e.now.Add(16 * time.Minute)
	e.h.checkOrphanCNINetns(context.Background(), pidsOf(), true)
	if !e.sdRan("umount -l /run/netns/cni-deadbeef") {
		t.Fatalf("no lazy umount of the orphan; sdcmds=%v", e.sdcmds)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatal("orphan netns file not removed")
	}
	if _, err := os.Stat(filepath.Join(e.state, "cni-netns-seen-cni-deadbeef")); !os.IsNotExist(err) {
		t.Fatal("confirmation marker not cleaned after reap")
	}
	if _, err := os.Stat(filepath.Join(dir, "keepme")); err != nil {
		t.Fatal("non-cni file was touched")
	}
	logs := logLines(t, e)
	if !strings.Contains(logs, "reaped orphan netns cni-deadbeef") {
		t.Fatalf("missing reap ACTION line:\n%s", logs)
	}
}

// TestOrphanCNINetnsLiveProcessProtected: a cni-* file whose nsfs
// inode is still referenced by a live process's /proc/<pid>/ns/net
// is NEVER a candidate — the marker is actively pruned so a later
// orphan episode re-arms the full window.
func TestOrphanCNINetnsLiveProcessProtected(t *testing.T) {
	e := fixture(t)
	dir := netnsFixture(t, e)
	live := filepath.Join(dir, "cni-live0000")
	writeFile(t, live, "")
	// proc/7001/ns/net hardlinks the same inode — the namespace is
	// still in use.
	nsdir := filepath.Join(e.proc, "7001", "ns")
	if err := os.MkdirAll(nsdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(live, filepath.Join(nsdir, "net")); err != nil {
		t.Fatalf("hardlink netns: %v", err)
	}
	e.sdReply["umount"] = ""

	for i := 0; i < 3; i++ {
		e.h.checkOrphanCNINetns(context.Background(), pidsOf(7001), true)
		e.now = e.now.Add(20 * time.Minute)
	}
	if e.sdRan("umount") {
		t.Fatal("umount ran on a live-referenced netns")
	}
	if _, err := os.Stat(filepath.Join(e.state, "cni-netns-seen-cni-live0000")); !os.IsNotExist(err) {
		t.Fatal("marker armed for a live-referenced netns")
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatal("live netns file removed")
	}
}

// TestOrphanCNINetnsUmountFailureKeepsMarker: a failed umount keeps
// the confirmation marker and the file — the next cycle retries
// rather than losing the reap.
func TestOrphanCNINetnsUmountFailureKeepsMarker(t *testing.T) {
	e := fixture(t)
	dir := netnsFixture(t, e)
	orphan := filepath.Join(dir, "cni-retryme")
	writeFile(t, orphan, "")
	// No sdReply["umount"] → the fake returns ENOENT.

	e.h.checkOrphanCNINetns(context.Background(), pidsOf(), true)
	e.now = e.now.Add(31 * time.Minute)
	e.h.checkOrphanCNINetns(context.Background(), pidsOf(), true)
	if _, err := os.Stat(filepath.Join(e.state, "cni-netns-seen-cni-retryme")); err != nil {
		t.Fatal("marker dropped on umount failure")
	}
	if _, err := os.Stat(orphan); err != nil {
		t.Fatal("file removed on umount failure")
	}
	if got := logLines(t, e); !strings.Contains(got, "umount /run/netns/cni-retryme failed") {
		t.Fatalf("missing umount-failure suspect line:\n%s", got)
	}

	// The retry succeeds once systemd answers.
	e.sdReply["umount"] = ""
	e.now = e.now.Add(31 * time.Minute)
	e.h.checkOrphanCNINetns(context.Background(), pidsOf(), true)
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatal("orphan not reaped on retry")
	}
}

// TestOrphanCNINetnsMissingDirAndMarkers: a missing netns dir is a
// quiet ok cycle, and markers whose files vanished are pruned.
func TestOrphanCNINetnsMissingDirAndMarkers(t *testing.T) {
	e := fixture(t)
	// NetnsDir defaults to /host/run/netns — nonexistent here.
	writeFile(t, filepath.Join(e.state, "cni-netns-seen-ghost"), "1\n")
	e.h.checkOrphanCNINetns(context.Background(), pidsOf(), true)
	if _, err := os.Stat(filepath.Join(e.state, "cni-netns-seen-ghost")); !os.IsNotExist(err) {
		t.Fatal("stale marker not pruned when the netns file is gone")
	}
}

// TestOrphanCNINetnsReappearedResetsWindow: a file that vanished and
// came back (fresh CNI sandbox reusing the name) re-arms the full
// confirmation window — the marker is only valid for the SAME inode
// episode.
func TestOrphanCNINetnsReappearedResetsWindow(t *testing.T) {
	e := fixture(t)
	dir := netnsFixture(t, e)
	p := filepath.Join(dir, "cni-recycle")
	writeFile(t, p, "")
	e.sdReply["umount"] = ""

	e.h.checkOrphanCNINetns(context.Background(), pidsOf(), true)
	// File vanishes; marker pruned on the next scan.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	e.h.checkOrphanCNINetns(context.Background(), pidsOf(), true)
	if _, err := os.Stat(filepath.Join(e.state, "cni-netns-seen-cni-recycle")); !os.IsNotExist(err) {
		t.Fatal("stale marker survived the file's disappearance")
	}
	// A NEW file with the same name starts a fresh window.
	writeFile(t, p, "")
	e.now = e.now.Add(31 * time.Minute)
	e.h.checkOrphanCNINetns(context.Background(), pidsOf(), true)
	if e.sdRan("umount") {
		t.Fatal("reaped a reappeared netns without a fresh confirmation")
	}
	if _, err := os.Stat(filepath.Join(e.state, "cni-netns-seen-cni-recycle")); err != nil {
		t.Fatal("fresh marker not armed for the reappeared file")
	}
}

// --- W9-NM4: containerd content-store prune ---

// TestCtrIngestGCContentPruneAboveWatermark: above the disk high
// watermark the store-wide `content prune` fires on its own 6h
// budget — in addition to the stale-ingest sweep.
func TestCtrIngestGCContentPruneAboveWatermark(t *testing.T) {
	e := fixture(t)
	e.diskUsed = 0.80
	prunes := 0
	e.h.cfg.Seams.ctrPruneContent = func(context.Context) error {
		prunes++
		return nil
	}

	e.h.checkCtrIngestGC(context.Background(), true)
	if prunes != 1 {
		t.Fatalf("content prunes = %d, want 1 above the watermark", prunes)
	}
	if got := logLines(t, e); !strings.Contains(got, "content prune ran") {
		t.Fatalf("missing prune ACTION line:\n%s", got)
	}

	// Inside the 6h budget a second high-watermark cycle does NOT
	// re-prune — the walk is too heavy to run every cycle.
	e.h.checkCtrIngestGC(context.Background(), true)
	if prunes != 1 {
		t.Fatalf("content prunes inside the budget = %d, want 1", prunes)
	}

	// Past the budget it fires again.
	e.now = e.now.Add(7 * time.Hour)
	e.h.checkCtrIngestGC(context.Background(), true)
	if prunes != 2 {
		t.Fatalf("content prunes past the budget = %d, want 2", prunes)
	}
}

// TestCtrIngestGCNoPruneBelowWatermark: under the watermark the
// periodic ingest rescan still runs but the store prune never does.
func TestCtrIngestGCNoPruneBelowWatermark(t *testing.T) {
	e := fixture(t)
	e.diskUsed = 0.50
	prunes := 0
	e.h.cfg.Seams.ctrPruneContent = func(context.Context) error {
		prunes++
		return nil
	}
	e.h.checkCtrIngestGC(context.Background(), true)
	if prunes != 0 {
		t.Fatalf("content prunes below the watermark = %d, want 0", prunes)
	}
}

// TestCtrIngestGCPruneFailureSuspect: a failed prune logs suspect
// and does NOT count the content_gc action — the budget stays
// spent (rate_spend parity) so a wedged ctr does not spin.
func TestCtrIngestGCPruneFailureSuspect(t *testing.T) {
	e := fixture(t)
	e.diskUsed = 0.80
	e.h.cfg.Seams.ctrPruneContent = func(context.Context) error {
		return errors.New("ctr content prune: exit status 1")
	}
	e.h.checkCtrIngestGC(context.Background(), true)
	if got := logLines(t, e); !strings.Contains(got, "content prune failed") {
		t.Fatalf("missing prune-failure suspect line:\n%s", got)
	}
	if got := testutil.ToFloat64(
		e.h.actions.WithLabelValues(checkIngestGC, "content_gc")); got != 0 {
		t.Fatalf("content_gc actions = %v, want 0 on prune failure", got)
	}
	// Budget spent → an immediate retry does not re-run the prune.
	calls := 0
	e.h.cfg.Seams.ctrPruneContent = func(context.Context) error {
		calls++
		return nil
	}
	e.h.checkCtrIngestGC(context.Background(), true)
	if calls != 0 {
		t.Fatalf("prune retried inside the budget (%d calls)", calls)
	}
}

// --- W9-NM1 (worker side): cilium_wg0 double-encap MTU guard ---

// TestCiliumMTUWG0DriftLatches: cilium_wg0 above nebula−60 latches
// cilium-mtu-drift even with NO cilium_net datapath — the wg0 path
// alone can blackhole under double encapsulation.
func TestCiliumMTUWG0DriftLatches(t *testing.T) {
	e := fixture(t)
	writeFile(t, filepath.Join(e.sysnet, "neb1", "mtu"), "1300\n")
	writeFile(t, filepath.Join(e.sysnet, "cilium_wg0", "mtu"), "1250\n")
	// cilium_net absent AND no runtime config → wg0 is the only vote.
	e.h.checkCiliumMTU(true)
	if !e.h.state.Exists("cilium-mtu-drift") {
		t.Fatal("no cilium-mtu-drift latch for wg0=1250 > 1300-60")
	}
	if got := logLines(t, e); !strings.Contains(got,
		"ACTION cilium-mtu-drift: cilium_wg0=1250 nebula=1300") {
		t.Fatalf("missing wg0 drift ACTION line:\n%s", got)
	}
}

// TestCiliumMTUWG0Boundary: wg0 == neb−60 is exactly at budget (no
// drift); wg0 == neb−59 exceeds it.
func TestCiliumMTUWG0Boundary(t *testing.T) {
	e := fixture(t)
	writeFile(t, filepath.Join(e.sysnet, "neb1", "mtu"), "1300\n")
	writeFile(t, filepath.Join(e.sysnet, "cilium_wg0", "mtu"), "1240\n")
	e.h.checkCiliumMTU(true)
	if e.h.state.Exists("cilium-mtu-drift") {
		t.Fatal("drift latched at exactly neb-60")
	}
	writeFile(t, filepath.Join(e.sysnet, "cilium_wg0", "mtu"), "1241\n")
	e.h.checkCiliumMTU(true)
	if !e.h.state.Exists("cilium-mtu-drift") {
		t.Fatal("no drift at neb-59")
	}
}

// TestCiliumMTUAbsentDatapathsNoVote: with nebula up but NEITHER
// datapath iface resolvable there is nothing to compare — no latch.
func TestCiliumMTUAbsentDatapathsNoVote(t *testing.T) {
	e := fixture(t)
	writeFile(t, filepath.Join(e.sysnet, "neb1", "mtu"), "1300\n")
	e.h.checkCiliumMTU(true)
	if e.h.state.Exists("cilium-mtu-drift") {
		t.Fatal("drift latched with no datapath MTU resolved")
	}
}

// TestCiliumMTUCiliumNetStillWins: when BOTH datapaths drift the
// cilium_net verdict is reported first (the primary datapath).
func TestCiliumMTUCiliumNetStillWins(t *testing.T) {
	e := fixture(t)
	writeFile(t, filepath.Join(e.sysnet, "neb1", "mtu"), "1300\n")
	writeFile(t, filepath.Join(e.sysnet, "cilium_net", "mtu"), "1400\n")
	writeFile(t, filepath.Join(e.sysnet, "cilium_wg0", "mtu"), "1290\n")
	e.h.checkCiliumMTU(true)
	if got := logLines(t, e); !strings.Contains(got,
		"ACTION cilium-mtu-drift: cilium_net=1400 nebula=1300") {
		t.Fatalf("cilium_net drift line missing (wg0 also drifts):\n%s", got)
	}
}
