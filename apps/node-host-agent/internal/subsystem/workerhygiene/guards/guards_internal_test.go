// guards_internal_test.go — package-internal coverage for the
// unexported guard helpers the external guards_test suites can only
// reach through full Cycles: the PSI thrash eviction helpers
// (pod memory.current, victim ranking, kernel slab-leak guard), the D-state
// wchan/comm classifiers and the calico orphan-veth GC.
package guards

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// gDeps builds a minimal *wdeps.Deps over the shared fixture — the
// same construction workerhygiene.New does, minus the parent
// package (importing it here would cycle).
func gDeps(t *testing.T) (*wdeps.Deps, *wdepstest.Fixture) {
	t.Helper()
	f := wdepstest.New(t)
	cfg := f.Cfg
	cfg.ApplyDefaults()
	// Isolate the cgroup-v2 root — pod memory.current fixtures are
	// planted under it and the real /sys/fs/cgroup must never be
	// touched by a unit test.
	cfg.Runtime.CgroupRoot = filepath.Join(t.TempDir(), "cgroup")
	d := &wdeps.Deps{
		Cfg:  cfg,
		Proc: procfs.New(cfg.ProcRoot),
		State: subframe.StoreAt(cfg.WatchdogStateDir, cfg.WatchdogLogFile,
			cfg.Seams.Host.Clock,
			func() *slog.Logger {
				return slog.New(slog.NewTextHandler(io.Discard, nil))
			}),
	}
	d.Cycles, d.Actions = subframe.Counters("guards-test",
		"test cycles", "test actions")
	f.Bind(d)
	return d, f
}

// mkPodMemProc plants /proc/<pid>/cgroup attributing pid to a pod
// uid plus the pod cgroup's memory.current under CgroupRoot — the
// kernel-accounted footprint highestRSSPod ranks victims by. memKB
// is the pod total in kB (memory.current bytes = memKB<<10).
func mkPodMemProc(t *testing.T, d *wdeps.Deps, pid int, uid string, memKB int64) {
	t.Helper()
	pdir := filepath.Join(d.Cfg.ProcRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(pdir, 0o755); err != nil {
		t.Fatal(err)
	}
	podComp := "kubepods-burstable-pod" + strings.ReplaceAll(uid, "-", "_") + ".slice"
	cg := "0::/kubepods.slice/kubepods-burstable.slice/" + podComp + "/cri-containerd-x.scope\n"
	if err := os.WriteFile(filepath.Join(pdir, "cgroup"), []byte(cg), 0o644); err != nil {
		t.Fatal(err)
	}
	cgdir := filepath.Join(d.Cfg.Runtime.CgroupRoot,
		"kubepods.slice", "kubepods-burstable.slice", podComp)
	if err := os.MkdirAll(cgdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgdir, "memory.current"),
		[]byte(strconv.FormatInt(memKB<<10, 10)), 0o644); err != nil {
		t.Fatal(err)
	}
}

// --- psi_thrash.go ---

func TestPodCgroupRelAndMemoryCurrent(t *testing.T) {
	d, _ := gDeps(t)
	mkPodMemProc(t, d, 500, wdepstest.UIDA, 100)
	rel := podCgroupRel(d, 500, wdepstest.UIDA)
	want := "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" +
		strings.ReplaceAll(wdepstest.UIDA, "-", "_") + ".slice"
	if rel != want {
		t.Fatalf("podCgroupRel=%q want %q", rel, want)
	}
	if got := podMemoryCurrent(d, rel); got != 100<<10 {
		t.Fatalf("podMemoryCurrent=%d want %d", got, 100<<10)
	}
	// Missing cgroup dir and empty rel both report 0 — the fail-
	// closed "below the floor" value.
	if got := podMemoryCurrent(d, "kubepods.slice/nope.slice"); got != 0 {
		t.Fatalf("podMemoryCurrent missing=%d want 0", got)
	}
	if got := podMemoryCurrent(d, ""); got != 0 {
		t.Fatalf("podMemoryCurrent empty=%d want 0", got)
	}
	if got := podCgroupRel(d, 424242, wdepstest.UIDA); got != "" {
		t.Fatalf("podCgroupRel missing pid=%q want empty", got)
	}
}

func TestOwnedByStatefulSet(t *testing.T) {
	p := &corev1.Pod{}
	if wdeps.OwnedByStatefulSet(p) {
		t.Fatal("no ownerReferences must be false")
	}
	p.OwnerReferences = []metav1.OwnerReference{{Kind: "ReplicaSet"}}
	if wdeps.OwnedByStatefulSet(p) {
		t.Fatal("ReplicaSet owner must be false")
	}
	p.OwnerReferences = append(p.OwnerReferences, metav1.OwnerReference{Kind: "StatefulSet"})
	if !wdeps.OwnedByStatefulSet(p) {
		t.Fatal("StatefulSet owner must be true")
	}
	// Database-operator owner kinds count too — CNPG Cluster,
	// Dragonfly, Scylla, Percona PGv2/PSMDB/PXC pods are never the
	// preferred eviction tier.
	for _, kind := range []string{
		"Cluster", "Dragonfly", "ScyllaCluster", "ScyllaDBDatacenter",
		"PerconaServerMongoDB", "PerconaXtraDBCluster", "PerconaPGCluster",
	} {
		q := &corev1.Pod{OwnerReferences: []metav1.OwnerReference{{Kind: kind}}}
		if !wdeps.OwnedByStatefulSet(q) {
			t.Fatalf("owner kind %s must be true", kind)
		}
	}
}

func TestCarriesDBQuorumLabel(t *testing.T) {
	for name, tc := range map[string]struct {
		labels map[string]string
		want   bool
	}{
		"none":             {labels: map[string]string{"app": "web"}, want: false},
		"value match":      {labels: map[string]string{"app": "rabbitmq-server"}, want: true},
		"key match":        {labels: map[string]string{"app.kubernetes.io/scylla": "yes"}, want: true},
		"case-insensitive": {labels: map[string]string{"DB": "PostgreSQL"}, want: true},
		"cnpg instanceRole": {labels: map[string]string{
			"cnpg.io/cluster": "pg", "cnpg.io/instanceRole": "primary"}, want: true},
		"crunchy role": {labels: map[string]string{
			"postgres-operator.crunchydata.com/role": "master"}, want: true},
		// Union semantics (wdeps.DBQuorumTokens): the bare
		// cnpg.io/cluster label every CNPG pod carries matches the
		// "cnpg" token — disk-bloat always protected it, psi now
		// does too.
		"cnpg cluster label alone is quorum": {labels: map[string]string{
			"cnpg.io/cluster": "pg"}, want: true},
	} {
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Labels: tc.labels}}
		if got := wdeps.CarriesDBQuorumLabel(p); got != tc.want {
			t.Fatalf("%s: carriesDBQuorumLabel=%v want %v", name, got, tc.want)
		}
	}
}

func psiPod(name, ns, uid, qos string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			UID:       types.UID(uid),
		},
		Status: corev1.PodStatus{QOSClass: corev1.PodQOSClass(qos)},
	}
}

func TestHighestRSSPodTiersAndRails(t *testing.T) {
	big := int64(1 << 20) // 1 GiB in kB — above the 512 MiB floor
	small := int64(1)     // far below the floor

	// Preferred (Burstable, not StatefulSet) vs fallback (Guaranteed):
	// the preferred tier wins even when the fallback pod's RSS is bigger.
	d1, _ := gDeps(t)
	mkPodMemProc(t, d1, 11, wdepstest.UIDA, big/2)
	mkPodMemProc(t, d1, 12, wdepstest.UIDB, big)
	preferred := psiPod("pref", "app", wdepstest.UIDA, string(corev1.PodQOSBurstable))
	fallback := psiPod("guar", "app", wdepstest.UIDB, string(corev1.PodQOSGuaranteed))
	victim, mem := highestRSSPod(d1, []corev1.Pod{preferred, fallback}, []int{11, 12})
	if victim == nil || victim.Name != "pref" {
		t.Fatalf("victim=%v want preferred tier pod pref", victim)
	}
	if mem != big/2<<10 {
		t.Fatalf("mem=%d want %d", mem, big/2<<10)
	}

	// Below the floor everywhere → no victim at all.
	d2, _ := gDeps(t)
	mkPodMemProc(t, d2, 21, wdepstest.UIDA, small)
	victim, mem = highestRSSPod(d2, []corev1.Pod{psiPod("tiny", "app", wdepstest.UIDA, "")}, []int{21})
	if victim != nil || mem != 0 {
		t.Fatalf("below-floor victim=%v mem=%d want nil/0", victim, mem)
	}

	// Excluded namespaces / critical priority classes / terminating
	// pods / db-quorum pods are never victims.
	d3, _ := gDeps(t)
	mkPodMemProc(t, d3, 31, wdepstest.UIDA, big)
	sys := psiPod("sys", "kube-system", wdepstest.UIDA, "")
	victim, _ = highestRSSPod(d3, []corev1.Pod{sys}, []int{31})
	if victim != nil {
		t.Fatal("kube-system pod must never be a victim")
	}

	crit := psiPod("crit", "app", wdepstest.UIDA, "")
	crit.Spec.PriorityClassName = "system-node-critical"
	victim, _ = highestRSSPod(d3, []corev1.Pod{crit}, []int{31})
	if victim != nil {
		t.Fatal("system-node-critical pod must never be a victim")
	}

	term := psiPod("term", "app", wdepstest.UIDA, "")
	now := metav1.Now()
	term.DeletionTimestamp = &now
	victim, _ = highestRSSPod(d3, []corev1.Pod{term}, []int{31})
	if victim != nil {
		t.Fatal("terminating pod must never be a victim")
	}

	quorum := psiPod("db", "scylla", wdepstest.UIDA, string(corev1.PodQOSGuaranteed))
	quorum.OwnerReferences = []metav1.OwnerReference{{Kind: "StatefulSet"}}
	quorum.Labels = map[string]string{"app": "scylla"}
	victim, _ = highestRSSPod(d3, []corev1.Pod{quorum}, []int{31})
	if victim != nil {
		t.Fatal("db-quorum pod must never be a victim")
	}

	// CNPG pod — owner Kind "Cluster" (postgresql.cnpg.io) with the
	// cnpg.io/instanceRole label — is excluded by the independent
	// carriesDBQuorumLabel gate even though its namespace is not on
	// the excluded list.
	cnpg := psiPod("pg-primary", "database", wdepstest.UIDA,
		string(corev1.PodQOSBurstable))
	cnpg.OwnerReferences = []metav1.OwnerReference{{Kind: "Cluster"}}
	cnpg.Labels = map[string]string{
		"cnpg.io/cluster": "pg", "cnpg.io/instanceRole": "primary"}
	if evictablePodOnNode(&cnpg) {
		t.Fatal("CNPG primary pod must not be evictable")
	}
	if wdeps.OwnedByStatefulSet(&cnpg) != true {
		t.Fatal("CNPG Cluster owner must count as stateful-owned")
	}
	victim, _ = highestRSSPod(d3, []corev1.Pod{cnpg}, []int{31})
	if victim != nil {
		t.Fatal("CNPG pod must never be a victim")
	}

	// A db-quorum pod NOT owned by any stateful kind is still
	// excluded — the label gate is independent of ownerReferences.
	loose := psiPod("loose-db", "app", wdepstest.UIDA, "")
	loose.Labels = map[string]string{
		"postgres-operator.crunchydata.com/role": "replica"}
	if evictablePodOnNode(&loose) {
		t.Fatal("crunchy-role pod must not be evictable without owner refs")
	}
	victim, _ = highestRSSPod(d3, []corev1.Pod{loose}, []int{31})
	if victim != nil {
		t.Fatal("unowned db-quorum pod must never be a victim")
	}

	// No pids → no victim.
	victim, _ = highestRSSPod(d3, []corev1.Pod{psiPod("p", "app", wdepstest.UIDA, "")}, nil)
	if victim != nil {
		t.Fatal("no pids must yield no victim")
	}
}

func TestGuardKernelSlabLeakEnterClearHysteresis(t *testing.T) {
	d, _ := gDeps(t)
	latch := latchdefs.LatchKernelSlabLeak

	// Ratio 0.30 — between enter (>0.35) and clear (<=0.25): no
	// latch, no action.
	if guardKernelSlabLeak(d, memInfo{totalKB: 1000, slabUnrecKB: 300, parsed: true}) {
		t.Fatal("hysteresis band must not latch")
	}
	if d.State.Exists(latch) {
		t.Fatal("no latch expected in hysteresis band")
	}

	// 0.40 — enter: latched, drop_caches budget spent → write lands.
	drop := filepath.Join(d.Cfg.ProcRoot, "sys", "vm", "drop_caches")
	if err := os.MkdirAll(filepath.Dir(drop), 0o755); err != nil {
		t.Fatal(err)
	}
	if !guardKernelSlabLeak(d, memInfo{totalKB: 1000, slabUnrecKB: 400, parsed: true}) {
		t.Fatal("enter ratio must hold the latch")
	}
	if !d.State.Exists(latch) {
		t.Fatal("kernel-slab-leak latch missing after enter")
	}
	data, err := os.ReadFile(drop)
	if err != nil || strings.TrimSpace(string(data)) != "2" {
		t.Fatalf("drop_caches=%q err=%v want 2", data, err)
	}

	// Refresh while latched keeps the latch (budget now spent — no
	// second write this hour).
	if err := os.Remove(drop); err != nil {
		t.Fatal(err)
	}
	if !guardKernelSlabLeak(d, memInfo{totalKB: 1000, slabUnrecKB: 400, parsed: true}) {
		t.Fatal("latched entry must stay held")
	}
	if _, err := os.Stat(drop); !os.IsNotExist(err) {
		t.Fatal("drop_caches must not re-run inside the 1h budget")
	}

	// 0.30 while latched — hysteresis keeps the latch held.
	if !guardKernelSlabLeak(d, memInfo{totalKB: 1000, slabUnrecKB: 300, parsed: true}) {
		t.Fatal("hysteresis band must keep a live latch")
	}

	// 0.20 — clear.
	if guardKernelSlabLeak(d, memInfo{totalKB: 1000, slabUnrecKB: 200, parsed: true}) {
		t.Fatal("clear ratio must drop the latch")
	}
	if d.State.Exists(latch) {
		t.Fatal("kernel-slab-leak latch must be exited on clear")
	}
}

func TestDropKernelCachesSuccessAndFailure(t *testing.T) {
	// Success: the "2" write lands and the action counter bumps.
	d, _ := gDeps(t)
	drop := filepath.Join(d.Cfg.ProcRoot, "sys", "vm", "drop_caches")
	if err := os.MkdirAll(filepath.Dir(drop), 0o755); err != nil {
		t.Fatal(err)
	}
	dropKernelCaches(d)
	data, err := os.ReadFile(drop)
	if err != nil || strings.TrimSpace(string(data)) != "2" {
		t.Fatalf("drop_caches=%q err=%v want 2", data, err)
	}

	// Failure: the vm dir is absent → suspect line, no counter.
	d2, _ := gDeps(t)
	dropKernelCaches(d2) // <ProcRoot>/sys/vm absent → WriteFile fails
	logData, rerr := os.ReadFile(d2.Cfg.WatchdogLogFile)
	if rerr != nil || !strings.Contains(string(logData), "suspect: kernel-slab-leak drop_caches write") {
		t.Fatalf("want suspect line in watchdog log, err=%v log=%q", rerr, logData)
	}
}

func TestPsiMemoryFullAvg60(t *testing.T) {
	d, _ := gDeps(t)
	psiPath := filepath.Join(d.Cfg.ProcRoot, "pressure", "memory")

	// Missing file — PSI disabled / unreadable procfs → not ok.
	if v, ok := psiMemoryFullAvg60(d); ok || v != 0 {
		t.Fatalf("missing pressure file: got %v,%v want 0,false", v, ok)
	}

	write := func(body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(psiPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(psiPath, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// some-line only, no full row → not ok.
	write("some avg10=1.00 avg60=9.99 avg300=0.10 total=1\n")
	if _, ok := psiMemoryFullAvg60(d); ok {
		t.Fatal("some-only PSI file must not report ok")
	}

	// full row present — avg60 extracted, some's avg60 ignored.
	write("some avg10=0.10 avg60=9.99 avg300=0.10 total=1\n" +
		"full avg10=0.20 avg60=26.10 avg300=0.30 total=2\n")
	if v, ok := psiMemoryFullAvg60(d); !ok || v != 26.10 {
		t.Fatalf("psiMemoryFullAvg60=%v,%v want 26.10,true", v, ok)
	}

	// Malformed avg60 on the full row → not ok (no silent 0).
	write("full avg10=0.20 avg60=bogus avg300=0.30 total=2\n")
	if _, ok := psiMemoryFullAvg60(d); ok {
		t.Fatal("unparseable avg60 must not report ok")
	}
}

func TestReadMeminfo(t *testing.T) {
	d, _ := gDeps(t)
	memPath := filepath.Join(d.Cfg.ProcRoot, "meminfo")

	// Missing file → parsed=false.
	if m := readMeminfo(d); m.parsed {
		t.Fatal("missing meminfo must not parse")
	}

	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(memPath, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write("MemTotal:       16384000 kB\n" +
		"MemFree:         1024000 kB\n" +
		"MemAvailable:    8192000 kB\n" +
		"SUnreclaim:       512000 kB\n" +
		"PageTables:        64000 kB\n" +
		"SecPageTables:      8000 kB\n")
	m := readMeminfo(d)
	if !m.parsed || m.totalKB != 16384000 || m.availKB != 8192000 ||
		m.slabUnrecKB != 512000 || m.pageTablesKB != 72000 {
		t.Fatalf("readMeminfo=%+v want parsed totals/slab/pageTables", m)
	}

	// Missing MemAvailable → unreadable.
	write("MemTotal:       16384000 kB\nSUnreclaim:       512000 kB\n")
	if m := readMeminfo(d); m.parsed {
		t.Fatal("meminfo without MemAvailable must not parse")
	}

	// Zero MemTotal → unreadable (division-by-zero guard upstream).
	write("MemTotal:             0 kB\nMemAvailable:    8192000 kB\n")
	if m := readMeminfo(d); m.parsed {
		t.Fatal("zero MemTotal must not parse")
	}
}

// --- dstate_scopes.go ---

func TestProcWchan(t *testing.T) {
	d, _ := gDeps(t)
	pdir := filepath.Join(d.Cfg.ProcRoot, "900")
	if err := os.MkdirAll(pdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pdir, "wchan"),
		[]byte("wait_transaction_locked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := procWchan(d, 900); got != "wait_transaction_locked" {
		t.Fatalf("procWchan=%q want kernel function", got)
	}
	if err := os.WriteFile(filepath.Join(pdir, "wchan"), []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := procWchan(d, 900); got != "" {
		t.Fatalf("procWchan running task=%q want empty", got)
	}
	if got := procWchan(d, 901); got != "" {
		t.Fatalf("procWchan missing file=%q want empty", got)
	}
}

func TestDstateRuntimeComm(t *testing.T) {
	for comm, want := range map[string]bool{
		"runc":            true,
		"containerd":      true,
		"containerd-shim": true,
		"k0s":             true,
		"kubelet":         true,
		"btrfs-":          true,
		"jbd2/vda1-8":     true,
		"bash":            false,
		"sleep":           false,
		"":                false,
	} {
		if got := DstateRuntimeComm(comm); got != want {
			t.Fatalf("DstateRuntimeComm(%q)=%v want %v", comm, got, want)
		}
	}
}

// --- calico.go ---

func TestGcCalicoOrphanVeths(t *testing.T) {
	d, f := gDeps(t)
	ctx := context.Background()
	ifaceDir := filepath.Join(d.Cfg.SysClassNet, "cali1234")
	if err := os.MkdirAll(ifaceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ifaceDir, "carrier"), []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The link-delete seam fails by default injection — the
	// delete-failure path logs suspect and keeps the marker.
	f.LinkDelErrs = map[string]error{"cali1234": errors.New("netlink denied")}
	gcCalicoOrphanVeths(d, ctx)
	marker := filepath.Join(d.Cfg.WatchdogStateDir, "veth-seen-cali1234")
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("candidate marker missing after first pass: %v", err)
	}

	// Age the marker past calicoVethGCMinAge with no link-delete
	// client → the skip-delete guard keeps the marker.
	f.Now = f.Now.Add(time.Hour)
	d.Cfg.Seams.Host.LinkDelFn = nil // no-client guard: skip delete, keep marker
	gcCalicoOrphanVeths(d, ctx)
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("no-client pass must keep the marker (skip delete)")
	}

	// Re-arm the seam with a failing delete — the suspect path
	// keeps the marker for the next cycle.
	f.Now = f.Now.Add(time.Hour)
	d.Cfg.Seams.Host.LinkDelFn = func(name string) error {
		return errors.New("netlink denied")
	}
	gcCalicoOrphanVeths(d, ctx)
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("failed delete must keep the marker")
	}
}

func TestGcCalicoOrphanVethsDeletesViaLinkDel(t *testing.T) {
	d, f := gDeps(t)
	ctx := context.Background()
	ifaceDir := filepath.Join(d.Cfg.SysClassNet, "caliabcd")
	if err := os.MkdirAll(ifaceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ifaceDir, "carrier"), []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gcCalicoOrphanVeths(d, ctx) // candidate + marker
	f.Now = f.Now.Add(time.Hour)
	gcCalicoOrphanVeths(d, ctx) // confirmed → link delete + prune
	if !f.LinkDelRan("caliabcd") {
		t.Fatal("confirmed orphan veth must be deleted via LinkDelFn")
	}
	if _, err := os.Stat(filepath.Join(d.Cfg.WatchdogStateDir,
		"veth-seen-caliabcd")); !os.IsNotExist(err) {
		t.Fatal("marker must be pruned after deletion")
	}

	// A live (carrier 1) veth's stale marker is pruned without exec.
	liveDir := filepath.Join(d.Cfg.SysClassNet, "calilive")
	if err := os.MkdirAll(liveDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(liveDir, "carrier"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(d.Cfg.WatchdogStateDir, "veth-seen-calilive")
	if err := os.WriteFile(stale, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gcCalicoOrphanVeths(d, ctx)
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("live veth must clear the stale marker")
	}

	// Markers for vanished ifaces are pruned.
	gone := filepath.Join(d.Cfg.WatchdogStateDir, "veth-seen-caligone")
	if err := os.WriteFile(gone, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gcCalicoOrphanVeths(d, ctx)
	if _, err := os.Stat(gone); !os.IsNotExist(err) {
		t.Fatal("marker for vanished iface must be pruned")
	}
}

// --- calico.go: checkWireguardCali (calico-wireguard-datapath-guard) ---

// wgIface writes the wireguard.cali sysfs pair the detector reads.
func wgIface(t *testing.T, d *wdeps.Deps, operstate, carrier string) {
	t.Helper()
	dir := filepath.Join(d.Cfg.SysClassNet, "wireguard.cali")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if operstate != "" {
		wdepstest.WriteFile(t, filepath.Join(dir, "operstate"), operstate+"\n")
	}
	if carrier != "" {
		wdepstest.WriteFile(t, filepath.Join(dir, "carrier"), carrier+"\n")
	}
}

func TestCheckWireguardCaliAbsentAndHealthy(t *testing.T) {
	d, _ := gDeps(t)
	c := &CalicoCheck{d: d}
	ctx := context.Background()

	// No wireguard.cali dir — not a Calico-WireGuard node, not a
	// fault; the streak stays cleared.
	c.checkWireguardCali(ctx, nil)
	if c.wgFails != 0 {
		t.Fatalf("absent iface wgFails=%d want 0", c.wgFails)
	}

	// operstate=up + carrier=1 — the datapath is alive.
	wgIface(t, d, "up", "1")
	c.checkWireguardCali(ctx, nil)
	if c.wgFails != 0 {
		t.Fatalf("healthy iface wgFails=%d want 0", c.wgFails)
	}

	// Neither sysfs file readable — inconclusive: the streak is
	// kept untouched rather than reset on a partial read.
	if err := os.RemoveAll(filepath.Join(d.Cfg.SysClassNet, "wireguard.cali")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(d.Cfg.SysClassNet, "wireguard.cali"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.wgFails = 3 // pre-existing streak must survive the inconclusive read
	c.checkWireguardCali(ctx, nil)
	if c.wgFails != 3 {
		t.Fatalf("unreadable iface wgFails=%d want streak kept at 3", c.wgFails)
	}
}

func TestCheckWireguardCaliStreakAndRemedy(t *testing.T) {
	d, f := gDeps(t)
	c := &CalicoCheck{d: d}
	ctx := context.Background()
	wgIface(t, d, "down", "1")

	// ConsecNeeded=2: the first down read only arms the streak.
	c.checkWireguardCali(ctx, nil)
	if c.wgFails != 1 {
		t.Fatalf("first down read wgFails=%d want 1", c.wgFails)
	}
	// Confirmed down with no Running calico-node pod — diagnose
	// only, no restart possible.
	c.checkWireguardCali(ctx, nil)
	if c.wgFails != 2 {
		t.Fatalf("second down read wgFails=%d want 2", c.wgFails)
	}
	if log := f.LogLines(t); !strings.Contains(log,
		"wireguard.cali down but no Running calico-node pod") {
		t.Fatalf("want no-pod skip line, log=%q", log)
	}

	// carrier=0 alone also counts as down.
	wgIface(t, d, "up", "0")
	// Seed the felix pod in the fake clientset so the delete lands.
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "calico-node-abc", Namespace: "kube-system",
		UID: types.UID("uid-wg")}}
	if _, err := f.CS.CoreV1().Pods("kube-system").Create(
		ctx, pod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	// The remedy delete must carry the pod's UID as its precondition
	// (reactor-captured) — the name-reuse race applies here too.
	gotUID := deleteUIDPrecondition(f)
	// Third confirmed read spends the last-calico-restart budget →
	// ACTION line + pod delete.
	c.checkWireguardCali(ctx, pod)
	if log := f.LogLines(t); !strings.Contains(log,
		"ACTION: calico-hygiene deleted pod kube-system/calico-node-abc"+
			" - wireguard.cali down/no-carrier") {
		t.Fatalf("want ACTION delete line, log=%q", log)
	}
	if gotUID == nil || *gotUID != types.UID("uid-wg") {
		t.Fatalf("wireguard remedy delete precondition UID=%v want uid-wg", gotUID)
	}
	if _, err := f.CS.CoreV1().Pods("kube-system").Get(
		ctx, "calico-node-abc", metav1.GetOptions{}); err == nil {
		t.Fatal("calico-node pod must be deleted by the remedy")
	}

	// The budget is spent — the next confirmed read hits the
	// cooldown skip instead of a second delete.
	c.checkWireguardCali(ctx, pod)
	if log := f.LogLines(t); !strings.Contains(log,
		"wireguard.cali down but pod restart in cooldown") {
		t.Fatalf("want cooldown skip line, log=%q", log)
	}
}

// --- dstate_scopes.go: checkDeactivating (deactivating-unit-detector) ---

func TestCheckDeactivating(t *testing.T) {
	d, f := gDeps(t)
	c := &ScopesCheck{d: d}
	ctx := context.Background()
	ce := &wdeps.CycleEnv{}

	// scopeNamesInState keeps only .scope-suffixed names whose
	// ActiveState or SubState matches — services and units in
	// other states never reach the streak. (Scopes report
	// "deactivating" in SUB while ACTIVE stays "active".)
	units := []systemd.UnitInfo{
		{Name: "cri-containerd-abc123.scope", LoadState: "loaded",
			ActiveState: "active", SubState: "deactivating"},
		{Name: "some.service", LoadState: "loaded",
			ActiveState: "active", SubState: "deactivating"},
		{Name: "cri-containerd-ok.scope", LoadState: "loaded",
			ActiveState: "active", SubState: "running"},
		{Name: "cri-containerd-failed.scope", LoadState: "loaded",
			ActiveState: "failed", SubState: "failed"},
	}
	got := scopeNamesInState(units, "deactivating")
	if len(got) != 1 || got[0] != "cri-containerd-abc123.scope" {
		t.Fatalf("scopeNamesInState deactivating=%v want [cri-containerd-abc123.scope]",
			got)
	}

	// Empty unit set → streak resets. A failed sweep-level
	// list-units aborts in Run before this helper runs, so the
	// streak-kept-on-transport-failure property is structural —
	// TestScopesRunSweepAndReset pins the abort path.
	c.deactStreak = 5
	c.checkDeactivating(ctx, ce, nil)
	if c.deactStreak != 0 {
		t.Fatalf("empty list deactStreak=%d want 0", c.deactStreak)
	}

	// One wedged scope: streak 1 stays silent (alert needs ≥2).
	c.checkDeactivating(ctx, ce, []string{"cri-containerd-abc123.scope"})
	if c.deactStreak != 1 {
		t.Fatalf("first wedged sweep deactStreak=%d want 1", c.deactStreak)
	}
	// Second consecutive sweep → the diagnose-only suspect line.
	c.checkDeactivating(ctx, ce, []string{"cri-containerd-abc123.scope"})
	if c.deactStreak != 2 {
		t.Fatalf("second wedged sweep deactStreak=%d want 2", c.deactStreak)
	}
	if log := f.LogLines(t); !strings.Contains(log,
		"deactivating count=1 streak=2") {
		t.Fatalf("want deactivating suspect line, log=%q", log)
	}
}

// TestReapDeactivatingOrphanedScopes — deactivating-scope-reaper: a cri-containerd
// scope wedged in `deactivating` across ≥2 sweeps whose container
// id belongs to NO Running pod is force-stopped (SIGKILL + stop);
// a scope still owned by a live pod stays diagnose-only.
func TestReapDeactivatingOrphanedScopes(t *testing.T) {
	d, f := gDeps(t)
	c := &ScopesCheck{d: d}
	ctx := context.Background()

	liveID := "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa7777bbbb8888"
	orphanID := "9999deadbeef0000111122223333444455556666777788889999aaaabbbbcccc"
	liveUnit := "cri-containerd-" + liveID + ".scope"
	orphanUnit := "cri-containerd-" + orphanID + ".scope"
	deactUnits := []string{liveUnit, orphanUnit}
	f.SDReply["kill -s SIGKILL"] = ""
	f.SDReply["stop cri-containerd-"] = ""
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "live"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:        "app",
				ContainerID: "containerd://" + liveID,
			}},
		},
	}
	ce := &wdeps.CycleEnv{Pods: []corev1.Pod{*pod}, APIOK: true}

	// Sweep 1 — streak 1, the per-unit ledger is still empty: no reap.
	c.checkDeactivating(ctx, ce, deactUnits)
	if f.SDRan("kill -s SIGKILL") {
		t.Fatal("reaped on the first sighting — needs ≥2 sweeps")
	}
	// Sweep 2 — streak 2: the orphan is SIGKILLed + stopped, the
	// live pod's scope is left alone.
	c.checkDeactivating(ctx, ce, deactUnits)
	if !f.SDRan("kill -s SIGKILL " + orphanUnit) {
		t.Fatal("orphaned scope not SIGKILLed")
	}
	if !f.SDRan("stop " + orphanUnit) {
		t.Fatal("orphaned scope not stopped")
	}
	if f.SDRan("kill -s SIGKILL "+liveUnit) ||
		f.SDRan("stop "+liveUnit) {
		t.Fatal("live pod's scope was reaped — would be a pod kill")
	}
	if log := f.LogLines(t); !strings.Contains(log,
		"deactivating reap unit="+orphanUnit) {
		t.Fatalf("want reap ACTION line, log=%q", log)
	}
}

// --- spegel.go ---

func TestSpegelSocketStale(t *testing.T) {
	podCreated := time.Now().Add(-10 * time.Minute)

	// Missing socket — inconclusive, never a false-positive delete.
	if spegelSocketStale(os.Stat, filepath.Join(t.TempDir(), "absent.sock"), podCreated) {
		t.Fatal("missing socket must report not-stale")
	}

	sock := filepath.Join(t.TempDir(), "containerd.sock")
	if err := os.WriteFile(sock, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Socket older than pod creation + margin → fresh bind-mount.
	old := podCreated.Add(-time.Hour)
	if err := os.Chtimes(sock, old, old); err != nil {
		t.Fatal(err)
	}
	if spegelSocketStale(os.Stat, sock, podCreated) {
		t.Fatal("socket older than pod start must report not-stale")
	}

	// Socket recreated after pod start + margin → stale inode.
	recent := podCreated.Add(spegelSockStaleMargin + time.Minute)
	if err := os.Chtimes(sock, recent, recent); err != nil {
		t.Fatal(err)
	}
	if !spegelSocketStale(os.Stat, sock, podCreated) {
		t.Fatal("socket recreated after pod start must report stale")
	}

	// Exactly at the margin boundary — After is strict → not stale.
	edge := podCreated.Add(spegelSockStaleMargin)
	if err := os.Chtimes(sock, edge, edge); err != nil {
		t.Fatal(err)
	}
	if spegelSocketStale(os.Stat, sock, podCreated) {
		t.Fatal("socket at exactly podCreated+margin must report not-stale")
	}
}
