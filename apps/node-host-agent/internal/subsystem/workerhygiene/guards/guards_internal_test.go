// guards_internal_test.go — package-internal coverage for the
// unexported guard helpers the external guards_test suites can only
// reach through full Cycles: the PSI thrash eviction helpers
// (procRSS, victim ranking, kernel slab-leak guard), the D-state
// wchan/comm classifiers and the calico orphan-veth GC.
package guards

import (
	"context"
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

// mkRSSProc plants /proc/<pid>/{cgroup,status} attributing pid to a
// pod uid with the given VmRSS kB.
func mkRSSProc(t *testing.T, d *wdeps.Deps, pid int, uid string, rssKB int64) {
	t.Helper()
	pdir := filepath.Join(d.Cfg.ProcRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(pdir, 0o755); err != nil {
		t.Fatal(err)
	}
	cg := "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" +
		strings.ReplaceAll(uid, "-", "_") + ".slice/cri-containerd-x.scope\n"
	if err := os.WriteFile(filepath.Join(pdir, "cgroup"), []byte(cg), 0o644); err != nil {
		t.Fatal(err)
	}
	status := "Name:\tx\n"
	if rssKB > 0 {
		status += "VmRSS:\t" + strconv.FormatInt(rssKB, 10) + " kB\n"
	}
	if err := os.WriteFile(filepath.Join(pdir, "status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
}

// --- psi_thrash.go ---

func TestProcRSSReadsKbAsBytes(t *testing.T) {
	d, _ := gDeps(t)
	mkRSSProc(t, d, 500, wdepstest.UIDA, 100)
	if got := procRSS(d, 500); got != 100<<10 {
		t.Fatalf("procRSS=%d want %d", got, 100<<10)
	}
	if got := procRSS(d, 424242); got != 0 {
		t.Fatalf("procRSS on missing pid=%d want 0", got)
	}
}

func TestOwnedByStatefulSet(t *testing.T) {
	p := &corev1.Pod{}
	if ownedByStatefulSet(p) {
		t.Fatal("no ownerReferences must be false")
	}
	p.OwnerReferences = []metav1.OwnerReference{{Kind: "ReplicaSet"}}
	if ownedByStatefulSet(p) {
		t.Fatal("ReplicaSet owner must be false")
	}
	p.OwnerReferences = append(p.OwnerReferences, metav1.OwnerReference{Kind: "StatefulSet"})
	if !ownedByStatefulSet(p) {
		t.Fatal("StatefulSet owner must be true")
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
	} {
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Labels: tc.labels}}
		if got := carriesDBQuorumLabel(p); got != tc.want {
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
	mkRSSProc(t, d1, 11, wdepstest.UIDA, big/2)
	mkRSSProc(t, d1, 12, wdepstest.UIDB, big)
	preferred := psiPod("pref", "app", wdepstest.UIDA, string(corev1.PodQOSBurstable))
	fallback := psiPod("guar", "app", wdepstest.UIDB, string(corev1.PodQOSGuaranteed))
	victim, rss := highestRSSPod(d1, []corev1.Pod{preferred, fallback}, []int{11, 12})
	if victim == nil || victim.Name != "pref" {
		t.Fatalf("victim=%v want preferred tier pod pref", victim)
	}
	if rss != big/2<<10 {
		t.Fatalf("rss=%d want %d", rss, big/2<<10)
	}

	// Below the floor everywhere → no victim at all.
	d2, _ := gDeps(t)
	mkRSSProc(t, d2, 21, wdepstest.UIDA, small)
	victim, rss = highestRSSPod(d2, []corev1.Pod{psiPod("tiny", "app", wdepstest.UIDA, "")}, []int{21})
	if victim != nil || rss != 0 {
		t.Fatalf("below-floor victim=%v rss=%d want nil/0", victim, rss)
	}

	// Excluded namespaces / critical priority classes / terminating
	// pods / StatefulSet+db-quorum pods are never victims.
	d3, _ := gDeps(t)
	mkRSSProc(t, d3, 31, wdepstest.UIDA, big)
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
		t.Fatal("StatefulSet+db-quorum pod must never be a victim")
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
	// The systemd fake fails every argv by default (ENOENT) — the
	// exec-failure path logs suspect and keeps the marker.
	gcCalicoOrphanVeths(d, ctx)
	marker := filepath.Join(d.Cfg.WatchdogStateDir, "veth-seen-cali1234")
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("candidate marker missing after first pass: %v", err)
	}

	// Age the marker past calicoVethGCMinAge with no systemd client →
	// the skip-delete guard keeps the marker.
	f.Now = f.Now.Add(time.Hour)
	d.Cfg.Systemd = nil // no-systemd guard: skip delete, keep marker
	gcCalicoOrphanVeths(d, ctx)
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("no-systemd pass must keep the marker (skip delete)")
	}
}

func TestGcCalicoOrphanVethsDeletesViaSystemd(t *testing.T) {
	d, f := gDeps(t)
	ctx := context.Background()
	f.SDReply["ip link delete"] = ""
	ifaceDir := filepath.Join(d.Cfg.SysClassNet, "caliabcd")
	if err := os.MkdirAll(ifaceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ifaceDir, "carrier"), []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gcCalicoOrphanVeths(d, ctx) // candidate + marker
	f.Now = f.Now.Add(time.Hour)
	gcCalicoOrphanVeths(d, ctx) // confirmed → ip link delete + prune
	if !f.SDRan("ip link delete caliabcd") {
		t.Fatal("confirmed orphan veth must be deleted via systemd")
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

// --- calico.go: checkWireguardCali (W20-NM3) ---

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

// --- dstate_scopes.go: checkDeactivating (W20-KR1) ---

func TestCheckDeactivating(t *testing.T) {
	d, f := gDeps(t)
	c := &ScopesCheck{d: d}
	ctx := context.Background()

	// list-units failure (no SDReply stub → ENOENT): inconclusive —
	// the streak is kept, not reset, and no count is logged.
	c.deactStreak = 5
	c.checkDeactivating(ctx)
	if c.deactStreak != 5 {
		t.Fatalf("exec failure deactStreak=%d want kept at 5", c.deactStreak)
	}
	if log := f.LogLines(t); !strings.Contains(log,
		"deactivating list-units failed") {
		t.Fatalf("want list-units failure line, log=%q", log)
	}

	// Empty output → streak resets.
	f.SDReply["state=deactivating"] = "\n"
	c.checkDeactivating(ctx)
	if c.deactStreak != 0 {
		t.Fatalf("empty list deactStreak=%d want 0", c.deactStreak)
	}

	// Non-.scope lines don't count toward the wedge.
	f.SDReply["state=deactivating"] =
		"some.service loaded active deactivating stopping\n" +
			"not-a-scope loaded active deactivating\n"
	c.checkDeactivating(ctx)
	if c.deactStreak != 0 {
		t.Fatalf("non-scope lines deactStreak=%d want 0", c.deactStreak)
	}

	// One wedged scope: streak 1 stays silent (alert needs ≥2).
	f.SDReply["state=deactivating"] =
		"cri-containerd-abc123.scope loaded active deactivating stopping\n"
	c.checkDeactivating(ctx)
	if c.deactStreak != 1 {
		t.Fatalf("first wedged sweep deactStreak=%d want 1", c.deactStreak)
	}
	// Second consecutive sweep → the diagnose-only suspect line.
	c.checkDeactivating(ctx)
	if c.deactStreak != 2 {
		t.Fatalf("second wedged sweep deactStreak=%d want 2", c.deactStreak)
	}
	if log := f.LogLines(t); !strings.Contains(log,
		"deactivating count=1 streak=2") {
		t.Fatalf("want deactivating suspect line, log=%q", log)
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
