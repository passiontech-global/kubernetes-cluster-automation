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
