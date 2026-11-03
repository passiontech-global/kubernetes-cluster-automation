package workerhygiene

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// env is the fixture: tempdir host trees + a stubbed kill function +
// a controllable clock. Tests run rootless — "live" processes are
// just entries in env.live plus a stat file under env.proc.
type env struct {
	h     *Hygiene
	cs    *fake.Clientset
	state string
	proc  string
	ctr   string
	sb    string
	resv  string
	unit  string
	live  map[int]bool
	kills []killRecord
	now   time.Time
}

type killRecord struct {
	pid int
	sig syscall.Signal
}

func fixture(t *testing.T, objs ...runtime.Object) *env {
	t.Helper()
	root := t.TempDir()
	e := &env{live: map[int]bool{}, now: time.Now()}
	e.state = filepath.Join(root, "watchdog")
	e.proc = filepath.Join(root, "proc")
	e.ctr = filepath.Join(root, "ctrtask")
	e.sb = filepath.Join(root, "sbctl")
	e.resv = filepath.Join(root, "resolv.conf")
	e.unit = filepath.Join(root, "k0sworker.service")
	for _, d := range []string{e.state, e.proc, e.ctr, e.sb} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A k0sworker unit with --node-ip — the worker gate plus the
	// konnectivity expected IP. Tests that need the gate OFF remove it.
	writeFile(t, e.unit, "[Service]\nExecStart=/usr/bin/k0s worker --node-ip=10.1.2.3\n")

	e.cs = fake.NewSimpleClientset(objs...)
	h, err := New(Config{
		NodeName:           "node-a",
		Enabled:            true,
		Interval:           time.Hour,
		WatchdogStateDir:   e.state,
		WatchdogLogFile:    filepath.Join(root, "watchdog.log"),
		ProcRoot:           e.proc,
		CtrTaskRoot:        e.ctr,
		SandboxCtlRoot:     e.sb,
		HostResolvConf:     e.resv,
		K0sWorkerUnitFile:  e.unit,
		Client:             e.cs,
		StuckDeleteAge:     15 * time.Minute,
		StuckWedgeAge:      30 * time.Minute,
		MaxForceDelete:     5,
		ConsecNeeded:       2,
		MinRestartInterval: 30 * time.Minute,
	}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	// Test seams: signals never touch real processes.
	h.cfg.killFn = func(pid int, sig syscall.Signal) error {
		if sig == 0 {
			if e.live[pid] {
				return nil
			}
			return syscall.ESRCH
		}
		e.kills = append(e.kills, killRecord{pid, sig})
		return nil
	}
	h.cfg.nowFn = func() time.Time { return e.now }
	e.h = h
	return e
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// mkTask creates a containerd task dir for pod uid; pid goes into
// init.pid — register it in env.live first for a "live" task.
func (e *env) mkTask(t *testing.T, uid, containerName string, pid int) {
	t.Helper()
	dir := filepath.Join(e.ctr, "task-"+containerName+"-"+uid[:8])
	cfg := fmt.Sprintf(`{"annotations":{"io.kubernetes.pod.uid":"%s",`+
		`"io.kubernetes.container.name":"%s"}}`, uid, containerName)
	writeFile(t, filepath.Join(dir, "config.json"), cfg)
	writeFile(t, filepath.Join(dir, "init.pid"), fmt.Sprintf("%d", pid))
}

// mkProc puts a fake process under ProcRoot: stat with the given
// state char + optional cmdline/environ content.
func (e *env) mkProc(t *testing.T, pid int, state string, cmdline, environ string) {
	t.Helper()
	writeFile(t, filepath.Join(e.proc, fmt.Sprintf("%d", pid), "stat"),
		fmt.Sprintf("%d (fakeproc) %s 0 0 0", pid, state))
	e.live[pid] = state != "Z"
	if cmdline != "" {
		writeFile(t, filepath.Join(e.proc, fmt.Sprintf("%d", pid), "cmdline"), cmdline)
	}
	if environ != "" {
		writeFile(t, filepath.Join(e.proc, fmt.Sprintf("%d", pid), "environ"), environ)
	}
}

const (
	uidA = "11111111-2222-3333-4444-555555555555"
	uidB = "22222222-2222-3333-4444-555555555555"
	uidC = "33333333-2222-3333-4444-555555555555"
	uidD = "44444444-2222-3333-4444-555555555555"
	uidE = "55555555-2222-3333-4444-555555555555"
	uidF = "66666666-2222-3333-4444-555555555555"
)

// terminatingPod builds a pod on node-a whose deletion started `ago` ago.
func terminatingPod(e *env, name, ns, uid string, ago time.Duration) *corev1.Pod {
	ts := metav1.NewTime(e.now.Add(-ago))
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns, UID: types.UID(uid),
			DeletionTimestamp: &ts,
		},
		Spec: corev1.PodSpec{NodeName: "node-a"},
	}
}

func deleteActions(cs *fake.Clientset) []k8stesting.DeleteAction {
	var out []k8stesting.DeleteAction
	for _, a := range cs.Actions() {
		if d, ok := a.(k8stesting.DeleteAction); ok && a.GetResource().Resource == "pods" {
			out = append(out, d)
		}
	}
	return out
}

func logLines(t *testing.T, e *env) string {
	t.Helper()
	data, err := os.ReadFile(e.h.cfg.WatchdogLogFile)
	if err != nil {
		return ""
	}
	return string(data)
}

// --- worker gate ---

func TestWorkerGateNoUnitNoOp(t *testing.T) {
	e := fixture(t)
	if err := os.Remove(e.unit); err != nil {
		t.Fatal(err)
	}
	// A terminating pod that WOULD be force-deleted if the gate were off.
	p := terminatingPod(e, "stuck", "default", uidA, 20*time.Minute)
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.h.Cycle(context.Background())
	if n := len(deleteActions(e.cs)); n != 0 {
		t.Fatalf("deletes=%d want 0 on controller gate", n)
	}
	if entries, _ := os.ReadDir(e.state); len(entries) != 0 {
		t.Fatalf("state files written on gated cycle: %v", entries)
	}
}

// --- check 1: pod-teardown ---

func TestForceDeleteDeadPod(t *testing.T) {
	e := fixture(t)
	p := terminatingPod(e, "stuck-pod", "default", uidA, 20*time.Minute)
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	// A task dir exists for the UID but its init pid is DEAD (no
	// /proc entry, not in live set) → zero live tasks → verified
	// object cleanup.
	e.mkTask(t, uidA, "app", 7777)
	// A pod on another node must be ignored.
	other := terminatingPod(e, "other-node", "default", uidB, 20*time.Minute)
	other.Spec.NodeName = "node-b"
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), other, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	e.h.Cycle(context.Background())

	dels := deleteActions(e.cs)
	if len(dels) != 1 {
		t.Fatalf("deletes=%d want 1", len(dels))
	}
	if dels[0].GetName() != "stuck-pod" {
		t.Fatalf("deleted pod=%s want stuck-pod", dels[0].GetName())
	}
	opts := dels[0].GetDeleteOptions()
	if opts.GracePeriodSeconds == nil || *opts.GracePeriodSeconds != 0 {
		t.Fatalf("GracePeriodSeconds=%v want 0", opts.GracePeriodSeconds)
	}
	if !strings.Contains(logLines(t, e), "force-delete pod default/stuck-pod") {
		t.Fatalf("watchdog log missing NPD contract line:\n%s", logLines(t, e))
	}
}

func TestForceDeleteSkipsProtectedPods(t *testing.T) {
	e := fixture(t)
	mk := func(name, uid string, ago time.Duration) *corev1.Pod {
		p := terminatingPod(e, name, "default", uid, ago)
		if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// finalizer: another controller owns cleanup.
	fin := mk("with-finalizer", uidA, 20*time.Minute)
	fin.Finalizers = []string{"example.com/gate"}
	if _, err := e.cs.CoreV1().Pods("default").Update(context.Background(), fin, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	// PVC: dual-mount risk on a wrong death verdict.
	withPVC := mk("with-pvc", uidB, 20*time.Minute)
	withPVC.Spec.Volumes = []corev1.Volume{{
		Name: "data",
		VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: "claim",
			},
		},
	}}
	if _, err := e.cs.CoreV1().Pods("default").Update(context.Background(), withPVC, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	// mirror pod: deleting the mirror object changes nothing.
	mirror := mk("mirror", uidC, 20*time.Minute)
	mirror.Annotations = map[string]string{"kubernetes.io/config.mirror": "x"}
	if _, err := e.cs.CoreV1().Pods("default").Update(context.Background(), mirror, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	// live task: kubelet may still be tearing down.
	mk("live-task", uidD, 20*time.Minute)
	e.mkProc(t, 6101, "S", "", "")
	e.mkTask(t, uidD, "app", 6101)
	// too young to be a candidate.
	mk("too-young", uidE, 5*time.Minute)
	// the eligible one — proves the check ran.
	mk("eligible", uidF, 20*time.Minute)
	e.mkTask(t, uidF, "app", 9999) // dead init pid

	e.h.Cycle(context.Background())

	dels := deleteActions(e.cs)
	if len(dels) != 1 || dels[0].GetName() != "eligible" {
		names := []string{}
		for _, d := range dels {
			names = append(names, d.GetName())
		}
		t.Fatalf("deletes=%v want [eligible]", names)
	}
}

func TestForceDeleteCap(t *testing.T) {
	e := fixture(t)
	e.h.cfg.MaxForceDelete = 2
	for i, uid := range []string{uidA, uidB, uidC} {
		p := terminatingPod(e, fmt.Sprintf("stuck-%d", i), "default", uid, 20*time.Minute)
		if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	e.h.Cycle(context.Background())
	if n := len(deleteActions(e.cs)); n != 2 {
		t.Fatalf("deletes=%d want 2 (MaxForceDelete cap)", n)
	}
}

func TestWedgeLatchLiveTask(t *testing.T) {
	e := fixture(t)
	p := terminatingPod(e, "wedged", "default", uidA, 40*time.Minute)
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.mkProc(t, 6201, "S", "", "")
	e.mkTask(t, uidA, "app", 6201) // live task at >30m → wedge evidence
	latch := filepath.Join(e.state, "state-pod-teardown-wedged")

	// Consecutive counter: first suspect cycle does not latch yet.
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch created before ConsecNeeded cycles")
	}
	// A live task also blocks the force-delete itself.
	if n := len(deleteActions(e.cs)); n != 0 {
		t.Fatalf("deletes=%d want 0 while a task is live", n)
	}
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("latch not created after %d cycles: %v", 2, err)
	}
	if !strings.Contains(logLines(t, e), "STATE-ENTER: pod-teardown-wedged") {
		t.Fatalf("missing STATE-ENTER log:\n%s", logLines(t, e))
	}

	// Pod gone → next cycle clears the latch (STATE-EXIT).
	if err := e.cs.CoreV1().Pods("default").Delete(context.Background(), "wedged", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch not cleared after wedged pod disappeared")
	}
	if !strings.Contains(logLines(t, e), "STATE-EXIT: pod-teardown-wedged") {
		t.Fatalf("missing STATE-EXIT log:\n%s", logLines(t, e))
	}
}

func TestWedgeLatchSuppressedWhenOverloaded(t *testing.T) {
	e := fixture(t)
	p := terminatingPod(e, "wedged", "default", uidA, 40*time.Minute)
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.mkProc(t, 6202, "S", "", "")
	e.mkTask(t, uidA, "app", 6202)
	// The shell runner's overload latch suppresses the wedge latch —
	// reboot under load is an amplifier.
	writeFile(t, filepath.Join(e.state, "state-node-overloaded"), "1\n")
	latch := filepath.Join(e.state, "state-pod-teardown-wedged")

	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("wedge latch created despite node-overloaded")
	}
	if !strings.Contains(logLines(t, e), "suppressed-overloaded") {
		t.Fatalf("missing suppression log:\n%s", logLines(t, e))
	}
}

func TestListFailureKeepsLatch(t *testing.T) {
	e := fixture(t)
	// Pre-existing latch must NOT be cleared when the API flakes —
	// the shell's "inconclusive keeps state" hysteresis.
	latch := filepath.Join(e.state, "state-pod-teardown-wedged")
	writeFile(t, latch, "1\n")
	e.cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver flake")
	})
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatal("latch cleared on an inconclusive (API-failed) cycle")
	}
}

// --- check 2: konnectivity ---

const proxyCmdline = "/proxy-agent\x00--agent-identifiers=host=%s\x00--proxy-server-host=1.2.3.4\x00"

func TestKonnectivityHealthy(t *testing.T) {
	e := fixture(t)
	e.mkProc(t, 7001, "S",
		fmt.Sprintf(proxyCmdline, "10.1.2.3"), "NODE_IP=10.1.2.3\x00FOO=bar\x00")
	e.h.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.state, "state-konnectivity-ip-mismatch")); !os.IsNotExist(err) {
		t.Fatal("mismatch latch on healthy agent")
	}
	if len(e.kills) != 0 || len(deleteActions(e.cs)) != 0 {
		t.Fatal("action taken on healthy agent")
	}
}

func TestKonnectivityOrphanDoesNotPoison(t *testing.T) {
	e := fixture(t)
	// A live agent baked with the CURRENT node-ip plus an orphaned
	// agent (dead shim, process alive) holding the OLD ip — any-match
	// wins, first-match would report stale forever.
	e.mkProc(t, 7001, "S",
		fmt.Sprintf(proxyCmdline, "10.1.2.3"), "NODE_IP=10.1.2.3\x00")
	e.mkProc(t, 7000, "S",
		fmt.Sprintf(proxyCmdline, "10.9.9.9"), "NODE_IP=10.9.9.9\x00")
	e.h.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.state, "state-konnectivity-ip-mismatch")); !os.IsNotExist(err) {
		t.Fatal("orphan process poisoned the detection")
	}
	if len(e.kills) != 0 || len(deleteActions(e.cs)) != 0 {
		t.Fatal("action taken with a healthy agent present")
	}
}

func TestKonnectivityMismatchRestartAndRateLimit(t *testing.T) {
	e := fixture(t)
	konn := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "konnectivity-agent-abc12", Namespace: "kube-system",
			UID: types.UID(uidB),
		},
		Spec: corev1.PodSpec{NodeName: "node-a"},
	}
	if _, err := e.cs.CoreV1().Pods("kube-system").Create(context.Background(), konn, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.mkProc(t, 7001, "S",
		fmt.Sprintf(proxyCmdline, "10.9.9.9"), "NODE_IP=10.9.9.9\x00")
	latch := filepath.Join(e.state, "state-konnectivity-ip-mismatch")

	// Cycle 1: suspect only (ConsecNeeded=2) + latch entered.
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("mismatch latch not created: %v", err)
	}
	if len(deleteActions(e.cs)) != 0 {
		t.Fatal("pod deleted before ConsecNeeded")
	}
	if !strings.Contains(logLines(t, e), "konnectivity stale identifier host=10.9.9.9") {
		t.Fatalf("missing suspect log:\n%s", logLines(t, e))
	}

	// Cycle 2: counter reached + rate budget available → recreate.
	e.h.Cycle(context.Background())
	if n := len(deleteActions(e.cs)); n != 1 {
		t.Fatalf("deletes=%d want 1 (konnectivity-agent pod)", n)
	}
	if _, err := os.Stat(filepath.Join(e.state, "last-konn-restart")); err != nil {
		t.Fatal("rate budget file not spent")
	}
	if !strings.Contains(logLines(t, e), "recreating konnectivity-agent sandbox") {
		t.Fatalf("missing restart log:\n%s", logLines(t, e))
	}
	if e.h.konnFails != 0 {
		t.Fatalf("counter=%d want 0 after action", e.h.konnFails)
	}

	// Cycle 3+4: mismatch persists (process still stale) — the
	// counter rebuilds but the rate budget blocks a second action.
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if n := len(deleteActions(e.cs)); n != 1 {
		t.Fatalf("deletes=%d want 1 (rate limited)", n)
	}
	if len(e.kills) != 0 {
		t.Fatal("fallback kill fired while pod-delete path worked")
	}
}

func TestKonnectivityFallbackKillWithoutPod(t *testing.T) {
	e := fixture(t)
	// No konnectivity-agent pod on the node → fallback SIGKILL on the
	// stale proxy-agent pid itself.
	e.mkProc(t, 7001, "S",
		fmt.Sprintf(proxyCmdline, "10.9.9.9"), "NODE_IP=10.9.9.9\x00")
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if len(e.kills) != 1 || e.kills[0].pid != 7001 || e.kills[0].sig != syscall.SIGKILL {
		t.Fatalf("kills=%v want [{7001 SIGKILL}]", e.kills)
	}
}

func TestKonnectivityCmdlineFallback(t *testing.T) {
	e := fixture(t)
	// environ unreadable (absent) → --agent-identifiers=host= on the
	// cmdline is the fallback identity source.
	e.mkProc(t, 7001, "S", fmt.Sprintf(proxyCmdline, "10.9.9.9"), "")
	e.h.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.state, "state-konnectivity-ip-mismatch")); err != nil {
		t.Fatalf("cmdline fallback not used: %v", err)
	}
}

// --- check 3: dns resolv drift ---

func dnsPod(e *env, name, uid string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: "kube-system", UID: types.UID(uid),
		},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func TestDNSResolvDriftKillPause(t *testing.T) {
	e := fixture(t)
	writeFile(t, e.resv, "nameserver 10.96.0.10\nnameserver 8.8.8.8\n")
	p := dnsPod(e, "node-local-dns-abc12", uidA)
	if _, err := e.cs.CoreV1().Pods("kube-system").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	// Live pause task + the pod's resolv.conf holds a STALE upstream.
	e.mkProc(t, 8001, "S", "", "")
	e.mkTask(t, uidA, "pause", 8001)
	writeFile(t, filepath.Join(e.proc, "8001", "root/etc/resolv.conf"), "nameserver 8.8.8.8\n")
	latch := filepath.Join(e.state, "state-dns-resolv-stale")

	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("stale latch not created: %v", err)
	}
	if len(e.kills) != 0 {
		t.Fatal("pause killed before ConsecNeeded")
	}
	e.h.Cycle(context.Background())
	if len(e.kills) != 1 || e.kills[0].pid != 8001 || e.kills[0].sig != syscall.SIGKILL {
		t.Fatalf("kills=%v want [{8001 SIGKILL}]", e.kills)
	}
	if !strings.Contains(logLines(t, e), "DNS-RESOLV-RESTART: killing pause 8001") {
		t.Fatalf("missing restart log:\n%s", logLines(t, e))
	}
	// The pod object is untouched — the goal is sandbox recreate, not
	// pod delete.
	if n := len(deleteActions(e.cs)); n != 0 {
		t.Fatalf("pod deletes=%d want 0 (pause kill only)", n)
	}
}

func TestDNSResolvMatchNoAction(t *testing.T) {
	e := fixture(t)
	writeFile(t, e.resv, "nameserver 10.96.0.10\n")
	p := dnsPod(e, "coredns-abc12-def34", uidA)
	if _, err := e.cs.CoreV1().Pods("kube-system").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.mkProc(t, 8002, "S", "", "")
	e.mkTask(t, uidA, "pause", 8002)
	writeFile(t, filepath.Join(e.proc, "8002", "root/etc/resolv.conf"), "nameserver 10.96.0.10\n")

	e.h.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.state, "state-dns-resolv-stale")); !os.IsNotExist(err) {
		t.Fatal("stale latch on matching resolv.conf")
	}
	if len(e.kills) != 0 {
		t.Fatal("action on matching resolv.conf")
	}
}

func TestDNSResolvSkipsClusterFirst(t *testing.T) {
	e := fixture(t)
	writeFile(t, e.resv, "nameserver 10.96.0.10\n")
	// A coredns-named pod whose resolv.conf carries svc.cluster.local
	// is ClusterFirst — never a host snapshot, never a kill target
	// (incident 2026-09-26: a matching-named JOB pod was SIGKILLed).
	p := dnsPod(e, "coredns-abc12-def34", uidA)
	if _, err := e.cs.CoreV1().Pods("kube-system").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.mkProc(t, 8003, "S", "", "")
	e.mkTask(t, uidA, "pause", 8003)
	writeFile(t, filepath.Join(e.proc, "8003", "root/etc/resolv.conf"),
		"search default.svc.cluster.local svc.cluster.local\nnameserver 169.254.20.10\n")

	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if len(e.kills) != 0 {
		t.Fatal("ClusterFirst pod pause killed — svc.cluster.local guard failed")
	}
}

func TestDNSResolvNonRunningAndJobNameSkipped(t *testing.T) {
	e := fixture(t)
	writeFile(t, e.resv, "nameserver 10.96.0.10\n")
	// Name matches a coredns JOB (coredns-stale-watchdog-*) — the
	// anchored regex must reject it.
	p := dnsPod(e, "coredns-stale-watchdog-x1y2", uidA)
	if _, err := e.cs.CoreV1().Pods("kube-system").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	// A Pending nld pod — not Running, skipped.
	q := dnsPod(e, "node-local-dns-zz999", uidB)
	q.Status.Phase = corev1.PodPending
	if _, err := e.cs.CoreV1().Pods("kube-system").Create(context.Background(), q, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.mkProc(t, 8004, "S", "", "")
	e.mkTask(t, uidA, "pause", 8004)
	writeFile(t, filepath.Join(e.proc, "8004", "root/etc/resolv.conf"), "nameserver 1.1.1.1\n")

	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if len(e.kills) != 0 {
		t.Fatal("job-named or non-running pod pause killed")
	}
}

// --- plumbing ---

func TestStateEnterExitTransitionLogsOnce(t *testing.T) {
	e := fixture(t)
	e.h.stateEnter("test-state", "extra=1")
	e.h.stateEnter("test-state", "extra=1") // idempotent — one log line
	if got := strings.Count(logLines(t, e), "STATE-ENTER: test-state"); got != 1 {
		t.Fatalf("STATE-ENTER lines=%d want 1", got)
	}
	content, err := os.ReadFile(filepath.Join(e.state, "state-test-state"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Sscanf(strings.TrimSpace(string(content)), "%d", new(int64)); err != nil {
		t.Fatalf("state file content=%q want epoch", content)
	}
	e.h.stateExit("test-state")
	e.h.stateExit("test-state")
	if got := strings.Count(logLines(t, e), "STATE-EXIT: test-state"); got != 1 {
		t.Fatalf("STATE-EXIT lines=%d want 1", got)
	}
}

func TestRateOKSpend(t *testing.T) {
	e := fixture(t)
	name := "last-test"
	if !e.h.rateOK(name, 30*time.Minute) {
		t.Fatal("rateOK on absent file want true")
	}
	e.h.rateSpend(name)
	if e.h.rateOK(name, 30*time.Minute) {
		t.Fatal("rateOK right after spend want false")
	}
	e.now = e.now.Add(31 * time.Minute)
	if !e.h.rateOK(name, 30*time.Minute) {
		t.Fatal("rateOK after interval want true")
	}
	// Garbage content → 0 → ok (shell parity).
	writeFile(t, filepath.Join(e.state, name), "garbage\n")
	if !e.h.rateOK(name, 30*time.Minute) {
		t.Fatal("rateOK on garbage file want true")
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	e := fixture(t)
	e.h.cfg.Interval = time.Hour // only the immediate cycle runs
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.h.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestName(t *testing.T) {
	e := fixture(t)
	if e.h.Name() != "workerhygiene" {
		t.Fatalf("Name()=%q want workerhygiene", e.h.Name())
	}
}
