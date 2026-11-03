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
	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/systemd"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/watchdogconf"
)

// env is the fixture: tempdir host trees + a stubbed kill function +
// a controllable clock. Tests run rootless — "live" processes are
// just entries in env.live plus a stat file under env.proc, systemd
// is a fake argv recorder, and HTTP/unix/journal probes are canned.
type env struct {
	h        *Hygiene
	cs       *fake.Clientset
	state    string
	proc     string
	ctr      string
	sb       string
	resv     string
	unit     string
	kubepods string
	live     map[int]bool
	kills    []killRecord
	now      time.Time
	sdcmds   [][]string
	sdReply  map[string]string
	probes   map[string]error // url → error (nil = healthy)
	unixBody []byte
	unixErr  error
	journal  string
}

type killRecord struct {
	pid int
	sig syscall.Signal
}

// sdRun is the systemd fake: records argv, answers is-active/show for
// k0sworker (active, settled >180s), errors on anything unconfigured.
func (e *env) sdRun(_ context.Context, argv []string) (string, error) {
	e.sdcmds = append(e.sdcmds, argv)
	joined := strings.Join(argv, " ")
	for k, v := range e.sdReply {
		if strings.Contains(joined, k) {
			return v, nil
		}
	}
	return "", syscall.ENOENT
}

func (e *env) sdRan(sub string) bool {
	for _, c := range e.sdcmds {
		if strings.Contains(strings.Join(c, " "), sub) {
			return true
		}
	}
	return false
}

func fixture(t *testing.T, objs ...runtime.Object) *env {
	t.Helper()
	root := t.TempDir()
	e := &env{
		live:    map[int]bool{},
		now:     time.Now(),
		sdReply: map[string]string{},
		probes:  map[string]error{},
	}
	e.state = filepath.Join(root, "watchdog")
	e.proc = filepath.Join(root, "proc")
	e.ctr = filepath.Join(root, "ctrtask")
	e.sb = filepath.Join(root, "sbctl")
	e.resv = filepath.Join(root, "resolv.conf")
	e.unit = filepath.Join(root, "k0sworker.service")
	e.kubepods = filepath.Join(root, "kubeletpods")
	for _, d := range []string{e.state, e.proc, e.ctr, e.sb, e.kubepods} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A k0sworker unit with --node-ip — the worker gate plus the
	// konnectivity expected IP. Tests that need the gate OFF remove it.
	writeFile(t, e.unit, "[Service]\nExecStart=/usr/bin/k0s worker --node-ip=10.1.2.3\n")

	e.cs = fake.NewSimpleClientset(objs...)
	sd := systemd.New(systemd.Config{HostRoot: "/", RunCmd: e.sdRun})
	// k0sworker is active and settled — the restart checks need both.
	e.sdReply["systemctl is-active k0sworker.service"] = "active\n"
	e.sdReply["ActiveEnterTimestamp --value k0sworker.service"] =
		e.now.Add(-time.Hour).UTC().Format("Mon 2006-01-02 15:04:05 MST") + "\n"
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
		KubeletPodsDir:     e.kubepods,
		Client:             e.cs,
		Systemd:            sd,
		StuckDeleteAge:     15 * time.Minute,
		StuckWedgeAge:      30 * time.Minute,
		KubeletWatchMinAge: 15 * time.Minute,
		MaxForceDelete:     5,
		MaxCtrTaskClean:    5,
		MaxShimKill:        10,
		ConsecNeeded:       2,
		MinRestartInterval: 30 * time.Minute,
	}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	// Test seams: signals never touch real processes, probes are
	// canned, the journal snapshot is a string.
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
	h.cfg.ProbeGap = 0 // tests run real-time — no 2s sleep between probes
	h.cfg.probeHTTP = func(_ context.Context, url string, _ time.Duration) error {
		return e.probes[url]
	}
	h.cfg.unixGet = func(_ context.Context, _, _ string) ([]byte, error) {
		return e.unixBody, e.unixErr
	}
	h.cfg.journalFn = func(_ context.Context) (string, error) {
		return e.journal, nil
	}
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

// --- lazy shared task map (tasksOnce) ---

func TestTaskMapBuiltOnceSharedAcrossChecks(t *testing.T) {
	e := fixture(t)
	e.mkProc(t, 8001, "S", "", "")
	e.mkTask(t, uidA, "pause", 8001)

	// checkPodTeardown needs the map: a Terminating pod exists
	// (too young to delete — the build is gated on Terminating alone).
	p := terminatingPod(e, "stuck", "default", uidB, 5*time.Minute)
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	// checkDNSResolvDrift needs it too: hostNS set + a Running dns pod.
	writeFile(t, e.resv, "nameserver 10.96.0.10\n")
	d := dnsPod(e, "node-local-dns-abc12", uidA)
	if _, err := e.cs.CoreV1().Pods("kube-system").Create(context.Background(), d, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	e.h.Cycle(context.Background())

	if e.h.taskMapBuilds != 1 {
		t.Fatalf("task map builds=%d want 1 (built once, "+
			"shared between teardown and dns checks)", e.h.taskMapBuilds)
	}
	if n := len(deleteActions(e.cs)); n != 0 {
		t.Fatalf("deletes=%d want 0 (terminating pod too young)", n)
	}
}

func TestTaskMapNotBuiltWithoutTriggers(t *testing.T) {
	e := fixture(t)
	e.mkProc(t, 8001, "S", "", "")
	e.mkTask(t, uidA, "pause", 8001)
	writeFile(t, e.resv, "nameserver 10.96.0.10\n")
	// A Running pod that is neither Terminating nor a dns-pod name —
	// the common idle cycle: the task map must stay unbuilt.
	ordinary := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ordinary-app", Namespace: "default", UID: types.UID(uidB),
		},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), ordinary, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	e.h.Cycle(context.Background())

	if e.h.taskMapBuilds != 0 {
		t.Fatalf("task map builds=%d want 0 (never built)", e.h.taskMapBuilds)
	}
}

func TestTaskMapNotBuiltWhenHostResolvEmpty(t *testing.T) {
	e := fixture(t)
	e.mkProc(t, 8001, "S", "", "")
	e.mkTask(t, uidA, "pause", 8001)
	// resolv.conf absent → hostNS empty → the dns check never reaches
	// the pause-pid lookup even with a Running dns pod.
	d := dnsPod(e, "node-local-dns-abc12", uidA)
	if _, err := e.cs.CoreV1().Pods("kube-system").Create(context.Background(), d, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}

	e.h.Cycle(context.Background())

	if e.h.taskMapBuilds != 0 {
		t.Fatalf("task map builds=%d want 0 (empty hostNS gates the build)", e.h.taskMapBuilds)
	}
}

// --- atomic stateEnter tmp naming ---

func TestStateEnterAtomicTmpLeavesNoResidue(t *testing.T) {
	e := fixture(t)
	// A stale tmp file from a crashed earlier write shares the
	// ".tmp-" prefix — the next stateEnter overwrites+renames it,
	// leaving exactly the latch. The old "state-<n>.tmp" shape would
	// have surfaced as a phantom hostmetrics watchdog_state series.
	writeFile(t, filepath.Join(e.state, ".tmp-state-x"), "stale\n")

	e.h.stateEnter("x", "")

	entries, err := os.ReadDir(e.state)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, en := range entries {
		names = append(names, en.Name())
	}
	if len(names) != 1 || names[0] != "state-x" {
		t.Fatalf("state dir after stateEnter=%v want [state-x] "+
			"(tmp residue or wrong latch name)", names)
	}
}

// --- check 4: kubelet-stall (05) ---

func TestKubeletStall10250DownRestarts(t *testing.T) {
	e := fixture(t)
	e.probes[defaultKubeletHealthzURL] = errors.New("connection refused")
	latch := filepath.Join(e.state, "state-kubelet-runtime-stall")

	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch on first suspect cycle")
	}
	if e.sdRan("restart k0sworker.service") {
		t.Fatal("restart before ConsecNeeded")
	}
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("latch missing after %d cycles: %v", 2, err)
	}
	if !e.sdRan("systemctl restart k0sworker.service") {
		t.Fatalf("k0sworker restart not issued, cmds=%v", e.sdcmds)
	}
	if _, err := os.Stat(filepath.Join(e.state, "last-restart")); err != nil {
		t.Fatal("last-restart budget not spent")
	}
	if e.h.stallFails != 0 {
		t.Fatalf("stallFails=%d want 0 after action", e.h.stallFails)
	}
	if !strings.Contains(logLines(t, e), "ACTION: restarting k0sworker - kubelet-10250-down") {
		t.Fatalf("missing ACTION log:\n%s", logLines(t, e))
	}
}

func TestKubeletStallPhantomPods(t *testing.T) {
	e := fixture(t)
	for i := 0; i < poddirThreshold; i++ {
		if err := os.MkdirAll(filepath.Join(e.kubepods, fmt.Sprintf("pod%d", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Zero live tasks (task root exists but is empty) → phantom-pods.
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.state, "state-kubelet-runtime-stall")); err != nil {
		t.Fatalf("stall latch missing: %v", err)
	}
	if !e.sdRan("restart k0sworker.service") {
		t.Fatal("no k0sworker restart for phantom pods")
	}
	if !strings.Contains(logLines(t, e), "phantom-pods poddirs=5 tasks=0") {
		t.Fatalf("missing phantom-pods log:\n%s", logLines(t, e))
	}
}

func TestKubeletStallLiveTasksNoRestart(t *testing.T) {
	e := fixture(t)
	for i := 0; i < poddirThreshold; i++ {
		if err := os.MkdirAll(filepath.Join(e.kubepods, fmt.Sprintf("pod%d", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A live task means containerd is fine — kubelet healthz answers.
	e.mkProc(t, 9001, "S", "", "")
	e.mkTask(t, uidA, "app", 9001)
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.state, "state-kubelet-runtime-stall")); !os.IsNotExist(err) {
		t.Fatal("stall latch with live tasks")
	}
	if e.sdRan("restart k0sworker.service") {
		t.Fatal("restart with live tasks")
	}
}

func TestKubeletStallOverloadedSuppresses(t *testing.T) {
	e := fixture(t)
	e.probes[defaultKubeletHealthzURL] = errors.New("refused")
	writeFile(t, filepath.Join(e.state, "state-node-overloaded"), "1\n")
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.state, "state-kubelet-runtime-stall")); !os.IsNotExist(err) {
		t.Fatal("stall latch written under overload (amplifier)")
	}
	if e.sdRan("restart k0sworker.service") {
		t.Fatal("restart under overload")
	}
	if !strings.Contains(logLines(t, e), "suppressed-overloaded") {
		t.Fatalf("missing suppression log:\n%s", logLines(t, e))
	}
}

func TestKubeletStallCooldownAndSettle(t *testing.T) {
	e := fixture(t)
	e.probes[defaultKubeletHealthzURL] = errors.New("refused")
	// Freshly spent budget → cooldown blocks the restart.
	writeFile(t, filepath.Join(e.state, "last-restart"),
		fmt.Sprintf("%d\n", e.now.Unix()))
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if e.sdRan("restart k0sworker.service") {
		t.Fatal("restart inside 30m cooldown")
	}
	// Now the budget is old enough but k0sworker just restarted —
	// the settle gate takes over.
	e.now = e.now.Add(time.Hour)
	e.sdReply["ActiveEnterTimestamp --value k0sworker.service"] =
		e.now.Add(-time.Minute).UTC().Format("Mon 2006-01-02 15:04:05 MST") + "\n"
	e.h.Cycle(context.Background())
	if e.sdRan("restart k0sworker.service") {
		t.Fatal("restart while k0sworker not settled (<180s active)")
	}
	if !strings.Contains(logLines(t, e), "not settled") {
		t.Fatalf("missing settle log:\n%s", logLines(t, e))
	}
}

// --- check 5: kubelet-watch-wedge (06) ---

// assignedPod is an old non-terminating pod on node-a with no kubelet
// pod dir — watch-wedge evidence.
func assignedPod(e *env, name, uid string, age time.Duration) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: "default", UID: types.UID(uid),
			CreationTimestamp: metav1.NewTime(e.now.Add(-age)),
		},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func TestKubeletWatchWedgeRestarts(t *testing.T) {
	e := fixture(t)
	p := assignedPod(e, "unseen-pod", uidA, 20*time.Minute)
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	latch := filepath.Join(e.state, "state-kubelet-watch-wedge")

	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch on first suspect cycle")
	}
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("wedge latch missing: %v", err)
	}
	if !e.sdRan("restart k0sworker.service") {
		t.Fatal("no k0sworker restart for watch wedge")
	}
	if !strings.Contains(logLines(t, e), "kubelet-watch-wedge unseen-pods=1") {
		t.Fatalf("missing wedge log:\n%s", logLines(t, e))
	}
}

func TestKubeletWatchWedgeYoungAndDirsSkipped(t *testing.T) {
	e := fixture(t)
	// Too young (below KubeletWatchMinAge).
	young := assignedPod(e, "young", uidA, 2*time.Minute)
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), young, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	// Old but the pod dir EXISTS (kubelet admitted it).
	old := assignedPod(e, "admitted", uidB, 30*time.Minute)
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), old, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(e.kubepods, uidB), 0o755); err != nil {
		t.Fatal(err)
	}
	// Terminating / Succeeded / Failed are skipped entirely.
	term := assignedPod(e, "term", uidC, 30*time.Minute)
	ts := metav1.NewTime(e.now.Add(-time.Minute))
	term.DeletionTimestamp = &ts
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), term, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	done := assignedPod(e, "done", uidD, 30*time.Minute)
	done.Status.Phase = corev1.PodSucceeded
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), done, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.state, "state-kubelet-watch-wedge")); !os.IsNotExist(err) {
		t.Fatal("wedge latch on ineligible pods")
	}
	if e.sdRan("restart k0sworker.service") {
		t.Fatal("restart on ineligible pods")
	}
}

func TestKubeletWatchWedgeUpstreamGate(t *testing.T) {
	e := fixture(t)
	e.h.cfg.APIBackends = []string{"10.0.0.1:6443", "10.0.0.2:6443"}
	p := assignedPod(e, "unseen", uidA, 20*time.Minute)
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	latch := filepath.Join(e.state, "state-kubelet-watch-wedge")
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("latch missing: %v", err)
	}
	// Only ONE backend stale → not an upstream wedge → restart.
	writeFile(t, filepath.Join(e.state, "state-apiserver-backend-stale-10-0-0-1"), "1\n")
	e.h.watchFails = 2
	e.h.Cycle(context.Background())
	if !e.sdRan("restart k0sworker.service") {
		t.Fatal("restart blocked by partial staleness")
	}
	// ALL backends stale → upstream gate blocks the restart.
	e.sdcmds = nil
	writeFile(t, filepath.Join(e.state, "state-apiserver-backend-stale-10-0-0-2"), "1\n")
	e.h.watchFails = 2
	e.h.Cycle(context.Background())
	if e.sdRan("restart k0sworker.service") {
		t.Fatal("restart fired despite all backends stale")
	}
	if !strings.Contains(logLines(t, e), "api backend stale") {
		t.Fatalf("missing upstream-gate log:\n%s", logLines(t, e))
	}
}

func TestKubeletWatchWedgeAPIFailKeepsLatch(t *testing.T) {
	e := fixture(t)
	writeFile(t, filepath.Join(e.state, "state-kubelet-watch-wedge"), "1\n")
	e.cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver flake")
	})
	e.h.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.state, "state-kubelet-watch-wedge")); err != nil {
		t.Fatal("latch cleared on inconclusive (API-failed) cycle")
	}
}

// --- check 6: ctr-tasks (31) ---

func TestCtrTasksWedgedDirTwoPhase(t *testing.T) {
	e := fixture(t)
	// Dead-init task dir (init.pid points at nothing live).
	dir := filepath.Join(e.ctr, "deadbeef"+strings.Repeat("a", 56))
	writeFile(t, filepath.Join(dir, "init.pid"), "77777")
	writeFile(t, filepath.Join(dir, "config.json"), `{"annotations":{}}`)
	writeFile(t, filepath.Join(dir, "log.json"), "{}\n")

	e.h.Cycle(context.Background())
	// First sighting: marker only — no cleanup yet.
	if _, err := os.Stat(dir); err != nil {
		t.Fatal("dir removed before marker confirmation")
	}
	if _, err := os.Stat(filepath.Join(e.state, "wedged-seen-"+filepath.Base(dir))); err != nil {
		t.Fatalf("marker not written: %v", err)
	}
	// Advance past the 5m confirm window → cleanup.
	e.now = e.now.Add(6 * time.Minute)
	e.h.Cycle(context.Background())
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("wedged dir not removed after 5m marker")
	}
	if _, err := os.Stat(filepath.Join(e.state,
		"wedged-seen-"+filepath.Base(dir))); !os.IsNotExist(err) {
		t.Fatal("marker not consumed by cleanup")
	}
	if !strings.Contains(logLines(t, e), "rm wedged task dir") {
		t.Fatalf("missing rm-dir log:\n%s", logLines(t, e))
	}
}

func TestCtrTasksLiveAndSandboxSkipped(t *testing.T) {
	e := fixture(t)
	// Live init, log.json present → healthy task, marker cleared.
	liveDir := filepath.Join(e.ctr, "livetask"+strings.Repeat("b", 57))
	writeFile(t, filepath.Join(liveDir, "init.pid"), "9100")
	writeFile(t, filepath.Join(liveDir, "config.json"), `{"annotations":{}}`)
	writeFile(t, filepath.Join(liveDir, "log.json"), "{}\n")
	e.mkProc(t, 9100, "S", "", "")
	// Sandbox (pause) missing log.json → legitimately skipped.
	sbDir := filepath.Join(e.ctr, "sandboxx"+strings.Repeat("c", 57))
	writeFile(t, filepath.Join(sbDir, "init.pid"), "9101")
	writeFile(t, filepath.Join(sbDir, "config.json"),
		`{"annotations":{"cri.container-type":"sandbox"}}`)
	e.mkProc(t, 9101, "S", "", "")
	for i := 0; i < 3; i++ {
		e.h.Cycle(context.Background())
		e.now = e.now.Add(6 * time.Minute)
	}
	if _, err := os.Stat(liveDir); err != nil {
		t.Fatal("live task dir removed")
	}
	if _, err := os.Stat(sbDir); err != nil {
		t.Fatal("sandbox dir removed (log.json missing is normal)")
	}
}

func TestCtrTasksMissingLogJSONKillsInit(t *testing.T) {
	e := fixture(t)
	dir := filepath.Join(e.ctr, "nologger"+strings.Repeat("d", 57))
	writeFile(t, filepath.Join(dir, "init.pid"), "9102")
	writeFile(t, filepath.Join(dir, "config.json"), `{"annotations":{}}`)
	// No log.json + LIVE init on a container task → dead wedge.
	e.mkProc(t, 9102, "S", "", "")
	e.h.Cycle(context.Background()) // marker
	e.now = e.now.Add(6 * time.Minute)
	e.h.Cycle(context.Background()) // confirm + clean
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("dir with missing log.json not removed")
	}
	if len(e.kills) == 0 || e.kills[0].pid != 9102 {
		t.Fatalf("init not SIGKILLed, kills=%v", e.kills)
	}
}

func TestCtrTasksOrphanShim(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("e", 64)
	// Orphan shim: cmdline holds -id <sid> but no task dir anywhere.
	e.mkProc(t, 9200, "S",
		"containerd-shim-runc-v2\x00-namespace\x00k8s.io\x00-id\x00"+sid+"\x00", "")
	// Fresh proc mtime — must survive the 5m orphan window.
	e.h.Cycle(context.Background())
	if len(e.kills) != 0 {
		t.Fatal("fresh shim killed before 5m window")
	}
	// Age the /proc entry past 5m.
	old := e.now.Add(-6 * time.Minute)
	if err := os.Chtimes(filepath.Join(e.proc, "9200"), old, old); err != nil {
		t.Fatal(err)
	}
	e.h.Cycle(context.Background())
	if len(e.kills) != 1 || e.kills[0].pid != 9200 || e.kills[0].sig != syscall.SIGKILL {
		t.Fatalf("orphan shim not killed, kills=%v", e.kills)
	}
}

func TestCtrTasksHealthyShimKept(t *testing.T) {
	e := fixture(t)
	sid := strings.Repeat("f", 64)
	e.mkProc(t, 9201, "S",
		"containerd-shim-runc-v2\x00-namespace\x00k8s.io\x00-id\x00"+sid+"\x00", "")
	// The task dir exists → shim is not an orphan.
	if err := os.MkdirAll(filepath.Join(e.ctr, sid), 0o755); err != nil {
		t.Fatal(err)
	}
	old := e.now.Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(e.proc, "9201"), old, old); err != nil {
		t.Fatal(err)
	}
	e.h.Cycle(context.Background())
	if len(e.kills) != 0 {
		t.Fatalf("healthy shim killed, kills=%v", e.kills)
	}
}

// --- check 7/8: cilium (32 + 35) ---

// mkCiliumTask creates a cilium-agent containerd task dir with a live
// init pid.
func (e *env) mkCiliumTask(t *testing.T, pid int) {
	t.Helper()
	dir := filepath.Join(e.ctr, "ciliumagent"+strings.Repeat("0", 54))
	cfg := `{"annotations":{"io.kubernetes.pod.uid":"` + uidE +
		`","io.kubernetes.container.name":"cilium-agent"}}`
	writeFile(t, filepath.Join(dir, "config.json"), cfg)
	writeFile(t, filepath.Join(dir, "init.pid"), fmt.Sprintf("%d", pid))
	writeFile(t, filepath.Join(dir, "log.json"), "{}\n")
	e.mkProc(t, pid, "S", "", "")
}

func TestCiliumDownKillsAgent(t *testing.T) {
	e := fixture(t)
	e.mkCiliumTask(t, 9300)
	e.probes[defaultCiliumHealthzURL] = errors.New("refused")
	latch := filepath.Join(e.state, "state-cilium-agent-down")

	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("latch missing on first healthz fail: %v", err)
	}
	if len(e.kills) != 0 {
		t.Fatal("agent killed before ConsecNeeded")
	}
	e.h.Cycle(context.Background())
	if len(e.kills) != 1 || e.kills[0].pid != 9300 || e.kills[0].sig != syscall.SIGKILL {
		t.Fatalf("agent not SIGKILLed, kills=%v", e.kills)
	}
	if _, err := os.Stat(filepath.Join(e.state, "last-cilium-restart")); err != nil {
		t.Fatal("cilium restart budget not spent")
	}
	if !strings.Contains(logLines(t, e), "killed cilium-agent container") {
		t.Fatalf("missing kill log:\n%s", logLines(t, e))
	}
}

func TestCiliumNoContainerClearsLatch(t *testing.T) {
	e := fixture(t)
	writeFile(t, filepath.Join(e.state, "state-cilium-agent-down"), "1\n")
	// No cilium-agent task dirs → node runs no cilium → stale latch
	// from a false positive must clear.
	e.h.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.state, "state-cilium-agent-down")); !os.IsNotExist(err) {
		t.Fatal("latch kept on a node without cilium")
	}
}

func TestCiliumInitStuckKills(t *testing.T) {
	e := fixture(t)
	e.mkCiliumTask(t, 9400)
	e.unixBody = []byte(`[{"id":1,"status":{"identity":{"labels":["reserved:init"]}}}]`)
	latch := filepath.Join(e.state, "state-cilium-init-stuck")

	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("init-stuck latch on first cycle")
	}
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("init-stuck latch missing: %v", err)
	}
	if len(e.kills) != 1 || e.kills[0].pid != 9400 {
		t.Fatalf("cilium-agent not killed for init-stuck, kills=%v", e.kills)
	}
}

func TestCiliumInitStuckTransientNoKill(t *testing.T) {
	e := fixture(t)
	e.mkCiliumTask(t, 9401)
	e.unixBody = []byte(`reserved:init`)
	e.h.Cycle(context.Background())
	// Endpoint resolves before the second cycle — transient, reset.
	e.unixBody = []byte(`[]`)
	e.h.Cycle(context.Background())
	if len(e.kills) != 0 {
		t.Fatal("transient init endpoint killed the agent")
	}
	if e.h.ciliumInitFails != 0 {
		t.Fatalf("counter=%d want 0 after recovery", e.h.ciliumInitFails)
	}
}

func TestCiliumInitStuckInconclusiveKeepsCounter(t *testing.T) {
	e := fixture(t)
	e.mkCiliumTask(t, 9402)
	e.unixBody = []byte(`reserved:init`)
	e.h.Cycle(context.Background())
	if e.h.ciliumInitFails != 1 {
		t.Fatalf("counter=%d want 1", e.h.ciliumInitFails)
	}
	// Endpoint list fails → inconclusive: counter kept, not reset.
	e.unixErr = errors.New("socket dead")
	e.h.Cycle(context.Background())
	if e.h.ciliumInitFails != 1 {
		t.Fatalf("counter=%d want 1 (inconclusive keeps)", e.h.ciliumInitFails)
	}
}

func TestKubeletStallStoppedTaskRecordsNotPhantom(t *testing.T) {
	e := fixture(t)
	for i := 0; i < poddirThreshold; i++ {
		if err := os.MkdirAll(filepath.Join(e.kubepods, fmt.Sprintf("pod%d", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Drained/evicted node shape: pod dirs remain, task dirs exist
	// but every init pid is DEAD (STOPPED records still count, like
	// `ctr tasks ls | wc -l` — not phantom).
	e.mkTask(t, uidA, "app", 0)
	e.mkTask(t, "uid-b-dead-pod-01234", "app", 9999) // dead pid (not in e.live)
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if e.sdRan("restart k0sworker.service") {
		t.Fatal("phantom-pods restart with stopped task records")
	}
}

func TestWorkerInactiveGatesAllChecks(t *testing.T) {
	e := fixture(t)
	e.sdReply["systemctl is-active k0sworker.service"] = "inactive\n"
	e.probes[defaultKubeletHealthzURL] = errors.New("refused")
	e.h.Cycle(context.Background())
	if e.sdRan("restart k0sworker.service") {
		t.Fatal("checks ran while k0sworker intentionally down")
	}
	for _, chk := range []string{checkStall, checkTeardown, checkKonn, checkDNS} {
		if got := e.h.cycles.WithLabelValues(chk, "gated"); testutil.ToFloat64(got) != 1 {
			t.Fatalf("%s gated=%v want 1", chk, testutil.ToFloat64(got))
		}
	}
}

func TestSignalDisabledSkipsCheck(t *testing.T) {
	e := fixture(t)
	e.h.cfg.Watchdog = &watchdogconf.Config{Disabled: map[string]bool{"cilium": true}}
	e.mkTask(t, uidA, "cilium-agent", 0)
	e.probes[defaultCiliumHealthzURL] = errors.New("refused")
	e.h.Cycle(context.Background())
	if got := e.h.cycles.WithLabelValues(checkCilium, "disabled"); testutil.ToFloat64(got) != 1 {
		t.Fatalf("cilium disabled=%v want 1", testutil.ToFloat64(got))
	}
}
