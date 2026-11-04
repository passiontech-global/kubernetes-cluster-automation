package workerhygiene

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

// env is the fixture: tempdir host trees + a stubbed kill function +
// a controllable clock. Tests run rootless — "live" processes are
// just entries in env.live plus a stat file under env.proc, systemd
// is a fake argv recorder, and HTTP/unix/journal probes are canned.
type env struct {
	h          *Hygiene
	cs         *fake.Clientset
	state      string
	proc       string
	ctr        string
	sb         string
	resv       string
	unit       string
	kubepods   string
	live       map[int]bool
	kills      []killRecord
	now        time.Time
	mu         sync.Mutex // guards sdcmds (feeder goroutine + Cycle both record)
	sdcmds     [][]string
	sdReply    map[string]string
	probes     map[string]error  // url → error (nil = healthy)
	status     map[string]int    // url → canned HTTP status for probeHTTPStatus
	bearer     map[string]string // url → bearer token the probe carried
	sockErrs   map[string]error  // unix socket path → dial error
	diskUsed   float64           // /var/lib/k0s fill ratio for statfsFn
	ingest     string            // CtrIngestDir
	sysnet     string            // SysClassNet
	ciliumRt   string            // CiliumRuntimeConfig
	bodyOK     map[string]bool   // :10248 healthz body=="ok" canned answers
	unixBody   []byte
	unixErr    error
	journal    string
	journalErr error
	jdir       string
}

type killRecord struct {
	pid int
	sig syscall.Signal
}

// sdRun is the systemd fake: records argv, answers is-active/show for
// k0sworker (active, settled >180s), errors on anything unconfigured.
func (e *env) sdRun(_ context.Context, argv []string) (string, error) {
	e.mu.Lock()
	e.sdcmds = append(e.sdcmds, argv)
	e.mu.Unlock()
	joined := strings.Join(argv, " ")
	for k, v := range e.sdReply {
		if strings.Contains(joined, k) {
			return v, nil
		}
	}
	return "", syscall.ENOENT
}

func (e *env) sdRan(sub string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
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
		live:     map[int]bool{},
		now:      time.Now(),
		sdReply:  map[string]string{},
		probes:   map[string]error{},
		status:   map[string]int{},
		bearer:   map[string]string{},
		sockErrs: map[string]error{},
		bodyOK:   map[string]bool{},
	}
	e.state = filepath.Join(root, "watchdog")
	e.proc = filepath.Join(root, "proc")
	e.ctr = filepath.Join(root, "ctrtask")
	e.sb = filepath.Join(root, "sbctl")
	e.resv = filepath.Join(root, "resolv.conf")
	e.unit = filepath.Join(root, "k0sworker.service")
	e.kubepods = filepath.Join(root, "kubeletpods")
	e.ingest = filepath.Join(root, "ingest")
	e.sysnet = filepath.Join(root, "sysnet")
	e.ciliumRt = filepath.Join(root, "agent-runtime-config.json")
	e.jdir = filepath.Join(root, "journal")
	for _, d := range []string{e.state, e.proc, e.ctr, e.sb, e.kubepods, e.ingest, e.sysnet, e.jdir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A k0sworker unit with --node-ip — the worker gate plus the
	// konnectivity expected IP. Tests that need the gate OFF remove it.
	writeFile(t, e.unit, "[Service]\nExecStart=/usr/bin/k0s worker --node-ip=10.1.2.3\n")

	e.cs = fake.NewSimpleClientset(objs...)
	// Host up 2h — the uptime file feeds BOTH h.uptimeSeconds (G1)
	// and systemd.ActiveAge's monotonic compare, so one file is one
	// host clock. ActiveEnterTimestampMonotonic is µs since boot:
	// uptimeµs - 1h → a 1h-old (settled) unit.
	writeFile(t, filepath.Join(e.proc, "uptime"), "7200.5 0\n")
	// RunCmd AND RunCmdCombined share the same fake — the journald
	// probes (Journal/journalAnyFn via ExecCombined) must observe
	// the canned replies too, and a nil combined seam would exec
	// REAL journalctl on the test host.
	sd := systemd.New(systemd.Config{HostRoot: "/", RunCmd: e.sdRun,
		RunCmdCombined: e.sdRun,
		ProcUptimeFile: filepath.Join(e.proc, "uptime")})
	// k0sworker is active and settled — the restart checks need both.
	e.sdReply["systemctl is-active k0sworker.service"] = "active\n"
	e.sdReply["ActiveEnterTimestampMonotonic --value k0sworker.service"] =
		fmt.Sprintf("%d\n", 7200500000-int64(time.Hour/time.Microsecond))
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
		// Wave-2 knobs: paths under the fixture root, never the real
		// /sys or /var/lib/k0s.
		CtrIngestDir:         e.ingest,
		K0sDataDir:           filepath.Join(root, "k0sdata"),
		SysClassNet:          e.sysnet,
		CiliumRuntimeConfig:  e.ciliumRt,
		ZombieStormThreshold: 500,
		JournalDirs:          []string{e.jdir},
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
	h.cfg.ProbeGap = 0            // tests run real-time — no 2s sleep between probes
	h.cfg.KubeletWdReprobeGap = 0 // same: no 3s sleep between Gate-0 re-probes
	h.cfg.probeHTTP = func(_ context.Context, url string, _ time.Duration) error {
		return e.probes[url]
	}
	// Feeder seam: bodyOK[url] answers "does :10248 return body 'ok'".
	// Unset entry → false (unhealthy) — gate tests want fails anyway.
	h.cfg.probeBodyOK = func(_ context.Context, url string, _ time.Duration) bool {
		return e.bodyOK[url]
	}
	h.cfg.unixGet = func(_ context.Context, _, _ string) ([]byte, error) {
		return e.unixBody, e.unixErr
	}
	h.cfg.journalFn = func(_ context.Context) (string, error) {
		return e.journal, e.journalErr
	}
	// Wave-2 seams: status-code probes default 200 (healthy) unless
	// probes[url] errors or status[url] overrides; the unix socket
	// probe answers from sockErrs (nil = connects); statfs reports
	// e.diskUsed of 100 blocks.
	h.cfg.probeHTTPStatus = func(_ context.Context, url, bearer string, _ time.Duration) (int, error) {
		e.bearer[url] = bearer
		if err := e.probes[url]; err != nil {
			return 0, err
		}
		if s, ok := e.status[url]; ok {
			return s, nil
		}
		return 200, nil
	}
	h.cfg.probeUnixSock = func(_ context.Context, socket string, _ time.Duration) error {
		return e.sockErrs[socket]
	}
	h.cfg.statfsFn = func(_ string, st *unix.Statfs_t) error {
		st.Blocks = 100
		st.Bavail = uint64(100 - int(e.diskUsed*100))
		return nil
	}
	h.cfg.ctrRmIngest = func(_ context.Context, ref string) error {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.sdcmds = append(e.sdcmds, []string{"ctr", "ingest", "rm", ref})
		return nil
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

// TestTeardownAbortOnUnreadableTaskRoot is the fail-closed guard:
// with the ctr task root unlistable the map cannot prove "zero live
// tasks", so a Terminating pod must NOT be force-deleted — the cycle
// is inconclusive (checkCtrTasks unreadable-root parity).
func TestTeardownAbortOnUnreadableTaskRoot(t *testing.T) {
	e := fixture(t)
	p := terminatingPod(e, "stuck-pod", "default", uidA, 20*time.Minute)
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	// Root gone entirely — on a live worker it should exist.
	if err := os.RemoveAll(e.ctr); err != nil {
		t.Fatal(err)
	}
	e.h.Cycle(context.Background())
	if n := len(deleteActions(e.cs)); n != 0 {
		t.Fatalf("deletes=%d want 0 on unreadable task root", n)
	}
	if !strings.Contains(logLines(t, e), "task map incomplete") {
		t.Fatalf("missing incomplete-map log:\n%s", logLines(t, e))
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

// TestDNSResolvSkipsForeignNamespace is the kube-system pin: a user
// pod named coredns-*/node-local-dns-* outside kube-system matches
// the name regex but is never a pause-kill target.
func TestDNSResolvSkipsForeignNamespace(t *testing.T) {
	e := fixture(t)
	writeFile(t, e.resv, "nameserver 10.96.0.10\n")
	p := dnsPod(e, "coredns-abc12-def34", uidA)
	p.Namespace = "default"
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.mkProc(t, 8005, "S", "", "")
	e.mkTask(t, uidA, "pause", 8005)
	writeFile(t, filepath.Join(e.proc, "8005", "root/etc/resolv.conf"), "nameserver 8.8.8.8\n")

	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if len(e.kills) != 0 {
		t.Fatal("foreign-namespace coredns-named pod pause killed")
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

// TestNewRequiresClient: a nil Clientset would nil-pointer panic on
// the first Cycle LIST — New must reject it (never-panic contract).
func TestNewRequiresClient(t *testing.T) {
	if _, err := New(Config{}, nil); err == nil {
		t.Fatal("New accepted a nil Client")
	}
}

// TestWithDefaultAPIPort covers the backend port defaulting — the
// trailing-colon form ("1.2.3.4:") previously passed through into a
// malformed URL that failed every /livez probe silently.
func TestWithDefaultAPIPort(t *testing.T) {
	for in, want := range map[string]string{
		"1.2.3.4":      "1.2.3.4:6443",
		"1.2.3.4:":     "1.2.3.4:6443",
		"1.2.3.4:7443": "1.2.3.4:7443",
		"[::1]:6443":   "[::1]:6443",
		"[::1]:":       "[::1]:6443",
	} {
		if got := withDefaultAPIPort(in); got != want {
			t.Fatalf("withDefaultAPIPort(%q)=%q want %q", in, got, want)
		}
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
	// the settle gate takes over (uptimeµs - 60s → age 60s < 180s).
	e.now = e.now.Add(time.Hour)
	e.sdReply["ActiveEnterTimestampMonotonic --value k0sworker.service"] = "7140500000\n"
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

// TestKubeletWatchWedgePodsDirGoneInconclusive: with the pods ROOT
// itself gone/unreadable every per-pod stat fails and ALL pods would
// count "missing" — the sweep must abort instead of latching a false
// wedge and spending a k0sworker restart on a filesystem blip.
func TestKubeletWatchWedgePodsDirGoneInconclusive(t *testing.T) {
	e := fixture(t)
	p := assignedPod(e, "unseen", uidA, 20*time.Minute)
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(e.kubepods); err != nil {
		t.Fatal(err)
	}
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.state, "state-kubelet-watch-wedge")); !os.IsNotExist(err) {
		t.Fatal("wedge latch on unstatable pods dir")
	}
	if e.sdRan("restart k0sworker.service") {
		t.Fatal("restart spent on unstatable pods dir")
	}
}

// TestKubeletWatchWedgePodsDirIsFileInconclusive: a REGULAR FILE at
// the pods-root path stats cleanly but every per-pod join then fails
// ENOTDIR — ALL assigned pods would count "missing" → the same false
// wedge + wasted k0sworker restart as the dir-gone case. The IsDir
// guard takes the same inconclusive path.
func TestKubeletWatchWedgePodsDirIsFileInconclusive(t *testing.T) {
	e := fixture(t)
	p := assignedPod(e, "unseen", uidA, 20*time.Minute)
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(e.kubepods); err != nil {
		t.Fatal(err)
	}
	writeFile(t, e.kubepods, "not a dir\n")
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if _, err := os.Stat(filepath.Join(e.state, "state-kubelet-watch-wedge")); !os.IsNotExist(err) {
		t.Fatal("wedge latch on file-as-pods-dir")
	}
	if e.sdRan("restart k0sworker.service") {
		t.Fatal("restart spent on file-as-pods-dir")
	}
	if !strings.Contains(logLines(t, e), "not a directory") {
		t.Fatalf("missing inconclusive log:\n%s", logLines(t, e))
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

// TestCtrTasksOverCapKeepsMarker: dirs dropped by the per-cycle cap
// must KEEP their confirmed wedged-seen marker — removing it on the
// capped pass forced over-cap dirs to re-confirm for 5m forever.
func TestCtrTasksOverCapKeepsMarker(t *testing.T) {
	e := fixture(t)
	e.h.cfg.MaxCtrTaskClean = 2
	// 4 confirmed-wedged dirs (dead init: no init.pid at all), each
	// with a marker already past the 5m confirm window.
	for i := 0; i < 4; i++ {
		id := fmt.Sprintf("wedged%02d%s", i, strings.Repeat("d", 55))
		if err := os.MkdirAll(filepath.Join(e.ctr, id), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(e.state, "wedged-seen-"+id),
			fmt.Sprintf("%d\n", e.now.Add(-10*time.Minute).Unix()))
	}
	e.h.Cycle(context.Background())
	// First two (ReadDir order) cleaned, markers consumed.
	for i := 0; i < 2; i++ {
		id := fmt.Sprintf("wedged%02d%s", i, strings.Repeat("d", 55))
		if _, err := os.Stat(filepath.Join(e.ctr, id)); !os.IsNotExist(err) {
			t.Fatalf("in-cap wedged dir %s not removed", id)
		}
	}
	// The capped two keep BOTH dir and marker — confirmed state
	// survives so next cycle cleans them without a new 5m wait.
	for i := 2; i < 4; i++ {
		id := fmt.Sprintf("wedged%02d%s", i, strings.Repeat("d", 55))
		if _, err := os.Stat(filepath.Join(e.state, "wedged-seen-"+id)); err != nil {
			t.Fatalf("over-cap marker %s dropped — dir would re-confirm forever", id)
		}
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

// --- T15: kubelet watchdog feeder + remediate gates ---

// feedTicks runs n feeder ticks synchronously (the 15s loop body).
func feedTicks(e *env, n int) {
	for i := 0; i < n; i++ {
		e.h.kubeletFeedTick(context.Background())
	}
}

func TestKubeletFeederFailThenRestart(t *testing.T) {
	e := fixture(t)
	// Happy path: :10248 dead, all gates pass (uptime absent →
	// fail-open, k0sworker settled, no overload latch, API fallback
	// livez unconfigured → probe map default nil = alive).
	e.sdReply["restart k0sworker.service"] = ""
	e.sdReply["reset-failed k0sworker.service"] = ""

	feedTicks(e, defaultKubeletWdMaxFail-1)
	if e.h.kubeletWdFails != defaultKubeletWdMaxFail-1 {
		t.Fatalf("fails=%d want %d", e.h.kubeletWdFails, defaultKubeletWdMaxFail-1)
	}
	if e.sdRan("restart k0sworker") {
		t.Fatal("restart before MaxFail consecutive fails")
	}
	feedTicks(e, 1) // 4th fail → gates → act
	if e.h.kubeletWdFails != 0 {
		t.Fatalf("fails=%d want 0 (re-armed after remediate)", e.h.kubeletWdFails)
	}
	if !e.sdRan("reset-failed k0sworker.service") {
		t.Fatalf("reset-failed not issued, cmds=%v", e.sdcmds)
	}
	if !e.sdRan("restart k0sworker.service") {
		t.Fatalf("k0sworker restart not issued, cmds=%v", e.sdcmds)
	}
	if _, err := os.Stat(filepath.Join(e.state, "last-restart")); err != nil {
		t.Fatal("last-restart budget not spent")
	}
	if !strings.Contains(logLines(t, e),
		"ACTION: restarting k0sworker (reason=systemd-watchdog-kubelet-healthz-60s") {
		t.Fatalf("missing NPD ACTION contract line:\n%s", logLines(t, e))
	}
}

func TestKubeletFeederProbeOKResetsFailsAndClearsLatch(t *testing.T) {
	e := fixture(t)
	latch := filepath.Join(e.state, "state-kubelet-healthz-down")
	writeFile(t, latch, "1\n")
	feedTicks(e, 2)
	if e.h.kubeletWdFails != 2 {
		t.Fatalf("fails=%d want 2", e.h.kubeletWdFails)
	}
	e.bodyOK[e.h.cfg.KubeletWdProbeURL] = true
	e.h.kubeletFeedTick(context.Background())
	if e.h.kubeletWdFails != 0 {
		t.Fatalf("fails=%d want 0 after probe OK", e.h.kubeletWdFails)
	}
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("healthz-down latch kept after probe OK")
	}
	if !strings.Contains(logLines(t, e), "STATE-EXIT: kubelet-healthz-down") {
		t.Fatalf("missing STATE-EXIT log:\n%s", logLines(t, e))
	}
}

func TestKubeletFeederGateUptime(t *testing.T) {
	e := fixture(t)
	writeFile(t, filepath.Join(e.proc, "uptime"), "600.5 0\n") // <1200s
	// Gate-0 re-probe runs before every gate: 4 failed ticks + 2
	// failed re-probes before G1 is even evaluated.
	var probes int
	e.h.cfg.probeBodyOK = func(_ context.Context, _ string, _ time.Duration) bool {
		probes++
		return false
	}
	feedTicks(e, defaultKubeletWdMaxFail)
	if e.sdRan("restart k0sworker") {
		t.Fatal("restart under uptime gate")
	}
	if probes != defaultKubeletWdMaxFail+2 {
		t.Fatalf("probe calls=%d want %d (4 ticks + 2 re-probes)",
			probes, defaultKubeletWdMaxFail+2)
	}
	if !strings.Contains(logLines(t, e), "SKIP(G1-uptime)") {
		t.Fatalf("missing G1 log:\n%s", logLines(t, e))
	}
}

func TestKubeletFeederGateSettle(t *testing.T) {
	e := fixture(t)
	// k0sworker restarted a minute ago — kubelet may still be initing
	// (uptimeµs - 60s → age 60s < 180s settle window).
	e.sdReply["ActiveEnterTimestampMonotonic --value k0sworker.service"] = "7140500000\n"
	feedTicks(e, defaultKubeletWdMaxFail)
	if e.sdRan("restart k0sworker") {
		t.Fatal("restart inside the 180s settle window")
	}
	if !strings.Contains(logLines(t, e), "SKIP(G2-settle)") {
		t.Fatalf("missing G2 log:\n%s", logLines(t, e))
	}
}

func TestKubeletFeederGateOverload(t *testing.T) {
	e := fixture(t)
	writeFile(t, filepath.Join(e.state, "state-node-overloaded"), "1\n")
	feedTicks(e, defaultKubeletWdMaxFail)
	if e.sdRan("restart k0sworker") {
		t.Fatal("restart under node-overloaded")
	}
	if !strings.Contains(logLines(t, e), "SKIP(G3-overload)") {
		t.Fatalf("missing G3 log:\n%s", logLines(t, e))
	}
}

func TestKubeletFeederGateAPIServer(t *testing.T) {
	e := fixture(t)
	// No backends configured → fallback api-local-lb livez is probed;
	// dead → node isolated → no restart.
	e.probes[e.h.cfg.APIFallbackURL] = errors.New("refused")
	feedTicks(e, defaultKubeletWdMaxFail)
	if e.sdRan("restart k0sworker") {
		t.Fatal("restart while API unreachable")
	}
	if !strings.Contains(logLines(t, e), "SKIP(G4-apiserver)") {
		t.Fatalf("missing G4 log:\n%s", logLines(t, e))
	}
}

func TestKubeletFeederGateAPIServerConfiguredBackends(t *testing.T) {
	e := fixture(t)
	// Configured API_BACKENDS are probed (ports preserved); the
	// fallback URL must NOT be consulted — kill it and keep one
	// backend alive.
	e.h.cfg.Watchdog = &watchdogconf.Config{
		Disabled: map[string]bool{},
		APIBackends: []watchdogconf.APIBackend{
			{Name: "ctrl1", Addr: "10.0.0.9:6443"},
			{Name: "ctrl2", Addr: "10.0.0.10:6443"},
		},
	}
	e.probes["https://10.0.0.9:6443/livez"] = errors.New("refused")
	// 10.0.0.10 unconfigured → probe map default nil = alive.
	e.probes[e.h.cfg.APIFallbackURL] = errors.New("refused")
	e.sdReply["restart k0sworker.service"] = ""
	feedTicks(e, defaultKubeletWdMaxFail)
	if !e.sdRan("restart k0sworker.service") {
		t.Fatal("restart blocked although a configured backend is live")
	}
}

func TestKubeletFeederGateRateLimitLatches(t *testing.T) {
	e := fixture(t)
	// Budget spent moments ago → G5 skips and escalates via the latch.
	writeFile(t, filepath.Join(e.state, "last-restart"),
		fmt.Sprintf("%d\n", e.now.Unix()))
	latch := filepath.Join(e.state, "state-kubelet-healthz-down")
	feedTicks(e, defaultKubeletWdMaxFail)
	if e.sdRan("restart k0sworker") {
		t.Fatal("restart inside 30m cooldown")
	}
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("kubelet-healthz-down latch missing (NHC escalation): %v", err)
	}
	if !strings.Contains(logLines(t, e), "SKIP(G5-ratelimit)") {
		t.Fatalf("missing G5 log:\n%s", logLines(t, e))
	}
	if strings.Contains(logLines(t, e), "ACTION: restarting k0sworker") {
		t.Fatal("ACTION logged inside cooldown")
	}
	// A recovered kubelet clears the escalation latch again.
	e.bodyOK[e.h.cfg.KubeletWdProbeURL] = true
	e.h.kubeletFeedTick(context.Background())
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch kept after kubelet recovered")
	}
}

func TestKubeletFeederStandsDownWhenWorkerInactive(t *testing.T) {
	e := fixture(t)
	// PartOf=k0sworker.service parity: an intentionally stopped unit
	// must not accumulate probe fails toward a restart — and a stale
	// healthz-down latch must clear too, else NHC→SNR reboots a
	// deliberately-stopped node.
	latch := filepath.Join(e.state, "state-kubelet-healthz-down")
	writeFile(t, latch, "1\n")
	e.sdReply["systemctl is-active k0sworker.service"] = "inactive\n"
	feedTicks(e, defaultKubeletWdMaxFail+1)
	if e.h.kubeletWdFails != 0 {
		t.Fatalf("fails=%d want 0 while k0sworker inactive", e.h.kubeletWdFails)
	}
	if e.sdRan("restart k0sworker") {
		t.Fatal("restart while k0sworker intentionally down")
	}
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("healthz-down latch kept while k0sworker intentionally stopped")
	}
}

func TestKubeletFeederActivation(t *testing.T) {
	e := fixture(t)
	if !e.h.kubeletFeederActive() {
		t.Fatal("feeder inactive on a default worker node (unit file present)")
	}
	// Off the worker list and no unit file → inactive.
	if err := os.Remove(e.unit); err != nil {
		t.Fatal(err)
	}
	if e.h.kubeletFeederActive() {
		t.Fatal("feeder active without unit file and without host listing")
	}
	// Listed in systemd_watchdog_hosts → active regardless of the
	// unit file (the shell install gate).
	e.h.cfg.KubeletWatchdogHosts = []string{"node-x", "node-a"}
	if !e.h.kubeletFeederActive() {
		t.Fatal("feeder inactive although node is listed")
	}
	// WD_SIG_KUBELET_WATCHDOG=off kills it even when listed.
	e.h.cfg.Watchdog = &watchdogconf.Config{
		Disabled: map[string]bool{"kubelet-watchdog": true},
	}
	if e.h.kubeletFeederActive() {
		t.Fatal("feeder active with WD_SIG kill switch off")
	}
	e.h.cfg.Watchdog = nil
	e.h.cfg.KubeletWatchdogHosts = nil
	if e.h.kubeletFeederActive() {
		t.Fatal("feeder active without unit file and unlisted")
	}
}

func TestKubeletFeederLoopStopsOnCancel(t *testing.T) {
	e := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.h.runKubeletFeeder(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runKubeletFeeder did not return after cancel")
	}
}

// --- remediate Gate-0 re-probe + feeder activation edges ---

func TestKubeletRemediateReprobeSelfCorrects(t *testing.T) {
	e := fixture(t)
	// Shell Gate-1 parity: after 4 failed ticks the remediate pass
	// re-probes :10248 twice ~3s apart before any gate. One "ok" —
	// the streak was a CPU-steal probe timeout — self-corrects: no
	// gates, no restart, fail streak and latch dropped.
	latch := filepath.Join(e.state, "state-kubelet-healthz-down")
	writeFile(t, latch, "1\n") // leftover from an earlier episode
	var probes int
	e.h.cfg.probeBodyOK = func(_ context.Context, _ string, _ time.Duration) bool {
		probes++
		return probes > defaultKubeletWdMaxFail // ticks 1..4 fail, re-probe 1 OK
	}
	feedTicks(e, defaultKubeletWdMaxFail)
	if e.sdRan("restart k0sworker") {
		t.Fatal("restart despite re-probe self-correct (steal blip kills kubelets)")
	}
	if e.h.kubeletWdFails != 0 {
		t.Fatalf("fails=%d want 0 after re-probe ok", e.h.kubeletWdFails)
	}
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("healthz-down latch kept after re-probe ok")
	}
	if !strings.Contains(logLines(t, e), "SKIP(G0-reprobe)") {
		t.Fatalf("missing G0 log:\n%s", logLines(t, e))
	}
	// One "ok" exits early — exactly one re-probe call, not two.
	if probes != defaultKubeletWdMaxFail+1 {
		t.Fatalf("probes=%d want %d (4 ticks + 1 re-probe)", probes, defaultKubeletWdMaxFail+1)
	}
}

func TestKubeletRemediateReprobeSecondProbeOK(t *testing.T) {
	e := fixture(t)
	// First re-probe fails, second answers — still self-corrects.
	var probes int
	e.h.cfg.probeBodyOK = func(_ context.Context, _ string, _ time.Duration) bool {
		probes++
		return probes > defaultKubeletWdMaxFail+1
	}
	feedTicks(e, defaultKubeletWdMaxFail)
	if e.sdRan("restart k0sworker") {
		t.Fatal("restart although the second re-probe answered")
	}
	if probes != defaultKubeletWdMaxFail+2 {
		t.Fatalf("probes=%d want %d (4 ticks + 2 re-probes)", probes, defaultKubeletWdMaxFail+2)
	}
}

func TestKubeletFeederReactivationResetsFails(t *testing.T) {
	e := fixture(t)
	// No "start" log while the feeder never activates — the goroutine
	// runs fleet-wide but logs only on an actual activation flip.
	if strings.Contains(logLines(t, e), "kubelet-feeder: start") {
		t.Fatal("start log before any tick")
	}
	// Two failed ticks while active, then deactivation.
	feedTicks(e, 2)
	if e.h.kubeletWdFails != 2 {
		t.Fatalf("setup fails=%d want 2", e.h.kubeletWdFails)
	}
	if err := os.Remove(e.unit); err != nil {
		t.Fatal(err)
	}
	e.h.kubeletFeedTick(context.Background()) // inactive tick — fails persist
	if e.h.kubeletWdFails != 2 {
		t.Fatalf("fails=%d want 2 kept while inactive", e.h.kubeletWdFails)
	}
	// Re-activation (unit file reappears) must drop the stale streak
	// before it can reach MaxFail — and logs exactly one "start" per
	// activation (the first active tick + this flip).
	e.bodyOK[e.h.cfg.KubeletWdProbeURL] = true
	writeFile(t, e.unit, "[Service]\nExecStart=/usr/bin/k0s worker --node-ip=10.1.2.3\n")
	e.h.kubeletFeedTick(context.Background())
	if e.h.kubeletWdFails != 0 {
		t.Fatalf("fails=%d want 0 on re-activation", e.h.kubeletWdFails)
	}
	if got := strings.Count(logLines(t, e), "kubelet-feeder: start"); got != 2 {
		t.Fatalf("start logs=%d want 2 (one per activation)", got)
	}
	if !strings.Contains(logLines(t, e), "dropping 2 stale fails") {
		t.Fatalf("missing stale-fails log:\n%s", logLines(t, e))
	}
}

// TestRateTrySpendAtomic: the shared last-* budgets are checked and
// spent by BOTH the feeder goroutine and Cycle — check+spend under
// rateMu means exactly one winner per window.
func TestRateTrySpendAtomic(t *testing.T) {
	e := fixture(t)
	const n = 8
	var wins atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e.h.rateTrySpend("last-restart", e.h.cfg.MinRestartInterval) {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := wins.Load(); got != 1 {
		t.Fatalf("rateTrySpend wins=%d want 1 (check+spend must be atomic)", got)
	}
	if _, err := os.Stat(filepath.Join(e.state, "last-restart")); err != nil {
		t.Fatal("budget file not written by the winner")
	}
}

// --- check: ctr-image-healer (37) ---

// waitingPod builds a Pending pod on node-a whose single container is
// stuck Waiting with the given reason/message/image — 37 evidence.
// imageID is the CRI repoDigest record (e.g.
// docker.io/library/nginx@sha256:…) kubelet reports alongside Image —
// the healer removes both records.
func waitingPod(name, ns, uid, image, imageID, reason, msg string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns, UID: types.UID(uid),
		},
		Spec: corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{
			Phase: corev1.PodPending,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:    "app",
				Image:   image,
				ImageID: imageID,
				State: corev1.ContainerState{
					Waiting: &corev1.ContainerStateWaiting{Reason: reason, Message: msg},
				},
			}},
		},
	}
}

func TestCtrImageHealerRemovesCorruptedImage(t *testing.T) {
	e := fixture(t)
	var removed []string
	e.h.cfg.ctrRmImage = func(_ context.Context, img string) error {
		removed = append(removed, img)
		return nil
	}
	p := waitingPod("stuck-pull", "default", uidA, "registry.local/app:v1",
		"registry.local/app@sha256:f00dcafe",
		"ImagePullBackOff",
		`rpc error: code = Unknown desc = failed to pull and unpack image: `+
			`content digest sha256:abc123def456: not found`)
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.h.Cycle(context.Background())
	// One corrupted container → two store records (tag + repoDigest).
	want := []string{"registry.local/app:v1", "registry.local/app@sha256:f00dcafe"}
	if !slices.Equal(removed, want) {
		t.Fatalf("removed=%v want %v", removed, want)
	}
	if _, err := os.Stat(filepath.Join(e.state, "last-ctr-image-rm")); err != nil {
		t.Fatal("last-ctr-image-rm budget not spent")
	}
	if !strings.Contains(logLines(t, e),
		"ACTION: removed corrupted image registry.local/app:v1") {
		t.Fatalf("missing NPD ACTION contract line:\n%s", logLines(t, e))
	}
}

func TestCtrImageHealerReasonAndMessageFilter(t *testing.T) {
	e := fixture(t)
	var removed []string
	e.h.cfg.ctrRmImage = func(_ context.Context, img string) error {
		removed = append(removed, img)
		return nil
	}
	mk := func(name, uid, image, imageID, reason, msg string) {
		p := waitingPod(name, "default", uid, image, imageID, reason, msg)
		if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	// Wrong reason — a plain CrashLoopBackOff with the corrupt text is
	// a runtime crash, not a store-corruption signal.
	mk("crashloop", uidA, "registry.local/app:v1", "registry.local/app@sha256:f00d",
		"CrashLoopBackOff", "content digest sha256:abc123: not found")
	// Right reason, unrelated message — a quota deny is not a
	// corrupted layer.
	mk("quota-deny", uidB, "registry.local/app:v1", "registry.local/app@sha256:f00d",
		"ErrImagePull", "pull rate limit exceeded")
	// Right reason + matching message but no image recorded — nothing
	// to remove.
	mk("no-image", uidC, "", "",
		"ImagePullBackOff", "content digest sha256:abc123: not found")
	// A pod on another node must be ignored entirely.
	other := waitingPod("other-node", "default", uidD, "registry.local/app:v1",
		"registry.local/app@sha256:f00d",
		"CreateContainerError", "failed to extract layer")
	other.Spec.NodeName = "node-b"
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), other, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.h.Cycle(context.Background())
	if len(removed) != 0 {
		t.Fatalf("removed=%v want none (reason/message/node filters)", removed)
	}
	if _, err := os.Stat(filepath.Join(e.state, "last-ctr-image-rm")); !os.IsNotExist(err) {
		t.Fatal("budget spent with nothing to remove")
	}
}

func TestCtrImageHealerAllSignatures(t *testing.T) {
	e := fixture(t)
	var removed []string
	e.h.cfg.ctrRmImage = func(_ context.Context, img string) error {
		removed = append(removed, img)
		return nil
	}
	mk := func(name, uid, image, imageID, reason, msg string) {
		p := waitingPod(name, "default", uid, image, imageID, reason, msg)
		if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	mk("extract", uidA, "img/extract:1", "docker.io/img/extract@sha256:e1e1",
		"CreateContainerError", "failed to extract layer sha256:abc: unexpected EOF")
	mk("snapshot", uidB, "img/snapshot:2", "docker.io/img/snapshot@sha256:52",
		"ErrImagePull", "parent snapshot sha256:def456 does not exist")
	mk("digest", uidC, "img/digest:3", "docker.io/img/digest@sha256:d363",
		"CreateContainerError", "content digest sha256:789abc: not found")
	e.h.Cycle(context.Background())
	// Each corrupted container removes its tag record AND its
	// repoDigest record → 2 refs per pod.
	want := []string{
		"docker.io/img/digest:3", "docker.io/img/digest@sha256:d363",
		"docker.io/img/extract:1", "docker.io/img/extract@sha256:e1e1",
		"docker.io/img/snapshot:2", "docker.io/img/snapshot@sha256:52",
	}
	if !slices.Equal(removed, want) {
		t.Fatalf("removed=%v want %v (tag+digest per corrupted image)", removed, want)
	}
}

func TestCtrImageHealerDedupesAndRateLimits(t *testing.T) {
	e := fixture(t)
	var removed []string
	e.h.cfg.ctrRmImage = func(_ context.Context, img string) error {
		removed = append(removed, img)
		return nil
	}
	msg := "content digest sha256:aaa111: not found"
	for i, uid := range []string{uidA, uidB} {
		p := waitingPod(fmt.Sprintf("dup-%d", i), "default", uid,
			"registry.local/app:v1", "registry.local/app@sha256:aaa111",
			"ImagePullBackOff", msg)
		if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	e.h.Cycle(context.Background())
	if len(removed) != 2 {
		t.Fatalf("removed=%v want 2 (tag+digest deduped across pods)", removed)
	}
	// Second cycle: evidence unchanged but the 15m budget is spent.
	e.h.Cycle(context.Background())
	if len(removed) != 2 {
		t.Fatalf("removed=%v want 2 (15m cooldown blocks the repeat)", removed)
	}
	if !strings.Contains(logLines(t, e), "in rm cooldown (<15m)") {
		t.Fatalf("missing cooldown suspect line:\n%s", logLines(t, e))
	}
	// Budget aged out → the next cycle may rm again.
	e.now = e.now.Add(16 * time.Minute)
	e.h.Cycle(context.Background())
	if len(removed) != 4 {
		t.Fatalf("removed=%v want 4 after cooldown expired", removed)
	}
}

func TestCtrImageHealerRmErrorKeepsGoing(t *testing.T) {
	e := fixture(t)
	e.h.cfg.ctrRmImage = func(_ context.Context, img string) error {
		if img == "docker.io/library/bad:1" {
			return errors.New("ctr exploded")
		}
		return nil
	}
	mk := func(name, uid, image, imageID string) {
		p := waitingPod(name, "default", uid, image, imageID, "CreateContainerError",
			"failed to extract layer sha256:x")
		if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	mk("a", uidA, "bad:1", "docker.io/library/bad@sha256:b1")
	mk("b", uidB, "good:2", "docker.io/library/good@sha256:62")
	e.h.Cycle(context.Background())
	if !strings.Contains(logLines(t, e),
		"ctr image rm docker.io/library/bad:1 failed: ctr exploded") {
		t.Fatalf("missing rm-failure log:\n%s", logLines(t, e))
	}
	if !strings.Contains(logLines(t, e),
		"ACTION: removed corrupted image docker.io/library/good:2") {
		t.Fatalf("one rm failure must not block the next image:\n%s", logLines(t, e))
	}
}

func TestCtrImageHealerDefaultSeamUsesSystemdExec(t *testing.T) {
	e := fixture(t)
	// No seam override — the default wraps Systemd.Exec. The fake
	// answers any `ctr images rm` argv with success.
	e.sdReply["images rm"] = ""
	p := waitingPod("stuck", "default", uidA, "registry.local/app:v1",
		"registry.local/app@sha256:feed",
		"ImagePullBackOff", "content digest sha256:abc123: not found")
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.h.Cycle(context.Background())
	if !e.sdRan("k0s ctr --namespace k8s.io images rm --sync registry.local/app:v1") {
		t.Fatalf("default seam did not exec ctr images rm, cmds=%v", e.sdcmds)
	}
	if !e.sdRan("k0s ctr --namespace k8s.io images rm --sync registry.local/app@sha256:feed") {
		t.Fatalf("default seam did not exec ctr images rm on the repoDigest, cmds=%v", e.sdcmds)
	}
}

func TestCtrImageHealerAPIFailNoAction(t *testing.T) {
	e := fixture(t)
	var removed []string
	e.h.cfg.ctrRmImage = func(_ context.Context, img string) error {
		removed = append(removed, img)
		return nil
	}
	e.cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver flake")
	})
	e.h.Cycle(context.Background())
	if len(removed) != 0 {
		t.Fatal("image rm fired on an inconclusive (API-failed) cycle")
	}
	if got := e.h.cycles.WithLabelValues(checkCtrImages, "abort"); testutil.ToFloat64(got) != 1 {
		t.Fatalf("abort=%v want 1", testutil.ToFloat64(got))
	}
}

// TestNormalizeCRIImageName pins the docker reference convention the
// CRI plugin applies at pull time — `ctr images rm` matches store
// names verbatim, so every spec must be canonicalized first.
func TestNormalizeCRIImageName(t *testing.T) {
	cases := []struct{ in, want string }{
		// Short dockerhub names → docker.io/library/.
		{"nginx:1.25", "docker.io/library/nginx:1.25"},
		{"nginx", "docker.io/library/nginx"},
		{"docker.io/nginx:1.25", "docker.io/library/nginx:1.25"},
		// Org path → docker.io/org/, no library insertion.
		{"org/app:1.0", "docker.io/org/app:1.0"},
		{"docker.io/org/app:1.0", "docker.io/org/app:1.0"},
		// Private registries pass through untouched — '.'/':'/
		// "localhost" mark the first segment as a domain, and
		// library/ is a docker.io-only convention.
		{"registry.local/app:v1", "registry.local/app:v1"},
		{"registry.local:5000/team/app:v2", "registry.local:5000/team/app:v2"},
		{"localhost/app:1", "localhost/app:1"},
		{"localhost:5000/app:1", "localhost:5000/app:1"},
		// Digest refs canonicalize to name@sha256:… — the tag is
		// dropped, a registry port is not.
		{"nginx:1.25@sha256:abc", "docker.io/library/nginx@sha256:abc"},
		{"nginx@sha256:abc", "docker.io/library/nginx@sha256:abc"},
		{"registry.local/app:v1@sha256:abc", "registry.local/app@sha256:abc"},
		{"localhost:5000/app@sha256:abc", "localhost:5000/app@sha256:abc"},
		// Already-canonical refs are idempotent.
		{"docker.io/library/nginx:1.25", "docker.io/library/nginx:1.25"},
		{"docker.io/library/nginx@sha256:abc", "docker.io/library/nginx@sha256:abc"},
	}
	for _, c := range cases {
		if got := normalizeCRIImageName(c.in); got != c.want {
			t.Errorf("normalizeCRIImageName(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

// The whole point of the fix: a short dockerhub spec must reach
// ctrRmImage as the canonical docker.io/library/… ref, and the
// repoDigest record goes with it.
func TestCtrImageHealerNormalizesDockerHubShortName(t *testing.T) {
	e := fixture(t)
	var removed []string
	e.h.cfg.ctrRmImage = func(_ context.Context, img string) error {
		removed = append(removed, img)
		return nil
	}
	p := waitingPod("stuck-pull", "default", uidA, "nginx:1.25",
		"docker.io/library/nginx@sha256:beef",
		"ImagePullBackOff", "content digest sha256:abc123: not found")
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.h.Cycle(context.Background())
	want := []string{"docker.io/library/nginx:1.25", "docker.io/library/nginx@sha256:beef"}
	if !slices.Equal(removed, want) {
		t.Fatalf("removed=%v want %v", removed, want)
	}
}

// Spec and ImageID naming the same canonical digest ref must produce
// ONE rm — the image store holds a single record for it.
func TestCtrImageHealerDigestRefDedupes(t *testing.T) {
	e := fixture(t)
	var removed []string
	e.h.cfg.ctrRmImage = func(_ context.Context, img string) error {
		removed = append(removed, img)
		return nil
	}
	p := waitingPod("stuck-pull", "default", uidA, "nginx@sha256:beef",
		"docker.io/library/nginx@sha256:beef",
		"CreateContainerError", "failed to extract layer sha256:abc")
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.h.Cycle(context.Background())
	want := []string{"docker.io/library/nginx@sha256:beef"}
	if !slices.Equal(removed, want) {
		t.Fatalf("removed=%v want %v (spec+ImageID same ref → single rm)", removed, want)
	}
}

// name:tag@digest spec → the tag is stripped, digest wins.
func TestCtrImageHealerTagPlusDigestStripsTag(t *testing.T) {
	e := fixture(t)
	var removed []string
	e.h.cfg.ctrRmImage = func(_ context.Context, img string) error {
		removed = append(removed, img)
		return nil
	}
	p := waitingPod("stuck-pull", "default", uidA, "nginx:1.25@sha256:beef",
		"docker.io/library/nginx@sha256:beef",
		"ImagePullBackOff", "content digest sha256:abc123: not found")
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.h.Cycle(context.Background())
	want := []string{"docker.io/library/nginx@sha256:beef"}
	if !slices.Equal(removed, want) {
		t.Fatalf("removed=%v want %v (tag+digest → digest only)", removed, want)
	}
}

// Private-registry refs (with port, multi-segment path) must reach
// ctrRmImage byte-for-byte unchanged — no docker.io/library rewrite.
func TestCtrImageHealerPrivateRegistryUntouched(t *testing.T) {
	e := fixture(t)
	var removed []string
	e.h.cfg.ctrRmImage = func(_ context.Context, img string) error {
		removed = append(removed, img)
		return nil
	}
	p := waitingPod("stuck-pull", "default", uidA,
		"registry.local:5000/team/app:v2", "registry.local:5000/team/app@sha256:cafe",
		"ErrImagePull", "parent snapshot sha256:def456 does not exist")
	if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.h.Cycle(context.Background())
	want := []string{
		"registry.local:5000/team/app:v2",
		"registry.local:5000/team/app@sha256:cafe",
	}
	if !slices.Equal(removed, want) {
		t.Fatalf("removed=%v want %v", removed, want)
	}
}

// --- check: cilium-bpf-ipam (38) ---

// runningPod builds a Running pod on node-a; hostNetwork excludes it
// from the IPAM in-use count.
func runningPod(name, ns, uid string, hostNetwork bool) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns, UID: types.UID(uid),
		},
		Spec:   corev1.PodSpec{NodeName: "node-a", HostNetwork: hostNetwork},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	if !hostNetwork {
		// The IPAM check counts "pods holding an address" — a pod
		// without status.podIP is treated as not holding one.
		p.Status.PodIP = "10.0.0.1"
	}
	return p
}

func TestCiliumIPAMLeakedLatch(t *testing.T) {
	e := fixture(t)
	// 40 cilium-allocated IPs but only 5 in-use pods → 35 leaked.
	e.unixBody = []byte(`{"ipam":{"ipv4":{"used":40,"available":100}}}`)
	latch := filepath.Join(e.state, "state-cilium-ipam-exhausted")
	for i := 0; i < 5; i++ {
		p := runningPod(fmt.Sprintf("app-%d", i), "default",
			fmt.Sprintf("uid-%d", i), false)
		if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch on first suspect cycle")
	}
	if !strings.Contains(logLines(t, e), "leaked=35") {
		t.Fatalf("missing suspect log:\n%s", logLines(t, e))
	}
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("latch missing after %d consecutive cycles: %v", 2, err)
	}
	if !strings.Contains(logLines(t, e), "STATE-ENTER: cilium-ipam-exhausted") {
		t.Fatalf("missing STATE-ENTER log:\n%s", logLines(t, e))
	}
	if got := testutil.ToFloat64(e.h.ciliumAllocated); got != 40 {
		t.Fatalf("allocated gauge=%v want 40", got)
	}
	if got := testutil.ToFloat64(e.h.ciliumLeaked); got != 35 {
		t.Fatalf("leaked gauge=%v want 35", got)
	}
}

func TestCiliumIPAMAvailableLowLatches(t *testing.T) {
	e := fixture(t)
	// Leak-free but the pool is nearly exhausted: available <=2 alone
	// arms the latch after ConsecNeeded.
	e.unixBody = []byte(`{"ipam":{"ipv4":{"used":5,"available":2}}}`)
	for i := 0; i < 5; i++ {
		p := runningPod(fmt.Sprintf("app-%d", i), "default",
			fmt.Sprintf("uid-%d", i), false)
		if _, err := e.cs.CoreV1().Pods("default").Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	latch := filepath.Join(e.state, "state-cilium-ipam-exhausted")
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch on first suspect cycle")
	}
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("latch missing on available<=2: %v", err)
	}
	if got := testutil.ToFloat64(e.h.ciliumLeaked); got != 0 {
		t.Fatalf("leaked gauge=%v want 0", got)
	}
}

func TestCiliumIPAMHealthyClearsLatch(t *testing.T) {
	e := fixture(t)
	e.unixBody = []byte(`{"ipam":{"ipv4":{"used":40,"available":100}}}`)
	latch := filepath.Join(e.state, "state-cilium-ipam-exhausted")
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("setup latch missing: %v", err)
	}
	// IPs reclaimed — leaked drops under the threshold.
	e.unixBody = []byte(`{"ipam":{"ipv4":{"used":10,"available":130}}}`)
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch kept after IPAM recovered")
	}
	if e.h.ciliumIPAMFails != 0 {
		t.Fatalf("counter=%d want 0 after recovery", e.h.ciliumIPAMFails)
	}
	if !strings.Contains(logLines(t, e), "STATE-EXIT: cilium-ipam-exhausted") {
		t.Fatalf("missing STATE-EXIT log:\n%s", logLines(t, e))
	}
}

func TestCiliumIPAMHostNetworkExcludedFromInUse(t *testing.T) {
	e := fixture(t)
	// used=32, one normal Running pod, one hostNetwork pod — if
	// hostNetwork were counted in-use would be 2 → leaked 30 (no
	// latch); correct exclusion gives leaked=31 >30 → latch.
	e.unixBody = []byte(`{"ipam":{"ipv4":{"used":32,"available":100}}}`)
	for _, p := range []*corev1.Pod{
		runningPod("app", "default", uidA, false),
		runningPod("node-local-dns-x", "kube-system", uidB, true),
	} {
		if _, err := e.cs.CoreV1().Pods(p.Namespace).Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	latch := filepath.Join(e.state, "state-cilium-ipam-exhausted")
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("latch missing — hostNetwork pod wrongly counted in-use: %v", err)
	}
	if got := testutil.ToFloat64(e.h.ciliumLeaked); got != 31 {
		t.Fatalf("leaked gauge=%v want 31 (hostNetwork excluded)", got)
	}
}

func TestCiliumIPAMInconclusiveKeepsCounter(t *testing.T) {
	e := fixture(t)
	e.unixBody = []byte(`{"ipam":{"ipv4":{"used":40,"available":100}}}`)
	e.h.Cycle(context.Background())
	if e.h.ciliumIPAMFails != 1 {
		t.Fatalf("counter=%d want 1", e.h.ciliumIPAMFails)
	}
	// Socket fails → inconclusive: counter kept, not reset (same
	// hysteresis rule as checkCiliumInitStuck).
	e.unixErr = errors.New("socket dead")
	e.h.Cycle(context.Background())
	if e.h.ciliumIPAMFails != 1 {
		t.Fatalf("counter=%d want 1 (inconclusive keeps)", e.h.ciliumIPAMFails)
	}
	if got := e.h.cycles.WithLabelValues(checkCiliumIPAM, "abort"); testutil.ToFloat64(got) != 1 {
		t.Fatalf("abort=%v want 1", testutil.ToFloat64(got))
	}
	// Garbage body → same inconclusive path.
	e.unixErr = nil
	e.unixBody = []byte(`{"cilium":{"state":"Ok"}}`)
	e.h.Cycle(context.Background())
	if e.h.ciliumIPAMFails != 1 {
		t.Fatalf("counter=%d want 1 (unparseable keeps)", e.h.ciliumIPAMFails)
	}
}

func TestCiliumIPAMUpstreamArrayShape(t *testing.T) {
	e := fixture(t)
	// Real cilium healthz shape: ipam.ipv4 is the allocated-IP list
	// and allocations maps each IP to an owner-name STRING
	// ({"ip": "pod-a"}) — cluster-pool free slots appear as entries
	// with an empty-string owner. used=40 allocated, 2 free.
	ips := make([]string, 0, 40)
	var b strings.Builder
	b.WriteString(`{"ipam":{"ipv4":[`)
	for i := 0; i < 40; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i+1)
		ips = append(ips, ip)
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "%q", ip)
	}
	b.WriteString(`],"allocations":{`)
	for i, ip := range ips {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "%q:%q", ip, fmt.Sprintf("pod-%d", i))
	}
	// Two pool entries with empty owner → available=2.
	b.WriteString(`,"10.0.0.250":"","10.0.0.251":""}}}`)
	e.unixBody = []byte(b.String())
	latch := filepath.Join(e.state, "state-cilium-ipam-exhausted")
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("latch missing (leaked=40>30 AND available=2): %v", err)
	}
	if got := testutil.ToFloat64(e.h.ciliumAllocated); got != 40 {
		t.Fatalf("allocated gauge=%v want 40 (array length)", got)
	}
}

func TestParseCiliumIPAMShapes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		body      string
		wantUsed  int
		wantAvail int
		wantOK    bool
	}{
		{"object numbers", `{"ipam":{"ipv4":{"used":10,"available":3}}}`, 10, 3, true},
		{"object collections", `{"ipam":{"ipv4":{"used":["a","b"],"available":[]}}}`, 2, 0, true},
		{"object missing available", `{"ipam":{"ipv4":{"used":4}}}`, 4, -1, true},
		{"array", `{"ipam":{"ipv4":["10.0.0.1","10.0.0.2"]}}`, 2, -1, true},
		{"array real allocations", `{"ipam":{"ipv4":["10.0.0.1"],"allocations":{"10.0.0.1":"pod-a","10.0.0.9":""}}}`, 1, 1, true},
		{"array all-owned allocations", `{"ipam":{"ipv4":["10.0.0.1"],"allocations":{"10.0.0.1":"pod-a"}}}`, 1, -1, true},
		{"bare number", `{"ipam":{"ipv4":7}}`, 7, -1, true},
		{"no ipam", `{"cilium":{"state":"Ok"}}`, 0, -1, false},
		{"garbage", `not json`, 0, -1, false},
		{"empty ipv4", `{"ipam":{"status":"Ok"}}`, 0, -1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			used, avail, ok := parseCiliumIPAM([]byte(tc.body))
			if ok != tc.wantOK || used != tc.wantUsed || avail != tc.wantAvail {
				t.Fatalf("parseCiliumIPAM(%s)=(%d,%d,%v) want (%d,%d,%v)",
					tc.body, used, avail, ok, tc.wantUsed, tc.wantAvail, tc.wantOK)
			}
		})
	}
}

// --- Wave-2 tests: A4 syncloop + containerd-sock ---

func TestSyncloopDownLatchesOnPLEGFreeze(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.status["https://127.0.0.1:10250/healthz/syncloop"] = 500
	for i := 0; i < 2; i++ {
		e.h.Cycle(context.Background())
	}
	if !e.h.stateExists("kubelet-syncloop-down") {
		t.Fatal("state-kubelet-syncloop-down should latch after 2 failed syncloop probes")
	}
	e.status["https://127.0.0.1:10250/healthz/syncloop"] = 200
	e.h.Cycle(context.Background())
	if e.h.stateExists("kubelet-syncloop-down") {
		t.Fatal("recovery should clear the syncloop latch")
	}
}

// TestSyncloopNon200LogsStatusCode: a non-200 answer carries no Go
// error — the suspect/latch lines must still record the code, not
// "last_err=<nil>".
func TestSyncloopNon200LogsStatusCode(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.status["https://127.0.0.1:10250/healthz/syncloop"] = 500
	e.h.Cycle(context.Background()) // streak 1 → suspect line
	if got := logLines(t, e); !strings.Contains(got, "status 500") {
		t.Fatalf("suspect line must carry the HTTP code, got:\n%s", got)
	}
	e.h.Cycle(context.Background()) // streak 2 → latch
	if !e.h.stateExists("kubelet-syncloop-down") {
		t.Fatal("latch expected after ConsecNeeded failed probes")
	}
	if got := logLines(t, e); strings.Contains(got, "last_err=<nil>") {
		t.Fatalf("latch extra must record the code, got:\n%s", got)
	}
}

func TestSyncloopFailClosedWhenActiveCheckErrors(t *testing.T) {
	e := fixture(t)
	// Force the Active() error path: no is-active reply leaves the
	// fake answering ENOENT — the gate is wired but unverifiable,
	// so worker checks must gate off (fail closed). The syncloop
	// probe is ALSO failing — if the gate didn't hold, two cycles
	// would latch kubelet-syncloop-down.
	delete(e.sdReply, "systemctl is-active k0sworker.service")
	e.status["https://127.0.0.1:10250/healthz/syncloop"] = 500
	for i := 0; i < 2; i++ {
		e.h.Cycle(context.Background())
	}
	if e.h.stateExists("kubelet-syncloop-down") {
		t.Fatal("no latch may be written while the unit state is unknown")
	}
}

// TestSyncloopUnauthorizedIsInconclusive: a 401/403 answer means
// kubelet is alive but won't divulge the syncloop verdict — the
// check must neither latch nor count failures, and the notice is
// logged once per unauth streak, not every cycle.
func TestSyncloopUnauthorizedIsInconclusive(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.status["https://127.0.0.1:10250/healthz/syncloop"] = 401
	for i := 0; i < 3; i++ {
		e.h.Cycle(context.Background())
	}
	if e.h.stateExists("kubelet-syncloop-down") {
		t.Fatal("401 must not latch kubelet-syncloop-down")
	}
	got := logLines(t, e)
	if !strings.Contains(got, "probe unauthorized") {
		t.Fatalf("expected an unauthorized/inconclusive log line, got:\n%s", got)
	}
	if n := strings.Count(got, "probe unauthorized"); n != 1 {
		t.Fatalf("unauthorized should log once per streak, got %d lines:\n%s", n, got)
	}
	// A real verdict ends the streak — a later unauth stretch logs
	// again.
	e.status["https://127.0.0.1:10250/healthz/syncloop"] = 200
	e.h.Cycle(context.Background())
	e.status["https://127.0.0.1:10250/healthz/syncloop"] = 401
	e.h.Cycle(context.Background())
	if n := strings.Count(logLines(t, e), "probe unauthorized"); n != 2 {
		t.Fatalf("unauth after a healthy verdict must re-log, got %d lines", n)
	}
}

// TestSyncloopProbeSendsBearerToken: kubelet :10250 denies anonymous
// /healthz — the SA token from KubeletTokenPath must ride the probe.
func TestSyncloopProbeSendsBearerToken(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	tok := filepath.Join(e.state, "sa-token")
	writeFile(t, tok, "tok-abc-123\n")
	e.h.cfg.KubeletTokenPath = tok
	e.h.Cycle(context.Background())
	if got := e.bearer["https://127.0.0.1:10250/healthz/syncloop"]; got != "tok-abc-123" {
		t.Fatalf("syncloop probe bearer = %q, want the SA token", got)
	}
}

func TestContainerdSockDownLatches(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.sockErrs[e.h.cfg.ContainerdSocket] = fmt.Errorf("connection refused")
	for i := 0; i < 2; i++ {
		e.h.Cycle(context.Background())
	}
	if !e.h.stateExists("containerd-sock-down") {
		t.Fatal("state-containerd-sock-down should latch after 2 socket failures")
	}
	e.sockErrs[e.h.cfg.ContainerdSocket] = nil
	e.h.Cycle(context.Background())
	if e.h.stateExists("containerd-sock-down") {
		t.Fatal("recovery should clear the containerd-sock latch")
	}
}

// TestContainerdSocketDefaultPinsK0sPath: k0s puts the containerd
// socket at /run/k0s/containerd.sock — the nested
// /run/k0s/containerd/ dir is containerd's state root, NOT the
// socket. Probing inside it is a permanent ENOENT that latches
// containerd-sock-down on every agent start (the A4 bug this
// pins).
func TestContainerdSocketDefaultPinsK0sPath(t *testing.T) {
	c := Config{}
	c.applyDefaults()
	if c.ContainerdSocket != "/host/run/k0s/containerd.sock" {
		t.Fatalf("default ContainerdSocket=%q, want /host/run/k0s/containerd.sock",
			c.ContainerdSocket)
	}
	if c.KubeletTokenPath != "/var/run/secrets/kubernetes.io/serviceaccount/token" {
		t.Fatalf("default KubeletTokenPath=%q, want the pod SA token path",
			c.KubeletTokenPath)
	}
}

// --- A3: ingest GC ---

func TestCtrIngestGCCleansStaleDirs(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.diskUsed = 0.90 // above the 75% watermark
	stale := filepath.Join(e.ingest, "deadbeefref")
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-4 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	e.h.Cycle(context.Background())
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale ingest dir should be removed, stat err=%v", err)
	}
	if !e.sdRan("ctr ingest rm deadbeefref") {
		t.Fatal("ctr ingest rm should run for the stale ref")
	}
	got, err := counterValue(e.h.ctrIngestsCleaned)
	if err != nil || got != 1 {
		t.Fatalf("ctr_ingests_cleaned_total=%v err=%v want 1", got, err)
	}
}

func TestCtrIngestGCSkipsFreshDirsWhenDiskLow(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.diskUsed = 0.10
	// first cycle marks lastIngestScan (due on start); make a fresh
	// dir and verify a second cycle under low disk skips it.
	e.h.Cycle(context.Background())
	fresh := filepath.Join(e.ingest, "stillpulling")
	if err := os.MkdirAll(fresh, 0o755); err != nil {
		t.Fatal(err)
	}
	e.h.Cycle(context.Background())
	if _, err := os.Stat(fresh); err != nil {
		t.Fatal("fresh ingest dir must not be removed")
	}
}

// TestCtrIngestGCFailedScanRetriesNextCycle: a transient ReadDir
// failure must NOT stamp lastIngestScan — stamping would defer the
// retry by a full 6h CtrIngestScanInterval. The next cycle after
// the dir recovers must still scan (disk below the watermark, so
// only the unstamped due-check lets it in).
func TestCtrIngestGCFailedScanRetriesNextCycle(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.diskUsed = 0.10 // below watermark — only `due` triggers a scan
	// Break the ingest dir: a plain FILE where a dir is expected →
	// ReadDir errors (ENOTDIR, not IsNotExist) → abort, no stamp.
	if err := os.RemoveAll(e.ingest); err != nil {
		t.Fatal(err)
	}
	writeFile(t, e.ingest, "not a dir")
	e.h.Cycle(context.Background())
	// Repair the dir with one stale ingest — if the failed scan
	// had stamped lastIngestScan this cycle would be not-due and
	// skip the cleanup.
	if err := os.Remove(e.ingest); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(e.ingest, "deadbeefref")
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-4 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	e.h.Cycle(context.Background())
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("failed scan must not defer retry — stale dir should be removed, stat err=%v", err)
	}
}

// TestCtrIngestGCBavailOverBlocksSaturates: btrfs/XFS can report
// Bavail > Blocks — the uint64 subtraction wraps to ~2^64 and
// diskHigh sticks true, sweeping the GC every cycle. The saturation
// guard must keep it low (concourse fsPressure parity).
func TestCtrIngestGCBavailOverBlocksSaturates(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.h.cfg.statfsFn = func(_ string, st *unix.Statfs_t) error {
		st.Blocks, st.Bavail = 100, 120 // free > total
		return nil
	}
	// First cycle stamps lastIngestScan so the second is not `due`.
	e.h.Cycle(context.Background())
	stale := filepath.Join(e.ingest, "deadbeefref")
	if err := os.MkdirAll(stale, 0o755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-4 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	e.h.Cycle(context.Background())
	if _, err := os.Stat(stale); err != nil {
		t.Fatal("stale ingest dir swept under wrapped-free disk pressure")
	}
}

// --- A2: zombie storm ---

// mkZombieProc writes a Z-state stat for pid whose parent is ppid.
func mkZombieProc(t *testing.T, e *env, pid, ppid int) {
	t.Helper()
	d := filepath.Join(e.proc, fmt.Sprint(pid))
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	stat := fmt.Sprintf("%d (defunct) Z %d 0 0 0", pid, ppid)
	if err := os.WriteFile(filepath.Join(d, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestZombieStormLatchesAndLogsAction(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.h.cfg.ZombieStormThreshold = 3 // fake proc trees are small
	uid := "11111111_2222_3333_4444_555555555555"
	parent := filepath.Join(e.proc, "777")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	cg := "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + uid + ".slice/cri-containerd-x.scope\n"
	if err := os.WriteFile(filepath.Join(parent, "cgroup"), []byte(cg), 0o644); err != nil {
		t.Fatal(err)
	}
	for pid := 800; pid < 805; pid++ {
		mkZombieProc(t, e, pid, 777)
	}
	for i := 0; i < 2; i++ {
		e.h.Cycle(context.Background())
	}
	if !e.h.stateExists("zombie-storm") {
		t.Fatal("state-zombie-storm should latch after 2 storm cycles")
	}
	data, err := os.ReadFile(e.h.cfg.WatchdogLogFile)
	if err != nil {
		t.Fatal(err)
	}
	want := "ACTION zombie-storm: pod_uid=11111111-2222-3333-4444-555555555555 zombies=5"
	if !strings.Contains(string(data), want) {
		t.Fatalf("log should contain %q; got:\n%s", want, data)
	}
}

// mkParentProc writes a LIVE parent's stat under ProcRoot with the
// given starttime (field 22) — the streak key's generation tag, so
// tests can simulate PID reuse by rewriting start.
func mkParentProc(t *testing.T, e *env, pid int, starttime string) {
	t.Helper()
	// Fields after ')' start at field 3: f[0]=state … f[19]=
	// starttime (field 22) — 20 fields total.
	writeFile(t, filepath.Join(e.proc, fmt.Sprint(pid), "stat"),
		fmt.Sprintf("%d (parent) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 %s",
			pid, starttime))
}

// TestZombieStormActionLoggedOncePerEpisode: while the storm
// persists the latch holds but the ACTION line must NOT repeat —
// every repeat becomes a fresh K8s Event via nodereporter.
func TestZombieStormActionLoggedOncePerEpisode(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.h.cfg.ZombieStormThreshold = 3
	mkParentProc(t, e, 777, "111111")
	for pid := 800; pid < 805; pid++ {
		mkZombieProc(t, e, pid, 777)
	}
	for i := 0; i < 4; i++ {
		e.h.Cycle(context.Background())
	}
	if !e.h.stateExists("zombie-storm") {
		t.Fatal("storm latch should hold while the storm persists")
	}
	if n := strings.Count(logLines(t, e), "ACTION zombie-storm:"); n != 1 {
		t.Fatalf("ACTION zombie-storm logged %d times over 4 storm cycles, want 1", n)
	}
}

// TestZombieStormPIDReuseResetsStreak: streaks key on (ppid,
// starttime) — a recycled ppid starts at 0 instead of inheriting
// the dead parent's count and holding a dead latch open.
func TestZombieStormPIDReuseResetsStreak(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.h.cfg.ZombieStormThreshold = 3
	mkParentProc(t, e, 777, "111111")
	for pid := 800; pid < 805; pid++ {
		mkZombieProc(t, e, pid, 777)
	}
	e.h.Cycle(context.Background()) // streak 1
	e.h.Cycle(context.Background()) // streak 2 → ACTION + latch
	if !e.h.stateExists("zombie-storm") {
		t.Fatal("latch expected after 2 storm cycles")
	}
	// pid 777 is RECYCLED — same ppid, different starttime. The
	// dead parent's streak must not carry: the new generation
	// restarts at streak 1, the latch drops, no second ACTION yet.
	mkParentProc(t, e, 777, "222222")
	e.h.Cycle(context.Background())
	if e.h.stateExists("zombie-storm") {
		t.Fatal("recycled ppid must not inherit the dead parent's streak")
	}
	if n := strings.Count(logLines(t, e), "ACTION zombie-storm:"); n != 1 {
		t.Fatalf("ACTION zombie-storm count=%d want 1", n)
	}
	// The new generation earns its own streak — latch + ACTION
	// again on its own entry.
	e.h.Cycle(context.Background())
	if !e.h.stateExists("zombie-storm") {
		t.Fatal("recycled parent's own streak should re-latch")
	}
	if n := strings.Count(logLines(t, e), "ACTION zombie-storm:"); n != 2 {
		t.Fatalf("recycled parent logs its own ACTION on streak entry; count=%d want 2", n)
	}
}

// TestZombieStormLatchDropsBelowThreshold: a stored streak must be
// re-validated against THIS cycle's count before it can hold the
// latch — previously the streak loop latched on any live parent
// with ≥1 zombie, keeping the latch one extra cycle after the
// storm dropped under the threshold.
func TestZombieStormLatchDropsBelowThreshold(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.h.cfg.ZombieStormThreshold = 3
	mkParentProc(t, e, 777, "111111")
	for pid := 800; pid < 805; pid++ {
		mkZombieProc(t, e, pid, 777)
	}
	e.h.Cycle(context.Background())
	e.h.Cycle(context.Background())
	if !e.h.stateExists("zombie-storm") {
		t.Fatal("latch expected after 2 storm cycles")
	}
	// Storm drains to 2 zombies (≤ threshold but >0) — the parent
	// still has zombie children, but the latch must drop NOW.
	for pid := 800; pid < 803; pid++ {
		if err := os.RemoveAll(filepath.Join(e.proc, fmt.Sprint(pid))); err != nil {
			t.Fatal(err)
		}
	}
	e.h.Cycle(context.Background())
	if e.h.stateExists("zombie-storm") {
		t.Fatal("latch held an extra cycle after storm dropped below threshold")
	}
}

// --- A5: journald integrity ---

func TestJournaldCorruptionRotates(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.journal = "File corruption detected at /var/log/journal/x.journal"
	for i := 0; i < 2; i++ {
		e.h.Cycle(context.Background())
	}
	if !e.sdRan("journalctl --rotate --vacuum-time=3d") {
		t.Fatal("corrupt journal should trigger rotate --vacuum-time=3d")
	}
}

func TestJournaldEmptyWhileActiveRotates(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.journal = "" // abnormally empty
	// …and the unfiltered `journalctl -n 1` probe errors too (no
	// sdReply → ENOENT) — journald itself is anomalous, so the
	// empty k0sworker window counts as corruption evidence.
	for i := 0; i < 2; i++ {
		e.h.Cycle(context.Background())
	}
	if !e.sdRan("journalctl --rotate --vacuum-time=3d") {
		t.Fatal("empty journal for active unit should trigger rotate")
	}
}

// TestJournaldEmptyAndUnfilteredEmptyRotates: same remediation when
// the second probe answers but the whole journal is silent.
func TestJournaldEmptyAndUnfilteredEmptyRotates(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.journal = ""
	e.sdReply["journalctl -n 1"] = "" // journald answers — with nothing
	for i := 0; i < 2; i++ {
		e.h.Cycle(context.Background())
	}
	if !e.sdRan("journalctl --rotate --vacuum-time=3d") {
		t.Fatal("journald-wide silence should trigger rotate")
	}
}

// TestJournaldQuietUnitHealthyJournaldNoRotate is the false-
// positive guard: an empty k0sworker window is only corruption
// evidence when journald ITSELF is anomalous. A healthy-but-quiet
// unit (journald returns real entries unfiltered) must NOT spend
// the rotate+vacuum remedy every cooldown.
func TestJournaldQuietUnitHealthyJournaldNoRotate(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.journal = "" // no k0sworker lines in 10m — just a quiet unit
	e.sdReply["journalctl -n 1"] =
		"May 01 12:00:00 node-a systemd[1]: Started Daily Cleanup.\n"
	for i := 0; i < 2; i++ {
		e.h.Cycle(context.Background())
	}
	if e.sdRan("journalctl --rotate --vacuum-time=3d") {
		t.Fatal("quiet unit on a healthy journald must not trigger rotate+vacuum")
	}
	if !e.sdRan("journalctl -n 1 --no-pager") {
		t.Fatal("the unfiltered journald probe should have run for the empty case")
	}
}

// TestJournaldExecErrorNoVacuum: an exec-level read failure
// (nsenter/journalctl timeout) is journal-UNREADABLE, not corruption
// — it must never spend the rotate+vacuum remedy.
func TestJournaldExecErrorNoVacuum(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.journalErr = fmt.Errorf("exec timeout")
	for i := 0; i < 3; i++ {
		e.h.Cycle(context.Background())
	}
	if e.sdRan("journalctl --rotate --vacuum-time=3d") {
		t.Fatal("rotate+vacuum spent on a transient exec failure")
	}
}

// --- B1: cilium-envoy ---

// mkCiliumContainer registers a cilium container task dir named
// like the container (cilium-agent / cilium-envoy) with a live pid.
func mkCiliumContainer(t *testing.T, e *env, name string, pid int) {
	t.Helper()
	d := filepath.Join(e.ctr, "id-"+name)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := `{"labels":{"io.kubernetes.container.name":"` + name + `"}}`
	if err := os.WriteFile(filepath.Join(d, "config.json"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "init.pid"), []byte(fmt.Sprint(pid)), 0o644); err != nil {
		t.Fatal(err)
	}
	e.live[pid] = true
}

func TestCiliumEnvoyUnreadyKillAfterConsec(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	mkCiliumContainer(t, e, "cilium-envoy", 555)
	e.status["http://127.0.0.1:9964/ready"] = 503
	for i := 0; i < 2; i++ {
		e.h.Cycle(context.Background())
	}
	if !e.h.stateExists("cilium-envoy-down") {
		t.Fatal("state-cilium-envoy-down should latch after 2 unready cycles")
	}
	found := false
	for _, k := range e.kills {
		if k.pid == 555 && k.sig == syscall.SIGKILL {
			found = true
		}
	}
	if !found {
		t.Fatal("envoy pid should be SIGKILLed after ConsecNeeded unready cycles")
	}
}

func TestCiliumEnvoyKilledWithAgent(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	mkCiliumContainer(t, e, "cilium-agent", 444)
	mkCiliumContainer(t, e, "cilium-envoy", 555)
	e.probes["http://127.0.0.1:9879/healthz"] = fmt.Errorf("down")
	for i := 0; i < 2; i++ {
		e.h.Cycle(context.Background())
	}
	killed := map[int]bool{}
	for _, k := range e.kills {
		if k.sig == syscall.SIGKILL {
			killed[k.pid] = true
		}
	}
	if !killed[444] || !killed[555] {
		t.Fatalf("agent kill must restart envoy too; kills=%v", e.kills)
	}
}

// --- B4: MTU drift ---

func TestCiliumMTUDriftLatchesAndLogs(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	writeFile(t, filepath.Join(e.sysnet, "neb1", "mtu"), "1300\n")
	writeFile(t, filepath.Join(e.sysnet, "cilium_net", "mtu"), "1500\n")
	e.h.Cycle(context.Background())
	if !e.h.stateExists("cilium-mtu-drift") {
		t.Fatal("state-cilium-mtu-drift should latch when cilium_mtu > neb1")
	}
	data, err := os.ReadFile(e.h.cfg.WatchdogLogFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "ACTION cilium-mtu-drift: cilium=1500 nebula=1300") {
		t.Fatalf("log missing drift ACTION line:\n%s", data)
	}
	// Drift fixed → latch clears.
	writeFile(t, filepath.Join(e.sysnet, "cilium_net", "mtu"), "1300\n")
	e.h.Cycle(context.Background())
	if e.h.stateExists("cilium-mtu-drift") {
		t.Fatal("latch should clear once MTUs align")
	}
}

func TestCiliumMTURuntimeConfigFallback(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	writeFile(t, filepath.Join(e.sysnet, "neb1", "mtu"), "1300\n")
	writeFile(t, e.ciliumRt, `{"mtu":1500,"other":1}`)
	e.h.Cycle(context.Background())
	if !e.h.stateExists("cilium-mtu-drift") {
		t.Fatal("runtime-config MTU 1500 > neb1 1300 should latch drift")
	}
}

// TestRuntimeConfigMTUMaxDeterministic pins the multi-mtu
// behaviour: several `mtu`-keyed values (nested maps AND arrays)
// must resolve to the MAX — a "first match" walk is unstable
// under Go's random map iteration order.
func TestRuntimeConfigMTUMaxDeterministic(t *testing.T) {
	e := fixture(t)
	writeFile(t, e.ciliumRt,
		`{"a":{"mtu":1300},"list":[{"mtu":1400},{"mtu":1500}],"z":{"MTU":900}}`)
	got, ok := runtimeConfigMTU(e.ciliumRt)
	if !ok || got != 1500 {
		t.Fatalf("runtimeConfigMTU=%v,%v want 1500,true (max of all mtu keys)", got, ok)
	}
}

// TestProbeUnixSockDefaultReturnsNilOnConnect: a successful dial IS
// the verdict — conn.Close()'s error must not leak into the result.
func TestProbeUnixSockDefaultReturnsNilOnConnect(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "probe.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c := Config{}
	c.applyDefaults()
	if err := c.probeUnixSock(context.Background(), sock, time.Second); err != nil {
		t.Fatalf("successful unix dial want nil, got %v", err)
	}
}

// counterValue reads a prometheus.Counter for tests.
func counterValue(c prometheus.Counter) (float64, error) {
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		return 0, err
	}
	return m.GetCounter().GetValue(), nil
}

// --- journal-unreadable blindness latch (journalwatch tracker) ---
// A broken journald (killed journalctl, "No journal files", or a
// journald-wide empty reply) blinds the 05/06 signature greps AND
// the A5 probe itself — this must surface as state-journal-unreadable,
// not just rotate+vacuum cooldowns.

func TestJournalUnreadableLatchesAfterConsecFails(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.journalErr = fmt.Errorf("signal: killed") // journalctl dies every read
	// Each cycle feeds up to two reads into the tracker (the lazy
	// journalOnce snapshot + the A5 probe) — one cycle is a streak
	// below Needed, three must have latched.
	e.h.Cycle(context.Background())
	if e.h.stateExists(stateJournalUnreadable) {
		t.Fatal("latched before the streak reached Needed")
	}
	for i := 0; i < 2; i++ {
		e.h.Cycle(context.Background())
	}
	if !e.h.stateExists(stateJournalUnreadable) {
		t.Fatal("state-journal-unreadable not latched after persistent read failures")
	}
	if n := strings.Count(logLines(t, e), "suspect: journal-unreadable"); n != 1 {
		t.Fatalf("suspect lines=%d want 1 on latch entry", n)
	}
	// Held latch: no repeat lines on later cycles.
	for i := 0; i < 3; i++ {
		e.h.Cycle(context.Background())
	}
	if n := strings.Count(logLines(t, e), "suspect: journal-unreadable"); n != 1 {
		t.Fatalf("suspect repeated while latch held: %d", n)
	}
}

func TestJournalUnreadableClearsOnRecovery(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.journalErr = fmt.Errorf("signal: killed")
	for i := 0; i < defaultJournalUnreadableNeeded; i++ {
		e.h.Cycle(context.Background())
	}
	if !e.h.stateExists(stateJournalUnreadable) {
		t.Fatal("precondition: latch should be held")
	}
	e.journalErr = nil
	e.journal = "Oct 01 node k0sworker: healthy line\n"
	e.h.Cycle(context.Background())
	if e.h.stateExists(stateJournalUnreadable) {
		t.Fatal("latch not cleared on first healthy read")
	}
	if n := strings.Count(logLines(t, e), "STATE-EXIT: journal-unreadable"); n != 1 {
		t.Fatalf("STATE-EXIT lines=%d want 1", n)
	}
}

func TestJournalUnreadableNoFireWithoutJournalDir(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	// No journal storage at all — journald legitimately absent is a
	// config, not a failure: reads failing forever must never latch.
	e.h.journalReads.Dirs = []string{filepath.Join(t.TempDir(), "missing")}
	e.journalErr = fmt.Errorf("signal: killed")
	for i := 0; i < defaultJournalUnreadableNeeded+2; i++ {
		e.h.Cycle(context.Background())
	}
	if e.h.stateExists(stateJournalUnreadable) {
		t.Fatal("latched without any journal storage — must not fire")
	}
	if n := strings.Count(logLines(t, e), "suspect: journal-unreadable"); n != 0 {
		t.Fatalf("suspect lines=%d want 0", n)
	}
}

func TestJournalUnreadableEmptyWindowSilentJournaldFires(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.journal = ""                    // empty 10m k0sworker window
	e.sdReply["journalctl -n 1"] = "" // …and journald-wide silence
	for i := 0; i < defaultJournalUnreadableNeeded; i++ {
		e.h.Cycle(context.Background())
	}
	if !e.h.stateExists(stateJournalUnreadable) {
		t.Fatal("journald-wide silence should latch journal-unreadable")
	}
}

func TestJournalUnreadableQuietUnitNoFire(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.journal = "" // quiet k0sworker window…
	e.sdReply["journalctl -n 1"] =
		"Oct 01 node systemd[1]: Started Daily Cleanup.\n" // …but journald answers
	for i := 0; i < defaultJournalUnreadableNeeded+2; i++ {
		e.h.Cycle(context.Background())
	}
	if e.h.stateExists(stateJournalUnreadable) {
		t.Fatal("quiet unit on healthy journald must not latch")
	}
}

func TestJournalUnreadableFilesGoneMarkerFires(t *testing.T) {
	e := fixture(t)
	e.sdReply["is-active k0sworker.service"] = "active"
	e.journal = "No journal files were found.\n"
	for i := 0; i < defaultJournalUnreadableNeeded; i++ {
		e.h.Cycle(context.Background())
	}
	if !e.h.stateExists(stateJournalUnreadable) {
		t.Fatal("'No journal files' reads should latch journal-unreadable")
	}
}
