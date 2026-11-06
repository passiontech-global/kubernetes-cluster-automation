package workerhygiene

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	nhatestutil "github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
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
	// sdHook, when set, runs inside sdRun before the reply lookup —
	// tests advance the fake clock here to simulate a slow host
	// call (e.g. a D-Bus round trip taking seconds).
	sdHook func(joined string)
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
	if e.sdHook != nil {
		e.sdHook(joined)
	}
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

	e.cs = nhatestutil.FakeKube(objs...)
	// Host up 2h — the uptime file feeds BOTH the Cycle G1 uptime
	// gate (hostutil.UptimeSeconds)
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
		K0sWorkerUnitFile:  e.unit,
		Client:             e.cs,
		Systemd:            sd,
		ConsecNeeded:       2,
		MinRestartInterval: 30 * time.Minute,
		Net: NetConfig{
			HostResolvConf: e.resv,
			SysClassNet:    e.sysnet,
		},
		Kubelet: KubeletConfig{
			PodsDir:     e.kubepods,
			WatchMinAge: 15 * time.Minute,
		},
		Teardown: TeardownConfig{
			StuckDeleteAge: 15 * time.Minute,
			StuckWedgeAge:  30 * time.Minute,
			MaxForceDelete: 5,
		},
		// Wave-2 knobs: paths under the fixture root, never the real
		// /sys or /var/lib/k0s.
		Ctr: CtrConfig{
			IngestDir:    e.ingest,
			MaxTaskClean: 5,
			MaxShimKill:  10,
		},
		Cilium: CiliumConfig{
			RuntimeConfig: e.ciliumRt,
		},
		Disk: DiskConfig{
			K0sDataDir: filepath.Join(root, "k0sdata"),
		},
		Pressure: PressureConfig{
			ZombieStormThreshold: 500,
		},
		Journal: JournalConfig{
			Dirs: []string{e.jdir},
		},
	}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	// Test seams: signals never touch real processes, probes are
	// canned, the journal snapshot is a string.
	h.cfg.Seams.killFn = func(pid int, sig syscall.Signal) error {
		if sig == 0 {
			if e.live[pid] {
				return nil
			}
			return syscall.ESRCH
		}
		e.kills = append(e.kills, killRecord{pid, sig})
		return nil
	}
	h.cfg.Seams.nowFn = func() time.Time { return e.now }
	h.cfg.ProbeGap = 0             // tests run real-time — no 2s sleep between probes
	h.cfg.Kubelet.WdReprobeGap = 0 // same: no 3s sleep between Gate-0 re-probes
	h.cfg.Seams.probeHTTP = func(_ context.Context, url string, _ time.Duration) error {
		return e.probes[url]
	}
	// Feeder seam: bodyOK[url] answers "does :10248 return body 'ok'".
	// Unset entry → false (unhealthy) — gate tests want fails anyway.
	h.cfg.Seams.probeBodyOK = func(_ context.Context, url string, _ time.Duration) bool {
		return e.bodyOK[url]
	}
	h.cfg.Seams.unixGet = func(_ context.Context, _, _ string) ([]byte, error) {
		return e.unixBody, e.unixErr
	}
	h.cfg.Seams.journalFn = func(_ context.Context) (string, error) {
		return e.journal, e.journalErr
	}
	// Wave-2 seams: status-code probes default 200 (healthy) unless
	// probes[url] errors or status[url] overrides; the unix socket
	// probe answers from sockErrs (nil = connects); statfs reports
	// e.diskUsed of 100 blocks.
	h.cfg.Seams.probeHTTPStatus = func(_ context.Context, url, bearer string, _ time.Duration) (int, error) {
		e.bearer[url] = bearer
		if err := e.probes[url]; err != nil {
			return 0, err
		}
		if s, ok := e.status[url]; ok {
			return s, nil
		}
		return 200, nil
	}
	h.cfg.Seams.probeUnixSock = func(_ context.Context, socket string, _ time.Duration) error {
		return e.sockErrs[socket]
	}
	h.cfg.Seams.statfsFn = func(_ string, st *unix.Statfs_t) error {
		st.Blocks = 100
		st.Bavail = uint64(100 - int(e.diskUsed*100))
		return nil
	}
	h.cfg.Seams.ctrRmIngest = func(_ context.Context, ref string) error {
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
	writeFile(t, filepath.Join(dir, "init.pid"), strconv.Itoa(pid))
}

// mkProc puts a fake process under ProcRoot: stat with the given
// state char + optional cmdline/environ content.
func (e *env) mkProc(t *testing.T, pid int, state string, cmdline, environ string) {
	t.Helper()
	writeFile(t, filepath.Join(e.proc, strconv.Itoa(pid), "stat"),
		fmt.Sprintf("%d (fakeproc) %s 0 0 0", pid, state))
	e.live[pid] = state != "Z"
	if cmdline != "" {
		writeFile(t, filepath.Join(e.proc, strconv.Itoa(pid), "cmdline"), cmdline)
	}
	if environ != "" {
		writeFile(t, filepath.Join(e.proc, strconv.Itoa(pid), "environ"), environ)
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

// evictActions returns the pod names evicted through the
// policy/v1 Eviction subresource — the fake clientset records them
// as create actions on pods/eviction carrying the *policyv1.Eviction
// object (W9: the PSI evictor uses the eviction API so PDBs are
// enforced, not raw deletes).
func evictActions(cs *fake.Clientset) []string {
	var out []string
	for _, a := range cs.Actions() {
		ca, ok := a.(k8stesting.CreateAction)
		if !ok || a.GetResource().Resource != "pods" ||
			a.GetSubresource() != "eviction" {
			continue
		}
		if ev, ok := ca.GetObject().(*policyv1.Eviction); ok {
			out = append(out, ev.Name)
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

// --- plumbing ---

func TestStateEnterExitTransitionLogsOnce(t *testing.T) {
	e := fixture(t)
	e.h.state.Enter("test-state", "extra=1")
	e.h.state.Enter("test-state", "extra=1") // idempotent — one log line
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
	e.h.state.Exit("test-state", nil)
	e.h.state.Exit("test-state", nil)
	if got := strings.Count(logLines(t, e), "STATE-EXIT: test-state"); got != 1 {
		t.Fatalf("STATE-EXIT lines=%d want 1", got)
	}
}

func TestRateOKSpend(t *testing.T) {
	e := fixture(t)
	name := "last-test"
	if !e.h.state.RateOK(name, 30*time.Minute) {
		t.Fatal("rateOK on absent file want true")
	}
	e.h.state.RateSpend(name)
	if e.h.state.RateOK(name, 30*time.Minute) {
		t.Fatal("rateOK right after spend want false")
	}
	e.now = e.now.Add(31 * time.Minute)
	if !e.h.state.RateOK(name, 30*time.Minute) {
		t.Fatal("rateOK after interval want true")
	}
	// Garbage content → 0 → ok (shell parity).
	writeFile(t, filepath.Join(e.state, name), "garbage\n")
	if !e.h.state.RateOK(name, 30*time.Minute) {
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

	e.h.state.Enter("x", "")

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

// --- check 7/8: cilium (32 + 35) ---

// mkCiliumTask creates a cilium-agent containerd task dir with a live
// init pid.
func (e *env) mkCiliumTask(t *testing.T, pid int) {
	t.Helper()
	dir := filepath.Join(e.ctr, "ciliumagent"+strings.Repeat("0", 54))
	cfg := `{"annotations":{"io.kubernetes.pod.uid":"` + uidE +
		`","io.kubernetes.container.name":"cilium-agent"}}`
	writeFile(t, filepath.Join(dir, "config.json"), cfg)
	writeFile(t, filepath.Join(dir, "init.pid"), strconv.Itoa(pid))
	writeFile(t, filepath.Join(dir, "log.json"), "{}\n")
	e.mkProc(t, pid, "S", "", "")
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

// TestRateTrySpendAtomic: the shared last-* budgets are checked and
// spent by BOTH the feeder goroutine and Cycle — check+spend under
// the hoststate store mutex means exactly one winner per window.
func TestRateTrySpendAtomic(t *testing.T) {
	e := fixture(t)
	const n = 8
	var wins atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e.h.state.RateTrySpend("last-restart", e.h.cfg.MinRestartInterval) {
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
