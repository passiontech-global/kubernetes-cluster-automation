package nodereporter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	nhatestutil "github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// env is the shared fixture: tempdir watchdog state dir + log file, a
// fake clientset holding one Node, and a controllable clock.
type env struct {
	r      *Reporter
	cs     *fake.Clientset
	reg    *prometheus.Registry
	dir    string // WatchdogStateDir
	log    string // WatchdogLogFile
	kmsg   string // KmsgFile
	mounts string // ProcMountsFile
	uptime string // ProcUptimeFile
	root   string // HostRoot
	now    time.Time
}

func fixture(t *testing.T, objs ...runtime.Object) *env {
	t.Helper()
	root := t.TempDir()
	e := &env{
		dir:    filepath.Join(root, "watchdog"),
		log:    filepath.Join(root, "node-watchdog.log"),
		kmsg:   filepath.Join(root, "kmsg"),
		mounts: filepath.Join(root, "mounts"),
		uptime: filepath.Join(root, "uptime"),
		root:   root,
		now:    time.Now().Truncate(time.Second),
	}
	if err := os.MkdirAll(e.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Keep every cycle hermetic: the kmsg tail and the journal seam
	// default to empty sources under t.TempDir, never the real host
	// /dev/kmsg or journalctl.
	for _, f := range []struct{ path, body string }{
		{e.mounts, "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n" +
			"/dev/vda1 / ext4 rw,relatime 0 0\n" +
			"/dev/vdb1 /var/lib/k0s ext4 rw,relatime 0 0\n"},
		{e.uptime, "3600.00 7200.00\n"},
		{e.kmsg, ""}, // present-but-empty → kernel monitor tails it, no journald fallback
	} {
		if err := os.WriteFile(f.path, []byte(f.body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if len(objs) == 0 {
		objs = []runtime.Object{&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "n1"},
		}}
	}
	e.cs = nhatestutil.FakeKube(objs...)
	e.reg = prometheus.NewRegistry()
	r, err := New(Config{
		NodeName:         "n1",
		Client:           e.cs,
		WatchdogStateDir: e.dir,
		WatchdogLogFile:  e.log,
		HostRoot:         e.root,
		KmsgFile:         e.kmsg,
		ProcMountsFile:   e.mounts,
		ProcUptimeFile:   e.uptime,
		journalFetch:     func(context.Context, ...string) (string, error) { return "", nil },
		nowFn:            func() time.Time { return e.now },
	}, e.reg)
	if err != nil {
		t.Fatal(err)
	}
	e.r = r
	return e
}

func (e *env) writeFile(name, content string) {
	if err := os.WriteFile(filepath.Join(e.dir, name), []byte(content), 0o644); err != nil {
		panic(err)
	}
}

func (e *env) node(t *testing.T) *corev1.Node {
	t.Helper()
	n, err := e.cs.CoreV1().Nodes().Get(context.Background(), "n1", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *env) cond(t *testing.T, typ corev1.NodeConditionType) corev1.NodeCondition {
	t.Helper()
	for _, c := range e.node(t).Status.Conditions {
		if c.Type == typ {
			return c
		}
	}
	t.Fatalf("condition %s not found on node", typ)
	return corev1.NodeCondition{}
}

// patches counts node status PATCH actions recorded on the tracker.
func (e *env) patches() int {
	n := 0
	for _, a := range e.cs.Actions() {
		if a.GetVerb() == "patch" && a.GetResource().Resource == "nodes" {
			n++
		}
	}
	return n
}

func (e *env) gauge(typ, reason string) float64 {
	return testutil.ToFloat64(e.r.problemGauge.WithLabelValues(typ, reason))
}

func (e *env) counter(reason string) float64 {
	return testutil.ToFloat64(e.r.problemCounter.WithLabelValues(reason))
}

func (e *env) cycle() { e.r.Cycle(context.Background()) }

func TestNewRequiresClientAndNode(t *testing.T) {
	if _, err := New(Config{NodeName: "n1"}, nil); err == nil {
		t.Fatal("expected error for nil Client")
	}
	cs := nhatestutil.FakeKube()
	if _, err := New(Config{Client: cs}, nil); err == nil {
		t.Fatal("expected error for empty NodeName")
	}
}

// TestAllConditionDefaults: empty state dir → all conditions False
// with the exact default Reason/Message ported from the NPD JSON —
// the watchdog latches plus the two NPD monitor conditions (and the
// agent-added JournaldUnreadable).
func TestAllConditionDefaults(t *testing.T) {
	e := fixture(t)
	e.cycle()
	want := map[corev1.NodeConditionType][2]string{
		"NodeOverloaded":      {"NodeLoadNormal", "node not overloaded (load15 <= 4xCPU)"},
		"WatchdogStale":       {"WatchdogFresh", "node-watchdog ran recently (last-run < 20 min)"},
		"CiliumAgentDown":     {"CiliumAgentUp", "cilium-agent healthz OK"},
		"CiliumInitStuck":     {"CiliumEndpointsReady", "no cilium endpoint stuck in init (informer healthy)"},
		"KubeletRuntimeStall": {"KubeletRuntimeOk", "no phantom-pods wedge (ctr alive, tasks > 0)"},
		"DnsFallbackActive":   {"DnsDirectOk", "DNS via resolv.conf healthy, no /etc/hosts pin"},
		"DnsResolvStale":      {"DnsResolvFresh", "DNS pods (nld/coredns) resolv.conf matches host"},
		"PodTeardownWedged":   {"PodTeardownOk", "no long-Terminating pod with leftover task"},
		"KubeletWatchWedge":   {"KubeletWatchOk", "kubelet receives pod assignment normally (no unseen pod)"},
		"KernelDeadlock":      {"KernelHasNoDeadlock", "kernel has no deadlock"},
		"ReadonlyFilesystem":  {"FilesystemIsNotReadOnly", "Filesystem is not read-only"},
		"JournaldUnreadable":  {"JournaldReadable", "journald journal reads return entries"},
		"FilesystemReadOnly":  {"FilesystemReadWrite", "all probed filesystems are read-write"},
		"KernelHungTasks":     {"KernelTasksRunOk", "no D-state task storm (uninterruptible sleep below threshold)"},
		// Wave-8 latch→condition surface.
		"NebulaIsolated":              {"NebulaMeshHealthy", "all nebula peers handshake normally"},
		"NebulaDegraded":              {"NebulaDataplaneOk", "nebula dataplane healthy (no relay/latency degradation)"},
		"CiliumEnvoyDown":             {"CiliumEnvoyReady", "cilium-envoy admin /ready OK"},
		"CiliumIPAMExhausted":         {"CiliumIPAMOk", "cilium IPAM pool has headroom (no address leak)"},
		"CiliumBPFMapPressure":        {"CiliumBPFMapsOk", "critical cilium BPF maps below 90% capacity"},
		"SpegelMirrorDegraded":        {"SpegelMirrorReady", "spegel P2P mirror pod Ready"},
		"CalicoVethLeak":              {"CalicoVethCountOk", "cali* veth count matches pod count (no CNI DEL leak)"},
		"CalicoFelixDown":             {"CalicoFelixReady", "calico felix :9099 readiness OK"},
		"Fail2banDown":                {"Fail2banActive", "fail2ban service installed and active"},
		"ConntrackPressure":           {"ConntrackNormal", "nf_conntrack table below pressure threshold"},
		"KernelKeysPressure":          {"KernelKeysNormal", "kernel keyring quota below pressure threshold"},
		"ControlPlaneCertReloadStale": {"ControlPlaneCertReloadFresh", "control-plane cert reload markers fresh"},
		"MemoryPSIThrashing":          {"MemoryPSINormal", "memory PSI full avg60 <= 25% or free memory >= 8%"},
		// Wave-9 latch→condition surface.
		"ClockUnsynchronized": {"ClockSynchronized", "kernel clock disciplined (adjtimex synced, esterror <= 500ms)"},
		"KernelSlabLeak":      {"KernelSlabNormal", "unreclaimable kernel slab below pressure threshold"},
		"NebulaPMTUBlackhole": {"NebulaPMTUOk", "nebula overlay passes DF probes at probe size"},
		// Wave-10 latch→condition surface.
		"KernelResourceExhaustion": {"KernelResourcesNormal", "kernel threads/pids and fd table below exhaustion threshold"},
		"ClockSkewDetected":        {"ClockSkewOk", "clock offset within 2.0s of NTP source"},
	}
	conds := e.node(t).Status.Conditions
	if len(conds) != len(want) {
		t.Fatalf("got %d conditions, want %d", len(conds), len(want))
	}
	for typ, wantRM := range want {
		c := e.cond(t, typ)
		if c.Status != corev1.ConditionFalse || c.Reason != wantRM[0] || c.Message != wantRM[1] {
			t.Errorf("%s = {%s %q %q}, want {False %s %q}",
				typ, c.Status, c.Reason, c.Message, wantRM[0], wantRM[1])
		}
	}
}

// TestLatchSetsConditionTrue: a state-<key> file flips its condition
// to True with the problem reason and the check-watchdog-state.sh
// message; removing it flips back to the default.
func TestLatchSetsConditionTrue(t *testing.T) {
	e := fixture(t)
	e.writeFile("state-cilium-agent-down", "1700000001\n")
	e.writeFile("state-dns-resolv-stale", "")
	e.cycle()

	c := e.cond(t, "CiliumAgentDown")
	if c.Status != corev1.ConditionTrue || c.Reason != "CiliumAgentDownDetected" {
		t.Fatalf("CiliumAgentDown = {%s %s}, want True/CiliumAgentDownDetected", c.Status, c.Reason)
	}
	if c.Message != "watchdog state cilium-agent-down active since 1700000001" {
		t.Fatalf("unexpected message %q", c.Message)
	}
	// Empty latch content → "unknown" (shell `|| echo unknown`).
	if m := e.cond(t, "DnsResolvStale").Message; m != "watchdog state dns-resolv-stale active since unknown" {
		t.Fatalf("unexpected message %q", m)
	}
	if got := e.gauge("CiliumAgentDown", "CiliumAgentDownDetected"); got != 1 {
		t.Fatalf("problem_gauge = %v, want 1", got)
	}
	if got := e.gauge("NodeOverloaded", "NodeOverloadedDetected"); got != 0 {
		t.Fatalf("problem_gauge = %v, want 0", got)
	}

	if err := os.Remove(filepath.Join(e.dir, "state-cilium-agent-down")); err != nil {
		t.Fatal(err)
	}
	e.cycle()
	c = e.cond(t, "CiliumAgentDown")
	if c.Status != corev1.ConditionFalse || c.Reason != "CiliumAgentUp" {
		t.Fatalf("cleared CiliumAgentDown = {%s %s}, want False/CiliumAgentUp", c.Status, c.Reason)
	}
	if got := e.gauge("CiliumAgentDown", "CiliumAgentDownDetected"); got != 0 {
		t.Fatalf("problem_gauge after clear = %v, want 0", got)
	}
}

// TestClockSlabPMTULatchConditions: the three Wave-9 state-* latches each
// flip their permanent NodeCondition to True with the problem
// reason — clock-unsync (nethealth H1), kernel-slab-leak
// (workerhygiene W9-KR3), nebula-pmtu-blackhole (nethealth W9-NM1).
func TestClockSlabPMTULatchConditions(t *testing.T) {
	e := fixture(t)
	e.writeFile("state-clock-unsync", "1700000001\n")
	e.writeFile("state-kernel-slab-leak", "1700000002\n")
	e.writeFile("state-nebula-pmtu-blackhole", "1700000003\n")
	e.cycle()

	for _, tc := range []struct {
		typ    corev1.NodeConditionType
		reason string
	}{
		{"ClockUnsynchronized", "ClockUnsynchronizedDetected"},
		{"KernelSlabLeak", "KernelSlabLeakDetected"},
		{"NebulaPMTUBlackhole", "NebulaPMTUBlackholeDetected"},
	} {
		c := e.cond(t, tc.typ)
		if c.Status != corev1.ConditionTrue || c.Reason != tc.reason {
			t.Errorf("%s = {%s %s}, want True/%s", tc.typ, c.Status, c.Reason, tc.reason)
		}
	}
}

// TestWatchdogStaleProbe is check-watchdog-fresh.sh ported:
// installed marker gates, last-run content (or installed's as
// baseline) strictly older than 1200s → stale. It exercises
// watchdogStale() directly.
func TestWatchdogStaleProbe(t *testing.T) {
	e := fixture(t)

	// No installed marker → never stale, even with an ancient
	// last-run left behind.
	e.writeFile("last-run", strconv.FormatInt(e.now.Unix()-99999, 10))
	if stale, _ := e.r.watchdogStale(); stale {
		t.Fatal("no installed marker: stale = true")
	}

	// installed + fresh last-run → fresh.
	e.writeFile("installed", strconv.FormatInt(e.now.Unix()-3000, 10))
	e.writeFile("last-run", strconv.FormatInt(e.now.Unix()-60, 10))
	if stale, _ := e.r.watchdogStale(); stale {
		t.Fatal("fresh last-run: stale = true")
	}

	// Boundary: the shell uses -gt — age == 1200 is still fresh.
	e.writeFile("last-run", strconv.FormatInt(e.now.Unix()-1200, 10))
	if stale, age := e.r.watchdogStale(); stale || age != 1200 {
		t.Fatalf("age==1200: stale=%v age=%d, want fresh/1200", stale, age)
	}
	e.writeFile("last-run", strconv.FormatInt(e.now.Unix()-1201, 10))
	if stale, age := e.r.watchdogStale(); !stale || age != 1201 {
		t.Fatalf("age==1201: stale=%v age=%d, want stale/1201", stale, age)
	}

	// last-run missing → installed content is the baseline.
	if err := os.Remove(filepath.Join(e.dir, "last-run")); err != nil {
		t.Fatal(err)
	}
	if stale, _ := e.r.watchdogStale(); !stale {
		t.Fatal("installed-only baseline 3000s: want stale")
	}
	e.writeFile("installed", strconv.FormatInt(e.now.Unix()-60, 10))
	if stale, _ := e.r.watchdogStale(); stale {
		t.Fatal("fresh installed baseline: stale = true")
	}

	// Garbage parses to 0 (shell arithmetic parity) → stale; a
	// future timestamp clamps to fresh.
	e.writeFile("last-run", "not-a-number")
	if stale, _ := e.r.watchdogStale(); !stale {
		t.Fatal("garbage last-run: want stale (ts=0)")
	}
	e.writeFile("last-run", strconv.FormatInt(e.now.Unix()+600, 10))
	if stale, age := e.r.watchdogStale(); stale || age != 0 {
		t.Fatalf("future last-run: stale=%v age=%d, want fresh/0", stale, age)
	}
}

// TestHeartbeatFiles: the FIRST cycle seeds installed + last-run
// only when absent — the one-time initialization (BUG-H1). Later
// cycles must NOT refresh last-run: the periodic refresh belongs
// to the hygiene Cycle()s, and a reporter that refreshed its own
// staleness probe could never trip.
func TestHeartbeatFiles(t *testing.T) {
	e := fixture(t)
	e.cycle()

	read := func(name string) int64 {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(e.dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return parseEpoch(data)
	}
	installEpoch := read("installed")
	if installEpoch != e.now.Unix() {
		t.Fatalf("installed = %d, want %d", installEpoch, e.now.Unix())
	}
	if got := read("last-run"); got != e.now.Unix() {
		t.Fatalf("last-run = %d, want %d", got, e.now.Unix())
	}

	// A later cycle keeps both files untouched — installed is
	// force:false, and last-run is NOT refreshed by the reporter.
	e.now = e.now.Add(time.Minute)
	e.cycle()
	if got := read("installed"); got != installEpoch {
		t.Fatalf("installed rewritten: %d, want %d", got, installEpoch)
	}
	if got := read("last-run"); got != installEpoch {
		t.Fatalf("last-run refreshed by reporter: %d, want unchanged %d",
			got, installEpoch)
	}
}

// TestHeartbeatKeepsExistingFiles: pre-existing installed/last-run
// (written by the hygiene Cycle before the reporter started) are
// never overwritten — even when they carry the real current epoch.
func TestHeartbeatKeepsExistingFiles(t *testing.T) {
	e := fixture(t)
	e.writeFile("installed", strconv.FormatInt(e.now.Unix()-9000, 10))
	e.writeFile("last-run", strconv.FormatInt(e.now.Unix()-60, 10))
	e.cycle()
	data, err := os.ReadFile(filepath.Join(e.dir, "last-run"))
	if err != nil {
		t.Fatal(err)
	}
	if got := parseEpoch(data); got != e.now.Unix()-60 {
		t.Fatalf("existing last-run overwritten: %d, want %d",
			got, e.now.Unix()-60)
	}
}

// TestWatchdogStaleCondition exercises the stale→fresh condition
// path through full cycles: a stale last-run survives evaluation
// (the reporter never refreshes it, BUG-H1) → True on every cycle;
// a fresh last-run written by the watchdog side clears it to False.
func TestWatchdogStaleCondition(t *testing.T) {
	e := fixture(t)
	e.writeFile("installed", strconv.FormatInt(e.now.Unix()-3000, 10))
	e.writeFile("last-run", strconv.FormatInt(e.now.Unix()-1300, 10))
	e.cycle()
	c := e.cond(t, "WatchdogStale")
	if c.Status != corev1.ConditionTrue || c.Reason != "WatchdogStaleDetected" {
		t.Fatalf("stale: got {%s %s}", c.Status, c.Reason)
	}
	wantMsg := "node-watchdog missed heartbeat 1300s (timer dead or run failed)"
	if c.Message != wantMsg {
		t.Fatalf("message = %q, want %q", c.Message, wantMsg)
	}
	// A second cycle must not mask the staleness — last-run is
	// still the old epoch, so the condition stays True.
	e.now = e.now.Add(5 * time.Minute)
	e.cycle()
	if c := e.cond(t, "WatchdogStale"); c.Status != corev1.ConditionTrue {
		t.Fatalf("stale across cycles: got {%s %s}", c.Status, c.Reason)
	}

	// The watchdog side heartbeats again → next cycle clears.
	e.writeFile("last-run", strconv.FormatInt(e.now.Unix()-60, 10))
	e.cycle()
	c = e.cond(t, "WatchdogStale")
	if c.Status != corev1.ConditionFalse || c.Reason != "WatchdogFresh" {
		t.Fatalf("after watchdog heartbeat: got {%s %s}", c.Status, c.Reason)
	}
}

// TestWatchdogStaleNotRefreshedAcrossCycles is the BUG-H1
// regression: with a last-run older than the staleness threshold,
// ANY number of Cycle() calls must keep reporting
// WatchdogStale=True — the reporter must never refresh the very
// file its probe reads.
func TestWatchdogStaleNotRefreshedAcrossCycles(t *testing.T) {
	e := fixture(t)
	e.r.cfg.StaleThreshold = 600 * time.Second
	e.writeFile("installed", strconv.FormatInt(e.now.Unix()-3000, 10))
	e.writeFile("last-run", strconv.FormatInt(e.now.Unix()-700, 10))
	for i := 0; i < 3; i++ {
		e.cycle()
		if c := e.cond(t, "WatchdogStale"); c.Status != corev1.ConditionTrue {
			t.Fatalf("cycle %d: WatchdogStale = {%s %s}, want True — "+
				"the reporter refreshed last-run", i, c.Status, c.Reason)
		}
	}
	// The file itself must still hold the stale epoch.
	data, err := os.ReadFile(filepath.Join(e.dir, "last-run"))
	if err != nil {
		t.Fatal(err)
	}
	if got := parseEpoch(data); got != e.now.Unix()-700 {
		t.Fatalf("last-run = %d, want the stale %d untouched", got, e.now.Unix()-700)
	}
}

// TestZeroChurn: repeated cycles with unchanged latches must not
// PATCH the node again; a change PATCHes exactly once more. The NPD
// conditions live in a second patch, so the first cycle patches
// twice (watchdog conditions + NPD conditions), then a watchdog
// latch change adds one.
func TestZeroChurn(t *testing.T) {
	e := fixture(t)
	e.cycle()
	if n := e.patches(); n != 2 {
		t.Fatalf("first cycle: %d patches, want 2", n)
	}
	e.cycle()
	e.cycle()
	if n := e.patches(); n != 2 {
		t.Fatalf("unchanged cycles: %d patches, want 2 (zero-churn)", n)
	}
	e.writeFile("state-node-overloaded", "1700000002")
	e.cycle()
	if n := e.patches(); n != 3 {
		t.Fatalf("after latch: %d patches, want 3", n)
	}
	e.cycle()
	if n := e.patches(); n != 3 {
		t.Fatalf("after stable latch: %d patches, want 3", n)
	}
}

// TestSeedFromLiveNode: when the node already carries matching
// conditions (e.g. written before an agent restart), the first cycle
// must not PATCH — restart doesn't churn the API.
func TestSeedFromLiveNode(t *testing.T) {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}
	for _, d := range conditionDefs {
		node.Status.Conditions = append(node.Status.Conditions, corev1.NodeCondition{
			Type:    d.typ,
			Status:  corev1.ConditionFalse,
			Reason:  d.defaultReason,
			Message: d.defaultMessage,
		})
	}
	node.Status.Conditions = append(node.Status.Conditions,
		corev1.NodeCondition{Type: "KernelDeadlock", Status: corev1.ConditionFalse,
			Reason: kernelDeadlockDefaultReason, Message: kernelDeadlockDefaultMsg},
		corev1.NodeCondition{Type: "ReadonlyFilesystem", Status: corev1.ConditionFalse,
			Reason: readonlyDefaultReason, Message: readonlyDefaultMsg})
	e := fixture(t, node)
	e.cycle()
	if n := e.patches(); n != 0 {
		t.Fatalf("seeded node: %d patches, want 0", n)
	}
}

// TestMessageOnlyNoChurn: a latch whose content changed (new epoch →
// different message) but same Status+Reason does NOT trigger a patch
// — only Status/Reason transitions do.
func TestMessageOnlyNoChurn(t *testing.T) {
	e := fixture(t)
	e.writeFile("state-node-overloaded", "1700000001")
	e.cycle()
	if n := e.patches(); n != 2 {
		t.Fatalf("first cycle: %d patches, want 2 (watchdog + npd)", n)
	}
	e.writeFile("state-node-overloaded", "1700000009")
	e.cycle()
	if n := e.patches(); n != 2 {
		t.Fatalf("message-only change: %d patches, want 2", n)
	}
}

// TestKubeErrorsNeverFatal: a failing node GET skips the patch, bumps
// the error counter, and still updates problem_gauge — no panic, and
// the next cycle self-heals.
func TestKubeErrorsNeverFatal(t *testing.T) {
	e := fixture(t)
	var failGets atomic.Bool
	failGets.Store(true)
	e.cs.PrependReactor("get", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
		if failGets.Load() {
			return true, nil, errors.New("apiserver down")
		}
		return false, nil, nil // fall through to the default tracker
	})
	e.writeFile("state-node-overloaded", "1700000001")
	e.cycle() // must not panic
	if got := e.gauge("NodeOverloaded", "NodeOverloadedDetected"); got != 1 {
		t.Fatalf("gauge despite GET error = %v, want 1", got)
	}
	if got := testutil.ToFloat64(e.r.cycles.WithLabelValues("error")); got != 1 {
		t.Fatalf("cycles{error} = %v, want 1", got)
	}
	// Recover → conditions land normally.
	failGets.Store(false)
	e.cycle()
	if c := e.cond(t, "NodeOverloaded"); c.Status != corev1.ConditionTrue {
		t.Fatalf("post-recovery NodeOverloaded = %s, want True", c.Status)
	}
}

// TestTransitionTimes: LastTransitionTime moves only on a status
// flip — a reason-preserving re-patch keeps the original timestamp.
func TestTransitionTimes(t *testing.T) {
	e := fixture(t)
	e.now = time.Unix(1_700_000_000, 0)
	e.writeFile("state-node-overloaded", "1700000001")
	e.cycle()
	ltt1 := e.cond(t, "NodeOverloaded").LastTransitionTime.Time
	if !ltt1.Equal(e.now) {
		t.Fatalf("LTT at flip = %v, want %v", ltt1, e.now)
	}
	lttOther := e.cond(t, "CiliumAgentDown").LastTransitionTime.Time

	// Unlatch at a later time → LTT moves.
	e.now = e.now.Add(2 * time.Minute)
	if err := os.Remove(filepath.Join(e.dir, "state-node-overloaded")); err != nil {
		t.Fatal(err)
	}
	e.cycle()
	if ltt2 := e.cond(t, "NodeOverloaded").LastTransitionTime.Time; !ltt2.Equal(e.now) {
		t.Fatalf("LTT after clear = %v, want %v", ltt2, e.now)
	}
	// The never-touched condition kept its original LTT.
	if ltt := e.cond(t, "CiliumAgentDown").LastTransitionTime.Time; !ltt.Equal(lttOther) {
		t.Fatalf("untouched condition LTT moved: %v -> %v", lttOther, ltt)
	}
}

// TestKubeletRuntimeStallDualLatch: the T15 kubelet watchdog latches
// state-kubelet-healthz-down when the restart budget is exhausted —
// KubeletRuntimeStall must trip on it (the NHC
// k0sworker-remediate-exhausted rule) exactly as on
// state-kubelet-runtime-stall. The primary latch wins the message.
func TestKubeletRuntimeStallDualLatch(t *testing.T) {
	e := fixture(t)
	e.writeFile("state-kubelet-healthz-down", "1700000005\n")
	e.cycle()

	c := e.cond(t, "KubeletRuntimeStall")
	if c.Status != corev1.ConditionTrue || c.Reason != "KubeletRuntimeStallDetected" {
		t.Fatalf("KubeletRuntimeStall = {%s %s}, want True/KubeletRuntimeStallDetected",
			c.Status, c.Reason)
	}
	if c.Message != "watchdog state kubelet-healthz-down active since 1700000005" {
		t.Fatalf("unexpected message %q", c.Message)
	}
	if got := e.gauge("KubeletRuntimeStall", "KubeletRuntimeStallDetected"); got != 1 {
		t.Fatalf("problem_gauge = %v, want 1", got)
	}

	// Both latches → the primary key's message wins (evaluated
	// directly — the zero-churn patch gate keeps the OLD message on
	// the node while Status/Reason stay True/Detected, so the live
	// object can't observe this).
	e.writeFile("state-kubelet-runtime-stall", "1700000001\n")
	for _, ev := range e.r.evalConditions() {
		if ev.def.typ == "KubeletRuntimeStall" &&
			ev.message != "watchdog state kubelet-runtime-stall active since 1700000001" {
			t.Fatalf("primary latch lost the eval message: %q", ev.message)
		}
	}
	e.cycle()

	// Secondary latch removed but primary still latched → stays True;
	// removing both flips back to the default.
	if err := os.Remove(filepath.Join(e.dir, "state-kubelet-healthz-down")); err != nil {
		t.Fatal(err)
	}
	e.cycle()
	if c := e.cond(t, "KubeletRuntimeStall"); c.Status != corev1.ConditionTrue {
		t.Fatalf("cleared alt latch: KubeletRuntimeStall = %s, want True", c.Status)
	}
	if err := os.Remove(filepath.Join(e.dir, "state-kubelet-runtime-stall")); err != nil {
		t.Fatal(err)
	}
	e.cycle()
	c = e.cond(t, "KubeletRuntimeStall")
	if c.Status != corev1.ConditionFalse || c.Reason != "KubeletRuntimeOk" {
		t.Fatalf("all latches cleared: KubeletRuntimeStall = {%s %s}, want False/KubeletRuntimeOk",
			c.Status, c.Reason)
	}
}

// TestKubeletRuntimeStallA4Latches is the BUG-H4 pairing: the A4
// probes' latches — a frozen PLEG (state-kubelet-syncloop-down) and
// a hung containerd socket (state-containerd-sock-down) — are
// runtime stalls even though :10250 /healthz still answers; both
// must fire KubeletRuntimeStall.
func TestKubeletRuntimeStallA4Latches(t *testing.T) {
	for _, latch := range []string{
		"state-kubelet-syncloop-down",
		"state-containerd-sock-down",
	} {
		t.Run(latch, func(t *testing.T) {
			e := fixture(t)
			e.writeFile(latch, "1700000005\n")
			e.cycle()
			c := e.cond(t, "KubeletRuntimeStall")
			if c.Status != corev1.ConditionTrue || c.Reason != "KubeletRuntimeStallDetected" {
				t.Fatalf("%s latch: KubeletRuntimeStall = {%s %s}, want True/KubeletRuntimeStallDetected",
					latch, c.Status, c.Reason)
			}
			if got := e.gauge("KubeletRuntimeStall", "KubeletRuntimeStallDetected"); got != 1 {
				t.Fatalf("problem_gauge = %v, want 1", got)
			}
		})
	}
}

// TestInfraLatchConditions: every Wave-8 latch maps 1:1 to its
// permanent NodeCondition — the NHC→SNR chain and the
// problem_gauge series cover the full latch set.
func TestInfraLatchConditions(t *testing.T) {
	for latch, typ := range map[string]string{
		"state-nebula-isolated":         "NebulaIsolated",
		"state-nebula-degraded":         "NebulaDegraded",
		"state-cilium-envoy-down":       "CiliumEnvoyDown",
		"state-cilium-ipam-exhausted":   "CiliumIPAMExhausted",
		"state-cilium-bpf-map-pressure": "CiliumBPFMapPressure",
		"state-spegel-mirror-degraded":  "SpegelMirrorDegraded",
		"state-calico-veth-leak":        "CalicoVethLeak",
		"state-calico-felix-down":       "CalicoFelixDown",
		"state-fail2ban-down":           "Fail2banDown",
		"state-conntrack-pressure":      "ConntrackPressure",
		"state-kernel-keys-pressure":    "KernelKeysPressure",
		"state-cp-cert-reload-stale":    "ControlPlaneCertReloadStale",
		"state-psi-memory-thrash":       "MemoryPSIThrashing",
	} {
		t.Run(latch, func(t *testing.T) {
			e := fixture(t)
			e.writeFile(latch, "1700000005\n")
			e.cycle()
			c := e.cond(t, corev1.NodeConditionType(typ))
			if c.Status != corev1.ConditionTrue {
				t.Fatalf("latch %s: %s = {%s %s %q}, want True",
					latch, typ, c.Status, c.Reason, c.Message)
			}
			if want := "watchdog state " + strings.TrimPrefix(latch, "state-") +
				" active since 1700000005"; c.Message != want {
				t.Fatalf("message = %q, want %q", c.Message, want)
			}
		})
	}
}

// TestJournalUnreadableLatchSetsCondition: the journalwatch
// blindness latch (state-journal-unreadable, written by the hygiene
// subsystems' shared tracker) flips the agent-added
// JournaldUnreadable condition True and drops problem_gauge — the
// nodereporter-visible half of "journal checks are blind".
func TestJournalUnreadableLatchSetsCondition(t *testing.T) {
	e := fixture(t)
	e.writeFile("state-journal-unreadable", "1700000003\n")
	e.cycle()

	c := e.cond(t, "JournaldUnreadable")
	if c.Status != corev1.ConditionTrue || c.Reason != "JournaldUnreadableDetected" {
		t.Fatalf("JournaldUnreadable = {%s %s}, want True/JournaldUnreadableDetected",
			c.Status, c.Reason)
	}
	if c.Message != "watchdog state journal-unreadable active since 1700000003" {
		t.Fatalf("unexpected message %q", c.Message)
	}
	if got := e.gauge("JournaldUnreadable", "JournaldUnreadableDetected"); got != 1 {
		t.Fatalf("problem_gauge = %v, want 1", got)
	}

	if err := os.Remove(filepath.Join(e.dir, "state-journal-unreadable")); err != nil {
		t.Fatal(err)
	}
	e.cycle()
	c = e.cond(t, "JournaldUnreadable")
	if c.Status != corev1.ConditionFalse || c.Reason != "JournaldReadable" {
		t.Fatalf("cleared JournaldUnreadable = {%s %s}, want False/JournaldReadable",
			c.Status, c.Reason)
	}
}
