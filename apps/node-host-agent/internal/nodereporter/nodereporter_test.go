package nodereporter

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
)

// env is the shared fixture: tempdir watchdog state dir + log file, a
// fake clientset holding one Node, and a controllable clock.
type env struct {
	r   *Reporter
	cs  *fake.Clientset
	reg *prometheus.Registry
	dir string // WatchdogStateDir
	log string // WatchdogLogFile
	now time.Time
}

func fixture(t *testing.T, objs ...runtime.Object) *env {
	t.Helper()
	root := t.TempDir()
	e := &env{
		dir: filepath.Join(root, "watchdog"),
		log: filepath.Join(root, "node-watchdog.log"),
		now: time.Now().Truncate(time.Second),
	}
	if err := os.MkdirAll(e.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if len(objs) == 0 {
		objs = []runtime.Object{&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "n1"},
		}}
	}
	e.cs = fake.NewSimpleClientset(objs...)
	e.reg = prometheus.NewRegistry()
	r, err := New(Config{
		NodeName:         "n1",
		Client:           e.cs,
		WatchdogStateDir: e.dir,
		WatchdogLogFile:  e.log,
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
	cs := fake.NewSimpleClientset()
	if _, err := New(Config{Client: cs}, nil); err == nil {
		t.Fatal("expected error for empty NodeName")
	}
}

// TestAllNineDefaults: empty state dir → all 9 conditions False with
// the exact default Reason/Message ported from the NPD JSON.
func TestAllNineDefaults(t *testing.T) {
	e := fixture(t)
	e.cycle()
	want := map[corev1.NodeConditionType][2]string{
		"NodeOverloaded":      {"NodeLoadNormal", "node khong qua tai (load15 <= 4xCPU)"},
		"WatchdogStale":       {"WatchdogFresh", "node-watchdog chay gan day (last-run < 20 phut)"},
		"CiliumAgentDown":     {"CiliumAgentUp", "cilium-agent healthz OK"},
		"CiliumInitStuck":     {"CiliumEndpointsReady", "khong co cilium endpoint keo init (informer binh thuong)"},
		"KubeletRuntimeStall": {"KubeletRuntimeOk", "khong co phantom-pods wedge (ctr song, tasks > 0)"},
		"DnsFallbackActive":   {"DnsDirectOk", "DNS qua resolv.conf binh thuong, khong co /etc/hosts pin"},
		"DnsResolvStale":      {"DnsResolvFresh", "DNS pods (nld/coredns) co resolv.conf khop host"},
		"PodTeardownWedged":   {"PodTeardownOk", "khong co pod Terminating keo dai voi task con sot"},
		"KubeletWatchWedge":   {"KubeletWatchOk", "kubelet nhan pod assignment binh thuong (khong co unseen pod)"},
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

// TestWatchdogStaleProbe is check-watchdog-fresh.sh ported:
// installed marker gates, last-run content (or installed's as
// baseline) strictly older than 1200s → stale. It exercises
// watchdogStale() directly — a full Cycle() refreshes last-run
// before evaluating, so a stale fixture can't survive one.
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

// TestHeartbeatFiles: each cycle rewrites last-run with the current
// epoch and creates installed once (content = first-heartbeat epoch)
// when absent — the agent-owned replacement for the shell watchdog's
// prom_emit trap.
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

	// installed is force:false — a later cycle keeps the original
	// epoch; last-run tracks the cycle time.
	e.now = e.now.Add(time.Minute)
	e.cycle()
	if got := read("installed"); got != installEpoch {
		t.Fatalf("installed rewritten: %d, want %d", got, installEpoch)
	}
	if got := read("last-run"); got != e.now.Unix() {
		t.Fatalf("last-run not refreshed: %d, want %d", got, e.now.Unix())
	}
}

// TestHeartbeatClearsStale: a stale last-run left behind by the dead
// shell watchdog is overwritten by the agent's first cycle —
// WatchdogStale goes straight to False and never false-positives.
func TestHeartbeatClearsStale(t *testing.T) {
	e := fixture(t)
	e.writeFile("installed", strconv.FormatInt(e.now.Unix()-9000, 10))
	e.writeFile("last-run", strconv.FormatInt(e.now.Unix()-9000, 10))
	e.cycle()
	if c := e.cond(t, "WatchdogStale"); c.Status != corev1.ConditionFalse || c.Reason != "WatchdogFresh" {
		t.Fatalf("WatchdogStale = {%s %s}, want False/WatchdogFresh", c.Status, c.Reason)
	}
	data, err := os.ReadFile(filepath.Join(e.dir, "last-run"))
	if err != nil {
		t.Fatal(err)
	}
	if got := parseEpoch(data); got != e.now.Unix() {
		t.Fatalf("last-run = %d, want refreshed %d", got, e.now.Unix())
	}
}

// TestWatchdogStaleCondition exercises the stale→fresh condition
// path through a full cycle: a poisoned tmp path makes the atomic
// heartbeat write fail while reads still work, so the old last-run
// survives evaluation → True; unpoison → next cycle's heartbeat
// clears it back to False.
func TestWatchdogStaleCondition(t *testing.T) {
	e := fixture(t)
	e.writeFile("installed", strconv.FormatInt(e.now.Unix()-3000, 10))
	e.writeFile("last-run", strconv.FormatInt(e.now.Unix()-1300, 10))
	if err := os.Mkdir(filepath.Join(e.dir, "last-run.tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.cycle()
	c := e.cond(t, "WatchdogStale")
	if c.Status != corev1.ConditionTrue || c.Reason != "WatchdogStaleDetected" {
		t.Fatalf("stale: got {%s %s}", c.Status, c.Reason)
	}
	wantMsg := "node-watchdog khong ghi heartbeat 1300s (timer dead hoac run fail)"
	if c.Message != wantMsg {
		t.Fatalf("message = %q, want %q", c.Message, wantMsg)
	}
	if got := testutil.ToFloat64(e.r.cycles.WithLabelValues("error")); got != 1 {
		t.Fatalf("cycles{error} = %v, want 1", got)
	}

	if err := os.Remove(filepath.Join(e.dir, "last-run.tmp")); err != nil {
		t.Fatal(err)
	}
	e.cycle()
	c = e.cond(t, "WatchdogStale")
	if c.Status != corev1.ConditionFalse || c.Reason != "WatchdogFresh" {
		t.Fatalf("after heartbeat recovery: got {%s %s}", c.Status, c.Reason)
	}
}

// TestZeroChurn: repeated cycles with unchanged latches must not
// PATCH the node again; a change PATCHes exactly once more.
func TestZeroChurn(t *testing.T) {
	e := fixture(t)
	e.cycle()
	if n := e.patches(); n != 1 {
		t.Fatalf("first cycle: %d patches, want 1", n)
	}
	e.cycle()
	e.cycle()
	if n := e.patches(); n != 1 {
		t.Fatalf("unchanged cycles: %d patches, want 1 (zero-churn)", n)
	}
	e.writeFile("state-node-overloaded", "1700000002")
	e.cycle()
	if n := e.patches(); n != 2 {
		t.Fatalf("after latch: %d patches, want 2", n)
	}
	e.cycle()
	if n := e.patches(); n != 2 {
		t.Fatalf("after stable latch: %d patches, want 2", n)
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
	if n := e.patches(); n != 1 {
		t.Fatalf("first cycle: %d patches", n)
	}
	e.writeFile("state-node-overloaded", "1700000009")
	e.cycle()
	if n := e.patches(); n != 1 {
		t.Fatalf("message-only change: %d patches, want 1", n)
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
			return true, nil, fmt.Errorf("apiserver down")
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
