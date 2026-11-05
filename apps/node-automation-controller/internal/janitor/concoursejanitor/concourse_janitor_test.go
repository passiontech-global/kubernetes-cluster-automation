package concoursejanitor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// Fakes + builders (cj-prefixed)
// ---------------------------------------------------------------------------

// cjFakeStats records "stats:<node>" and answers through fn(node,
// callNumber) so tests can return different readings before/after a
// wipe (call is per-node, starting at 1).
type cjFakeStats struct {
	events *[]string
	calls  map[string]int
	fn     func(node string, call int) (int64, int64, int64, error)
}

func (f *cjFakeStats) Summary(_ context.Context, node string) (int64, int64, int64, error) {
	*f.events = append(*f.events, "stats:"+node)
	f.calls[node]++
	return f.fn(node, f.calls[node])
}

// cjFakeATC records every call; landWorker flips the recorded worker
// state to "landed" so the drain loop finishes on the first poll.
// landErr makes the land call fail (drain never starts); stateFn, if
// set, answers workerState calls with per-call control.
type cjFakeATC struct {
	events   *[]string
	loginErr error
	stateErr error
	landErr  error
	states   map[string]string
	stateFn  func(name string) (string, error)
}

func (f *cjFakeATC) login(_ context.Context, user, _ string) error {
	*f.events = append(*f.events, "login:"+user)
	return f.loginErr
}

func (f *cjFakeATC) workerState(_ context.Context, name string) (string, error) {
	*f.events = append(*f.events, "state:"+name)
	if f.stateFn != nil {
		return f.stateFn(name)
	}
	if f.stateErr != nil {
		return "", f.stateErr
	}
	return f.states[name], nil
}

func (f *cjFakeATC) landWorker(_ context.Context, name string) error {
	*f.events = append(*f.events, "land:"+name)
	if f.landErr != nil {
		return f.landErr
	}
	f.states[name] = "landed"
	return nil
}

func (f *cjFakeATC) pruneWorker(_ context.Context, name string) error {
	*f.events = append(*f.events, "prune:"+name)
	return nil
}

func cjWorkerPod(name, uid, node string, ready bool, annos map[string]string) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: cjNamespace, Name: name,
			UID: types.UID(uid), Annotations: annos,
		},
		Spec: corev1.PodSpec{NodeName: node},
	}
	if ready {
		p.Status.Conditions = []corev1.PodCondition{
			{Type: corev1.PodReady, Status: corev1.ConditionTrue},
		}
	}
	return p
}

func cjWorkerSTS(replicas int32) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: cjNamespace, Name: cjStatefulSet},
		Spec:       appsv1.StatefulSetSpec{Replicas: &replicas},
	}
}

func cjLocalUsers() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: cjNamespace, Name: cjSecretName},
		Data:       map[string][]byte{cjSecretKey: []byte("admin:s3cr3t\nbackup:x\n")},
	}
}

var cjPodsGVR = schema.GroupVersionResource{Version: "v1", Resource: "pods"}

// cjPlanDynFake returns a dynamic fake that knows the PlanList kind
// for the maintenance-mutex autopilot check (the autopilot Plan CRD
// is in testutil.NewDynamicClient's baked-in table).
func cjPlanDynFake(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return testutil.NewDynamicClient(objs...)
}

// cjAutopilotPlan builds a Plan CR in `state`.
func cjAutopilotPlan(name, state string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "autopilot.k0sproject.io/v1beta2",
		"kind":       "Plan",
		"metadata":   map[string]any{"name": name},
		"status":     map[string]any{"state": state},
	}}
}

// cjReplaceOnDelete makes the fake apiserver behave like the
// StatefulSet controller + init-rm: deleting a worker pod instantly
// installs a successor (same node) with a fresh UID, Ready when the
// caller says so.
func cjReplaceOnDelete(cs *fake.Clientset, events *[]string, ready bool) {
	cs.PrependReactor("delete", "pods", func(a ktesting.Action) (bool, runtime.Object, error) {
		d := a.(ktesting.DeleteAction)
		*events = append(*events, "delete:"+d.GetName())
		node := "node-a"
		if old, err := cs.Tracker().Get(cjPodsGVR, d.GetNamespace(), d.GetName()); err == nil {
			if p, ok := old.(*corev1.Pod); ok {
				node = p.Spec.NodeName
			}
		}
		if err := cs.Tracker().Delete(cjPodsGVR, d.GetNamespace(), d.GetName()); err != nil {
			return true, nil, err
		}
		return true, nil, cs.Tracker().Add(
			cjWorkerPod(d.GetName(), "uid-new-"+d.GetName(), node, ready, nil))
	})
}

// cjTestJanitor builds a janitor with shrunk timeouts — every poll
// fires immediately on the first check; timeouts only matter for the
// failure tests. dyn is an empty autopilot-aware fake — tests that
// exercise the maintenance mutex install a real Plan themselves.
func cjTestJanitor(cs *fake.Clientset, st nodeStatsReader, atc atcIface) *concourseWorkdirJanitor {
	return &concourseWorkdirJanitor{queue: "concourse-workdir-janitor",
		cs: cs, stats: st, atc: atc,
		enabled:        true,
		dyn:            cjPlanDynFake(),
		runTimeout:     10 * time.Second,
		reqTimeout:     10 * time.Second,
		drainTimeout:   50 * time.Millisecond,
		landFailWait:   10 * time.Millisecond,
		pruneStateWait: 10 * time.Millisecond,
		deleteTimeout:  100 * time.Millisecond,
		uidPollTimeout: 100 * time.Millisecond,
		readyTimeout:   100 * time.Millisecond,
		fastPoll:       time.Millisecond,
		slowPoll:       time.Millisecond,
	}
}

func cjPod(t *testing.T, cs *fake.Clientset, name string) *corev1.Pod {
	t.Helper()
	p, err := cs.CoreV1().Pods(cjNamespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get pod %s: %v", name, err)
	}
	return p
}

// ---------------------------------------------------------------------------
// Module tests
// ---------------------------------------------------------------------------

// Disabled: the tick logs and returns without touching anything.
func TestConcourseJanitorDisabled(t *testing.T) {
	j := &concourseWorkdirJanitor{queue: "concourse-workdir-janitor", enabled: false}
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
}

// 2.7 maintenance mutex — any positive signal defers the whole wipe
// cycle before ATC login: no land, no stats, no delete. Signals
// tested: cordoned node, kured lock annotation, active autopilot plan.
func TestConcourseJanitorMaintenanceMutexDefers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		objs  []runtime.Object
		plans []runtime.Object
	}{
		{"cordoned node", []runtime.Object{func() *corev1.Node {
			n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "w1"}}
			n.Spec.Unschedulable = true
			return n
		}()}, nil},
		{"kured lock", []runtime.Object{&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system", Name: "kured",
			Annotations: map[string]string{shared.KuredLockAnno: "w1"}}}}, nil},
		{"active plan", nil,
			[]runtime.Object{cjAutopilotPlan("autopilot", "InProgress")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var events []string
			objs := append([]runtime.Object{
				cjWorkerSTS(1),
				cjWorkerPod("concourse-worker-0", "uid-0", "node-a", true, nil),
				cjLocalUsers(),
			}, tc.objs...)
			cs := fake.NewSimpleClientset(objs...)
			j := cjTestJanitor(cs,
				&cjFakeStats{events: &events, calls: map[string]int{},
					fn: func(string, int) (int64, int64, int64, error) {
						return 160 * gib, 200 * gib, 10 * gib, nil // would wipe
					}},
				&cjFakeATC{events: &events, states: map[string]string{}})
			j.dyn = cjPlanDynFake(tc.plans...)
			if err := j.run(ctx); err != nil {
				t.Fatal(err)
			}
			if len(events) != 0 {
				t.Fatalf("wipe cycle ran during maintenance: events %v", events)
			}
			if got := cjPod(t, cs, "concourse-worker-0").UID; got != "uid-0" {
				t.Fatalf("pod replaced during maintenance (uid %s)", got)
			}
		})
	}
}

// A nil dynamic client makes the autopilot mutex check unverifiable —
// the run errors like any other check failure: "unknown" must mean
// "no", never a silent "no signal".
func TestConcourseJanitorNilDynFailsClosed(t *testing.T) {
	var events []string
	cs := fake.NewSimpleClientset(
		cjWorkerSTS(1),
		cjWorkerPod("concourse-worker-0", "uid-0", "node-a", true, nil),
		cjLocalUsers())
	j := cjTestJanitor(cs,
		&cjFakeStats{events: &events, calls: map[string]int{},
			fn: func(string, int) (int64, int64, int64, error) {
				return 160 * gib, 200 * gib, 10 * gib, nil // would wipe
			}},
		&cjFakeATC{events: &events, states: map[string]string{}})
	j.dyn = nil // wiring bug — must not read as "no maintenance"
	if err := j.run(ctx); err == nil {
		t.Fatal("expected error when dyn is nil")
	}
	if len(events) != 0 {
		t.Fatalf("wipe cycle ran with an unverifiable mutex check: %v", events)
	}
}

// Workdir under cap AND nodefs under threshold → keep the cache, no
// delete. No annotation → baseline estimated as imageFs + 32GiB:
// 50-10-32 = 8GiB <= 100, nodefs 25% < 60%.
func TestConcourseJanitorKeepCache(t *testing.T) {
	var events []string
	cs := fake.NewSimpleClientset(
		cjWorkerSTS(1),
		cjWorkerPod("concourse-worker-0", "uid-0", "node-a", true, nil),
		cjLocalUsers())
	st := &cjFakeStats{events: &events, calls: map[string]int{},
		fn: func(string, int) (int64, int64, int64, error) {
			return 50 * gib, 200 * gib, 10 * gib, nil
		}}
	j := cjTestJanitor(cs, st,
		&cjFakeATC{events: &events, states: map[string]string{}})
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cjPod(t, cs, "concourse-worker-0").UID; got != "uid-0" {
		t.Fatalf("pod was replaced despite staying under thresholds (uid %s)", got)
	}
	want := []string{"login:admin", "stats:node-a"}
	if fmt.Sprint(events) != fmt.Sprint(want) {
		t.Fatalf("events %v, want %v", events, want)
	}
}

// The full wipe path, ordinals descending: stats → land →
// drained → delete → prune (inside the init-rm window) → new uid →
// Ready → baseline annotation stamped from the post-wipe nodefs.
func TestConcourseJanitorFullWipeOrder(t *testing.T) {
	var events []string
	cs := fake.NewSimpleClientset(
		cjWorkerSTS(2),
		cjWorkerPod("concourse-worker-0", "uid-0", "node-a", true, nil),
		cjWorkerPod("concourse-worker-1", "uid-1", "node-b", true, nil),
		cjLocalUsers())
	cjReplaceOnDelete(cs, &events, true)
	st := &cjFakeStats{events: &events, calls: map[string]int{},
		fn: func(_ string, call int) (int64, int64, int64, error) {
			if call == 1 {
				return 160 * gib, 200 * gib, 10 * gib, nil // 80% → wipe
			}
			return 40 * gib, 200 * gib, 10 * gib, nil // post-wipe baseline
		}}
	j := cjTestJanitor(cs, st,
		&cjFakeATC{events: &events, states: map[string]string{}})
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"login:admin",
		"stats:node-b",
		"land:concourse-worker-1", "state:concourse-worker-1",
		"delete:concourse-worker-1",
		"state:concourse-worker-1", "prune:concourse-worker-1",
		"stats:node-b",
		"stats:node-a",
		"land:concourse-worker-0", "state:concourse-worker-0",
		"delete:concourse-worker-0",
		"state:concourse-worker-0", "prune:concourse-worker-0",
		"stats:node-a",
	}
	if fmt.Sprint(events) != fmt.Sprint(want) {
		t.Fatalf("events:\n%v\nwant:\n%v", events, want)
	}
	for _, name := range []string{"concourse-worker-0", "concourse-worker-1"} {
		p := cjPod(t, cs, name)
		if p.UID != types.UID("uid-new-"+name) {
			t.Fatalf("pod %s not replaced: uid %s", name, p.UID)
		}
		if got := p.Annotations[cjBaselineAnno]; got != "40" {
			t.Fatalf("pod %s baseline annotation %q, want \"40\"", name, got)
		}
	}
}

// ATC login failure is fail-open: no land/drain/prune, but the pod is
// still deleted and replaced (pre-stop retire is the fallback).
func TestConcourseJanitorNoFlyStillDeletes(t *testing.T) {
	var events []string
	cs := fake.NewSimpleClientset(
		cjWorkerSTS(1),
		cjWorkerPod("concourse-worker-0", "uid-0", "node-a", true, nil),
		cjLocalUsers())
	cjReplaceOnDelete(cs, &events, true)
	st := &cjFakeStats{events: &events, calls: map[string]int{},
		fn: func(_ string, call int) (int64, int64, int64, error) {
			if call == 1 {
				return 160 * gib, 200 * gib, 10 * gib, nil
			}
			return 40 * gib, 200 * gib, 10 * gib, nil
		}}
	atc := &cjFakeATC{events: &events, loginErr: errors.New("atc down"),
		states: map[string]string{}}
	j := cjTestJanitor(cs, st, atc)
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"login:admin",
		"stats:node-a",
		"delete:concourse-worker-0",
		"stats:node-a",
	}
	if fmt.Sprint(events) != fmt.Sprint(want) {
		t.Fatalf("events %v, want %v", events, want)
	}
	if got := cjPod(t, cs, "concourse-worker-0").UID; got != "uid-new-concourse-worker-0" {
		t.Fatalf("pod not replaced without ATC: uid %s", got)
	}
}

// Unreadable stats fail OPEN to a wipe — the cleanup must never be
// lost to a broken metrics path — but the blind wipe IS metered:
// IncError on the stats read and again on the wipe decision.
func TestConcourseJanitorStatsErrorFailOpen(t *testing.T) {
	var events []string
	cs := fake.NewSimpleClientset(
		cjWorkerSTS(1),
		cjWorkerPod("concourse-worker-0", "uid-0", "node-a", true, nil),
		cjLocalUsers())
	cjReplaceOnDelete(cs, &events, true)
	st := &cjFakeStats{events: &events, calls: map[string]int{},
		fn: func(string, int) (int64, int64, int64, error) {
			return 0, 0, 0, errors.New("kubelet down")
		}}
	j := cjTestJanitor(cs, st,
		&cjFakeATC{events: &events, states: map[string]string{}})
	before := testutil.QueueErrorCount(t, "concourse-workdir-janitor")
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cjPod(t, cs, "concourse-worker-0").UID; got != "uid-new-concourse-worker-0" {
		t.Fatalf("stats error did not fail open to a wipe: uid %s", got)
	}
	found := false
	for _, e := range events {
		if e == "delete:concourse-worker-0" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a delete in events %v", events)
	}
	// stats read error + blind-wipe decision + the post-wipe re-read
	// all meter — at least the read + the wipe must count.
	if got := testutil.QueueErrorCount(t, "concourse-workdir-janitor") - before; got < 2 {
		t.Fatalf("fail-open wipe under-metered: error delta = %v, want >= 2", got)
	}
}

// The baseline annotation wins over the imageFs estimate — and makes
// workdir computable even when imageFs is absent (-1). Here
// 50-30 = 20GiB <= 100 → keep (without the annotation this would be a
// fail-open wipe).
func TestConcourseJanitorBaselineAnnotation(t *testing.T) {
	var events []string
	cs := fake.NewSimpleClientset(
		cjWorkerSTS(1),
		cjWorkerPod("concourse-worker-0", "uid-0", "node-a", true,
			map[string]string{cjBaselineAnno: "30"}),
		cjLocalUsers())
	st := &cjFakeStats{events: &events, calls: map[string]int{},
		fn: func(string, int) (int64, int64, int64, error) {
			return 50 * gib, 200 * gib, -1, nil // imageFs absent
		}}
	j := cjTestJanitor(cs, st,
		&cjFakeATC{events: &events, states: map[string]string{}})
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cjPod(t, cs, "concourse-worker-0").UID; got != "uid-0" {
		t.Fatalf("annotated baseline ignored — pod wiped: uid %s", got)
	}
}

// No replacement pod inside the uid-poll window aborts the run —
// bash `exit 1` ("new pod not created").
func TestConcourseJanitorNewPodNeverAppears(t *testing.T) {
	var events []string
	cs := fake.NewSimpleClientset(
		cjWorkerSTS(1),
		cjWorkerPod("concourse-worker-0", "uid-0", "node-a", true, nil),
		cjLocalUsers())
	// Default tracker delete — object vanishes, nothing replaces it.
	st := &cjFakeStats{events: &events, calls: map[string]int{},
		fn: func(string, int) (int64, int64, int64, error) {
			return 160 * gib, 200 * gib, 10 * gib, nil
		}}
	j := cjTestJanitor(cs, st,
		&cjFakeATC{events: &events, states: map[string]string{}})
	if err := j.run(ctx); err == nil ||
		!strings.Contains(err.Error(), "new pod not created") {
		t.Fatalf("expected 'new pod not created' error, got %v", err)
	}
}

// A replacement that never goes Ready (init-rm still wiping past the
// window) is a run error too.
func TestConcourseJanitorReadyTimeout(t *testing.T) {
	var events []string
	cs := fake.NewSimpleClientset(
		cjWorkerSTS(1),
		cjWorkerPod("concourse-worker-0", "uid-0", "node-a", true, nil),
		cjLocalUsers())
	cjReplaceOnDelete(cs, &events, false) // successor never Ready
	st := &cjFakeStats{events: &events, calls: map[string]int{},
		fn: func(string, int) (int64, int64, int64, error) {
			return 160 * gib, 200 * gib, 10 * gib, nil
		}}
	j := cjTestJanitor(cs, st,
		&cjFakeATC{events: &events, states: map[string]string{}})
	if err := j.run(ctx); err == nil || !strings.Contains(err.Error(), "not Ready") {
		t.Fatalf("expected a Ready-timeout error, got %v", err)
	}
}

// Missing StatefulSet is a hard error — bash `exit 1`.
func TestConcourseJanitorMissingSTS(t *testing.T) {
	var events []string
	cs := fake.NewSimpleClientset(cjLocalUsers())
	j := cjTestJanitor(cs, &cjFakeStats{
		events: &events, calls: map[string]int{},
		fn: func(string, int) (int64, int64, int64, error) { return 0, 0, 0, nil }},
		&cjFakeATC{events: &events, states: map[string]string{}})
	if err := j.run(ctx); err == nil {
		t.Fatal("expected error when sts concourse-worker is missing")
	}
}

// A young pod that is not yet Ready is skipped entirely — it is almost
// certainly inside init-rm from an earlier wipe; deleting it again
// would only reset rm -rf progress. The guard lifts at readyTimeout.
func TestConcourseJanitorSkipsYoungNotReadyPod(t *testing.T) {
	var events []string
	p := cjWorkerPod("concourse-worker-0", "uid-0", "node-a", false, nil)
	p.CreationTimestamp = metav1.NewTime(time.Now()) // younger than readyTimeout
	cs := fake.NewSimpleClientset(cjWorkerSTS(1), p, cjLocalUsers())
	st := &cjFakeStats{events: &events, calls: map[string]int{},
		fn: func(string, int) (int64, int64, int64, error) {
			return 160 * gib, 200 * gib, 10 * gib, nil // 80% — would wipe
		}}
	j := cjTestJanitor(cs, st,
		&cjFakeATC{events: &events, states: map[string]string{}})
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cjPod(t, cs, "concourse-worker-0").UID; got != "uid-0" {
		t.Fatalf("young not-Ready pod was replaced (uid %s)", got)
	}
	// stats still ran (they decide the keep/wipe side); no land,
	// no delete — the guard fires right after the keep-cache check.
	want := []string{"login:admin", "stats:node-a"}
	if fmt.Sprint(events) != fmt.Sprint(want) {
		t.Fatalf("events %v, want %v", events, want)
	}
}

// The same pod past readyTimeout is wiped normally — the guard exists
// to protect init-rm progress, not to shelter a wedged pod.
func TestConcourseJanitorWipesOldNotReadyPod(t *testing.T) {
	var events []string
	p := cjWorkerPod("concourse-worker-0", "uid-0", "node-a", false, nil)
	p.CreationTimestamp = metav1.NewTime(time.Now().Add(-time.Hour))
	cs := fake.NewSimpleClientset(cjWorkerSTS(1), p, cjLocalUsers())
	cjReplaceOnDelete(cs, &events, true)
	st := &cjFakeStats{events: &events, calls: map[string]int{},
		fn: func(string, int) (int64, int64, int64, error) {
			return 160 * gib, 200 * gib, 10 * gib, nil
		}}
	j := cjTestJanitor(cs, st,
		&cjFakeATC{events: &events, states: map[string]string{}})
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e == "delete:concourse-worker-0" {
			return // wiped as expected
		}
	}
	t.Fatalf("old not-Ready pod was not wiped: %v", events)
}

// An ATC error during drain polling is NOT "worker gone" — the poll
// keeps waiting (until drainTimeout) so a transient blip cannot cut
// in-flight builds early. With every state call failing, the drain
// times out (shrunk to 50ms in tests) and the pod is still deleted —
// many state polls must have happened, not just one.
func TestConcourseJanitorDrainKeepsPollingOnATCError(t *testing.T) {
	var events []string
	cs := fake.NewSimpleClientset(
		cjWorkerSTS(1),
		cjWorkerPod("concourse-worker-0", "uid-0", "node-a", true, nil),
		cjLocalUsers())
	cjReplaceOnDelete(cs, &events, true)
	st := &cjFakeStats{events: &events, calls: map[string]int{},
		fn: func(string, int) (int64, int64, int64, error) {
			return 160 * gib, 200 * gib, 10 * gib, nil
		}}
	atc := &cjFakeATC{events: &events,
		stateErr: errors.New("atc 502"), states: map[string]string{}}
	j := cjTestJanitor(cs, st, atc)
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	stateCalls := 0
	deleted := false
	for _, e := range events {
		if e == "state:concourse-worker-0" {
			stateCalls++
		}
		if e == "delete:concourse-worker-0" {
			deleted = true
		}
	}
	if stateCalls < 2 {
		t.Fatalf("drain treated ATC error as drained after %d poll(s): %v", stateCalls, events)
	}
	if !deleted {
		t.Fatalf("pod not deleted after drain timeout: %v", events)
	}
}

// land-worker failure means the drain never started — the wait is
// bounded by landFailWait, not drainTimeout: a worker stuck reading
// "running" gives up inside the small bound and the pod is still
// deleted on the same policy as a timed-out drain.
func TestConcourseJanitorLandFailShortensDrain(t *testing.T) {
	var events []string
	cs := fake.NewSimpleClientset(
		cjWorkerSTS(1),
		cjWorkerPod("concourse-worker-0", "uid-0", "node-a", true, nil),
		cjLocalUsers())
	cjReplaceOnDelete(cs, &events, true)
	st := &cjFakeStats{events: &events, calls: map[string]int{},
		fn: func(string, int) (int64, int64, int64, error) {
			return 160 * gib, 200 * gib, 10 * gib, nil
		}}
	atc := &cjFakeATC{events: &events, landErr: errors.New("atc 503"),
		states: map[string]string{"concourse-worker-0": "running"}}
	j := cjTestJanitor(cs, st, atc)
	// If the failed-land path used drainTimeout the run would stall
	// for this full window; landFailWait must bound it instead.
	j.drainTimeout = 5 * time.Second
	j.landFailWait = 20 * time.Millisecond
	start := time.Now()
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("drain waited %s past the land-fail bound — drainTimeout used", elapsed)
	}
	deleted := false
	for _, e := range events {
		if e == "delete:concourse-worker-0" {
			deleted = true
		}
	}
	if !deleted {
		t.Fatalf("pod not deleted after land-fail wait: %v", events)
	}
}

// The ATC de-registers a dead worker asynchronously — a state that
// still reads "running" right after pod delete flips a few polls
// later, and the bounded poll must catch it before deciding (no
// prune while "running", prune once it settles).
func TestConcourseJanitorPruneWaitsForStateSettle(t *testing.T) {
	var events []string
	cs := fake.NewSimpleClientset(
		cjWorkerSTS(1),
		cjWorkerPod("concourse-worker-0", "uid-0", "node-a", true, nil),
		cjLocalUsers())
	cjReplaceOnDelete(cs, &events, true)
	st := &cjFakeStats{events: &events, calls: map[string]int{},
		fn: func(string, int) (int64, int64, int64, error) {
			return 160 * gib, 200 * gib, 10 * gib, nil
		}}
	stateCalls := 0
	atc := &cjFakeATC{events: &events, states: map[string]string{},
		stateFn: func(name string) (string, error) {
			stateCalls++
			// Drain needs "landed" fast; the post-delete prune poll
			// then sees the async lag: "running" twice, then settled.
			if stateCalls <= 1 {
				return "landed", nil // drain poll
			}
			if stateCalls <= 3 {
				return "running", nil // lagging de-registration
			}
			return "landed", nil
		}}
	j := cjTestJanitor(cs, st, atc)
	j.pruneStateWait = 50 * time.Millisecond
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	pruned := false
	for _, e := range events {
		if e == "prune:concourse-worker-0" {
			pruned = true
		}
	}
	if !pruned {
		t.Fatalf("worker record lagged but prune never ran: %v", events)
	}
	if stateCalls < 4 {
		t.Fatalf("expected the prune poll to retry past the lag, got %d state calls", stateCalls)
	}
}

// deletePod passes the re-fetched UID as a delete precondition — a
// pod that churned to a different UID between re-get and delete must
// conflict rather than be removed unvetted.
func TestConcourseJanitorDeletePodUIDPrecondition(t *testing.T) {
	cs := fake.NewSimpleClientset(
		cjWorkerPod("concourse-worker-0", "uid-0", "node-a", true, nil))
	var gotUID *types.UID
	cs.PrependReactor("delete", "pods",
		func(a ktesting.Action) (bool, runtime.Object, error) {
			opts := a.(ktesting.DeleteAction).GetDeleteOptions()
			if opts.Preconditions != nil {
				gotUID = opts.Preconditions.UID
			}
			return false, nil, nil // fall through to the tracker
		})
	j := cjTestJanitor(cs, nil, nil)
	if err := j.deletePod(ctx, "concourse-worker-0", "uid-0"); err != nil {
		t.Fatal(err)
	}
	if gotUID == nil || *gotUID != "uid-0" {
		t.Fatalf("delete missing the UID precondition: %v", gotUID)
	}
}

// local-users parsing: first line, split on FIRST colon, CRLF trimmed.
// Every malformed shape fails closed → flyOK=false (delete-only mode).
func TestConcourseJanitorATCCredentials(t *testing.T) {
	for _, tc := range []struct {
		name     string
		data     map[string][]byte
		wantUser string
		wantPass string
		wantErr  bool
	}{
		{"normal", map[string][]byte{cjSecretKey: []byte("admin:s3cr3t\nbackup:x\n")}, "admin", "s3cr3t", false},
		{"crlf", map[string][]byte{cjSecretKey: []byte("admin:s3cr3t\r\nbackup:x\r\n")}, "admin", "s3cr3t", false},
		{"colon in pass", map[string][]byte{cjSecretKey: []byte("admin:p:a:s:s\n")}, "admin", "p:a:s:s", false},
		{"missing key", map[string][]byte{"other": []byte("x")}, "", "", true},
		{"no colon", map[string][]byte{cjSecretKey: []byte("justauser\n")}, "", "", true},
		{"empty user", map[string][]byte{cjSecretKey: []byte(":pw\n")}, "", "", true},
		{"empty pass ok", map[string][]byte{cjSecretKey: []byte("admin:\n")}, "admin", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset(&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: cjNamespace, Name: cjSecretName},
				Data:       tc.data,
			})
			j := &concourseWorkdirJanitor{queue: "concourse-workdir-janitor", cs: cs, reqTimeout: 10 * time.Second}
			u, p, err := j.atcCredentials(ctx)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q:%q", u, p)
				}
				return
			}
			if err != nil || u != tc.wantUser || p != tc.wantPass {
				t.Fatalf("got %q:%q err=%v, want %q:%q", u, p, err, tc.wantUser, tc.wantPass)
			}
		})
	}
	// Missing secret object entirely → error → flyOK=false.
	cs := fake.NewSimpleClientset()
	j := &concourseWorkdirJanitor{queue: "concourse-workdir-janitor", cs: cs, reqTimeout: 10 * time.Second}
	if _, _, err := j.atcCredentials(ctx); err == nil {
		t.Fatal("expected error for missing secret")
	}
}

// ---------------------------------------------------------------------------
// ATC client tests (httptest)
// ---------------------------------------------------------------------------

// atcRecorder is a httptest handler capturing "METHOD path auth" per
// request plus the token POST form, and serving programmable replies.
type atcRecorder struct {
	requests  []string
	tokenForm map[string]string
	tokenCode int
	tokenBody string
	workers   string
	putCode   int
}

func (r *atcRecorder) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.requests = append(r.requests,
			fmt.Sprintf("%s %s auth=%q", req.Method, req.URL.Path, req.Header.Get("Authorization")))
		switch req.URL.Path {
		case "/sky/issuer/token":
			_ = req.ParseForm()
			r.tokenForm = map[string]string{}
			for k := range req.PostForm {
				r.tokenForm[k] = req.PostForm.Get(k)
			}
			w.WriteHeader(r.tokenCode)
			_, _ = w.Write([]byte(r.tokenBody))
		case "/api/v1/workers":
			_, _ = w.Write([]byte(r.workers))
		default:
			code := r.putCode
			if code == 0 {
				code = http.StatusOK
			}
			w.WriteHeader(code)
		}
	})
}

// OAuth2 password grant (Concourse ≥3.15, deployed 8.3.2): POST
// /sky/issuer/token with Basic client creds fly:Zmx5, then Bearer on
// every subsequent call. Asserts method+path+Authorization for
// token/workers/land/prune — worker routes are NOT team-scoped.
func TestATCClientOAuthShape(t *testing.T) {
	rec := &atcRecorder{
		tokenCode: http.StatusOK,
		tokenBody: `{"access_token":"tok-oauth","token_type":"Bearer"}`,
		workers:   `[{"name":"w1","state":"running"},{"name":"w2","state":"landed"}]`,
	}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()
	c := newATCClient(srv.URL, srv.Client())

	if err := c.login(ctx, "admin", "pw"); err != nil {
		t.Fatalf("login: %v", err)
	}
	if rec.tokenForm["grant_type"] != "password" ||
		rec.tokenForm["username"] != "admin" ||
		rec.tokenForm["password"] != "pw" ||
		!strings.Contains(rec.tokenForm["scope"], "federated:id") {
		t.Fatalf("bad token form: %v", rec.tokenForm)
	}
	st, err := c.workerState(ctx, "w2")
	if err != nil || st != "landed" {
		t.Fatalf("workerState = %q, %v; want landed", st, err)
	}
	if st, err := c.workerState(ctx, "gone"); err != nil || st != "" {
		t.Fatalf("unknown worker = %q, %v; want \"\"", st, err)
	}
	if err := c.landWorker(ctx, "w2"); err != nil {
		t.Fatalf("landWorker: %v", err)
	}
	if err := c.pruneWorker(ctx, "w2"); err != nil {
		t.Fatalf("pruneWorker: %v", err)
	}
	// base64("fly:Zmx5") = Zmx5OlpteDU= — the token request carries
	// fly's public client creds, everything after carries the bearer.
	want := []string{
		`POST /sky/issuer/token auth="Basic Zmx5OlpteDU="`,
		`GET /api/v1/workers auth="Bearer tok-oauth"`,
		`GET /api/v1/workers auth="Bearer tok-oauth"`,
		`PUT /api/v1/workers/w2/land auth="Bearer tok-oauth"`,
		`PUT /api/v1/workers/w2/prune auth="Bearer tok-oauth"`,
	}
	if fmt.Sprint(rec.requests) != fmt.Sprint(want) {
		t.Fatalf("requests:\n%v\nwant:\n%v", rec.requests, want)
	}
}

// Non-2xx on the token endpoint fails login — caller degrades to
// flyOK=false (no Basic-auth fallback exists on Concourse 8.x).
func TestATCClientLoginError(t *testing.T) {
	rec := &atcRecorder{
		tokenCode: http.StatusUnauthorized,
		tokenBody: `{"error":"invalid_grant"}`,
	}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()
	c := newATCClient(srv.URL, srv.Client())
	if err := c.login(ctx, "u", "bad"); err == nil ||
		!strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401 login error, got %v", err)
	}
}

// Non-2xx on land/prune is an error carrying the status.
func TestATCClientNon2xx(t *testing.T) {
	rec := &atcRecorder{
		tokenCode: http.StatusOK,
		tokenBody: `{"access_token":"t","token_type":"Bearer"}`,
		putCode:   http.StatusInternalServerError,
	}
	srv := httptest.NewServer(rec.handler())
	defer srv.Close()
	c := newATCClient(srv.URL, srv.Client())
	if err := c.login(ctx, "u", "p"); err != nil {
		t.Fatal(err)
	}
	if err := c.landWorker(ctx, "w"); err == nil ||
		!strings.Contains(err.Error(), "500") {
		t.Fatalf("expected status error on land, got %v", err)
	}
}
