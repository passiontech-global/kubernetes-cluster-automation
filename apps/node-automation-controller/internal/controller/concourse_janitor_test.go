package controller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	ktesting "k8s.io/client-go/testing"
)

// ---------------------------------------------------------------------------
// Fakes + builders (cj-prefixed)
// ---------------------------------------------------------------------------

// cjFakeExec records "exec:<pod>" and can be told to fail — an exec
// failure alone must never trigger a wipe.
type cjFakeExec struct {
	events *[]string
	fail   bool
}

func (f *cjFakeExec) ExecBash(_ context.Context, _, pod, _ string, _ []byte) (string, error) {
	*f.events = append(*f.events, "exec:"+pod)
	if f.fail {
		return "", errors.New("exec boom")
	}
	return "pruned", nil
}

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
type cjFakeATC struct {
	events   *[]string
	loginErr error
	stateErr error
	states   map[string]string
}

func (f *cjFakeATC) login(_ context.Context, user, _ string) error {
	*f.events = append(*f.events, "login:"+user)
	return f.loginErr
}

func (f *cjFakeATC) workerState(_ context.Context, name string) (string, error) {
	*f.events = append(*f.events, "state:"+name)
	if f.stateErr != nil {
		return "", f.stateErr
	}
	return f.states[name], nil
}

func (f *cjFakeATC) landWorker(_ context.Context, name string) error {
	*f.events = append(*f.events, "land:"+name)
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

func cjScript(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "prune.sh")
	if err := os.WriteFile(p, []byte("echo prune\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// cjTestJanitor builds a janitor with shrunk timeouts — every poll
// fires immediately on the first check; timeouts only matter for the
// failure tests.
func cjTestJanitor(cs *fake.Clientset, ex podExecutor, st nodeStatsReader, atc atcIface, script string) *concourseWorkdirJanitor {
	return &concourseWorkdirJanitor{
		cs: cs, exec: ex, stats: st, atc: atc,
		enabled: true, scriptPath: script,
		runTimeout:     10 * time.Second,
		reqTimeout:     10 * time.Second,
		drainTimeout:   50 * time.Millisecond,
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
	j := &concourseWorkdirJanitor{enabled: false}
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
}

// A missing prune script is a hard error — unlike ATC/stats, this one
// is NOT fail-open.
func TestConcourseJanitorMissingScript(t *testing.T) {
	cs := fake.NewSimpleClientset(cjWorkerSTS(1), cjLocalUsers())
	j := cjTestJanitor(cs, &cjFakeExec{}, &cjFakeStats{}, &cjFakeATC{},
		filepath.Join(t.TempDir(), "does-not-exist.sh"))
	if err := j.run(ctx); err == nil {
		t.Fatal("expected error for a missing prune script")
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
	j := cjTestJanitor(cs, &cjFakeExec{events: &events}, st,
		&cjFakeATC{events: &events, states: map[string]string{}}, cjScript(t))
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cjPod(t, cs, "concourse-worker-0").UID; got != "uid-0" {
		t.Fatalf("pod was replaced despite staying under thresholds (uid %s)", got)
	}
	want := []string{"login:admin", "exec:concourse-worker-0", "stats:node-a"}
	if fmt.Sprint(events) != fmt.Sprint(want) {
		t.Fatalf("events %v, want %v", events, want)
	}
}

// The full wipe path, ordinals descending: exec → stats → land →
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
	j := cjTestJanitor(cs, &cjFakeExec{events: &events}, st,
		&cjFakeATC{events: &events, states: map[string]string{}}, cjScript(t))
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"login:admin",
		"exec:concourse-worker-1", "stats:node-b",
		"land:concourse-worker-1", "state:concourse-worker-1",
		"delete:concourse-worker-1",
		"state:concourse-worker-1", "prune:concourse-worker-1",
		"stats:node-b",
		"exec:concourse-worker-0", "stats:node-a",
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
	j := cjTestJanitor(cs, &cjFakeExec{events: &events}, st, atc, cjScript(t))
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"login:admin",
		"exec:concourse-worker-0", "stats:node-a",
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
// lost to a broken metrics path.
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
	j := cjTestJanitor(cs, &cjFakeExec{events: &events}, st,
		&cjFakeATC{events: &events, states: map[string]string{}}, cjScript(t))
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
}

// An exec failure alone is NOT grounds to wipe — warn and continue to
// the stats decision (pod mid-init etc.).
func TestConcourseJanitorExecFailKeepsCache(t *testing.T) {
	var events []string
	cs := fake.NewSimpleClientset(
		cjWorkerSTS(1),
		cjWorkerPod("concourse-worker-0", "uid-0", "node-a", true, nil),
		cjLocalUsers())
	st := &cjFakeStats{events: &events, calls: map[string]int{},
		fn: func(string, int) (int64, int64, int64, error) {
			return 50 * gib, 200 * gib, 10 * gib, nil
		}}
	j := cjTestJanitor(cs, &cjFakeExec{events: &events, fail: true}, st,
		&cjFakeATC{events: &events, states: map[string]string{}}, cjScript(t))
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cjPod(t, cs, "concourse-worker-0").UID; got != "uid-0" {
		t.Fatalf("exec failure alone caused a wipe: uid %s", got)
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
	j := cjTestJanitor(cs, &cjFakeExec{events: &events}, st,
		&cjFakeATC{events: &events, states: map[string]string{}}, cjScript(t))
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
	j := cjTestJanitor(cs, &cjFakeExec{events: &events}, st,
		&cjFakeATC{events: &events, states: map[string]string{}}, cjScript(t))
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
	j := cjTestJanitor(cs, &cjFakeExec{events: &events}, st,
		&cjFakeATC{events: &events, states: map[string]string{}}, cjScript(t))
	if err := j.run(ctx); err == nil || !strings.Contains(err.Error(), "not Ready") {
		t.Fatalf("expected a Ready-timeout error, got %v", err)
	}
}

// Missing StatefulSet is a hard error — bash `exit 1`.
func TestConcourseJanitorMissingSTS(t *testing.T) {
	var events []string
	cs := fake.NewSimpleClientset(cjLocalUsers())
	j := cjTestJanitor(cs, &cjFakeExec{events: &events}, &cjFakeStats{
		events: &events, calls: map[string]int{},
		fn: func(string, int) (int64, int64, int64, error) { return 0, 0, 0, nil }},
		&cjFakeATC{events: &events, states: map[string]string{}}, cjScript(t))
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
	j := cjTestJanitor(cs, &cjFakeExec{events: &events}, st,
		&cjFakeATC{events: &events, states: map[string]string{}}, cjScript(t))
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cjPod(t, cs, "concourse-worker-0").UID; got != "uid-0" {
		t.Fatalf("young not-Ready pod was replaced (uid %s)", got)
	}
	// exec+stats still ran (stats decide the keep/wipe side); no land,
	// no delete — the guard fires right after the keep-cache check.
	want := []string{"login:admin", "exec:concourse-worker-0", "stats:node-a"}
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
	j := cjTestJanitor(cs, &cjFakeExec{events: &events}, st,
		&cjFakeATC{events: &events, states: map[string]string{}}, cjScript(t))
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
	j := cjTestJanitor(cs, &cjFakeExec{events: &events}, st, atc, cjScript(t))
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
			j := &concourseWorkdirJanitor{cs: cs, reqTimeout: 10 * time.Second}
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
	j := &concourseWorkdirJanitor{cs: cs, reqTimeout: 10 * time.Second}
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
		switch {
		case req.URL.Path == "/sky/issuer/token":
			_ = req.ParseForm()
			r.tokenForm = map[string]string{}
			for k := range req.PostForm {
				r.tokenForm[k] = req.PostForm.Get(k)
			}
			w.WriteHeader(r.tokenCode)
			_, _ = w.Write([]byte(r.tokenBody))
		case req.URL.Path == "/api/v1/workers":
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

// ---------------------------------------------------------------------------
// spdyExecutor.transports — the shared SPDY transport pair.
// ---------------------------------------------------------------------------

// transports() builds the RoundTripper+upgrader exactly once (the
// per-exec remotecommand.NewSPDYExecutor used to leak a fresh
// http.Transport + conn pool per worker pod) and hands the same pair
// to every subsequent call.
func TestSPDYExecutorTransportsCached(t *testing.T) {
	e := &spdyExecutor{cfg: &rest.Config{Host: "https://127.0.0.1:6443"}}
	rt1, up1, err := e.transports()
	if err != nil {
		t.Fatalf("transports: %v", err)
	}
	if rt1 == nil || up1 == nil {
		t.Fatal("transports returned a nil leg")
	}
	rt2, up2, err := e.transports()
	if err != nil {
		t.Fatalf("second transports: %v", err)
	}
	if rt2 != rt1 || up2 != up1 {
		t.Fatal("transports did not return the cached pair")
	}
}

// A config RoundTripperFor rejects (here: unparsable CA data) keeps
// its error cached too — the config never changes between calls, so
// retrying could only repeat the same failure.
func TestSPDYExecutorTransportsErrorCached(t *testing.T) {
	e := &spdyExecutor{cfg: &rest.Config{
		Host:            "https://127.0.0.1:6443",
		TLSClientConfig: rest.TLSClientConfig{CAData: []byte("not-a-pem")},
	}}
	_, _, err1 := e.transports()
	if err1 == nil {
		t.Fatal("expected a transport build error for bad CA data")
	}
	_, _, err2 := e.transports()
	if err2 != err1 {
		t.Fatalf("cached error mismatch: first %v, second %v", err1, err2)
	}
}
