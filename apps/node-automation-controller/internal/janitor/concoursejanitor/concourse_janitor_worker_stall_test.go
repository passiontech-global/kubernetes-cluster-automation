package concoursejanitor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// ---------------------------------------------------------------------------
// concourse-worker-stall — stalled / Garden max-containers recovery
// ---------------------------------------------------------------------------

// cjSteadyWorkerPod is a worker Ready since `readyAt` — past the
// cjSteadyWorkerMinAge steady-state gate when readyAt is old.
func cjSteadyWorkerPod(name, uid, node string, readyAt time.Time) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: cjNamespace, Name: name,
			UID: types.UID(uid), CreationTimestamp: metav1.NewTime(readyAt),
		},
		Spec: corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{Conditions: []corev1.PodCondition{
			{Type: corev1.PodReady, Status: corev1.ConditionTrue,
				LastTransitionTime: metav1.NewTime(readyAt)},
		}},
	}
}

// The Garden fault classifier matches both observed signatures and
// stays clean on worker noise.
func TestWorkerGardenFaultClassifier(t *testing.T) {
	for _, tc := range []struct {
		logs string
		want string
	}{
		{"", ""},
		{"worker: build 42 finished\nworker: volume gc ok\n", ""},
		{"gardener: error: max containers reached for this worker\n", "garden-max-containers"},
		{"baggageclaim: failed to create volume: no space left on device\n", "baggageclaim-volume-create-failed"},
		{"BAGGAGECLAIM: FAILED TO CREATE VOLUME: disk full\n", "baggageclaim-volume-create-failed"},
		{"some other garden error\n", ""},
	} {
		if got := workerGardenFault(tc.logs); got != tc.want {
			t.Errorf("workerGardenFault(%q) = %q, want %q", tc.logs, got, tc.want)
		}
	}
}

// A steady-state worker TSA-recorded `stalled` with a perfectly
// healthy cache is wiped through the standard chain: stats → land →
// drained → delete → prune → Ready.
func TestConcourseJanitorStalledWorkerWipedDespiteUnderCapCache(t *testing.T) {
	var events []string
	old := time.Now().Add(-time.Hour)
	cs := fake.NewSimpleClientset(
		cjWorkerSTS(1),
		cjSteadyWorkerPod("concourse-worker-0", "uid-0", "node-a", old),
		cjReadySibling(),
		cjLocalUsers())
	cjReplaceOnDelete(cs, &events, true)
	st := &cjFakeStats{events: &events, calls: map[string]int{},
		fn: func(string, int) (int64, int64, int64, error) {
			return 50 * gib, 200 * gib, 10 * gib, nil // under caps
		}}
	j := cjTestJanitor(cs, st,
		&cjFakeATC{events: &events,
			states: map[string]string{"concourse-worker-0": "stalled"}})
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"login:admin",
		"stats:node-a",
		"state:concourse-worker-0", // stalled detection
		"land:concourse-worker-0", "state:concourse-worker-0",
		"delete:concourse-worker-0",
		"state:concourse-worker-0", "prune:concourse-worker-0",
		"stats:node-a",
	}
	if fmt.Sprint(events) != fmt.Sprint(want) {
		t.Fatalf("events:\n%v\nwant:\n%v", events, want)
	}
	if got := cjPod(t, cs, "concourse-worker-0").UID; got != "uid-new-concourse-worker-0" {
		t.Fatalf("stalled worker not replaced: uid %s", got)
	}
}

// A steady-state worker whose TSA state is healthy but whose
// concourse-worker log carries the Garden max-containers signature is
// also wiped; the log read rides the workerLogTail seam.
func TestConcourseJanitorMaxContainersLogWiped(t *testing.T) {
	var events []string
	old := time.Now().Add(-time.Hour)
	cs := fake.NewSimpleClientset(
		cjWorkerSTS(1),
		cjSteadyWorkerPod("concourse-worker-0", "uid-0", "node-a", old),
		cjReadySibling(),
		cjLocalUsers())
	cjReplaceOnDelete(cs, &events, true)
	st := &cjFakeStats{events: &events, calls: map[string]int{},
		fn: func(string, int) (int64, int64, int64, error) {
			return 50 * gib, 200 * gib, 10 * gib, nil
		}}
	j := cjTestJanitor(cs, st,
		&cjFakeATC{events: &events,
			states: map[string]string{"concourse-worker-0": "running"}})
	j.workerLogTail = func(_ context.Context, _ *corev1.Pod) (string, error) {
		return "gardener: max containers reached\n", nil
	}
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cjPod(t, cs, "concourse-worker-0").UID; got != "uid-new-concourse-worker-0" {
		t.Fatalf("max-containers worker not replaced: uid %s", got)
	}
	if !strings.Contains(fmt.Sprint(events), "land:concourse-worker-0") {
		t.Fatalf("recovery chain skipped the land step: %v", events)
	}
}

// The detection stays armed only past the steady-state age: a worker
// Ready 5 minutes ago (likely still inside init-rm from a previous
// wipe) is kept even when the TSA says stalled. State is never
// queried for young pods.
func TestConcourseJanitorYoungWorkerKeptEvenWhenStalled(t *testing.T) {
	var events []string
	fresh := time.Now().Add(-5 * time.Minute)
	cs := fake.NewSimpleClientset(
		cjWorkerSTS(1),
		cjSteadyWorkerPod("concourse-worker-0", "uid-0", "node-a", fresh),
		cjLocalUsers())
	st := &cjFakeStats{events: &events, calls: map[string]int{},
		fn: func(string, int) (int64, int64, int64, error) {
			return 50 * gib, 200 * gib, 10 * gib, nil
		}}
	j := cjTestJanitor(cs, st,
		&cjFakeATC{events: &events,
			states: map[string]string{"concourse-worker-0": "stalled"}})
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cjPod(t, cs, "concourse-worker-0").UID; got != "uid-0" {
		t.Fatalf("young stalled worker was replaced: uid %s", got)
	}
	for _, e := range events {
		if strings.HasPrefix(e, "state:") {
			t.Fatalf("worker state queried for a young pod: %v", events)
		}
	}
}

// concourse-worker-stall parity — a worker pod that is NOT Ready and
// has stayed that way past cjSteadyWorkerMinAge is wedged: it takes
// no builds while the cache looks healthy, so the under-cap branch
// must not skip it forever. It goes through the standard
// drain → delete → prune → waitReady chain even though the TSA state
// read is never consulted (the wedged verdict precedes it).
func TestConcourseJanitorWedgedNotReadyPodReplacedDespiteUnderCap(t *testing.T) {
	var events []string
	old := time.Now().Add(-time.Hour)
	p := cjWorkerPod("concourse-worker-0", "uid-0", "node-a", false, nil)
	p.CreationTimestamp = metav1.NewTime(old)
	p.Status.Conditions = []corev1.PodCondition{
		{Type: corev1.PodReady, Status: corev1.ConditionFalse,
			LastTransitionTime: metav1.NewTime(old)},
	}
	cs := fake.NewSimpleClientset(cjWorkerSTS(1), p, cjLocalUsers(), cjReadySibling())
	cjReplaceOnDelete(cs, &events, true)
	st := &cjFakeStats{events: &events, calls: map[string]int{},
		fn: func(string, int) (int64, int64, int64, error) {
			return 50 * gib, 200 * gib, 10 * gib, nil // under caps
		}}
	j := cjTestJanitor(cs, st,
		&cjFakeATC{events: &events,
			states: map[string]string{"concourse-worker-0": "running"}})
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fmt.Sprint(events), "delete:concourse-worker-0") {
		t.Fatalf("wedged not-Ready pod was not deleted: %v", events)
	}
	if got := cjPod(t, cs, "concourse-worker-0").UID; got != "uid-new-concourse-worker-0" {
		t.Fatalf("wedged not-Ready worker not replaced: uid %s", got)
	}
}

// A not-Ready pod whose Ready condition flipped recently is still
// churning (or mid init-rm) — the under-cap branch keeps it and never
// queries the TSA state for it.
func TestConcourseJanitorYoungNotReadyPodKeptDespiteUnderCap(t *testing.T) {
	var events []string
	p := cjWorkerPod("concourse-worker-0", "uid-0", "node-a", false, nil)
	p.CreationTimestamp = metav1.NewTime(time.Now().Add(-time.Hour)) // past readyTimeout guard
	p.Status.Conditions = []corev1.PodCondition{
		{Type: corev1.PodReady, Status: corev1.ConditionFalse,
			LastTransitionTime: metav1.NewTime(time.Now().Add(-5 * time.Minute))},
	}
	cs := fake.NewSimpleClientset(cjWorkerSTS(1), p, cjLocalUsers(), cjReadySibling())
	st := &cjFakeStats{events: &events, calls: map[string]int{},
		fn: func(string, int) (int64, int64, int64, error) {
			return 50 * gib, 200 * gib, 10 * gib, nil // under caps
		}}
	j := cjTestJanitor(cs, st,
		&cjFakeATC{events: &events, states: map[string]string{}})
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cjPod(t, cs, "concourse-worker-0").UID; got != "uid-0" {
		t.Fatalf("young not-Ready pod was replaced: uid %s", got)
	}
	for _, e := range events {
		if strings.HasPrefix(e, "state:") || strings.HasPrefix(e, "delete:") {
			t.Fatalf("young not-Ready pod was touched: %v", events)
		}
	}
}

// A pod still inside init-rm (an init container has not terminated)
// is never replaced by the wedged-not-Ready path — replacing mid-wipe
// restarts the wipe without freeing anything new.
func TestConcourseJanitorInitRmNotReadyPodUntouched(t *testing.T) {
	var events []string
	old := time.Now().Add(-time.Hour)
	p := cjWorkerPod("concourse-worker-0", "uid-0", "node-a", false, nil)
	p.CreationTimestamp = metav1.NewTime(old)
	p.Status.Conditions = []corev1.PodCondition{
		{Type: corev1.PodReady, Status: corev1.ConditionFalse,
			LastTransitionTime: metav1.NewTime(old)},
	}
	p.Status.InitContainerStatuses = []corev1.ContainerStatus{{
		Name: "init-rm",
		State: corev1.ContainerState{
			Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(old)},
		},
	}}
	cs := fake.NewSimpleClientset(cjWorkerSTS(1), p, cjLocalUsers(), cjReadySibling())
	st := &cjFakeStats{events: &events, calls: map[string]int{},
		fn: func(string, int) (int64, int64, int64, error) {
			return 50 * gib, 200 * gib, 10 * gib, nil // under caps
		}}
	j := cjTestJanitor(cs, st,
		&cjFakeATC{events: &events, states: map[string]string{}})
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cjPod(t, cs, "concourse-worker-0").UID; got != "uid-0" {
		t.Fatalf("mid init-rm pod was replaced: uid %s", got)
	}
	for _, e := range events {
		if strings.HasPrefix(e, "state:") || strings.HasPrefix(e, "delete:") {
			t.Fatalf("mid init-rm pod was touched: %v", events)
		}
	}
}

// ---------------------------------------------------------------------------
// fetchWorkerLogTail — the production workerLogTail seam: a bounded
// GetLogs tail of the concourse-worker container. The fake clientset's
// get/pods/log reactor serves the body; a fetch failure propagates so
// the caller reads inconclusive, never "no fault".
// ---------------------------------------------------------------------------
func TestFetchWorkerLogTail(t *testing.T) {
	pod := cjWorkerPod("worker-1", "uid-1", "node-a", true, nil)

	t.Run("returns the log tail", func(t *testing.T) {
		cs := fake.NewSimpleClientset(pod)
		cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
			"line one\nbaggageclaim: failed to create volume: no space\n", nil))
		j := &concourseWorkdirJanitor{queue: "concourse-workdir-janitor",
			cs: cs, cfg: cjConfig{reqTimeout: 10 * time.Second}}
		logs, err := j.fetchWorkerLogTail(ctx, pod)
		if err != nil {
			t.Fatalf("fetchWorkerLogTail: %v", err)
		}
		if !strings.Contains(logs, "baggageclaim") {
			t.Fatalf("log tail = %q, want the worker log body", logs)
		}
	})

	t.Run("fetch failure propagates", func(t *testing.T) {
		cs := fake.NewSimpleClientset(pod)
		cs.PrependReactor("get", "pods", testutil.ProbeLogReactor(
			"", errors.New("kubelet log read boom")))
		j := &concourseWorkdirJanitor{queue: "concourse-workdir-janitor",
			cs: cs, cfg: cjConfig{reqTimeout: 10 * time.Second}}
		if _, err := j.fetchWorkerLogTail(ctx, pod); err == nil {
			t.Fatal("log fetch failure must propagate")
		}
	})
}
