package concoursejanitor

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// Workdir under cap AND nodefs under threshold → keep the cache, no
// delete. No annotation → baseline estimated as imageFs + 32GiB:
// 50-10-32 = 8GiB <= 100, nodefs 25% < 60%.
func TestConcourseJanitorKeepCache(t *testing.T) {
	var events []string
	cs := fake.NewSimpleClientset(
		cjWorkerSTS(1),
		cjWorkerPod("concourse-worker-0", "uid-0", "node-a", true, nil),
		cjReadySibling(),
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
		cjReadySibling(),
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
// lost to a broken metrics path — and the blind wipe IS metered by
// readStats itself, exactly once (the pre-decision read; the
// post-wipe re-read feeds no decision so it is never metered — the
// same broken path must not count twice per pod per run).
func TestConcourseJanitorStatsErrorFailOpen(t *testing.T) {
	var events []string
	cs := fake.NewSimpleClientset(
		cjWorkerSTS(1),
		cjWorkerPod("concourse-worker-0", "uid-0", "node-a", true, nil),
		cjReadySibling(),
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
	// Exactly one unreadable read is metered — the pre-decision read
	// that drove the wipe. The post-wipe baseline re-read is
	// best-effort (`|| true` in bash) and feeds no decision, so its
	// failure is logged but never counted.
	if got := testutil.QueueErrorCount(t, "concourse-workdir-janitor") - before; got != 1 {
		t.Fatalf("fail-open wipe metered %v times, want exactly 1 (pre-decision read only)", got)
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
		cjReadySibling(),
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
		cjReadySibling(),
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

// A worker pod recreated outside the wipe path (node reboot, manual
// delete, STS rollout) runs init-rm on start but carries no baseline
// annotation — the imageFs+32GiB fallback reads workdir=108GiB here
// (>100 → oan wipe) because the node's non-Concourse local PVCs push
// real nodefs to 150GiB. Inside the stamp window of Ready the
// work-dir is near-empty, so the janitor stamps the current nodefs
// as baseline and keeps the cache.
func TestConcourseJanitorStampsBaselineOnFreshWorker(t *testing.T) {
	var events []string
	cs := fake.NewSimpleClientset(
		cjWorkerSTS(1),
		cjWorkerPod("concourse-worker-0", "uid-0", "node-a", true, nil),
		cjReadySibling(),
		cjLocalUsers())
	st := &cjFakeStats{events: &events, calls: map[string]int{},
		fn: func(string, int) (int64, int64, int64, error) {
			return 150 * gib, 400 * gib, 10 * gib, nil // 37% nodefs
		}}
	j := cjTestJanitor(cs, st,
		&cjFakeATC{events: &events, states: map[string]string{}})
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	p := cjPod(t, cs, "concourse-worker-0")
	if p.UID != "uid-0" {
		t.Fatalf("fresh worker wiped on the fallback estimate: uid %s", p.UID)
	}
	if got := p.Annotations[cjBaselineAnno]; got != "150" {
		t.Fatalf("baseline annotation %q, want \"150\"", got)
	}
	for _, e := range events {
		if e == "delete:concourse-worker-0" {
			t.Fatalf("fresh worker deleted: %v", events)
		}
	}
}

// A worker Ready for 25m (between the old 20m window and the 40m
// window covering the 30m sweep interval + margin) is still inside
// cjBaselineStampWindow: it must be stamped with cjBaselineAnno and
// NOT wiped on the fallback estimate.
func TestConcourseJanitorStampsBaselineMidWindow(t *testing.T) {
	var events []string
	base := time.Now()
	p := cjWorkerPod("concourse-worker-0", "uid-0", "node-a", true, nil)
	p.Status.Conditions[0].LastTransitionTime = metav1.NewTime(base.Add(-25 * time.Minute))
	cs := fake.NewSimpleClientset(
		cjWorkerSTS(1), p, cjReadySibling(), cjLocalUsers())
	st := &cjFakeStats{events: &events, calls: map[string]int{},
		fn: func(string, int) (int64, int64, int64, error) {
			return 150 * gib, 400 * gib, 10 * gib, nil // 37% nodefs, 108GiB fallback
		}}
	j := cjTestJanitor(cs, st,
		&cjFakeATC{events: &events, states: map[string]string{}})
	j.now = func() time.Time { return base }
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	gotPod := cjPod(t, cs, "concourse-worker-0")
	if gotPod.UID != "uid-0" {
		t.Fatalf("mid-window worker wiped on fallback estimate: uid %s", gotPod.UID)
	}
	if got := gotPod.Annotations[cjBaselineAnno]; got != "150" {
		t.Fatalf("baseline annotation %q, want \"150\"", got)
	}
	for _, e := range events {
		if e == "delete:concourse-worker-0" {
			t.Fatalf("mid-window worker deleted: %v", events)
		}
	}
}

// The same pod past the stamp window keeps the fallback estimate —
// its work-dir may already hold real build output, so stamping now
// would hide it. workdir=150-10-32=108 > 100 → normal wipe.
func TestConcourseJanitorNoStampOnSettledWorker(t *testing.T) {
	var events []string
	p := cjWorkerPod("concourse-worker-0", "uid-0", "node-a", true, nil)
	p.Status.Conditions[0].LastTransitionTime = metav1.NewTime(
		time.Now().Add(-cjBaselineStampWindow - time.Minute))
	cs := fake.NewSimpleClientset(
		cjWorkerSTS(1), p, cjReadySibling(), cjLocalUsers())
	cjReplaceOnDelete(cs, &events, true)
	st := &cjFakeStats{events: &events, calls: map[string]int{},
		fn: func(string, int) (int64, int64, int64, error) {
			return 150 * gib, 400 * gib, 10 * gib, nil
		}}
	j := cjTestJanitor(cs, st,
		&cjFakeATC{events: &events, states: map[string]string{}})
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e == "delete:concourse-worker-0" {
			return // wiped on the fallback estimate, as before
		}
	}
	t.Fatalf("settled worker without annotation was not wiped: %v", events)
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
	base := time.Now()
	p := cjWorkerPod("concourse-worker-0", "uid-0", "node-a", false, nil)
	p.CreationTimestamp = metav1.NewTime(base) // younger than readyTimeout
	cs := fake.NewSimpleClientset(cjWorkerSTS(1), p, cjLocalUsers(), cjReadySibling())
	st := &cjFakeStats{events: &events, calls: map[string]int{},
		fn: func(string, int) (int64, int64, int64, error) {
			return 160 * gib, 200 * gib, 10 * gib, nil // 80% — would wipe
		}}
	j := cjTestJanitor(cs, st,
		&cjFakeATC{events: &events, states: map[string]string{}})
	j.now = func() time.Time { return base.Add(10 * time.Millisecond) }
	if err := j.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := cjPod(t, cs, "concourse-worker-0").UID; got != "uid-0" {
		t.Fatalf("young not-Ready pod was replaced (uid %s)", got)
	}
	// The mid-init-rm guard precedes readStats: no stats read, no
	// land, no delete — login is the only side effect.
	want := []string{"login:admin"}
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
	cs := fake.NewSimpleClientset(cjWorkerSTS(1), p, cjLocalUsers(), cjReadySibling())
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
