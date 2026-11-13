package concoursejanitor

import (
	"errors"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

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
		cjReadySibling(),
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
		cjReadySibling(),
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
	j.cfg.drainTimeout = 5 * time.Second
	j.cfg.landFailWait = 20 * time.Millisecond
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
		cjReadySibling(),
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
	j.cfg.pruneStateWait = 50 * time.Millisecond
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
