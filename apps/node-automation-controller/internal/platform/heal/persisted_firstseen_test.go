package heal

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
)

const testAnnoKey = "passiontech.dev/first-seen-test"

// applyPatch simulates the apiserver landing a merge-annotations
// patch on obj so later calls see the stamped/cleared state.
func applyPatch(obj *corev1.Pod) func(context.Context, []byte) error {
	return func(_ context.Context, data []byte) error {
		var doc struct {
			Metadata struct {
				Annotations map[string]*string `json:"annotations"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			return err
		}
		if obj.Annotations == nil {
			obj.Annotations = map[string]string{}
		}
		for k, v := range doc.Metadata.Annotations {
			if v == nil {
				delete(obj.Annotations, k)
				continue
			}
			obj.Annotations[k] = *v
		}
		return nil
	}
}

// First sight: inside the window, ledger stamps now AND the stamp
// is merge-patched onto the object — the durable half exists from
// the first observation, not just once the window elapses.
func TestFirstSeenPersistedFirstSightStamps(t *testing.T) {
	now := time.Now()
	var fs state.FirstSeenLedger
	obj := &corev1.Pod{}

	if FirstSeenPersisted(ctx, logr.Discard(), &fs, obj,
		testAnnoKey, "k", time.Minute, now, applyPatch(obj)) {
		t.Fatal("first sight reported past the window")
	}
	var m map[string]string
	raw := obj.Annotations[testAnnoKey]
	if raw == "" {
		t.Fatal("no annotation stamped on first sight")
	}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("anno value not a JSON map: %v", err)
	}
	if m["k"] != now.UTC().Format(time.RFC3339) {
		t.Fatalf("anno stamp = %q, want %q", m["k"],
			now.UTC().Format(time.RFC3339))
	}
}

// The post-restart restore: an empty ledger + a persisted stamp
// older than minAge reports the window elapsed on the FIRST call —
// the signature held continuously; a fresh in-RAM window would sit
// the remediation out a second time.
func TestFirstSeenPersistedRestartResume(t *testing.T) {
	now := time.Now()
	old := now.Add(-15 * time.Minute)
	var fs state.FirstSeenLedger
	obj := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
		testAnnoKey: `{"k":"` + old.UTC().Format(time.RFC3339) + `"}`}}}

	if !FirstSeenPersisted(ctx, logr.Discard(), &fs, obj,
		testAnnoKey, "k", 10*time.Minute, now, applyPatch(obj)) {
		t.Fatal("persisted window not honored on an empty ledger")
	}
	// The ledger restored the persisted stamp (Seed), so the verdict
	// stays stable if the annotation later vanishes mid-sweep.
	if age, ok := fs.Seen("k", now); !ok || age < 15*time.Minute {
		t.Fatalf("ledger did not restore the persisted stamp: %v %v", age, ok)
	}
}

// The wider clock wins BOTH ways: a ledger stamp older than the
// annotation keeps governing (in-RAM evidence of an earlier sight).
func TestFirstSeenPersistedLedgerIsWider(t *testing.T) {
	now := time.Now()
	var fs state.FirstSeenLedger
	// 20 minutes of in-RAM sightings; the object carries a stamp
	// only 5m old — the verdict must read the 20m window.
	fs.Seed("k", now.Add(-20*time.Minute))
	obj := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
		testAnnoKey: `{"k":"` + now.Add(-5*time.Minute).UTC().Format(time.RFC3339) + `"}`}}}

	patches := 0
	if !FirstSeenPersisted(ctx, logr.Discard(), &fs, obj,
		testAnnoKey, "k", 10*time.Minute, now,
		func(_ context.Context, _ []byte) error { patches++; return nil }) {
		t.Fatal("wider ledger window lost to a younger annotation")
	}
	if patches == 0 {
		t.Fatal("younger annotation not converged to the ledger stamp")
	}
}

// A failed stamp never fails the verdict — the ledger still counts
// the window and the stamp retries next sweep (the signature must
// not fail the sweep on a write error).
func TestFirstSeenPersistedStampFailureTolerated(t *testing.T) {
	now := time.Now()
	var fs state.FirstSeenLedger
	fs.Seed("k", now.Add(-time.Hour))
	obj := &corev1.Pod{}

	fail := func(context.Context, []byte) error {
		return errors.New("patch rejected")
	}
	if !FirstSeenPersisted(ctx, logr.Discard(), &fs, obj,
		testAnnoKey, "k", time.Minute, now, fail) {
		t.Fatal("stamp failure suppressed the in-RAM verdict")
	}
	if _, ok := obj.Annotations[testAnnoKey]; ok {
		t.Fatal("failed patch wrote an annotation")
	}
}

// Clear drops the key from BOTH clocks — the ledger Forget plus the
// map entry removed; the annotation itself survives while sibling
// keys remain.
func TestClearPersistedFirstSeen(t *testing.T) {
	now := time.Now()
	var fs state.FirstSeenLedger
	fs.Observe("k", now)
	obj := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
		testAnnoKey: `{"k":"` + now.Format(time.RFC3339) +
			`","other":"` + now.Format(time.RFC3339) + `"}`}}}

	if err := ClearPersistedFirstSeen(ctx, logr.Discard(), &fs, obj,
		testAnnoKey, "k", applyPatch(obj)); err != nil {
		t.Fatal(err)
	}
	if _, ok := fs.Seen("k", now); ok {
		t.Fatal("ledger key survived the clear")
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(obj.Annotations[testAnnoKey]), &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["k"]; ok {
		t.Fatal("cleared key still in the annotation map")
	}
	if m["other"] == "" {
		t.Fatal("clear of one key wiped a sibling signature's stamp")
	}
}

// Last key leaving removes the whole annotation; an untracked clear
// pays no patch at all.
func TestClearPersistedFirstSeenEdge(t *testing.T) {
	now := time.Now()
	var fs state.FirstSeenLedger

	// Never tracked — no patch issued.
	obj := &corev1.Pod{}
	if err := ClearPersistedFirstSeen(ctx, logr.Discard(), &fs, obj,
		testAnnoKey, "k", func(context.Context, []byte) error {
			t.Fatal("patch issued for a never-stamped key")
			return nil
		}); err != nil {
		t.Fatal(err)
	}

	// Last remaining key → the anno is removed entirely.
	obj = &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
		testAnnoKey: `{"k":"` + now.Format(time.RFC3339) + `"}`}}}
	if err := ClearPersistedFirstSeen(ctx, logr.Discard(), &fs, obj,
		testAnnoKey, "k", applyPatch(obj)); err != nil {
		t.Fatal(err)
	}
	if _, ok := obj.Annotations[testAnnoKey]; ok {
		t.Fatal("empty map did not remove the annotation")
	}
}

// A NIL ledger must not panic — the nil posture ClearPersistedFirstSeen
// already honors (callers without an in-RAM ledger, e.g. ad-hoc
// verdict sites): the window lives entirely in the annotation, the
// first sight stamps now and reports inside-the-window, and a
// persisted stamp older than minAge reports elapsed on the first call.
func TestFirstSeenPersistedNilLedger(t *testing.T) {
	now := time.Now()

	// First sight with no ledger: false, and the stamp lands on the
	// object so a restart (or a later ledger-bearing caller) resumes.
	obj := &corev1.Pod{}
	if FirstSeenPersisted(ctx, logr.Discard(), nil, obj,
		testAnnoKey, "k", time.Minute, now, applyPatch(obj)) {
		t.Fatal("nil ledger first sight reported past the window")
	}
	if obj.Annotations[testAnnoKey] == "" {
		t.Fatal("nil ledger first sight did not stamp the annotation")
	}

	// Persisted window already proven — no ledger needed to see it.
	old := now.Add(-15 * time.Minute)
	obj = &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
		testAnnoKey: `{"k":"` + old.UTC().Format(time.RFC3339) + `"}`}}}
	if !FirstSeenPersisted(ctx, logr.Discard(), nil, obj,
		testAnnoKey, "k", 10*time.Minute, now, applyPatch(obj)) {
		t.Fatal("nil ledger dropped a persisted window")
	}
	// The nil ledger must not have re-stamped the older window with now.
	var m map[string]string
	if err := json.Unmarshal([]byte(obj.Annotations[testAnnoKey]), &m); err != nil {
		t.Fatal(err)
	}
	if m["k"] != old.UTC().Format(time.RFC3339) {
		t.Fatalf("nil ledger rejuvenated the persisted stamp: %q", m["k"])
	}
}
