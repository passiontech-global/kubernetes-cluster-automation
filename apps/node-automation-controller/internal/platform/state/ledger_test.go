package state

import (
	"fmt"
	"testing"
)

type ledgerKey struct{ ns, name string }

// recordingDelete captures the label-value tuples Prune hands to the
// gauge's DeleteLabelValues.
func recordingDelete(deleted *[][]string) func(...string) bool {
	return func(lv ...string) bool {
		*deleted = append(*deleted, append([]string{}, lv...))
		return true
	}
}

func TestGaugeLedgerPrunesResolved(t *testing.T) {
	var led GaugeLedger[ledgerKey]

	// Sweep 1: two tuples emitted.
	led.Emit(ledgerKey{"ns", "a"}, "ns", "a")
	led.Emit(ledgerKey{"ns", "b"}, "ns", "b")
	var deleted [][]string
	if n := led.Prune(recordingDelete(&deleted)); n != 0 {
		t.Fatalf("first Prune deleted %d, want 0", n)
	}
	if len(deleted) != 0 {
		t.Fatalf("first Prune deleted %v", deleted)
	}

	// Sweep 2: only "b" re-emitted — "a" resolved and must be pruned.
	led.Emit(ledgerKey{"ns", "b"}, "ns", "b")
	deleted = nil
	if n := led.Prune(recordingDelete(&deleted)); n != 1 {
		t.Fatalf("Prune = %d, want 1", n)
	}
	if fmt.Sprint(deleted) != "[[ns a]]" {
		t.Fatalf("deleted = %v, want [[ns a]]", deleted)
	}

	// Sweep 3: nothing emitted — the survivor prunes too.
	deleted = nil
	if n := led.Prune(recordingDelete(&deleted)); n != 1 {
		t.Fatalf("Prune = %d, want 1", n)
	}
	if fmt.Sprint(deleted) != "[[ns b]]" {
		t.Fatalf("deleted = %v, want [[ns b]]", deleted)
	}
}

func TestGaugeLedgerZeroValue(t *testing.T) {
	// A literally-constructed module (no Setup) must work: zero-value
	// ledger, first Prune is a no-op.
	var led GaugeLedger[string]
	var deleted [][]string
	if n := led.Prune(recordingDelete(&deleted)); n != 0 || len(deleted) != 0 {
		t.Fatalf("zero-value Prune = %d/%v", n, deleted)
	}
}

func TestGaugeLedgerLastCarryForward(t *testing.T) {
	var led GaugeLedger[ledgerKey]
	led.Emit(ledgerKey{"ns", "a"}, "ns", "a")
	led.Emit(ledgerKey{"ns", "b"}, "ns", "b")
	led.Prune(recordingDelete(&[][]string{}))

	// This sweep the source is unverifiable: carry last sweep's
	// tuples forward by re-Emitting them — Prune must keep them.
	for k, lv := range led.Last() {
		led.Emit(k, lv...)
	}
	var deleted [][]string
	led.Prune(recordingDelete(&deleted))
	if len(deleted) != 0 {
		t.Fatalf("carry-forward pruned %v", deleted)
	}
	// Last() now reflects the carried-forward sweep.
	if len(led.Last()) != 2 {
		t.Fatalf("Last() = %v", led.Last())
	}
}

func TestGaugeLedgerReconcile(t *testing.T) {
	var led GaugeLedger[string]
	var deleted [][]string
	del := func(lv ...string) bool {
		deleted = append(deleted, append([]string{}, lv...))
		return true
	}
	// First sweep: two tuples emitted, nothing to prune.
	if n := led.Reconcile(map[string][]string{
		"a": {"A"}, "b": {"B"}}, del); n != 0 || len(deleted) != 0 {
		t.Fatalf("first Reconcile pruned %d/%v", n, deleted)
	}
	// Second sweep: "a" persists, "b" resolved, "c" is new.
	deleted = nil
	if n := led.Reconcile(map[string][]string{
		"a": {"A"}, "c": {"C"}}, del); n != 1 {
		t.Fatalf("Reconcile = %d, want 1", n)
	}
	if fmt.Sprint(deleted) != "[[B]]" {
		t.Fatalf("deleted = %v, want [[B]]", deleted)
	}
}

func TestGaugeLedgerEmitClonesLabelValues(t *testing.T) {
	var led GaugeLedger[string]
	lv := []string{"ns", "a"}
	led.Emit("k", lv...)
	lv[0] = "corrupted" // caller mutates its slice after Emit
	led.Prune(recordingDelete(&[][]string{}))

	// Re-emit under a fresh key so "k" is absent next sweep and its
	// stored label values surface in the prune.
	led.Emit("other", "x")
	var deleted [][]string
	led.Prune(recordingDelete(&deleted))
	if fmt.Sprint(deleted) != "[[ns a]]" {
		t.Fatalf("deleted = %v — stored label values were not cloned", deleted)
	}
}
