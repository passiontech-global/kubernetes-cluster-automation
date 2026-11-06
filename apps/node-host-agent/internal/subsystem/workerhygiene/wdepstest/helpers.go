// helpers.go — the free helpers the workerhygiene test files share:
// file writers, pod-UID constants, clientset action filters, pid
// closures, the PSI-thrash proc files, and the typed check accessor
// the external domain test packages reach check state through.
package wdepstest

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// Pod UIDs shared across the suite (was uidA..uidF in
// workerhygiene_test.go).
const (
	UIDA = "11111111-2222-3333-4444-555555555555"
	UIDB = "22222222-2222-3333-4444-555555555555"
	UIDC = "33333333-2222-3333-4444-555555555555"
	UIDD = "44444444-2222-3333-4444-555555555555"
	UIDE = "55555555-2222-3333-4444-555555555555"
	UIDF = "66666666-2222-3333-4444-555555555555"
)

// WriteFile writes path with parent dirs — the fixture's file-layer
// (was writeFile in workerhygiene_test.go).
func WriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// DeleteActions returns the pod delete actions the fake clientset
// recorded.
func DeleteActions(cs *fake.Clientset) []k8stesting.DeleteAction {
	var out []k8stesting.DeleteAction
	for _, a := range cs.Actions() {
		if d, ok := a.(k8stesting.DeleteAction); ok && a.GetResource().Resource == "pods" {
			out = append(out, d)
		}
	}
	return out
}

// EvictActions returns the pod names evicted through the
// policy/v1 Eviction subresource — the fake clientset records them
// as create actions on pods/eviction carrying the *policyv1.Eviction
// object (W9: the PSI evictor uses the eviction API so PDBs are
// enforced, not raw deletes).
func EvictActions(cs *fake.Clientset) []string {
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

// PidsOf returns a CycleEnv.PidsOnce closure answering the given
// pids — the canned /proc sweep (was pidsOf in
// node_health_guards_test.go).
func PidsOf(pids ...int) func() []int {
	return func() []int { return pids }
}

// WriteThrashFiles lays down the PSI pressure/memory + meminfo files
// the thrash check reads: full avg60 (percent) and
// MemAvailable/MemTotal in kB (was writeThrashFiles in
// watchdog_healing_test.go).
func WriteThrashFiles(t *testing.T, f *Fixture, avg60 float64, availKB, totalKB int) {
	t.Helper()
	WriteFile(t, filepath.Join(f.ProcDir, "pressure", "memory"), fmt.Sprintf(
		"some avg10=1.00 avg60=%.2f avg300=1.00 total=1\nfull avg10=1.00 avg60=%.2f avg300=1.00 total=1\n",
		avg60, avg60))
	WriteFile(t, filepath.Join(f.ProcDir, "meminfo"), fmt.Sprintf(
		"MemTotal: %d kB\nMemFree: %d kB\nMemAvailable: %d kB\n",
		totalKB, availKB, availKB))
}

// CheckNamer is the slice of *workerhygiene.Hygiene the typed
// accessor needs — declared here so this package never imports
// workerhygiene (the parent's own test package imports THIS one).
type CheckNamer interface {
	Check(name string) wdeps.Check
}

// Check returns the Hygiene's registered check name typed as C —
// the external domain test packages' handle on their check's
// streak/latch state (Hygiene's named fields are unexported, so
// parent-package tests use those while package X_test files use
// this). It panics on a wrong name or type — a fixture bug, not a
// test failure.
func Check[C wdeps.Check](h CheckNamer, name string) C {
	c := h.Check(name)
	if c == nil {
		panic("wdepstest.Check: no check named " + name)
	}
	typed, ok := c.(C)
	if !ok {
		var want C
		panic(fmt.Sprintf("wdepstest.Check: %s is %T, not %T", name, c, want))
	}
	return typed
}
