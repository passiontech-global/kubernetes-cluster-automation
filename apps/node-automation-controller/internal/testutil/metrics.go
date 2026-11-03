package testutil

import (
	"testing"

	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// ReconcileErrorCount reads the native error counter for module `name`
// off the controller-runtime registry (the one internal/metrics.init
// registers into) — end-to-end proof an error path calls IncError.
func ReconcileErrorCount(t *testing.T, name string) float64 {
	t.Helper()
	mfs, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather registry: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "node_automation_reconcile_errors_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "controller" && lp.GetValue() == name {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

// QueueErrorCount reads the legacy hook-error counter for a queue —
// IncError deltas are the observable side-effect for refuse/error
// paths.
func QueueErrorCount(t *testing.T, queue string) float64 {
	t.Helper()
	fams, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, f := range fams {
		if f.GetName() != "shell_operator_hook_run_errors_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "queue" && l.GetValue() == queue {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}
