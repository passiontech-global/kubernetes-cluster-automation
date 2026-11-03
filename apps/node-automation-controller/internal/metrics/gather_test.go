package metrics

import (
	"testing"

	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

func TestGatherFindsCounters(t *testing.T) {
	IncError("q")
	ObserveHealthCheck("q", true, 0)
	fams, _ := ctrlmetrics.Registry.Gather()
	names := map[string]bool{}
	for _, f := range fams {
		names[f.GetName()] = true
	}
	for _, want := range []string{
		"shell_operator_hook_run_errors_total",
		"node_automation_reconcile_errors_total",
		"kuberhealthy_check",
		"kuberhealthy_check_seconds_since_success",
	} {
		if !names[want] {
			t.Fatalf("family %s not in registry", want)
		}
	}
}
