package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

// TestIncErrorIncrementsBothCounters pins the dual-metric contract:
// every module error must bump the shell-operator-compatible counter
// AND the native controller counter under the same label value.
func TestIncErrorIncrementsBothCounters(t *testing.T) {
	const name = "test-queue"
	hook := hookRunErrors.WithLabelValues(name)
	native := reconcileErrors.WithLabelValues(name)

	h0, n0 := testutil.ToFloat64(hook), testutil.ToFloat64(native)
	IncError(name)
	IncError(name)

	if got := testutil.ToFloat64(hook); got != h0+2 {
		t.Fatalf("hookRunErrors{%q} = %v, want %v", name, got, h0+2)
	}
	if got := testutil.ToFloat64(native); got != n0+2 {
		t.Fatalf("reconcileErrors{%q} = %v, want %v", name, got, n0+2)
	}
}

// TestIncErrorLabelNames guards the alert contract — the legacy
// counter's label must stay "queue", the native one's "controller".
func TestIncErrorLabelNames(t *testing.T) {
	cases := []struct {
		counter interface{ Write(*dto.Metric) error }
		want    string
	}{
		{hookRunErrors.WithLabelValues("x"), "queue"},
		{reconcileErrors.WithLabelValues("x"), "controller"},
	}
	for _, c := range cases {
		m := &dto.Metric{}
		if err := c.counter.Write(m); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		if len(m.GetLabel()) != 1 || m.GetLabel()[0].GetName() != c.want {
			t.Fatalf("labels = %v, want single label %q", m.GetLabel(), c.want)
		}
	}
}
