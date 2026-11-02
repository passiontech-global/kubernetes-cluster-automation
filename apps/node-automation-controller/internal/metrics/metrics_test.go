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

// TestObserveAPIBackend verifies both per-backend gauges land under
// the backend-IP label: rvGap passes through (incl. the -1 probe-fail
// sentinel) and quarantined maps bool → 0/1.
func TestObserveAPIBackend(t *testing.T) {
	const ip = "10.9.9.9"

	ObserveAPIBackend(ip, 137, false)
	if got := testutil.ToFloat64(apiBackendRVGap.WithLabelValues(ip)); got != 137 {
		t.Fatalf("rvGap = %v, want 137", got)
	}
	if got := testutil.ToFloat64(apiBackendQuarantined.WithLabelValues(ip)); got != 0 {
		t.Fatalf("quarantined = %v, want 0", got)
	}

	ObserveAPIBackend(ip, -1, true)
	if got := testutil.ToFloat64(apiBackendRVGap.WithLabelValues(ip)); got != -1 {
		t.Fatalf("rvGap = %v, want -1 (probe failure sentinel)", got)
	}
	if got := testutil.ToFloat64(apiBackendQuarantined.WithLabelValues(ip)); got != 1 {
		t.Fatalf("quarantined = %v, want 1", got)
	}
}

// TestForgetAPIBackend prunes a backend's series when it leaves the
// controller set so /metrics does not leak stale label values.
func TestForgetAPIBackend(t *testing.T) {
	const ip = "10.8.8.8"

	ObserveAPIBackend(ip, 42, true)
	ForgetAPIBackend(ip)

	// DeleteLabelValues reports whether a series existed — a second
	// Forget must find nothing.
	if apiBackendRVGap.DeleteLabelValues(ip) {
		t.Fatal("rvGap series still present after ForgetAPIBackend")
	}
	if apiBackendQuarantined.DeleteLabelValues(ip) {
		t.Fatal("quarantined series still present after ForgetAPIBackend")
	}
}
