package integration

import (
	"context"
	"maps"
	"testing"

	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var ctx = context.Background()

// gaugeSeriesValue reads one GaugeVec series off the controller-
// runtime registry WITHOUT creating it — promtestutil.ToFloat64(
// vec.WithLabelValues(...)) instantiates the tuple at 0, which makes
// "want 0" assertions vacuous (absent and emitted-0 are
// indistinguishable). Returns (value, present).
func gaugeSeriesValue(t *testing.T, family string, want map[string]string) (float64, bool) {
	t.Helper()
	fams, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, f := range fams {
		if f.GetName() != family {
			continue
		}
		for _, m := range f.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			if maps.Equal(labels, want) {
				return m.GetGauge().GetValue(), true
			}
		}
	}
	return 0, false
}
