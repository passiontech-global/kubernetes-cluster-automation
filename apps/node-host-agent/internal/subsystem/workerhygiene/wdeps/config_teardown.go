// config_teardown.go — the pod-teardown knobs (36-pod-teardown.sh):
// TeardownConfig, its defaults and its NODE_HOST_AGENT_HYGIENE_*
// env rows.
package wdeps

import (
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// TeardownConfig groups the pod-teardown knobs (36-pod-teardown.sh).
type TeardownConfig struct {
	StuckDeleteAge time.Duration // Terminating age → force-delete candidate
	StuckWedgeAge  time.Duration // Terminating age + task dir → wedge latch
	MaxForceDelete int           // force-delete cap per cycle
}

func (t *TeardownConfig) applyDefaults() {
	if t.StuckDeleteAge <= 0 {
		t.StuckDeleteAge = defaultStuckDeleteAge
	}
	if t.StuckWedgeAge <= 0 {
		t.StuckWedgeAge = defaultStuckWedgeAge
	}
	if t.MaxForceDelete <= 0 {
		t.MaxForceDelete = defaultMaxForceDelete
	}
}

// envKnobs returns the teardown domain's env rows — the stuck-age
// thresholds and the per-cycle force-delete cap.
func (t *TeardownConfig) envKnobs() []envx.Knob {
	return []envx.Knob{
		envx.DurationKnob("NODE_HOST_AGENT_HYGIENE_STUCK_DELETE_AGE", &t.StuckDeleteAge, defaultStuckDeleteAge),
		envx.DurationKnob("NODE_HOST_AGENT_HYGIENE_STUCK_WEDGE_AGE", &t.StuckWedgeAge, defaultStuckWedgeAge),
		envx.IntKnob("NODE_HOST_AGENT_HYGIENE_MAX_FORCE_DELETE", &t.MaxForceDelete, defaultMaxForceDelete),
	}
}
