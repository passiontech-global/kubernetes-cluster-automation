package agent

import (
	"context"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
)

func TestLivenessWedgedScenarios(t *testing.T) {
	a := &Agent{}

	// 1. Inactive subBeat with stale fallback -> not wedged.
	inactive := &subBeat{}
	liveInactive := cycle.NewLiveness()
	liveInactive.Fallback().StampAt(time.Now().Add(-time.Hour))
	inactive.live.Store(liveInactive)
	a.beats.Store("inactive", inactive)
	if a.livenessWedged() {
		t.Fatal("inactive subsystem should not be reported wedged")
	}

	// 2. Active but exempt subBeat with stale fallback -> not wedged.
	exempt := &subBeat{}
	exempt.active.Store(true)
	liveExempt := cycle.NewLiveness()
	cycle.Exempt(cycle.WithLiveness(context.Background(), liveExempt))
	liveExempt.Fallback().StampAt(time.Now().Add(-time.Hour))
	exempt.live.Store(liveExempt)
	a.beats.Store("exempt", exempt)
	if a.livenessWedged() {
		t.Fatal("exempt subsystem should not be reported wedged")
	}

	// 3. Active loop beat within budget -> not wedged.
	fresh := &subBeat{}
	fresh.active.Store(true)
	liveFresh := cycle.NewLiveness()
	lb := liveFresh.RegisterLoop("fast", time.Minute, time.Minute)
	lb.Stamp()
	fresh.live.Store(liveFresh)
	a.beats.Store("fresh", fresh)
	if a.livenessWedged() {
		t.Fatal("fresh loop beat should not be reported wedged")
	}

	// 4. Active stale loop beat -> wedged.
	lb.StampAt(time.Now().Add(-time.Hour))
	if !a.livenessWedged() {
		t.Fatal("stale loop beat should be reported wedged")
	}

	// 5. Clear stale loop beat, add stale fallback beat on subsystem with no loops -> wedged.
	a.beats.Delete("fresh")
	fb := &subBeat{}
	fb.active.Store(true)
	liveFB := cycle.NewLiveness()
	liveFB.Fallback().StampAt(time.Now().Add(-time.Hour))
	fb.live.Store(liveFB)
	a.beats.Store("fallback", fb)
	if !a.livenessWedged() {
		t.Fatal("stale fallback beat should be reported wedged")
	}
}
