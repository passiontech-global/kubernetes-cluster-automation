// Wave-9-NM1 tests — the Nebula DF PMTU probe: small-packet overlay
// pings keep passing while a 1200-byte don't-fragment probe
// blackholes (double-encapsulation path MTU below the overlay MTU).
// The probe only runs while nebula is the active overlay AND at
// least one overlay target answered the small pings; ConsecNeeded
// consecutive DF failures latch state-nebula-pmtu-blackhole.

package nethealth

import (
	"context"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/watchdogconf"
)

// dfProbeRan reports whether the DF ping ran against target — the
// exact argv the W9 probe emits.
func dfProbeRan(e *env, target string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, c := range e.cmds {
		j := strings.Join(c, " ")
		if strings.Contains(j, "-M do") && strings.Contains(j, "1200") &&
			strings.HasSuffix(j, " "+target) {
			return true
		}
	}
	return false
}

// TestNebulaPMTUDFProbeLatchesBlackhole: DF probes fail for
// ConsecNeeded cycles while small pings stay green → the
// nebula-pmtu-blackhole latch enters.
func TestNebulaPMTUDFProbeLatchesBlackhole(t *testing.T) {
	e := nebulaEnv(t, nil)
	e.cmdFail["-M do"] = true // DF ping errors; small pings unaffected

	e.n.Cycle(context.Background())
	if stateExists(e, "nebula-pmtu-blackhole") {
		t.Fatal("pmtu latch on the first failed DF probe")
	}
	e.n.Cycle(context.Background())
	if !stateExists(e, "nebula-pmtu-blackhole") {
		t.Fatal("no nebula-pmtu-blackhole latch after ConsecNeeded DF failures")
	}
	if !dfProbeRan(e, "10.8.0.1") {
		t.Fatalf("DF probe did not target the first alive overlay target; cmds=%v", e.cmds)
	}
	// Neither isolated nor degraded may fire — the small pings are
	// all green; PMTU owns this diagnosis alone.
	if stateExists(e, "nebula-isolated") || stateExists(e, "nebula-degraded") {
		t.Fatal("isolated/degraded latch alongside a pure PMTU failure")
	}
}

// TestNebulaPMTUClearsOnRecovery: a passing DF probe clears the
// streak and the latch.
func TestNebulaPMTUClearsOnRecovery(t *testing.T) {
	e := nebulaEnv(t, nil)
	e.cmdFail["-M do"] = true
	e.n.Cycle(context.Background())
	e.n.Cycle(context.Background())
	if !stateExists(e, "nebula-pmtu-blackhole") {
		t.Fatal("no latch to clear")
	}
	delete(e.cmdFail, "-M do")
	e.n.Cycle(context.Background())
	if stateExists(e, "nebula-pmtu-blackhole") {
		t.Fatal("pmtu latch not cleared after a passing DF probe")
	}
}

// TestNebulaPMTUStreakResetsOnSuccess: a single DF failure between
// successes never accumulates — the streak needs ConsecNeeded
// CONSECUTIVE failures.
func TestNebulaPMTUStreakResetsOnSuccess(t *testing.T) {
	e := nebulaEnv(t, nil)
	e.cmdFail["-M do"] = true
	e.n.Cycle(context.Background()) // fail 1
	delete(e.cmdFail, "-M do")
	e.n.Cycle(context.Background()) // success → streak reset
	e.cmdFail["-M do"] = true
	e.n.Cycle(context.Background()) // fail 1 again
	if stateExists(e, "nebula-pmtu-blackhole") {
		t.Fatal("latch after an interleaved success — streak did not reset")
	}
}

// TestNebulaPMTUSkippedWhenNoAliveTarget: total overlay failure is
// the isolated/degraded verdict's job — no DF probe runs and no
// PMTU latch may appear.
func TestNebulaPMTUSkippedWhenNoAliveTarget(t *testing.T) {
	e := nebulaEnv(t, nil)
	for k := range e.pingOK {
		e.pingOK[k] = false
	}
	e.n.Cycle(context.Background())
	if stateExists(e, "nebula-isolated") {
		// expected — dataplane dead
	} else {
		t.Fatal("isolated latch missing on total overlay failure")
	}
	if stateExists(e, "nebula-pmtu-blackhole") {
		t.Fatal("pmtu latch on total overlay failure")
	}
	if dfProbeRan(e, "10.8.0.1") || e.cmdRan("-M do") {
		t.Fatal("DF probe ran with no alive overlay target")
	}
}

// TestNebulaPMTUClearedWhenOverlayLeavesNebula: switching the active
// overlay to tinc disables the probe and drops any stale latch.
func TestNebulaPMTUClearedWhenOverlayLeavesNebula(t *testing.T) {
	e := nebulaEnv(t, func(wd *watchdogconf.Config) {
		wd.OverlayActive = "tinc"
	})
	e.cmdFail["-M do"] = true
	// Seed a stale latch — the tinc path must clear it.
	writeFile(t, e.state+"/state-nebula-pmtu-blackhole", "1\n")
	e.n.Cycle(context.Background())
	if stateExists(e, "nebula-pmtu-blackhole") {
		t.Fatal("pmtu latch kept while tinc is the active overlay")
	}
	if e.cmdRan("-M do") {
		t.Fatal("DF probe ran while tinc is the active overlay")
	}
}

// TestNebulaPMTUFirstAliveTarget: the probe picks the FIRST
// reachable target in probe order — a dead lead target must not
// waste the probe on an unreachable address.
func TestNebulaPMTUFirstAliveTarget(t *testing.T) {
	e := nebulaEnv(t, nil)
	// 10.8.0.1 dead; 10.8.0.2 + markers alive → probe hits 10.8.0.2.
	e.pingOK["10.8.0.1|false"] = false
	e.cmdFail["-M do"] = true
	e.n.Cycle(context.Background())
	if !dfProbeRan(e, "10.8.0.2") {
		t.Fatalf("DF probe did not target the first ALIVE target; cmds=%v", e.cmds)
	}
	if dfProbeRan(e, "10.8.0.1") {
		t.Fatal("DF probe ran against a dead target")
	}
}
