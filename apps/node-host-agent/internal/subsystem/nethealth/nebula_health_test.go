// nebula_health_test.go — nebula-health socket/dataplane probes and isolated/degraded/slowpath/siteedge latches.

package nethealth

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func TestNebulaHealthy(t *testing.T) {
	e := nebulaEnv(t, nil)
	e.n.Cycle(context.Background())
	if stateExists(e, "nebula-isolated") || stateExists(e, "nebula-degraded") {
		t.Fatal("false latch on healthy nebula")
	}
	if e.sd.Ran("restart nebula") {
		t.Fatal("restart on healthy nebula")
	}
}

func TestNebulaNoSocketRestart(t *testing.T) {
	e := nebulaEnv(t, nil)
	testutil.WriteFile(t, e.procudp, "  sl  local_address rem_address   st\n"+
		"  1: 0100007F:0050 00000000:0000 07\n") // no :B9B6 (45670)
	e.n.Cycle(context.Background())
	if e.sd.Ran("restart nebula") {
		t.Fatal("restart before ConsecNeeded")
	}
	e.n.Cycle(context.Background())
	if !e.sd.Ran("restart nebula@interdc") {
		t.Fatalf("nebula not restarted, cmds=%v", e.sd.Cmds())
	}
	if _, err := os.Stat(filepath.Join(e.state, "last-nebula-restart")); err != nil {
		t.Fatal("budget not spent")
	}
}

func TestNebulaDataplaneDeadIsolates(t *testing.T) {
	e := nebulaEnv(t, nil)
	for _, ip := range []string{"10.8.0.1", "10.8.0.2"} {
		e.pingOK[ip+"|false"] = false // all pub targets dead
	}
	e.n.Cycle(context.Background())
	if !stateExists(e, "nebula-isolated") {
		t.Fatal("isolated latch missing on dataplane dead")
	}
	e.n.Cycle(context.Background())
	if !e.sd.Ran("restart nebula@interdc") {
		t.Fatal("no restart on persistent dataplane dead")
	}
}

func TestNebulaDegradedLatch(t *testing.T) {
	e := nebulaEnv(t, func(wd *watchdogconf.Config) {
		wd.OverlayProbeMarkers = []string{"10.8.1.1", "10.8.1.2", "10.8.1.3"}
	})
	// 2 of 3 markers dead but one alive → degraded, not isolated
	// (isolated needs ALL of a group dead).
	e.pingOK["10.8.1.3|false"] = true
	e.pingOK["10.8.1.1|false"] = false
	e.pingOK["10.8.1.2|false"] = false
	e.n.Cycle(context.Background())
	if stateExists(e, "nebula-degraded") {
		t.Fatal("degraded latch before DEGRADED_CONSEC")
	}
	e.n.Cycle(context.Background())
	if !stateExists(e, "nebula-degraded") {
		t.Fatal("degraded latch missing after 2 runs")
	}
	if stateExists(e, "nebula-isolated") {
		t.Fatal("isolated latch on partial loss")
	}
	if e.sd.Ran("restart nebula") {
		t.Fatal("degraded is not a restart reason")
	}
}

func TestNebulaNotActiveCleansStates(t *testing.T) {
	e := nebulaEnv(t, nil)
	e.sd.On("is-active nebula@interdc", "inactive\n")
	testutil.WriteFile(t, filepath.Join(e.state, "state-nebula-isolated"), "1\n")
	e.n.Cycle(context.Background())
	if stateExists(e, "nebula-isolated") {
		t.Fatal("nebula state kept while inactive")
	}
}

func TestNebulaOverlayTincSkipsDataplane(t *testing.T) {
	e := nebulaEnv(t, func(wd *watchdogconf.Config) {
		wd.OverlayActive = "tinc"
	})
	// All probes dead — but overlay=tinc → no dataplane probing, no
	// dataplane states.
	for k := range e.pingOK {
		e.pingOK[k] = false
	}
	e.n.Cycle(context.Background())
	if stateExists(e, "nebula-isolated") || stateExists(e, "nebula-degraded") {
		t.Fatal("dataplane latch while tinc is active overlay")
	}
	if e.sd.Ran("restart nebula") {
		t.Fatal("restart while only dataplane evidence (asymmetric probe)")
	}
}

func TestNebulaSlowpathAndSiteedge(t *testing.T) {
	e := nebulaEnv(t, func(wd *watchdogconf.Config) {
		wd.OverlaySlowpathMarkers = []string{"10.8.1.1"}
		wd.OverlaySiteMarkers = []string{"10.9.0.1"}
	})
	e.pingOK["10.9.0.1|false"] = true
	e.pingRTT["10.8.1.1|false"] = 150 // > slowpath 100ms
	e.pingRTT["10.9.0.1|false"] = 80  // > siteedge 50ms
	e.n.Cycle(context.Background())
	if !stateExists(e, "nebula-slowpath") {
		t.Fatal("slowpath latch missing")
	}
	if !stateExists(e, "nebula-siteedge") {
		t.Fatal("siteedge latch missing")
	}
}
