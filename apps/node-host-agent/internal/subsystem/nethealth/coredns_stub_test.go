// coredns_stub_test.go — coredns stub resolver restart on loopback resolv.conf.

package nethealth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// --- coredns-stub (21) ---

func TestCoreDNSStubRestart(t *testing.T) {
	e := fixture(t, nil)
	testutil.WriteFile(t, e.resv, "nameserver 127.0.0.1\nnameserver 10.1.1.1\n")
	e.sd.On("LoadState --value coredns.service", "loaded\n")
	e.sd.On("is-active coredns.service", "inactive\n")
	e.n.Cycle(context.Background())
	if !e.sd.Ran("restart coredns.service") {
		t.Fatalf("coredns not restarted, cmds=%v", e.sd.Cmds())
	}
	// Cooldown: second cycle does not re-restart.
	e.sd.ClearLog()
	e.n.Cycle(context.Background())
	if e.sd.Ran("restart coredns.service") {
		t.Fatal("restart inside 5m cooldown")
	}
}

func TestCoreDNSStubNoLoopbackNoRestart(t *testing.T) {
	e := fixture(t, nil)
	testutil.WriteFile(t, e.resv, "nameserver 10.1.1.1\n")
	e.sd.On("LoadState --value coredns.service", "loaded\n")
	e.sd.On("is-active coredns.service", "inactive\n")
	e.n.Cycle(context.Background())
	if e.sd.Ran("coredns") {
		t.Fatal("restart without loopback resolv.conf")
	}
}

// Fail closed on the existence probe: an unanswerable `show -p
// LoadState` counts as PRESENT — the opposite lie (absent) would
// skip-gate a restart while the stub is down and resolv.conf dead.
func TestCoreDNSStubExistsProbeErrorFailsClosed(t *testing.T) {
	e := fixture(t, nil)
	testutil.WriteFile(t, e.resv, "nameserver 127.0.0.1\n")
	e.sd.FailOn("LoadState --value coredns.service", errCmdFail)
	e.sd.On("is-active coredns.service", "inactive\n")
	e.sd.On("restart coredns.service", "")
	e.n.Cycle(context.Background())
	if !e.sd.Ran("restart coredns.service") {
		t.Fatalf("failed existence probe must read as present → restart, cmds=%v",
			e.sd.Cmds())
	}
}

// A genuinely absent unit never restarts.
func TestCoreDNSStubUnitAbsentNoRestart(t *testing.T) {
	e := fixture(t, nil)
	testutil.WriteFile(t, e.resv, "nameserver 127.0.0.1\n")
	e.sd.On("LoadState --value coredns.service", "not-found\n")
	e.sd.On("is-active coredns.service", "inactive\n")
	e.n.Cycle(context.Background())
	if e.sd.Ran("restart") {
		t.Fatal("restart attempted on a not-found unit")
	}
}

// Fail closed on the is-active probe: an unanswerable probe must not
// read "active" (that would skip the restart the dead stub needs).
func TestCoreDNSStubActiveProbeErrorFailsClosed(t *testing.T) {
	e := fixture(t, nil)
	testutil.WriteFile(t, e.resv, "nameserver 127.0.0.1\n")
	e.sd.On("LoadState --value coredns.service", "loaded\n")
	e.sd.FailOn("is-active coredns.service", errCmdFail)
	e.n.Cycle(context.Background())
	if e.sd.Ran("restart") {
		t.Fatal("restart on an unanswerable is-active probe")
	}
}

// The cooldown skip is observable: the dead stub inside the 5m
// window re-logs a throttled suspect line and never re-restarts.
func TestCoreDNSStubCooldownLogsSkip(t *testing.T) {
	e := fixture(t, nil)
	testutil.WriteFile(t, e.resv, "nameserver 127.0.0.1\n")
	e.sd.On("LoadState --value coredns.service", "loaded\n")
	e.sd.On("is-active coredns.service", "inactive\n")
	e.sd.On("restart coredns.service", "")
	e.n.Cycle(context.Background()) // restart #1 + budget spend
	e.host.ClearLog()               // drop the restart's conntrack flush
	e.sd.ClearLog()
	e.n.Cycle(context.Background()) // inside cooldown
	if e.sd.Ran("restart coredns.service") {
		t.Fatal("restart refired inside the 5m cooldown")
	}
	if !strings.Contains(logLines(t, e), "restart cooldown (<5m), skip") {
		t.Fatalf("missing cooldown suspect line:\n%s", logLines(t, e))
	}
	// Budget elapsed → the dead stub is restarted again.
	e.now = e.now.Add(corednsRestartInterval + time.Minute)
	e.n.Cycle(context.Background())
	if !e.sd.Ran("restart coredns.service") {
		t.Fatal("no restart after the 5m cooldown elapsed")
	}
}
