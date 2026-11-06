// coredns_stub_test.go — coredns stub resolver restart on loopback resolv.conf.

package nethealth

import (
	"context"
	"testing"

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
