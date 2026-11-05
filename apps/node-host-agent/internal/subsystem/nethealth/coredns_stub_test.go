// coredns_stub_test.go — coredns stub resolver restart on loopback resolv.conf.

package nethealth

import (
	"context"
	"testing"
)

// --- coredns-stub (21) ---

func TestCoreDNSStubRestart(t *testing.T) {
	e := fixture(t, nil)
	writeFile(t, e.resv, "nameserver 127.0.0.1\nnameserver 10.1.1.1\n")
	e.sdReply["LoadState --value coredns.service"] = "loaded\n"
	e.sdReply["is-active coredns.service"] = "inactive\n"
	e.n.Cycle(context.Background())
	if !e.sdRan("restart coredns.service") {
		t.Fatalf("coredns not restarted, cmds=%v", e.sdcmds)
	}
	// Cooldown: second cycle does not re-restart.
	e.sdcmds = nil
	e.n.Cycle(context.Background())
	if e.sdRan("restart coredns.service") {
		t.Fatal("restart inside 5m cooldown")
	}
}

func TestCoreDNSStubNoLoopbackNoRestart(t *testing.T) {
	e := fixture(t, nil)
	writeFile(t, e.resv, "nameserver 10.1.1.1\n")
	e.sdReply["LoadState --value coredns.service"] = "loaded\n"
	e.sdReply["is-active coredns.service"] = "inactive\n"
	e.n.Cycle(context.Background())
	if e.sdRan("coredns") {
		t.Fatal("restart without loopback resolv.conf")
	}
}
