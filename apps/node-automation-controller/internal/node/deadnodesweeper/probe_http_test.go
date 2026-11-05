// probe_http_test.go — coverage for the kubelet healthz probe the
// dead-node sweeper makes through the apiserver proxy.
package deadnodesweeper

import (
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

func TestDeadNodeSweeperProbeHTTP(t *testing.T) {
	// Single attempt: "ok" body is the only healthy verdict.
	s := &deadNodeSweeper{cs: testutil.ProbeClientset(t, testutil.ProbeHealthzHandler(200, "ok"))}
	if ok, err := s.probe(ctx, "w1"); err != nil || !ok {
		t.Fatalf("ok=%v err=%v, want true/nil", ok, err)
	}

	// A 200 without "ok" is a clean negative, NOT an error — the
	// apiserver served the request, the kubelet didn't.
	s = &deadNodeSweeper{cs: testutil.ProbeClientset(t,
		testutil.ProbeHealthzHandler(200, "error trying to reach service: connection refused"))}
	if ok, err := s.probe(ctx, "w1"); err != nil || ok {
		t.Fatalf("ok=%v err=%v, want false/nil", ok, err)
	}

	// 5xx surfaces as a DoRaw error — still a failed probe.
	s = &deadNodeSweeper{cs: testutil.ProbeClientset(t, testutil.ProbeHealthzHandler(500, "oops"))}
	if ok, err := s.probe(ctx, "w1"); err == nil || ok {
		t.Fatalf("ok=%v err=%v, want false/err", ok, err)
	}
}
