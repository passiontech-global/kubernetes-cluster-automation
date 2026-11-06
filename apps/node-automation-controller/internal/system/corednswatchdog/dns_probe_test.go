// dns_probe_test.go — coverage for the dual-transport freshness
// query: each coredns pod must answer over BOTH UDP :53 and TCP :53
// and every answer must land inside the expected endpoint set.
package corednswatchdog

import (
	"context"
	"errors"
	"testing"

	"k8s.io/client-go/kubernetes/fake"
)

// exchangeStub builds a dnsExchangeFn serving per-transport results;
// called records which networks the probe actually dialed.
func exchangeStub(answers map[string][]string, errs map[string]error,
	called *[]string) func(context.Context, string, string, string) ([]string, error) {

	return func(_ context.Context, network, _, _ string) ([]string, error) {
		*called = append(*called, network)
		if err := errs[network]; err != nil {
			return nil, err
		}
		return answers[network], nil
	}
}

// Both transports answering on-set IPs passes and merges — the union
// is what the caller diffs against the endpoint set.
func TestCoreDNSDNSProbeBothTransportsPass(t *testing.T) {
	var called []string
	w := &coreDNSWatchdog{dnsExchangeFn: exchangeStub(
		map[string][]string{
			"udp": {"10.1.2.3"},
			"tcp": {"10.1.2.3", "10.1.2.4"},
		}, nil, &called)}
	ips, err := w.dnsProbe(ctx, "10.0.0.1", "svc.ns.svc.cluster.local")
	if err != nil {
		t.Fatalf("both-pass probe errored: %v", err)
	}
	if len(ips) != 2 || !dnsAnswerFresh(ips, map[string]bool{"10.1.2.3": true, "10.1.2.4": true}) {
		t.Fatalf("merged answers = %v, want union of both transports", ips)
	}
	if len(called) != 2 || called[0] != "udp" || called[1] != "tcp" {
		t.Fatalf("transports probed = %v, want [udp tcp]", called)
	}
}

// A failure on EITHER transport is the failure — UDP wedged while TCP
// answers still means the pod is not reliably serving DNS.
func TestCoreDNSDNSProbeUDPFailsTCPPasses(t *testing.T) {
	var called []string
	w := &coreDNSWatchdog{dnsExchangeFn: exchangeStub(
		map[string][]string{"tcp": {"10.1.2.3"}},
		map[string]error{"udp": errors.New("i/o timeout")}, &called)}
	if _, err := w.dnsProbe(ctx, "10.0.0.1", "svc.ns.svc.cluster.local"); err == nil {
		t.Fatal("UDP failure must error even though TCP answered")
	}
}

// The mirror image: TCP wedged while UDP answers.
func TestCoreDNSDNSProbeTCPFailsUDPPasses(t *testing.T) {
	var called []string
	w := &coreDNSWatchdog{dnsExchangeFn: exchangeStub(
		map[string][]string{"udp": {"10.1.2.3"}},
		map[string]error{"tcp": errors.New("connection refused")}, &called)}
	if _, err := w.dnsProbe(ctx, "10.0.0.1", "svc.ns.svc.cluster.local"); err == nil {
		t.Fatal("TCP failure must error even though UDP answered")
	}
}

// An empty answer set on either transport is NODATA — the stale-watch
// signature — even when the other transport answers fine.
func TestCoreDNSDNSProbeEmptyAnswerOnOneTransport(t *testing.T) {
	for _, emptyNet := range []string{"udp", "tcp"} {
		var called []string
		answers := map[string][]string{"udp": {"10.1.2.3"}, "tcp": {"10.1.2.3"}}
		answers[emptyNet] = nil
		w := &coreDNSWatchdog{dnsExchangeFn: exchangeStub(answers, nil, &called)}
		if _, err := w.dnsProbe(ctx, "10.0.0.1", "svc.ns.svc.cluster.local"); err == nil {
			t.Fatalf("empty %s answer must error", emptyNet)
		}
	}
}

// The caller judges the union — an off-set IP served by EITHER
// transport lands in it and fails dnsAnswerFresh, marking the pod
// stale.
func TestCoreDNSDNSProbeAnswerMismatch(t *testing.T) {
	var called []string
	w := &coreDNSWatchdog{dnsExchangeFn: exchangeStub(
		map[string][]string{
			"udp": {"10.1.2.3"},
			"tcp": {"10.9.9.9"}, // stale record the live set no longer carries
		}, nil, &called)}
	ips, err := w.dnsProbe(ctx, "10.0.0.1", "svc.ns.svc.cluster.local")
	if err != nil {
		t.Fatalf("mismatched answers must still return the union, got err=%v", err)
	}
	if dnsAnswerFresh(ips, map[string]bool{"10.1.2.3": true}) {
		t.Fatal("off-set TCP answer must fail the freshness diff")
	}
}

// End-to-end: run() driving the REAL dnsProbe over the transport seam
// — a pod whose TCP listener refuses goes suspect on the first run
// and stale on the second, then recovery deletes it.
func TestCoreDNSWatchdogLayer2TransportFailGoesStale(t *testing.T) {
	ready := true
	svc, es := cdnsProbeService("fresh-svc", "app-ns", 0, &ready)
	cs := fake.NewSimpleClientset(
		cdnsPod("cdns-a", "10.0.0.1"),
		cdnsPod("cdns-b", "10.0.0.2"),
		cdnsDeployment(2, 2, nil),
		svc, es)
	w := newCDNSWatchdog(cs)
	w.dnsFn = w.dnsProbe // exercise the real dual-transport probe
	w.dnsExchangeFn = func(_ context.Context, network, podIP, _ string) ([]string, error) {
		if podIP == "10.0.0.1" && network == "tcp" {
			return nil, errors.New("connection refused")
		}
		return []string{"10.1.2.3"}, nil
	}

	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if got := w.streak.Count("cdns-a"); got != 1 {
		t.Fatalf("first run streak=%d, want 1", got)
	}
	if !cdnsPodExists(t, cs, "cdns-a") {
		t.Fatal("pod deleted on streak 1")
	}
	if err := w.run(ctx); err != nil {
		t.Fatal(err)
	}
	if cdnsPodExists(t, cs, "cdns-a") {
		t.Fatal("TCP-wedged pod not deleted after streak max")
	}
	if !cdnsPodExists(t, cs, "cdns-b") {
		t.Fatal("healthy pod deleted")
	}
}
