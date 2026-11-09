// kubelet_syncloop_test.go — A4 syncloop probe (PLEG freeze
// detection, auth-inconclusive handling) and the containerd
// unix-socket liveness check.
package kubelet_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// --- syncloop + containerd-sock tests ---

func TestSyncloopDownLatchesOnPLEGFreeze(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	e.Status["https://127.0.0.1:10250/healthz/syncloop"] = 500
	for i := 0; i < 2; i++ {
		e.H.Cycle(context.Background())
	}
	if !e.H.State.Exists("kubelet-syncloop-down") {
		t.Fatal("state-kubelet-syncloop-down should latch after 2 failed syncloop probes")
	}
	e.Status["https://127.0.0.1:10250/healthz/syncloop"] = 200
	e.H.Cycle(context.Background())
	if e.H.State.Exists("kubelet-syncloop-down") {
		t.Fatal("recovery should clear the syncloop latch")
	}
}

// TestSyncloopNon200LogsStatusCode: a non-200 answer carries no Go
// error — the suspect/latch lines must still record the code, not
// "last_err=<nil>".
func TestSyncloopNon200LogsStatusCode(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	e.Status["https://127.0.0.1:10250/healthz/syncloop"] = 500
	e.H.Cycle(context.Background()) // streak 1 → suspect line
	if got := e.LogLines(t); !strings.Contains(got, "status 500") {
		t.Fatalf("suspect line must carry the HTTP code, got:\n%s", got)
	}
	e.H.Cycle(context.Background()) // streak 2 → latch
	if !e.H.State.Exists("kubelet-syncloop-down") {
		t.Fatal("latch expected after ConsecNeeded failed probes")
	}
	if got := e.LogLines(t); strings.Contains(got, "last_err=<nil>") {
		t.Fatalf("latch extra must record the code, got:\n%s", got)
	}
}

func TestSyncloopFailClosedWhenActiveCheckErrors(t *testing.T) {
	e := fixture(t)
	// Force the Active() error path: no is-active reply leaves the
	// fake answering ENOENT — the gate is wired but unverifiable,
	// so worker checks must gate off (fail closed). The syncloop
	// probe is ALSO failing — if the gate didn't hold, two cycles
	// would latch kubelet-syncloop-down.
	delete(e.SDReply, "systemctl is-active k0sworker.service")
	e.Status["https://127.0.0.1:10250/healthz/syncloop"] = 500
	for i := 0; i < 2; i++ {
		e.H.Cycle(context.Background())
	}
	if e.H.State.Exists("kubelet-syncloop-down") {
		t.Fatal("no latch may be written while the unit state is unknown")
	}
}

// TestSyncloopUnauthorizedIsInconclusive: a 401/403 answer means
// kubelet is alive but won't divulge the syncloop verdict — the
// check must neither latch nor count failures, and the notice is
// logged once per unauth streak, not every cycle.
func TestSyncloopUnauthorizedIsInconclusive(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	e.Status["https://127.0.0.1:10250/healthz/syncloop"] = 401
	for i := 0; i < 3; i++ {
		e.H.Cycle(context.Background())
	}
	if e.H.State.Exists("kubelet-syncloop-down") {
		t.Fatal("401 must not latch kubelet-syncloop-down")
	}
	got := e.LogLines(t)
	if !strings.Contains(got, "probe unauthorized") {
		t.Fatalf("expected an unauthorized/inconclusive log line, got:\n%s", got)
	}
	if n := strings.Count(got, "probe unauthorized"); n != 1 {
		t.Fatalf("unauthorized should log once per streak, got %d lines:\n%s", n, got)
	}
	// A real verdict ends the streak — a later unauth stretch logs
	// again.
	e.Status["https://127.0.0.1:10250/healthz/syncloop"] = 200
	e.H.Cycle(context.Background())
	e.Status["https://127.0.0.1:10250/healthz/syncloop"] = 401
	e.H.Cycle(context.Background())
	if n := strings.Count(e.LogLines(t), "probe unauthorized"); n != 2 {
		t.Fatalf("unauth after a healthy verdict must re-log, got %d lines", n)
	}
}

// TestSyncloopProbeSendsBearerToken: kubelet :10250 denies anonymous
// /healthz — the SA token from KubeletTokenPath must ride the probe.
func TestSyncloopProbeSendsBearerToken(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	tok := filepath.Join(e.StateDir, "sa-token")
	wdepstest.WriteFile(t, tok, "tok-abc-123\n")
	e.H.Cfg.Kubelet.TokenPath = tok
	e.H.Cycle(context.Background())
	if got := e.Bearer["https://127.0.0.1:10250/healthz/syncloop"]; got != "tok-abc-123" {
		t.Fatalf("syncloop probe bearer = %q, want the SA token", got)
	}
}

func TestContainerdSockDownLatches(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	e.SockErrs[e.H.Cfg.CtrSocket] = errors.New("connection refused")
	for i := 0; i < 2; i++ {
		e.H.Cycle(context.Background())
	}
	if !e.H.State.Exists("containerd-sock-down") {
		t.Fatal("state-containerd-sock-down should latch after 2 socket failures")
	}
	e.SockErrs[e.H.Cfg.CtrSocket] = nil
	e.H.Cycle(context.Background())
	if e.H.State.Exists("containerd-sock-down") {
		t.Fatal("recovery should clear the containerd-sock latch")
	}
}

// TestContainerdSocketDefaultPinsK0sPath: k0s puts the containerd
// socket at /run/k0s/containerd.sock — the nested
// /run/k0s/containerd/ dir is containerd's state root, NOT the
// socket. Probing inside it is a permanent ENOENT that latches
// containerd-sock-down on every agent start (the A4 bug this
// pins).
func TestContainerdSocketDefaultPinsK0sPath(t *testing.T) {
	c := wdeps.Config{}
	c.ApplyDefaults()
	if c.CtrSocket != "/host/run/k0s/containerd.sock" {
		t.Fatalf("default ContainerdSocket=%q, want /host/run/k0s/containerd.sock",
			c.CtrSocket)
	}
	if c.Kubelet.TokenPath != "/var/run/secrets/kubernetes.io/serviceaccount/token" {
		t.Fatalf("default KubeletTokenPath=%q, want the pod SA token path",
			c.Kubelet.TokenPath)
	}
}

// TestProbeUnixSockDefaultReturnsNilOnConnect: a successful dial IS
// the verdict — conn.Close()'s error must not leak into the result.
func TestProbeUnixSockDefaultReturnsNilOnConnect(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "probe.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	c := wdeps.Config{}
	c.ApplyDefaults()
	if err := c.Seams.Probe.ProbeUnixSock(context.Background(), sock, time.Second); err != nil {
		t.Fatalf("successful unix dial want nil, got %v", err)
	}
}

// --- PLEG metrics early warning (kubelet /metrics) ---

// kubelet_pleg_last_seen_seconds is a Unix TIMESTAMP upstream —
// fixtures must stamp it relative to the fixture clock, never a
// bare "age" number.
func plegMetricsHealthy(now time.Time) string {
	return fmt.Sprintf(`# HELP kubelet_pleg_relist_duration_seconds x
kubelet_pleg_relist_duration_seconds{quantile="0.5"} 0.2
kubelet_pleg_relist_duration_seconds{quantile="0.9"} 0.5
kubelet_pleg_relist_duration_seconds{quantile="0.99"} 1.0
kubelet_pleg_relist_duration_seconds_sum 40
kubelet_pleg_relist_duration_seconds_count 200
kubelet_pleg_last_seen_seconds %d
kubelet_pleg_discard_events 7
`, now.Unix()-2)
}

func plegMetricsSlow(now time.Time) string {
	return fmt.Sprintf(`kubelet_pleg_relist_duration_seconds{quantile="0.5"} 1.0
kubelet_pleg_relist_duration_seconds{quantile="0.9"} 6.5
kubelet_pleg_relist_duration_seconds{quantile="0.99"} 8.0
kubelet_pleg_relist_duration_seconds_sum 120
kubelet_pleg_relist_duration_seconds_count 200
kubelet_pleg_last_seen_seconds %d
kubelet_pleg_discard_events 12
`, now.Unix()-45)
}

// plegHistogram is the kubelet-1.37 exposition shape: relist
// duration is a HISTOGRAM (no quantile rows), last_seen a Unix
// timestamp. fast/sum/count describe the cumulative counters.
func plegHistogram(now time.Time, fast, slow, sum, count float64) string {
	return fmt.Sprintf(`kubelet_pleg_relist_duration_seconds_bucket{le="0.005"} 0
kubelet_pleg_relist_duration_seconds_bucket{le="0.05"} 80
kubelet_pleg_relist_duration_seconds_bucket{le="0.5"} %v
kubelet_pleg_relist_duration_seconds_bucket{le="5"} %v
kubelet_pleg_relist_duration_seconds_bucket{le="10"} %v
kubelet_pleg_relist_duration_seconds_bucket{le="+Inf"} %v
kubelet_pleg_relist_duration_seconds_sum %v
kubelet_pleg_relist_duration_seconds_count %v
kubelet_pleg_last_seen_seconds %d
`, fast-20, fast, fast+slow, fast+slow, sum, count, now.Unix())
}

// TestPLEGUnhealthyLatchesAfterConsecNeeded: a degraded relist /
// last-seen scrape must latch state-kubelet-pleg-unhealthy after
// ConsecNeeded cycles while /healthz/syncloop still answers 200 —
// and clear on recovery.
func TestPLEGUnhealthyLatchesAfterConsecNeeded(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	e.MetricsBody = plegMetricsSlow(e.Now)
	for i := 0; i < 2; i++ {
		e.H.Cycle(context.Background())
	}
	if !e.H.State.Exists("kubelet-pleg-unhealthy") {
		t.Fatal("state-kubelet-pleg-unhealthy should latch after 2 over-threshold scrapes")
	}
	if a := e.H.KubeletPLEGLastSeenAgeSec; a < 45 || a >= 46 {
		t.Fatalf("last-seen age gauge=%v want ~45 (timestamp-derived)", a)
	}
	if e.H.KubeletPLEGDiscardEvents != 12 {
		t.Fatalf("discard counter=%v want 12", e.H.KubeletPLEGDiscardEvents)
	}
	// Syncloop itself is still healthy — its latch stays clear.
	if e.H.State.Exists("kubelet-syncloop-down") {
		t.Fatal("PLEG metric degrade must not trip the syncloop latch")
	}
	e.MetricsBody = plegMetricsHealthy(e.Now)
	e.H.Cycle(context.Background())
	if e.H.State.Exists("kubelet-pleg-unhealthy") {
		t.Fatal("recovery should clear the pleg latch")
	}
	if e.H.KubeletPLEGDiscardEvents != 7 {
		t.Fatalf("discard counter=%v want 7 (passthrough)", e.H.KubeletPLEGDiscardEvents)
	}
}

// TestPLEGLiveTimestampNeverFlags — regression for the fleet-wide
// false cordon (all 6 workers latched KubeletPLEGUnhealthy at
// rollout): the metric is a Unix timestamp (~1.7e9 on a live node),
// which an age-comparison flags on EVERY scrape of EVERY node. A
// current timestamp must keep the latch clear — here in the
// kubelet-1.37 histogram exposition.
func TestPLEGLiveTimestampNeverFlags(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	e.MetricsBody = plegHistogram(e.Now, 100, 0, 3, 100)
	for i := 0; i < 3; i++ {
		e.H.Cycle(context.Background())
	}
	if e.H.State.Exists("kubelet-pleg-unhealthy") {
		t.Fatal("a live last-seen timestamp must never flag kubelet-pleg-unhealthy")
	}
}

// TestPLEGStaleTimestampLatches: a last-seen stamp older than 30s
// IS the stall signal — two consecutive stale scrapes latch.
func TestPLEGStaleTimestampLatches(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	e.MetricsBody = plegHistogram(e.Now.Add(-45*time.Second), 100, 0, 3, 100)
	for i := 0; i < 2; i++ {
		e.H.Cycle(context.Background())
	}
	if !e.H.State.Exists("kubelet-pleg-unhealthy") {
		t.Fatal("a 45s-old last-seen stamp should latch kubelet-pleg-unhealthy")
	}
}

// TestPLEGHistogramBaselineSeedsBeforeFlagging: the first scrape
// only seeds the relist baseline — a pre-existing slow tail is not
// counted. Only NEW >5s relists after the baseline flag.
func TestPLEGHistogramBaselineSeedsBeforeFlagging(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	// Node with 5 historical >5s relists — cumulative, not current.
	e.MetricsBody = plegHistogram(e.Now, 95, 5, 30, 100)
	for i := 0; i < 2; i++ {
		e.H.Cycle(context.Background())
	}
	if e.H.State.Exists("kubelet-pleg-unhealthy") {
		t.Fatal("a stable historical slow tail must not flag")
	}
	// Two consecutive scrapes each adding new >5s relists:
	// cumulative slow tail 5→10→15 flags on both cycles.
	e.MetricsBody = plegHistogram(e.Now, 190, 10, 35, 200)
	e.H.Cycle(context.Background())
	e.MetricsBody = plegHistogram(e.Now, 285, 15, 40, 300)
	e.H.Cycle(context.Background())
	if !e.H.State.Exists("kubelet-pleg-unhealthy") {
		t.Fatal("new >5s relists in the histogram tail should latch")
	}
}

// TestPLEGHistogramDeltaAvgLatches: new relists averaging over 5s
// flag via the Δsum/Δcount path even when none lands above le=5
// individually (impossible in practice — covers the avg half).
func TestPLEGHistogramDeltaAvgLatches(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	e.MetricsBody = plegHistogram(e.Now, 100, 0, 3, 100)
	e.H.Cycle(context.Background()) // seed baseline
	// Two consecutive scrapes of ~6s relists: delta avg 6.0 > 5
	// on both cycles (deltas only exist while count grows).
	e.MetricsBody = plegHistogram(e.Now, 100, 10, 63, 110)
	e.H.Cycle(context.Background())
	e.MetricsBody = plegHistogram(e.Now, 110, 10, 120, 120)
	e.H.Cycle(context.Background())
	if !e.H.State.Exists("kubelet-pleg-unhealthy") {
		t.Fatal("a >5s delta avg should latch kubelet-pleg-unhealthy")
	}
}

// TestPLEGScrapeErrorIsInconclusive: a failed /metrics GET must
// neither count a fail nor clear a held latch — same keep-state
// rule as the other failed-probe paths.
func TestPLEGScrapeErrorIsInconclusive(t *testing.T) {
	e := fixture(t)
	e.SDReply["is-active k0sworker.service"] = "active"
	e.MetricsBody = plegMetricsSlow(e.Now)
	for i := 0; i < 2; i++ {
		e.H.Cycle(context.Background())
	}
	if !e.H.State.Exists("kubelet-pleg-unhealthy") {
		t.Fatal("precondition: latch should be set")
	}
	e.MetricsErr = errors.New("connection refused")
	e.MetricsBody = ""
	e.H.Cycle(context.Background())
	if !e.H.State.Exists("kubelet-pleg-unhealthy") {
		t.Fatal("scrape error must keep the latch (inconclusive)")
	}
	// A body without PLEG series is inconclusive too.
	e.MetricsErr = nil
	e.MetricsBody = "kubelet_running_pods 5\n"
	e.H.Cycle(context.Background())
	if !e.H.State.Exists("kubelet-pleg-unhealthy") {
		t.Fatal("missing PLEG family must keep the latch")
	}
}
