// cilium_fqdn_test.go — external tests for #5A Cilium toFQDNs L1 guard
// (package cilium_test).
package cilium_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

func readPromTextfile(t *testing.T, e *env) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.H.PromTextfileDir(), "node-agent-hygiene.prom"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCiliumFQDNNonCiliumHost(t *testing.T) {
	e := fixture(t)
	probed := false
	e.H.Cfg.Seams.Probe.HTTPGetBody = func(context.Context, string, time.Duration) ([]byte, error) {
		probed = true
		return nil, errors.New("should not probe")
	}

	e.H.Series.CiliumFQDNPressure = 1 // verify reset on non-Cilium host
	e.H.Cycle(context.Background())

	if probed {
		t.Fatal("expected no metrics probe on non-Cilium host")
	}
	if e.H.Series.CiliumFQDNPressure != 0 {
		t.Fatalf("CiliumFQDNPressure=%d want 0", e.H.Series.CiliumFQDNPressure)
	}
	if !strings.Contains(readPromTextfile(t, e), "node_agent_cilium_fqdn_pressure 0\n") {
		t.Fatalf("missing zero gauge in textfile:\n%s", readPromTextfile(t, e))
	}
	evs, err := e.CS.EventsV1().Events("default").List(context.Background(), metav1.ListOptions{})
	if err != nil || len(evs.Items) != 0 {
		t.Fatalf("events=%v err=%v want 0", evs, err)
	}
	if len(e.Kills) != 0 {
		t.Fatalf("kills=%v want 0", e.Kills)
	}
}

func TestCiliumFQDNHealthy(t *testing.T) {
	e := fixture(t)
	e.MkCiliumTask(t, 4001)
	e.EndpointsBody = []byte(`[{"id":1,"status":{"state":"ready"}}]`)
	e.FQDNCacheBody = []byte(`[]`)
	e.HTTPBodies[e.H.Cfg.Cilium.MetricsURL] = []byte(
		"cilium_endpoint_state{endpoint_state=\"ready\"} 1\n" +
			"cilium_fqdn_gc_deletions_total 10\n",
	)

	for range 3 {
		e.H.Cycle(context.Background())
	}
	if e.H.Series.CiliumFQDNPressure != 0 {
		t.Fatalf("CiliumFQDNPressure=%d want 0", e.H.Series.CiliumFQDNPressure)
	}
	if !strings.Contains(readPromTextfile(t, e), "node_agent_cilium_fqdn_pressure 0\n") {
		t.Fatalf("expected node_agent_cilium_fqdn_pressure 0 in textfile:\n%s", readPromTextfile(t, e))
	}
	evs, err := e.CS.EventsV1().Events("default").List(context.Background(), metav1.ListOptions{})
	if err != nil || len(evs.Items) != 0 {
		t.Fatalf("events=%v err=%v want 0", evs, err)
	}
	if len(e.Kills) != 0 {
		t.Fatalf("kills=%v want 0", e.Kills)
	}
}

func TestCiliumFQDNTransientWaitingNoAlert(t *testing.T) {
	e := fixture(t)
	e.MkCiliumTask(t, 4002)
	e.EndpointsBody = []byte(`[{"id":1,"status":{"state":"waiting-to-regenerate"}}]`)
	e.FQDNCacheBody = []byte(`[]`)
	e.HTTPBodies[e.H.Cfg.Cilium.MetricsURL] = []byte(
		"cilium_endpoint_state{endpoint_state=\"waiting-to-regenerate\"} 1\n",
	)

	// 2 transient cycles (< 3) must NOT alert.
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if e.H.Series.CiliumFQDNPressure != 0 {
		t.Fatalf("transient 2-cycle pressure set gauge=%d want 0", e.H.Series.CiliumFQDNPressure)
	}
	evs, err := e.CS.EventsV1().Events("default").List(context.Background(), metav1.ListOptions{})
	if err != nil || len(evs.Items) != 0 {
		t.Fatalf("transient cycles must not emit events: %v err=%v", evs, err)
	}

	// Recovery on cycle 3 resets streak; two more stalled cycles still must not alert.
	e.EndpointsBody = []byte(`[{"id":1,"status":{"state":"ready"}}]`)
	e.HTTPBodies[e.H.Cfg.Cilium.MetricsURL] = []byte(
		"cilium_endpoint_state{endpoint_state=\"waiting-to-regenerate\"} 0\n",
	)
	e.H.Cycle(context.Background())

	e.EndpointsBody = []byte(`[{"id":1,"status":{"state":"waiting-to-regenerate"}}]`)
	e.HTTPBodies[e.H.Cfg.Cilium.MetricsURL] = []byte(
		"cilium_endpoint_state{endpoint_state=\"waiting-to-regenerate\"} 1\n",
	)
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if e.H.Series.CiliumFQDNPressure != 0 {
		t.Fatalf("reset streak failed: gauge=%d want 0", e.H.Series.CiliumFQDNPressure)
	}
	if len(e.Kills) != 0 {
		t.Fatalf("kills=%v want 0", e.Kills)
	}
}

func TestCiliumFQDNSustainedWaitingAlertAndRecovery(t *testing.T) {
	e := fixture(t)
	e.MkCiliumTask(t, 4003)
	e.EndpointsBody = []byte(`[{"id":1,"status":{"state":"waiting-to-regenerate"}}]`)
	e.FQDNCacheBody = []byte(`[{"fqdn":"api.github.com."}]`)
	e.HTTPBodies[e.H.Cfg.Cilium.MetricsURL] = []byte(
		"cilium_endpoint_state{endpoint_state=\"waiting-to-regenerate\"} 2\n",
	)

	// Cycles 1-2: pending.
	e.H.Cycle(context.Background())
	e.H.Cycle(context.Background())
	if e.H.Series.CiliumFQDNPressure != 0 {
		t.Fatalf("gauge=%d before 3 cycles", e.H.Series.CiliumFQDNPressure)
	}

	// Cycle 3: confirmed -> gauge=1 + Warning Event, zero cilium-agent kills.
	e.H.Cycle(context.Background())
	if e.H.Series.CiliumFQDNPressure != 1 {
		t.Fatalf("CiliumFQDNPressure=%d want 1 after 3 cycles", e.H.Series.CiliumFQDNPressure)
	}
	if !strings.Contains(readPromTextfile(t, e), "node_agent_cilium_fqdn_pressure 1\n") {
		t.Fatalf("expected node_agent_cilium_fqdn_pressure 1:\n%s", readPromTextfile(t, e))
	}
	evs, err := e.CS.EventsV1().Events("default").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs.Items) != 1 || evs.Items[0].Reason != "CiliumFQDNPressure" || evs.Items[0].Type != "Warning" {
		t.Fatalf("unexpected events: %+v", evs.Items)
	}

	// Cycle 4 within 30m cooldown: gauge stays 1, event is deduped.
	e.Now = e.Now.Add(5 * time.Minute)
	e.H.Cycle(context.Background())
	evs, err = e.CS.EventsV1().Events("default").List(context.Background(), metav1.ListOptions{})
	if err != nil || len(evs.Items) != 1 {
		t.Fatalf("expected event cooldown dedup (want 1 event, got %d, err=%v)", len(evs.Items), err)
	}
	if len(e.Kills) != 0 {
		t.Fatalf("detect-only check must never kill cilium-agent; kills=%v", e.Kills)
	}

	// Cycle 5: recovery resets gauge back to 0 in textfile.
	e.EndpointsBody = []byte(`[{"id":1,"status":{"state":"ready"}}]`)
	e.HTTPBodies[e.H.Cfg.Cilium.MetricsURL] = []byte(
		"cilium_endpoint_state{endpoint_state=\"waiting-to-regenerate\"} 0\n",
	)
	e.H.Cycle(context.Background())
	if e.H.Series.CiliumFQDNPressure != 0 {
		t.Fatalf("CiliumFQDNPressure=%d want 0 on recovery", e.H.Series.CiliumFQDNPressure)
	}
	if !strings.Contains(readPromTextfile(t, e), "node_agent_cilium_fqdn_pressure 0\n") {
		t.Fatalf("expected node_agent_cilium_fqdn_pressure 0 after recovery:\n%s", readPromTextfile(t, e))
	}
}

func TestCiliumFQDNGCSurgeWithToFQDNsPressure(t *testing.T) {
	e := fixture(t)
	e.MkCiliumTask(t, 4004)
	e.EndpointsBody = []byte(`[{"id":1,"status":{"state":"ready"}}]`)
	e.FQDNCacheBody = []byte(`[]`)
	e.HTTPBodies[e.H.Cfg.Cilium.MetricsURL] = []byte("cilium_fqdn_gc_deletions_total 10\n")

	// Cycle 1: baseline.
	e.H.Cycle(context.Background())
	if e.H.Series.CiliumFQDNPressure != 0 {
		t.Fatalf("baseline gauge=%d want 0", e.H.Series.CiliumFQDNPressure)
	}

	// Cycle 2: GC surge WITHOUT tofqdns pressure -> no alert.
	e.HTTPBodies[e.H.Cfg.Cilium.MetricsURL] = []byte("cilium_fqdn_gc_deletions_total 90\n")
	e.H.Cycle(context.Background())
	if e.H.Series.CiliumFQDNPressure != 0 {
		t.Fatalf("surge without tofqdns pressure set gauge=%d want 0", e.H.Series.CiliumFQDNPressure)
	}

	// Cycle 3: GC surge WITH tofqdns cache pressure -> alerts (detect-only).
	e.FQDNCacheBody = []byte(`[{"fqdn":"registry-1.docker.io."}]`)
	e.HTTPBodies[e.H.Cfg.Cilium.MetricsURL] = []byte("cilium_fqdn_gc_deletions_total 200\n")
	e.H.Cycle(context.Background())
	if e.H.Series.CiliumFQDNPressure != 1 {
		t.Fatalf("CiliumFQDNPressure=%d want 1 on GC surge + tofqdns pressure", e.H.Series.CiliumFQDNPressure)
	}
	if !strings.Contains(readPromTextfile(t, e), "node_agent_cilium_fqdn_pressure 1\n") {
		t.Fatalf("expected gauge=1 in textfile:\n%s", readPromTextfile(t, e))
	}
	evs, err := e.CS.EventsV1().Events("default").List(context.Background(), metav1.ListOptions{})
	if err != nil || len(evs.Items) != 1 {
		t.Fatalf("expected 1 CiliumFQDNPressure event, got %d (err=%v)", len(evs.Items), err)
	}
	if len(e.Kills) != 0 {
		t.Fatalf("detect-only check must never kill cilium-agent; kills=%v", e.Kills)
	}

	// Cycle 4: counter reset (< prev) recovers cleanly without false surge.
	e.HTTPBodies[e.H.Cfg.Cilium.MetricsURL] = []byte("cilium_fqdn_gc_deletions_total 5\n")
	e.H.Cycle(context.Background())
	if e.H.Series.CiliumFQDNPressure != 0 {
		t.Fatalf("counter reset left CiliumFQDNPressure=%d want 0", e.H.Series.CiliumFQDNPressure)
	}
}

func TestCiliumFQDNUnreachableAbortsPreservingState(t *testing.T) {
	e := fixture(t)
	e.MkCiliumTask(t, 4005)
	e.EndpointsBody = []byte(`[{"id":1,"status":{"state":"waiting-to-regenerate"}}]`)
	e.HTTPBodies[e.H.Cfg.Cilium.MetricsURL] = []byte(
		"cilium_endpoint_state{endpoint_state=\"waiting-to-regenerate\"} 1\n",
	)
	for range 3 {
		e.H.Cycle(context.Background())
	}
	if e.H.Series.CiliumFQDNPressure != 1 {
		t.Fatalf("setup failed: CiliumFQDNPressure=%d want 1", e.H.Series.CiliumFQDNPressure)
	}

	// Both socket and metrics fail -> abort, preserving CiliumFQDNPressure == 1.
	e.EndpointsBody = nil
	e.EndpointsErr = errors.New("socket missing")
	e.FQDNCacheBody = nil
	e.FQDNCacheErr = errors.New("socket missing")
	e.HTTPErrs[e.H.Cfg.Cilium.MetricsURL] = errors.New("connection refused")
	e.H.Cycle(context.Background())

	if got := testutil.ToFloat64(e.H.Cycles.WithLabelValues(wdeps.CheckCiliumFQDN, "abort")); got != 1 {
		t.Fatalf("abort cycles=%v want 1", got)
	}
	if e.H.Series.CiliumFQDNPressure != 1 {
		t.Fatalf("abort cleared CiliumFQDNPressure=%d want 1 preserved", e.H.Series.CiliumFQDNPressure)
	}
}
