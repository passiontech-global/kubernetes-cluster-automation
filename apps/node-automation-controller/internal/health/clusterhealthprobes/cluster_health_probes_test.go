// cluster_health_probes_test.go — prober-level coverage: the sweep
// runner's metric emission, error accounting and abort semantics,
// plus the HEALTH_* env-knob resolution. Per-check behavior lives in
// the check's own domain package tests.
package clusterhealthprobes

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/datastore"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/gitops"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/nethealth"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/nethealth/linkerd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/nodehealth"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/ported"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/watchdogs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

// testProber builds a prober with the env-equivalent defaults but
// deterministic seams: DNS always resolves, and the HTTP check points
// at a dead address (fast connection-refused FAIL) unless the test
// overrides Cfg.HTTPContent.URL/HTTPClient. dyn is a fake carrying
// every list-kind the sweep touches unconditionally — the fake
// PANICS on an unregistered GVR List, so tests that exercise the
// CR-scanning checks replace it via testProberDyn.
func testProber(cs *fake.Clientset) *clusterHealthProber {
	return testProberDyn(cs, probetest.OpDyn())
}

func testProberDyn(cs *fake.Clientset, dyn dynamic.Interface) *clusterHealthProber {
	// fleetCheckRegs() is valid by construction — an error here is a
	// refactor bug, not a fixture failure.
	p, err := newClusterHealthProber(shared.Deps{
		Name: "cluster-health-probes",
		CS:   cs, Dyn: dyn,
		CheckRegs: fleetCheckRegs(),
	}, probetest.NewDeps(cs, dyn).Cfg)
	if err != nil {
		panic(err)
	}
	p.LookupHost = func(context.Context, string) ([]string, error) {
		return []string{"10.0.0.1"}, nil
	}
	return p
}

// fleetCheckRegs mirrors the health section of registry.Modules —
// the full 52-check roster in sweep order, which is what
// SetupModules collects into Deps.CheckRegs on a default boot.
// clusterhealthprobes may not import internal/registry (depguard:
// domains never import the wiring layer — and a test-internal
// import would be an outright cycle since registry imports this
// package), so the mirror lives here; registry's
// TestCheckRegSweepOrder pins the canonical sequence this list
// copies, so drift between them fails THERE, not silently here.
func fleetCheckRegs() []shared.CheckReg {
	return []shared.CheckReg{
		{Name: ported.CheckNameDNS, New: ported.NewDNSStatusCheck},
		{Name: ported.CheckNameHTTPContent, New: ported.NewHTTPContentCheck},
		{Name: ported.CheckNamePodRestarts, New: ported.NewPodRestartsCheck},
		{Name: ported.CheckNamePodStatus, New: ported.NewPodStatusCheck},
		{Name: ported.CheckNameResourceQuota, New: ported.NewResourceQuotaCheck},
		{Name: watchdogs.CheckNameKCMWorkqueue, New: watchdogs.NewKcmWorkqueueCheck},
		{Name: watchdogs.CheckNameOperatorWorkqueue, New: watchdogs.NewOperatorWorkqueueCheck},
		{Name: datastore.CheckNameStatefulMasterless, New: datastore.NewStatefulMasterlessCheck},
		{Name: datastore.CheckNameRabbitMQSuspended, New: datastore.NewRabbitMQSuspendedCheck},
		{Name: nodehealth.CheckNameLocalPVStranded, New: nodehealth.NewLocalPVStrandedCheck},
		{Name: datastore.CheckNameOLMHealth, New: datastore.NewOlmHealthCheck},
		{Name: watchdogs.CheckNameSchedulerWatchdog, New: watchdogs.NewSchedulerWatchdogCheck},
		{Name: watchdogs.CheckNameMeshWatchdog, New: watchdogs.NewMeshControlPlaneCheck},
		{Name: nodehealth.CheckNameNodeHang, New: nodehealth.NewNodeHangCheck},
		{Name: linkerd.CheckNameLinkerdEndpointSync, New: linkerd.NewLinkerdEndpointSyncCheck},
		{Name: datastore.CheckNameScyllaHealth, New: datastore.NewScyllaHealthCheck},
		{Name: gitops.CheckNameFluxHRRetries, New: gitops.NewFluxHRRetriesCheck},
		{Name: datastore.CheckNamePerconaQuorum, New: datastore.NewPerconaQuorumCheck},
		{Name: nethealth.CheckNameCiliumBPFMapPressure, New: nethealth.NewCiliumBPFMapPressureCheck},
		{Name: linkerd.CheckNameLinkerdOpaqueStall, New: linkerd.NewLinkerdProtocolDetectionStallCheck},
		{Name: nethealth.CheckNameCoreDNSUpstream, New: nethealth.NewCoreDNSUpstreamCheck},
		{Name: nethealth.CheckNameCiliumNodeIPAM, New: nethealth.NewCiliumNodeIPAMExhaustionCheck},
		{Name: nodehealth.CheckNameNamespaceWedged, New: nodehealth.NewNamespaceTerminatingWedgedCheck},
		{Name: gitops.CheckNameArgoCDAppStuck, New: gitops.NewArgoCDAppStuckCheck},
		{Name: gitops.CheckNameKargoPromotionHealth, New: gitops.NewKargoPromotionHealthCheck},
		{Name: datastore.CheckNameRabbitMQQuorum, New: datastore.NewRabbitMQQuorumHealthCheck},
		{Name: datastore.CheckNameDragonflySyncStorm, New: datastore.NewDragonflyReplicaSyncStormCheck},
		{Name: nodehealth.CheckNameImagePullStorm, New: nodehealth.NewImagePullStormCheck},
		{Name: nodehealth.CheckNameAPIObjectSprawlReportGC, New: nodehealth.NewAPIObjectSprawlReportGCCheck},
		{Name: nodehealth.CheckNameCPUStealTaintSync, New: nodehealth.NewCPUStealTaintSyncCheck},
		{Name: nethealth.CheckNameCiliumMissingEndpoints, New: nethealth.NewCiliumMissingEndpointsCheck},
		{Name: linkerd.CheckNameLinkerdH2StreamGuard, New: linkerd.NewLinkerdH2StreamGuardCheck},
		{Name: nethealth.CheckNameCloudflaredTunnelHealth, New: nethealth.NewCloudflaredTunnelHealthCheck},
		{Name: nethealth.CheckNameLiqoTunnelHealth, New: nethealth.NewLiqoTunnelHealthCheck},
		{Name: nethealth.CheckNameKonnectivityTunnelHealth, New: nethealth.NewKonnectivityTunnelHealthCheck},
		{Name: datastore.CheckNamePostgresWALArchiveGuard, New: datastore.NewPostgresWALArchiveGuardCheck},
		{Name: datastore.CheckNameScyllaCompactionSchemaGuard, New: datastore.NewScyllaCompactionSchemaGuardCheck},
		{Name: datastore.CheckNameNatsJetstreamHealth, New: datastore.NewNatsJetstreamHealthCheck},
		{Name: nodehealth.CheckNameKedaScaledObjectGuard, New: nodehealth.NewKedaScaledObjectGuardCheck},
		{Name: nethealth.CheckNameGatewayRouteHealth, New: nethealth.NewGatewayRouteHealthCheck},
		{Name: nodehealth.CheckNameControllerLeaseGuard, New: nodehealth.NewControllerLeaseGuardCheck},
		{Name: datastore.CheckNamePVCResizeStallGuard, New: datastore.NewPVCResizeStallGuardCheck},
		{Name: nethealth.CheckNameEndpointSliceZoneStarvation, New: nethealth.NewEndpointSliceZoneStarvationCheck},
		{Name: nethealth.CheckNameLinkerdOutlierGuard, New: nethealth.NewLinkerdOutlierGuardCheck},
		{Name: nodehealth.CheckNameNodeCondSweeper, New: nodehealth.NewNodeConditionSweeperCheck},
		{Name: watchdogs.CheckNameOnePasswordConnectSync, New: watchdogs.NewOnePasswordConnectSyncCheck},
		{Name: nethealth.CheckNameLinkerdSidecarOOMGuard, New: nethealth.NewLinkerdSidecarOOMGuardCheck},
		{Name: nethealth.CheckNameCiliumDatapathMapGuard, New: nethealth.NewCiliumDatapathMapGuardCheck},
		{Name: watchdogs.CheckNameObservabilityPipelineGuard, New: watchdogs.NewObservabilityPipelineGuardCheck},
		// The three gated gitops rows close out the roster —
		// the sweep-order contract keeps them after the always-on
		// sequence.
		{Name: gitops.CheckNameFluxKustomizationHealth, New: gitops.NewFluxKustomizationHealthCheck},
		{Name: gitops.CheckNameWorkloadScaleFlapping, New: gitops.NewWorkloadScaleFlappingCheck},
		{Name: gitops.CheckNameImagePullSecretAuditor, New: gitops.NewImagePullSecretAuditorCheck},
	}
}

// ---------------------------------------------------------------------------
// run() — metric emission + error accounting
// ---------------------------------------------------------------------------

// A passing cycle emits OK=1/FAIL=0 for every check under the original
// HealthCheck names and the literal "kuberhealthy" namespace label.
func TestRunEmitsAllChecksPassing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "Prometheus Server is Healthy.")
	}))
	t.Cleanup(srv.Close)

	p := testProber(fake.NewSimpleClientset())
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	if err := p.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, check := range []string{
		ported.CheckNameDNS, ported.CheckNameHTTPContent, ported.CheckNamePodRestarts,
		ported.CheckNamePodStatus, ported.CheckNameResourceQuota, watchdogs.CheckNameKCMWorkqueue,
	} {
		v, ok := probetest.HealthGauge(t, check, "OK")
		if !ok || v != 1 {
			t.Fatalf("kuberhealthy_check{check=%s,status=OK} = %v,%v want 1", check, v, ok)
		}
		v, ok = probetest.HealthGauge(t, check, "FAIL")
		if !ok || v != 0 {
			t.Fatalf("kuberhealthy_check{check=%s,status=FAIL} = %v,%v want 0", check, v, ok)
		}
		m := probetest.FindMetric(t, "kuberhealthy_check_seconds_since_success",
			map[string]string{"check": check, "namespace": "kuberhealthy"})
		if m == nil {
			t.Fatalf("seconds_since_success series missing for %s", check)
		}
	}
}

// A check that keeps failing must report a growing
// seconds_since_success — the stale-alert contract.
func TestRunFailGrowsStaleness(t *testing.T) {
	p := testProber(fake.NewSimpleClientset())
	// Seed a past success so the fail path has something to measure.
	p.lastPass[ported.CheckNameDNS] = time.Now().Add(-time.Hour)
	p.LookupHost = func(context.Context, string) ([]string, error) {
		return nil, errors.New("SERVFAIL")
	}
	if err := p.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if v, _ := probetest.HealthGauge(t, ported.CheckNameDNS, "FAIL"); v != 1 {
		t.Fatalf("dns FAIL gauge = %v, want 1", v)
	}
	m := probetest.FindMetric(t, "kuberhealthy_check_seconds_since_success",
		map[string]string{"check": ported.CheckNameDNS, "namespace": "kuberhealthy"})
	if m == nil || m.GetGauge().GetValue() < 3599 {
		t.Fatalf("seconds_since_success = %v, want ~3600", m.GetGauge().GetValue())
	}
}

// An apiserver List error marks the check FAIL AND counts a queue run
// error, but the cycle still returns nil while other checks probe
// fine — check failures are the metric, not the run result.
func TestRunInfraErrorMarksFail(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "pods",
		func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("apiserver boom")
		})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "Prometheus Server is Healthy.")
	}))
	t.Cleanup(srv.Close)

	p := testProber(cs)
	p.Cfg.HTTPContent.URL = srv.URL
	p.HTTPClient = srv.Client()

	errCount := func() float64 {
		m := probetest.FindMetric(t, "shell_operator_hook_run_errors_total",
			map[string]string{"queue": p.Name})
		if m == nil {
			return 0
		}
		return m.GetCounter().GetValue()
	}
	before := errCount()

	if err := p.run(context.Background()); err != nil {
		t.Fatalf("partial infra failure must not fail the cycle: %v", err)
	}
	if v, _ := probetest.HealthGauge(t, ported.CheckNamePodRestarts, "FAIL"); v != 1 {
		t.Fatalf("pod-restarts FAIL gauge = %v, want 1 on List error", v)
	}
	if v, _ := probetest.HealthGauge(t, ported.CheckNamePodStatus, "FAIL"); v != 1 {
		t.Fatalf("pod-status FAIL gauge = %v, want 1 on List error", v)
	}
	// The two pod checks, the rabbitmq-suspended-listener sweep, the
	// localpv-stranded-pods scan, the W8-CP3 scheduler-watchdog
	// pending-pods List AND the W9-ST1 scylla-cluster-health census
	// all hit the same cluster-wide pods List error -> six run
	// errors, plus five W10 checks that also census pods:
	// linkerd-protocol-detection-stall, cilium-node-ipam-exhaustion
	// (pod-count fallback), rabbitmq-quorum-health,
	// coredns-upstream (readiness fallback), image-pull-storm, plus
	// five more pod-census checks added since: cilium-missing-endpoint,
	// linkerd-h2-stream-guard, cloudflared-tunnel-health,
	// postgres-wal-archive-guard, scylla-compaction-schema-guard,
	// controller-lease-guard (KSM wedge scan), plus
	// endpointslice-zone-starvation (zone-starvation) AND
	// imagepull-secret-auditor (pullsecret-audit — its pull-secret census
	// starts at AllPods), plus four more checks added since:
	// onepassword-connect-sync-probe and linkerd-sidecar-oom-guard
	// (pod censuses), cilium-datapath-map-guard and
	// observability-pipeline-guard (their Prometheus queries die on
	// the health-text stub) -> twenty-three total.
	// (linkerd-endpoint-sync skips its pod census entirely when no
	// namespace carries linkerd.io/inject=enabled, and
	// linkerd-outlier-guard bails on the failed Prometheus query
	// before ever listing pods.)
	if got := errCount() - before; got != 23 {
		t.Fatalf("run errors delta = %v, want 23", got)
	}
}

// A cancelled sweep context (SIGTERM during rollout/shutdown) aborts
// the run silently: no FAIL series — a dying pod emitting FAIL=1 would
// leave a fake health signal behind — and no run-error increment. The
// DNS probe cancels mid-sweep to simulate the shutdown landing inside
// the first check.
func TestRunAbortEmitsNothing(t *testing.T) {
	cctx, cancel := context.WithCancel(context.Background())
	p := testProber(fake.NewSimpleClientset())
	p.LookupHost = func(context.Context, string) ([]string, error) {
		cancel() // SIGTERM lands mid-sweep
		return []string{"10.0.0.1"}, nil
	}

	snapshot := func() map[string]float64 {
		out := map[string]float64{}
		for _, check := range []string{ported.CheckNameDNS, ported.CheckNameHTTPContent,
			ported.CheckNamePodRestarts, ported.CheckNamePodStatus, ported.CheckNameResourceQuota} {
			for _, status := range []string{"OK", "FAIL"} {
				if v, ok := probetest.HealthGauge(t, check, status); ok {
					out[check+"/"+status] = v
				}
			}
		}
		m := probetest.FindMetric(t, "shell_operator_hook_run_errors_total",
			map[string]string{"queue": p.Name})
		if m != nil {
			out["run-errors"] = m.GetCounter().GetValue()
		}
		return out
	}
	before := snapshot()

	if err := p.run(cctx); err != nil {
		t.Fatalf("aborted sweep must return nil, got %v", err)
	}
	after := snapshot()
	for k, v := range before {
		if after[k] != v {
			t.Fatalf("series %q changed by aborted run: %v -> %v",
				k, v, after[k])
		}
	}
	if len(after) != len(before) {
		t.Fatalf("aborted run emitted new series: %v -> %v", before, after)
	}
}

// HEALTH_* env knobs: garbage strings, zero and negative values must
// not silently produce dangerous config — HEALTH_CHECK_TIMEOUT=0
// would instant-fail every probe, HEALTH_MAX_POD_RESTARTS=-1 would
// flag every container, and a 0s interval would panic the ticker.
// Each falls back to the default (and logs a warning) via the shared
// env helpers.
func TestHealthEnvKnobsClampBadValues(t *testing.T) {
	// Unset → defaults.
	for _, k := range []string{
		"HEALTH_CHECK_TIMEOUT", "HEALTH_POD_SKIP_DURATION",
		"HEALTH_KCM_LEASE_MAX_AGE", "HEALTH_KCM_FREEZE_MIN_AGE",
		"HEALTH_MAX_POD_RESTARTS", "HEALTH_RESOURCE_QUOTA_THRESHOLD",
		"CLUSTER_HEALTH_PROBES_INTERVAL",
	} {
		t.Setenv(k, "")
	}
	cfg := healthProbeConfigFromEnv()
	if cfg.Timeouts.Check != 30*time.Second || cfg.Pods.SkipDuration != 10*time.Minute ||
		cfg.KCM.LeaseMaxAge != 30*time.Second || cfg.KCM.FreezeMinAge != 10*time.Minute {
		t.Fatalf("unset env produced non-default config: %+v", cfg)
	}
	if cfg.Pods.MaxRestarts != 10 || cfg.Quota.Threshold != 0.9 {
		t.Fatalf("unset env produced non-default config: %+v", cfg)
	}

	// Zero/negative durations → default, not instant-fail/panic.
	for _, v := range []string{"0", "0s", "-5s", "garbage"} {
		t.Setenv("HEALTH_CHECK_TIMEOUT", v)
		if got := healthProbeConfigFromEnv().Timeouts.Check; got != 30*time.Second {
			t.Fatalf("HEALTH_CHECK_TIMEOUT=%q → checkTimeout %v, want 30s default", v, got)
		}
	}
	// A parseable positive value wins.
	t.Setenv("HEALTH_CHECK_TIMEOUT", "15s")
	if got := healthProbeConfigFromEnv().Timeouts.Check; got != 15*time.Second {
		t.Fatalf("HEALTH_CHECK_TIMEOUT=15s → %v, want 15s", got)
	}

	// Negative int → default; 0 is a legitimate (strict) threshold.
	t.Setenv("HEALTH_MAX_POD_RESTARTS", "-1")
	if got := healthProbeConfigFromEnv().Pods.MaxRestarts; got != 10 {
		t.Fatalf("HEALTH_MAX_POD_RESTARTS=-1 → %d, want 10 default", got)
	}
	t.Setenv("HEALTH_MAX_POD_RESTARTS", "not-an-int")
	if got := healthProbeConfigFromEnv().Pods.MaxRestarts; got != 10 {
		t.Fatalf("HEALTH_MAX_POD_RESTARTS=not-an-int → %d, want 10 default", got)
	}
	t.Setenv("HEALTH_MAX_POD_RESTARTS", "0")
	if got := healthProbeConfigFromEnv().Pods.MaxRestarts; got != 0 {
		t.Fatalf("HEALTH_MAX_POD_RESTARTS=0 → %d, want 0 (any restart flags)", got)
	}

	// Unparseable float → default.
	t.Setenv("HEALTH_RESOURCE_QUOTA_THRESHOLD", "banana")
	if got := healthProbeConfigFromEnv().Quota.Threshold; got != 0.9 {
		t.Fatalf("HEALTH_RESOURCE_QUOTA_THRESHOLD=banana → %v, want 0.9", got)
	}
}
