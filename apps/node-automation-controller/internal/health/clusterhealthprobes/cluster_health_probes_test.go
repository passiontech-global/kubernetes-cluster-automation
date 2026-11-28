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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/datastore"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/datastore/dragonfly"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/datastore/nats"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/datastore/percona"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/datastore/postgres"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/datastore/rabbitmq"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/datastore/scylla"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/gitops"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/gitops/olm"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/nethealth"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/nethealth/cilium"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/nethealth/cloudflared"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/nethealth/connectionskew"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/nethealth/gateway"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/nethealth/linkerd"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/nethealth/liqo"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/nodehealth"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/ported"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probetest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/storage/localpv"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/storage/pvc"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/watchdogs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/watchdogs/leases"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/watchdogs/sprawl"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/probefw"
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
// the full 80-check roster in sweep order, which is what
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
		{Name: rabbitmq.CheckNameRabbitMQSuspended, New: rabbitmq.NewRabbitMQSuspendedCheck},
		{Name: localpv.CheckNameLocalPVStranded, New: localpv.NewLocalPVStrandedCheck},
		{Name: olm.CheckNameOLMHealth, New: olm.NewOlmHealthCheck},
		{Name: watchdogs.CheckNameSchedulerWatchdog, New: watchdogs.NewSchedulerWatchdogCheck},
		{Name: watchdogs.CheckNameMeshWatchdog, New: watchdogs.NewMeshControlPlaneCheck},
		{Name: nodehealth.CheckNameNodeHang, New: nodehealth.NewNodeHangCheck},
		{Name: linkerd.CheckNameLinkerdEndpointSync, New: linkerd.NewLinkerdEndpointSyncCheck},
		{Name: scylla.CheckNameScyllaHealth, New: scylla.NewScyllaHealthCheck},
		{Name: gitops.CheckNameFluxHRRetries, New: gitops.NewFluxHRRetriesCheck},
		{Name: percona.CheckNamePerconaQuorum, New: percona.NewPerconaQuorumCheck},
		{Name: cilium.CheckNameCiliumBPFMapPressure, New: cilium.NewCiliumBPFMapPressureCheck},
		{Name: linkerd.CheckNameLinkerdOpaqueStall, New: linkerd.NewLinkerdProtocolDetectionStallCheck},
		{Name: nethealth.CheckNameCoreDNSUpstream, New: nethealth.NewCoreDNSUpstreamCheck},
		{Name: cilium.CheckNameCiliumNodeIPAM, New: cilium.NewCiliumNodeIPAMExhaustionCheck},
		{Name: nodehealth.CheckNameNamespaceWedged, New: nodehealth.NewNamespaceTerminatingWedgedCheck},
		{Name: gitops.CheckNameArgoCDAppStuck, New: gitops.NewArgoCDAppStuckCheck},
		{Name: gitops.CheckNameKargoPromotionHealth, New: gitops.NewKargoPromotionHealthCheck},
		{Name: rabbitmq.CheckNameRabbitMQQuorum, New: rabbitmq.NewRabbitMQQuorumHealthCheck},
		{Name: dragonfly.CheckNameDragonflySyncStorm, New: dragonfly.NewDragonflyReplicaSyncStormCheck},
		{Name: nodehealth.CheckNameImagePullStorm, New: nodehealth.NewImagePullStormCheck},
		{Name: sprawl.CheckNameAPIObjectSprawlReportGC, New: sprawl.NewAPIObjectSprawlReportGCCheck},
		{Name: nodehealth.CheckNameCPUStealTaintSync, New: nodehealth.NewCPUStealTaintSyncCheck},
		{Name: cilium.CheckNameCiliumMissingEndpoints, New: cilium.NewCiliumMissingEndpointsCheck},
		{Name: linkerd.CheckNameLinkerdH2StreamGuard, New: linkerd.NewLinkerdH2StreamGuardCheck},
		{Name: cloudflared.CheckNameCloudflaredTunnelHealth, New: cloudflared.NewCloudflaredTunnelHealthCheck},
		{Name: liqo.CheckNameLiqoTunnelHealth, New: liqo.NewLiqoTunnelHealthCheck},
		{Name: nethealth.CheckNameKonnectivityTunnelHealth, New: nethealth.NewKonnectivityTunnelHealthCheck},
		{Name: postgres.CheckNamePostgresWALArchiveGuard, New: postgres.NewPostgresWALArchiveGuardCheck},
		{Name: scylla.CheckNameScyllaCompactionSchemaGuard, New: scylla.NewScyllaCompactionSchemaGuardCheck},
		{Name: nats.CheckNameNatsJetstreamHealth, New: nats.NewNatsJetstreamHealthCheck},
		{Name: gitops.CheckNameKedaScaledObjectGuard, New: gitops.NewKedaScaledObjectGuardCheck},
		{Name: gateway.CheckNameGatewayRouteHealth, New: gateway.NewGatewayRouteHealthCheck},
		{Name: leases.CheckNameControllerLeaseGuard, New: leases.NewControllerLeaseGuardCheck},
		{Name: pvc.CheckNamePVCResizeStallGuard, New: pvc.NewPVCResizeStallGuardCheck},
		{Name: nethealth.CheckNameEndpointSliceZoneStarvation, New: nethealth.NewEndpointSliceZoneStarvationCheck},
		{Name: linkerd.CheckNameLinkerdOutlierGuard, New: linkerd.NewLinkerdOutlierGuardCheck},
		{Name: nodehealth.CheckNameNodeCondSweeper, New: nodehealth.NewNodeConditionSweeperCheck},
		{Name: watchdogs.CheckNameOnePasswordConnectSync, New: watchdogs.NewOnePasswordConnectSyncCheck},
		{Name: linkerd.CheckNameLinkerdSidecarOOMGuard, New: linkerd.NewLinkerdSidecarOOMGuardCheck},
		{Name: cilium.CheckNameCiliumDatapathMapGuard, New: cilium.NewCiliumDatapathMapGuardCheck},
		{Name: cilium.CheckNameCiliumL2LeaseGuard, New: cilium.NewCiliumL2LeaseGuardCheck},
		{Name: watchdogs.CheckNameObservabilityPipelineGuard, New: watchdogs.NewObservabilityPipelineGuardCheck},
		{Name: watchdogs.CheckNameAPIServerRelistStorm, New: watchdogs.NewAPIServerRelistStormCheck},
		// The three gated gitops rows close out the roster —
		// the sweep-order contract keeps them after the always-on
		// sequence.
		{Name: gitops.CheckNameFluxKustomizationHealth, New: gitops.NewFluxKustomizationHealthCheck},
		{Name: gitops.CheckNameWorkloadScaleFlapping, New: gitops.NewWorkloadScaleFlappingCheck},
		{Name: gitops.CheckNameImagePullSecretAuditor, New: gitops.NewImagePullSecretAuditorCheck},
		{Name: gitops.CheckNameArgoCDAgentSpin, New: gitops.NewArgoCDAgentSpinCheck},
		{Name: nethealth.CheckNameApiserverNodeReachability, New: nethealth.NewApiserverNodeReachabilityCheck},
		{Name: watchdogs.CheckNameAPFSelfHealShield, New: watchdogs.NewAPFSelfHealShieldCheck},
		{Name: watchdogs.CheckNameStatefulSetRolloutUnstick, New: watchdogs.NewStatefulSetRolloutUnstickCheck},
		{Name: watchdogs.CheckNameDaemonSetRolloutWedge, New: watchdogs.NewDaemonSetRolloutWedgeCheck},
		{Name: watchdogs.CheckNameCronJobForbidZombie, New: watchdogs.NewCronJobForbidZombieCheck},
		{Name: watchdogs.CheckNameAPIServerWriteStorm, New: watchdogs.NewAPIServerWriteStormCheck},
		{Name: watchdogs.CheckNameCriticalDSStarvation, New: watchdogs.NewCriticalDaemonSetStarvationCheck},
		{Name: nethealth.CheckNameCoreDNSForwardSaturation, New: nethealth.NewCoreDNSForwardSaturationCheck},
		{Name: gitops.CheckNameHPAScalingGuard, New: gitops.NewHPAScalingGuardCheck},
		{Name: watchdogs.CheckNameDeploymentRolloutWedge, New: watchdogs.NewDeploymentRolloutWedgeCheck},
		{Name: watchdogs.CheckNameSubPathConfigDrift, New: watchdogs.NewSubPathConfigDriftCheck},
		{Name: nethealth.CheckNameServiceSelectorBlackhole, New: nethealth.NewServiceSelectorBlackholeCheck},
		{Name: watchdogs.CheckNameTopologyZoneDeadlock, New: watchdogs.NewTopologySpreadZoneDeadlockCheck},
		{Name: watchdogs.CheckNameAdmissionSecurityGuard, New: watchdogs.NewAdmissionSecurityGuardCheck},
		{Name: cilium.CheckNameCiliumPolicyBGPGuard, New: cilium.NewCiliumPolicyBGPGuardCheck},
		{Name: nethealth.CheckNameServiceTrafficPolicyGuard, New: nethealth.NewServiceTrafficPolicyGuardCheck},
		{Name: pvc.CheckNamePVCLifecycleGuard, New: pvc.NewPVCLifecycleGuardCheck},
		{Name: watchdogs.CheckNameWorkloadAdmissionBlockGuard, New: watchdogs.NewWorkloadAdmissionBlockGuardCheck},
		{Name: gitops.CheckNameGitOpsMassPruneGuard, New: gitops.NewGitOpsMassPruneGuardCheck},
		{Name: nodehealth.CheckNameImageResilienceAuditor, New: nodehealth.NewImageResilienceAuditorCheck},
		// Wave 5 checks — appended at end of healthRows.
		{Name: pvc.CheckNameVolumeSnapshotLifecycleGuard, New: pvc.NewVolumeSnapshotLifecycleGuardCheck},
		{Name: nodehealth.CheckNameDRAClaimWedgeGuard, New: nodehealth.NewDRAClaimWedgeGuardCheck},
		{Name: watchdogs.CheckNamePodResizeWedgeGuard, New: watchdogs.NewPodResizeWedgeGuardCheck},
		{Name: watchdogs.CheckNameIngressNginxRetirementGuard, New: watchdogs.NewIngressNginxRetirementGuardCheck},
		{Name: connectionskew.CheckNameWorkloadConnectionSkewGuard, New: connectionskew.NewWorkloadConnectionSkewGuardCheck},
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

	if err := p.run(t.Context()); err != nil {
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
	if err := p.run(t.Context()); err != nil {
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

	if err := p.run(t.Context()); err != nil {
		t.Fatalf("partial infra failure must not fail the cycle: %v", err)
	}
	if v, _ := probetest.HealthGauge(t, ported.CheckNamePodRestarts, "FAIL"); v != 1 {
		t.Fatalf("pod-restarts FAIL gauge = %v, want 1 on List error", v)
	}
	if v, _ := probetest.HealthGauge(t, ported.CheckNamePodStatus, "FAIL"); v != 1 {
		t.Fatalf("pod-status FAIL gauge = %v, want 1 on List error", v)
	}
	// The two pod checks, the rabbitmq-suspended-listener sweep, the
	// localpv-stranded-pods scan, the cp-freeze-heal scheduler-watchdog
	// pending-pods List AND the scylla-cluster-health scylla-cluster-health census
	// all hit the same cluster-wide pods List error -> six run
	// errors, plus five checks that also census pods:
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
	// the health-text stub), plus the mesh-net-guards mesh-controlplane scan
	// whose pod list is its only input (mesh-net-guards no longer swallows
	// the failure) -> twenty-four total.
	// (linkerd-endpoint-sync skips its pod census entirely when no
	// namespace carries linkerd.io/inject=enabled, and
	// linkerd-outlier-guard bails on the failed Prometheus query
	// before ever listing pods.) The dragonfly-operator leader-bounce
	// heal rides the shared AllPods census now (was a namespaced
	// list this pods-outage fake never hit), so it meters the same
	// failure — twenty-five total. The CNPG masterless candidate
	// census in stateful-masterless-services lists the same pods —
	// twenty-six total. dragonfly-replica-sync-storm's PRIMARY
	// master-link query dies on the health-text stub and now reports
	// Infra instead of passing silently — twenty-seven total.
	// Plus cilium-l2-lease-guard and apiserver-relist-storm-breaker /
	// argocd-agent-spin / apiserver-node-reachability added to bring
	// fleetCheckRegs to parity with the 56-check registry -> twenty-nine total.
	// cilium-bpf-map-pressure now reports Infra (not silent pass) on
	// the Prometheus outage this fake produces -> thirty total.
	// Bringing fleetCheckRegs to full 68-check parity adds the 8 newly
	// registered checks that census pods or query Prometheus -> thirty-eight total.
	// Wave 4C image-resilience-auditor reads AllPods -> thirty-nine total.
	// M4.3 switched deployment-rollout-wedge from eager AllPods in Run()
	// to lazy per-namespace PodsIn(ctx, ns) inside unwedgeDeployment(),
	// so an empty cluster with 0 wedged Deployments no longer lists pods
	// (PodsIn infra-error propagation is covered by
	// TestRolloutWedgeAllTypedReplicaSetsAndLazyPodsIn in
	// Internal/health/watchdogs/deployment_rollout_wedge_test.go) ->
	// thirty-eight total.
	// Wave 5 checks added to fleetCheckRegs(): pod-resize-wedge-guard and
	// ingress-nginx-retirement-guard unconditionally call AllPods (+1 each),
	// while volumesnapshot-lifecycle-guard and dra-claim-wedge-guard return
	// early on empty OpDyn() (+0) -> forty total.
	if got := errCount() - before; got != 40 {
		t.Fatalf("run errors delta = %v, want 40", got)
	}
}

// infraPassCheck models the check bug the prober must defend against:
// a Result with Pass=true but an Infra error attached (the old
// dragonfly infraClose shape). "Can't tell" must read FAIL.
type infraPassCheck struct{ err error }

func (c infraPassCheck) Run(context.Context) probefw.Result {
	return probefw.Result{Pass: true, Infra: c.err}
}

func TestRunCheckIsolatedInfraErrorIsFail(t *testing.T) {
	out := runCheckIsolated(checkEntry{
		name: "infra-pass", check: infraPassCheck{err: errors.New("api down")},
	}, t.Context(), time.Minute)
	if !out.ran {
		t.Fatal("check must have run")
	}
	if out.pass {
		t.Fatalf("Result{Pass:true, Infra:err} must become a FAIL verdict: %+v", out)
	}
	if out.infra == nil {
		t.Fatal("infra error must be carried through for the run's single IncError")
	}
	if clean := runCheckIsolated(checkEntry{
		name: "clean", check: infraPassCheck{},
	}, t.Context(), time.Minute); !clean.pass {
		t.Fatalf("a clean pass must still pass: %+v", clean)
	}
}

// A cancelled sweep context (SIGTERM during rollout/shutdown) aborts
// the run silently: no FAIL series — a dying pod emitting FAIL=1 would
// leave a fake health signal behind — and no run-error increment. The
// DNS probe cancels mid-sweep to simulate the shutdown landing inside
// the first check.
func TestRunAbortEmitsNothing(t *testing.T) {
	cctx, cancel := context.WithCancel(t.Context())
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
	if cfg.Timeouts.Check != 30*time.Second || cfg.Timeouts.PerCheck != 2*time.Minute {
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
}

// A roster that shrinks between passes must not strand lastPass
// entries for checks it no longer sweeps: the pass after the shrink
// prunes the dropped check's entry while keeping the survivors — a
// failed survivor keeps its seeded stamp (no pass, no re-stamp), a
// passing survivor is re-stamped as usual. The roster is boot-time
// today, so this only guards a future dynamic roster.
func TestRunShrunkRosterPrunesLastPass(t *testing.T) {
	p := testProber(fake.NewSimpleClientset())
	// Seed entries as if an earlier pass had recorded passes — the
	// TestRunFailGrowsStaleness seeding convention. HTTP content
	// fails on the dead default URL, DNS passes on the fake resolver.
	seeded := time.Now().Add(-time.Hour)
	for _, name := range []string{
		ported.CheckNameDNS, ported.CheckNameHTTPContent,
		gitops.CheckNameImagePullSecretAuditor,
	} {
		p.lastPass[name] = seeded
	}

	if err := p.run(t.Context()); err != nil {
		t.Fatalf("full-roster run: %v", err)
	}
	if _, ok := p.lastPass[gitops.CheckNameImagePullSecretAuditor]; !ok {
		t.Fatalf("full-roster pass lost %q before the shrink", gitops.CheckNameImagePullSecretAuditor)
	}

	// Shrink the roster the way a future dynamic registry would:
	// only the first two checks (DNS, HTTP content) survive.
	p.checks = p.checks[:2]
	if err := p.run(t.Context()); err != nil {
		t.Fatalf("shrunk-roster run: %v", err)
	}
	if _, ok := p.lastPass[gitops.CheckNameImagePullSecretAuditor]; ok {
		t.Fatalf("shrunk roster kept stale lastPass entry for %q", gitops.CheckNameImagePullSecretAuditor)
	}
	if got := p.lastPass[ported.CheckNameHTTPContent]; !got.Equal(seeded) {
		t.Fatalf("failing survivor's lastPass = %v, want seeded %v untouched", got, seeded)
	}
	if got, ok := p.lastPass[ported.CheckNameDNS]; !ok || got.Equal(seeded) {
		t.Fatalf("passing survivor's lastPass = %v,%v, want re-stamped past %v", got, ok, seeded)
	}
}

// parallelProbeCheck blocks until ALL pool members are running
// simultaneously, then reports — a serial sweep would starve the
// wait and leave serial=true, failing the test. verdict lets one
// member carry a FAIL so the outcome accounting is asserted too.
type parallelProbeCheck struct {
	started *atomic.Int32
	serial  bool
	verdict func() probefw.Result
}

func (c *parallelProbeCheck) Run(ctx context.Context) probefw.Result {
	if ctx.Err() != nil {
		return probefw.Result{Pass: false, Why: "cancelled"}
	}
	now := c.started.Add(1)
	deadline := time.Now().Add(3 * time.Second)
	for now < checkParallelism && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		now = c.started.Load()
	}
	if now < checkParallelism {
		c.serial = true // sweep is not running the pool concurrently
	}
	return c.verdict()
}

// TestRunBoundedParallelism pins the B9 worker-pool contract: a full
// wave of checkParallelism checks runs CONCURRENTLY (each observes
// every sibling mid-Run — the serial loop could never do that), every
// verdict is reported exactly once under its own series, a FAIL
// without Infra stays metric-only (no run error), and lastPass
// carries the whole roster.
func TestRunBoundedParallelism(t *testing.T) {
	p := testProber(fake.NewSimpleClientset())
	started := &atomic.Int32{}
	failing := checkParallelism - 1
	checks := make([]checkEntry, checkParallelism)
	names := make([]string, checkParallelism)
	for i := range checks {
		name := fmt.Sprintf("parallel-probe-%d", i)
		names[i] = name
		verdict := func() probefw.Result { return probefw.Result{Pass: true} }
		if i == failing {
			verdict = func() probefw.Result {
				return probefw.Result{Pass: false, Why: "synthetic gray failure"}
			}
		}
		checks[i] = checkEntry{name: name, check: &parallelProbeCheck{
			started: started, verdict: verdict,
		}}
	}
	p.checks = checks

	// Run errors are a package-shared counter (other tests in this
	// binary bump it) — assert the DELTA across this run, not zero.
	runErrsBefore := 0.0
	if m := probetest.FindMetric(t, "shell_operator_hook_run_errors_total",
		map[string]string{"queue": p.Name}); m != nil {
		runErrsBefore = m.GetCounter().GetValue()
	}
	if err := p.run(t.Context()); err != nil {
		t.Fatalf("parallel run: %v", err)
	}
	for i, c := range checks {
		probe := c.check.(*parallelProbeCheck)
		if probe.serial {
			t.Fatalf("check %d ran without full-pool concurrency — sweep serialized", i)
		}
		wantOK, wantFAIL := 1.0, 0.0
		if i == failing {
			wantOK, wantFAIL = 0.0, 1.0
		}
		if ok, _ := probetest.HealthGauge(t, names[i], "OK"); ok != wantOK {
			t.Fatalf("check %s OK series = %v, want %v", names[i], ok, wantOK)
		}
		if fail, _ := probetest.HealthGauge(t, names[i], "FAIL"); fail != wantFAIL {
			t.Fatalf("check %s FAIL series = %v, want %v", names[i], fail, wantFAIL)
		}
		if i != failing { // lastPass stamps PASSes only
			if _, ok := p.lastPass[names[i]]; !ok {
				t.Fatalf("check %s missing from lastPass", names[i])
			}
		}
	}
	if m := probetest.FindMetric(t, "shell_operator_hook_run_errors_total",
		map[string]string{"queue": p.Name}); m != nil &&
		m.GetCounter().GetValue()-runErrsBefore != 0 {
		t.Fatalf("metric-only FAIL bumped run errors: +%v",
			m.GetCounter().GetValue()-runErrsBefore)
	}
}

type funcCheck struct {
	fn func(context.Context) probefw.Result
}

func (f funcCheck) Run(ctx context.Context) probefw.Result { return f.fn(ctx) }

// Streaming commit must publish completed prefix checks immediately
// instead of blocking behind g.SetLimit(6) until the whole pool drains.
func TestRunStreamingCommitBeforePoolDrains(t *testing.T) {
	p := testProber(fake.NewSimpleClientset())
	releaseTail := make(chan struct{})
	defer func() {
		select {
		case <-releaseTail:
		default:
			close(releaseTail)
		}
	}()

	checks := make([]checkEntry, checkParallelism+2)
	checks[0] = checkEntry{
		name: "stream-prefix-0",
		check: funcCheck{fn: func(context.Context) probefw.Result {
			return probefw.Result{Pass: true}
		}},
	}
	for i := 1; i <= checkParallelism; i++ {
		checks[i] = checkEntry{
			name: fmt.Sprintf("stream-blocker-%d", i),
			check: funcCheck{fn: func(ctx context.Context) probefw.Result {
				select {
				case <-releaseTail:
				case <-ctx.Done():
				}
				return probefw.Result{Pass: true}
			}},
		}
	}
	checks[len(checks)-1] = checkEntry{
		name: "stream-tail",
		check: funcCheck{fn: func(context.Context) probefw.Result {
			return probefw.Result{Pass: true}
		}},
	}
	p.checks = checks

	done := make(chan error, 1)
	go func() {
		done <- p.run(t.Context())
	}()

	deadline := time.Now().Add(3 * time.Second)
	committedEarly := false
	for time.Now().Before(deadline) {
		if v, ok := probetest.HealthGauge(t, "stream-prefix-0", "OK"); ok && v == 1 {
			committedEarly = true
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	close(releaseTail)
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
	if !committedEarly {
		t.Fatal("prefix check stream-prefix-0 did not commit before tail blockers drained")
	}
}

func TestRunDeadlineExceededIncErrorVsCanceled(t *testing.T) {
	p := testProber(fake.NewSimpleClientset())
	p.checks = []checkEntry{{
		name: "slow-deadline-check",
		check: funcCheck{fn: func(ctx context.Context) probefw.Result {
			<-ctx.Done()
			return probefw.Result{Pass: true}
		}},
	}}

	runErrs := func() float64 {
		m := probetest.FindMetric(t, "shell_operator_hook_run_errors_total",
			map[string]string{"queue": p.Name})
		if m == nil {
			return 0
		}
		return m.GetCounter().GetValue()
	}

	before := runErrs()
	dctx, cancel := context.WithTimeout(t.Context(), 15*time.Millisecond)
	defer cancel()
	if err := p.run(dctx); err != nil {
		t.Fatalf("run must return nil on DeadlineExceeded after counting IncError: %v", err)
	}
	if delta := runErrs() - before; delta != 1 {
		t.Fatalf("DeadlineExceeded run_errors delta = %v, want 1", delta)
	}

	// Verify Periodic.RunTimeout hits DeadlineExceeded and increments
	// run_errors exactly once (no double-counting). Guarantee stop()
	// runs after the first invocation even if RunTimeout expires before
	// runCheckIsolated enters check.Run under heavy -race load.
	beforePeriodic := runErrs()
	ctx, stop := context.WithCancel(t.Context())
	defer stop()
	per := &shared.Periodic{
		Name:       p.Name,
		Interval:   time.Second,
		RunTimeout: 50 * time.Millisecond,
		Fn: func(c context.Context) error {
			defer stop()
			return p.run(c)
		},
	}
	p.checks = []checkEntry{{
		name: "slow-periodic-deadline",
		check: funcCheck{fn: func(c context.Context) probefw.Result {
			<-c.Done()
			return probefw.Result{Pass: true}
		}},
	}}
	if err := per.Start(ctx); err != nil {
		t.Fatalf("Periodic.Start: %v", err)
	}
	if delta := runErrs() - beforePeriodic; delta != 1 {
		t.Fatalf("Periodic RunTimeout run_errors delta = %v, want 1 (no double-count)", delta)
	}
}

func TestRunCheckIsolatedTimeoutBlocksPass(t *testing.T) {
	p := testProber(fake.NewSimpleClientset())
	p.Cfg.Timeouts.PerCheck = 10 * time.Millisecond
	p.checks = []checkEntry{{
		name: "ignore-ctx-timeout",
		check: funcCheck{fn: func(context.Context) probefw.Result {
			time.Sleep(35 * time.Millisecond)
			return probefw.Result{Pass: true}
		}},
	}}

	out := runCheckIsolated(p.checks[0], t.Context(), 10*time.Millisecond)
	if !out.timedOut {
		t.Fatal("expected out.timedOut == true")
	}
	if out.pass {
		t.Fatalf("timed-out check must not report pass=true: %+v", out)
	}
	if out.why == "" {
		t.Fatal("timed-out check must carry non-empty why")
	}

	if err := p.run(t.Context()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if fail, ok := probetest.HealthGauge(t, "ignore-ctx-timeout", "FAIL"); !ok || fail != 1 {
		t.Fatalf("timed-out check FAIL gauge = %v,%v want 1", fail, ok)
	}
	if _, stamped := p.lastPass["ignore-ctx-timeout"]; stamped {
		t.Fatal("timed-out check must not stamp lastPass")
	}
}

func TestRunCheckIsolatedPanicCapturesStack(t *testing.T) {
	out := runCheckIsolated(checkEntry{
		name: "panicking-check",
		check: funcCheck{fn: func(context.Context) probefw.Result {
			panic("boom-stack")
		}},
	}, t.Context(), time.Minute)
	if out.pass {
		t.Fatalf("panicking check must fail: %+v", out)
	}
	if out.infra == nil || !strings.Contains(out.infra.Error(), "boom-stack") {
		t.Fatalf("infra error = %v, want panic message", out.infra)
	}
	if !strings.Contains(out.stack, "TestRunCheckIsolatedPanicCapturesStack") {
		t.Fatalf("captured stack missing caller frame: %q", out.stack)
	}
}
