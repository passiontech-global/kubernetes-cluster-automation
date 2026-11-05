// cluster_health_probes.go — the sweep module root: Setup, the
// prober and the checkDefs registry. The 27 checks it drives live in
// per-domain subpackages under internal/health on top of the shared
// probefw framework:
//
//   - ported — the five kuberhealthy "passive" HealthChecks that used
//     to run as periodic checker Pods in the kuberhealthy namespace
//     (infrastructure/base/kuberhealthy/checks/ in
//     passiontech-fluxcd). The sixth check in that dir,
//     cronjob-checker, is deliberately NOT ported — cronjob-catchup
//     already sweeps CronJobs cluster-wide.
//   - watchdogs — the workqueue/control-plane watchdogs:
//     kcm-workqueue-watchdog (C6) detects a kube-controller-manager
//     whose leader Lease still renews while its object controllers
//     stop reconciling — a "gray" failure a dead-KCM check cannot
//     see — plus operator-workqueue-watchdog (W5.8, which
//     AUTO-HEALS: outside a maintenance window the stuck leader pod
//     is deleted, 1h cooldown persisted on the Lease), the
//     scheduler watchdog and the mesh control-plane watchdog.
//   - nodehealth — node/pod/namespace wedge checks (node-hang
//     pre-cordon, image-pull storm, stranded local-PV pods, wedged
//     terminating namespaces).
//   - nethealth — network control-plane checks (coredns upstream,
//     linkerd endpoint sync + protocol-detection stall, cilium BPF
//     map pressure + node IPAM exhaustion).
//   - datastore — datastore operator health (scylla, rabbitmq
//     quorum + suspended listener, dragonfly sync storm, percona
//     quorum, stateful-masterless-services W6.2, OLM subscriptions).
//   - gitops — argocd-app-stuck and flux-helmrelease-retries.
//
// Layout: each check lives in its domain package alongside its state
// maps and the NewXxxCheck constructor that builds it; the checkDefs
// registry below is the single sweep-order roster. Adding a check is
// two touch points — a checkDefs row + the constructor in the check's
// file — instead of the five (constant, prober field, lastPass seed,
// constructor literal, checks row) the monolithic prober needed.
//
// Metric contract: results go out on the SAME series kuberhealthy
// exported — kuberhealthy_check{check,namespace,status} and
// kuberhealthy_check_seconds_since_success{check,namespace} — under
// the original HealthCheck names and the literal "kuberhealthy"
// namespace label, so the KuberhealthyCheckFailed /
// KuberhealthyCheckStale PrometheusRule alerts keep firing with zero
// PromQL or dashboard changes.
//
// Error accounting: a check FAIL is the product — it is reported via
// metrics and logged, never as a run error. Only apiserver/client
// failures count against the queue's run-error counters (IncError,
// same pattern as cronjob-catchup's dedupe List). A cancelled sweep
// context (SIGTERM mid-cycle) aborts the run silently — it is a
// shutdown, not a health signal, so no FAIL series and no run error
// are emitted for it.
package clusterhealthprobes

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/health/datastore"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/health/gitops"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/health/nethealth"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/health/nodehealth"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/health/ported"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/health/watchdogs"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/promq"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

// healthProbeConfigFromEnv resolves the check knobs once at Setup.
// The live manifests are the ground truth for the defaults (e.g.
// http-content-check TARGET_URL is the prometheus /-/healthy
// endpoint, not alertmanager).
func healthProbeConfigFromEnv() probefw.Config {
	// Second hostname is a ClusterIP Service (DNS record exists
	// regardless of backend pod readiness) — a headless service like
	// alertmanager-operated NXDOMAINs whenever its single pod is
	// recreating, which would flap the DNS check during every
	// alertmanager rollout despite CoreDNS being fine.
	hosts := strings.Split(shared.Getenv("HEALTH_DNS_HOSTNAMES",
		"kubernetes.default.svc.cluster.local,"+
			"kube-prometheus-stack-prometheus.prometheus-operator.svc.cluster.local"), ",")
	trimmed := hosts[:0]
	for _, h := range hosts {
		if h = strings.TrimSpace(h); h != "" {
			trimmed = append(trimmed, h)
		}
	}
	return probefw.Config{
		DNS: probefw.DNSConfig{Hostnames: trimmed},
		Timeouts: probefw.TimeoutsConfig{
			// shared.GetenvDuration floors every duration knob at
			// 1s (the retired helpers accepted any d > 0) —
			// sub-second probe timeouts and persistence windows
			// were already pathological, so the tightened bound
			// changes no sane configuration.
			Check: shared.GetenvDuration("HEALTH_CHECK_TIMEOUT", 30*time.Second),
			// Bounds one check's share of the serial sweep — a hung
			// apiserver call used to stretch the whole cycle; past
			// the deadline the check's context is cancelled (the
			// in-flight call unwinds) and the sweep moves on. The
			// check's own error still surfaces as FAIL/infra, so
			// reporting semantics are unchanged — only the wait is
			// bounded.
			PerCheck: shared.GetenvDuration("HEALTH_PER_CHECK_TIMEOUT", 2*time.Minute),
		},
		HTTPContent: probefw.HTTPContentConfig{
			URL:      shared.Getenv("HEALTH_HTTP_CONTENT_URL", "http://kube-prometheus-stack-prometheus.prometheus-operator.svc:9090/-/healthy"),
			Expected: shared.Getenv("HEALTH_HTTP_EXPECTED_CONTENT", "Healthy"),
		},
		Pods: probefw.PodsConfig{
			Namespace:    shared.Getenv("HEALTH_POD_CHECK_NAMESPACE", "kube-system"),
			MaxRestarts:  int32(shared.GetenvIntMin("HEALTH_MAX_POD_RESTARTS", 10, 0)),
			SkipDuration: shared.GetenvDuration("HEALTH_POD_SKIP_DURATION", 10*time.Minute),
		},
		Quota: probefw.QuotaConfig{
			Threshold: shared.GetenvFloatPositive("HEALTH_RESOURCE_QUOTA_THRESHOLD", 0.9),
		},
		KCM: probefw.KCMConfig{
			// KCM leader-election defaults are LeaseDuration 15s,
			// RenewDeadline 10s, RetryPeriod ~2s, so a live holder's
			// renewTime is never more than a few seconds old. 30s —
			// 2× the lease duration — bounds "still renewing" with
			// margin for apiserver latency; anything older means
			// the holder is gone (a dead KCM, not a frozen one).
			LeaseMaxAge: shared.GetenvDuration("HEALTH_KCM_LEASE_MAX_AGE", 30*time.Second),
			// A freeze signature must persist this long before the
			// gauge fires — a healthy reconcile legitimately lags a
			// spec write by a sync period or two.
			FreezeMinAge: shared.GetenvDuration("HEALTH_KCM_FREEZE_MIN_AGE", 10*time.Minute),
		},
	}
}

// checkEntry is one registry row: the check name — the
// kuberhealthy_check label value alerts key on — and the check
// instance Run() invokes.
type checkEntry struct {
	name  string
	check probefw.Check
}

// checkDefs is the data-driven check registry — the single sweep-order
// roster the prober is built from. Order is the ops contract: the
// historical sweep order is preserved verbatim and the names are the
// kuberhealthy_check label values, so neither may change. Each row's
// constructor lives in the check's own domain package so its state-map
// initialization colocates with the check logic.
var checkDefs = []struct {
	name string
	new  func(*probefw.Deps) probefw.Check
}{
	{ported.CheckNameDNS, ported.NewDNSStatusCheck},
	{ported.CheckNameHTTPContent, ported.NewHTTPContentCheck},
	{ported.CheckNamePodRestarts, ported.NewPodRestartsCheck},
	{ported.CheckNamePodStatus, ported.NewPodStatusCheck},
	{ported.CheckNameResourceQuota, ported.NewResourceQuotaCheck},
	{watchdogs.CheckNameKCMWorkqueue, watchdogs.NewKcmWorkqueueCheck},
	{watchdogs.CheckNameOperatorWorkqueue, watchdogs.NewOperatorWorkqueueCheck},
	{datastore.CheckNameStatefulMasterless, datastore.NewStatefulMasterlessCheck},
	{datastore.CheckNameRabbitMQSuspended, datastore.NewRabbitMQSuspendedCheck},
	{nodehealth.CheckNameLocalPVStranded, nodehealth.NewLocalPVStrandedCheck},
	{datastore.CheckNameOLMHealth, datastore.NewOlmHealthCheck},
	{watchdogs.CheckNameSchedulerWatchdog, watchdogs.NewSchedulerWatchdogCheck},
	{watchdogs.CheckNameMeshWatchdog, watchdogs.NewMeshControlPlaneCheck},
	{nodehealth.CheckNameNodeHang, nodehealth.NewNodeHangCheck},
	{nethealth.CheckNameLinkerdEndpointSync, nethealth.NewLinkerdEndpointSyncCheck},
	{datastore.CheckNameScyllaHealth, datastore.NewScyllaHealthCheck},
	{gitops.CheckNameFluxHRRetries, gitops.NewFluxHRRetriesCheck},
	{datastore.CheckNamePerconaQuorum, datastore.NewPerconaQuorumCheck},
	{nethealth.CheckNameCiliumBPFMapPressure, nethealth.NewCiliumBPFMapPressureCheck},
	{nethealth.CheckNameLinkerdOpaqueStall, nethealth.NewLinkerdProtocolDetectionStallCheck},
	{nethealth.CheckNameCoreDNSUpstream, nethealth.NewCoreDNSUpstreamCheck},
	{nethealth.CheckNameCiliumNodeIPAM, nethealth.NewCiliumNodeIPAMExhaustionCheck},
	{nodehealth.CheckNameNamespaceWedged, nodehealth.NewNamespaceTerminatingWedgedCheck},
	{gitops.CheckNameArgoCDAppStuck, gitops.NewArgoCDAppStuckCheck},
	{datastore.CheckNameRabbitMQQuorum, datastore.NewRabbitMQQuorumHealthCheck},
	{datastore.CheckNameDragonflySyncStorm, datastore.NewDragonflyReplicaSyncStormCheck},
	{nodehealth.CheckNameImagePullStorm, nodehealth.NewImagePullStormCheck},
}

// clusterHealthProber is the thin sweep runner: the shared deps, the
// check registry run() iterates (built once at construction in the
// historical sweep order — each check instance colocates its own
// state with its logic in its own package), and the kuberhealthy
// series reporter. Check names are metric label values and must not
// change.
type clusterHealthProber struct {
	*probefw.Deps

	// boot stamps prober construction — report() lazily seeds a
	// never-passed check's staleness from boot (the semantics the
	// old 27-entry boot literal encoded), matching kuberhealthy's
	// count-from-check-creation behavior.
	boot time.Time

	// lastPass tracks the last OK per check name for the
	// seconds_since_success gauge — it holds REAL passes only; a
	// check with no entry yet counts staleness from p.boot (see
	// report), so a check that never passed still reports a growing
	// staleness.
	lastPass map[string]time.Time

	// checks is the run() registry — built once at construction from
	// checkDefs, in the historical sweep order.
	checks []checkEntry
}

func newClusterHealthProber(name string, cs kubernetes.Interface, dyn dynamic.Interface, cfg probefw.Config) *clusterHealthProber {
	d := &probefw.Deps{
		Name:       name,
		CS:         cs,
		Dyn:        dyn,
		Cfg:        cfg,
		LookupHost: (&net.Resolver{}).LookupHost,
		HTTPClient: &http.Client{},
		Now:        time.Now,
	}
	// The Prometheus client shares the HTTPClient seam tests swap
	// post-construction (PromQuery re-reads it per call) and bounds
	// each query by the check timeout — the posture the retired
	// promInstantQuery encoded inline.
	d.Prom = promq.Client{HTTP: d.HTTPClient, Timeout: cfg.Timeouts.Check}
	p := &clusterHealthProber{
		Deps:     d,
		boot:     time.Now(),
		lastPass: map[string]time.Time{},
	}
	for _, def := range checkDefs {
		p.checks = append(p.checks, checkEntry{name: def.name, check: def.new(d)})
	}
	return p
}

// Setup registers the 5-minute probe sweep. The
// kuberhealthy checks ran always-on, so the registration gate lives
// in CLUSTER_HEALTH_PROBES_ENABLED (default ON — explicit "false"
// opts out); setupModules evaluates it and stamps Deps.Disabled —
// disabled skips mgr.Add entirely, matching the
// cilium-taint-reaper pattern. dyn feeds the CRD scans inside the
// self-healing checks (W5.8/W6.2) — wired like every other
// dynamic-client module.
func Setup(d shared.Deps) error {
	// Config resolution stays BEFORE the disabled early-return so
	// knob-parse warnings still fire for a gated-off module — the
	// codebase's parse-before-gate contract.
	cfg := healthProbeConfigFromEnv()
	// shared.GetenvDuration rejects <1s (the retired helper accepted
	// any d > 0) — a sub-second sweep interval was already a
	// hot-loop bug, never a sane setting.
	interval := shared.GetenvDuration("CLUSTER_HEALTH_PROBES_INTERVAL", 5*time.Minute)
	if d.Disabled {
		return nil
	}
	p := newClusterHealthProber(d.Name, d.CS, d.Dyn, cfg)
	// Surface the resolved HEALTH_* knobs once at registration so an
	// operator can tell from the logs which targets/thresholds the
	// checks run with (an unparseable env value silently falls back
	// to the default — the effective value is what matters here).
	logf.Log.WithName(d.Name).Info("registered",
		"interval", interval, "perCheckTimeout", p.Cfg.Timeouts.PerCheck,
		"dnsHostnames", p.Cfg.DNS.Hostnames,
		"checkTimeout", p.Cfg.Timeouts.Check, "httpURL", p.Cfg.HTTPContent.URL,
		"httpExpectedContent", p.Cfg.HTTPContent.Expected,
		"podCheckNamespace", p.Cfg.Pods.Namespace,
		"maxPodRestarts", p.Cfg.Pods.MaxRestarts,
		"podSkipDuration", p.Cfg.Pods.SkipDuration,
		"quotaThreshold", p.Cfg.Quota.Threshold,
		"kcmLeaseMaxAge", p.Cfg.KCM.LeaseMaxAge,
		"kcmFreezeMinAge", p.Cfg.KCM.FreezeMinAge)
	return shared.AddPeriodic(d.Mgr, d.Name, interval, p.run)
}

func (p *clusterHealthProber) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	for _, c := range p.checks {
		// Bound one check's share of the serial sweep — a hung
		// apiserver call used to stretch the whole cycle. The child
		// deadline cancels the in-flight client call; the check's own
		// error usually surfaces as infra below, so FAIL/reporting
		// semantics are unchanged — only the wait is bounded.
		cctx, cancel := context.WithTimeout(ctx, p.Cfg.Timeouts.PerCheck)
		res := c.check.Run(cctx)
		cancel()
		// A cancelled sweep context (SIGTERM during rollout/shutdown)
		// is not a health signal: emitting FAIL=1 or a run error now
		// would leave fake series behind on the dying pod. Bail out
		// silently — the surviving leader's next cycle reports.
		if ctx.Err() != nil {
			return nil
		}
		if cctx.Err() == context.DeadlineExceeded {
			log.Info("health check exceeded per-check timeout",
				"check", c.name)
		}
		p.report(c.name, res.Pass)
		// A check FAIL is the product — it is reported via metrics and
		// logged, never as a run error. Only apiserver/client failures
		// count against the queue's run-error counters.
		if res.Infra != nil {
			metrics.IncError(p.Name)
			log.Error(res.Infra, "health check probe errored — marked FAIL",
				"check", c.name)
		} else if !res.Pass {
			log.Info("health check FAIL", "check", c.name, "reason", res.Why)
		}
	}
	return nil
}

// report updates the kuberhealthy-compatible series for one check.
func (p *clusterHealthProber) report(name string, ok bool) {
	now := p.Now()
	if ok {
		p.lastPass[name] = now
	}
	// Lazy seed: a check with no recorded pass yet counts staleness
	// from prober boot — the semantics the old boot-time lastPass
	// literal encoded — so a never-passing check still alerts stale.
	last, seeded := p.lastPass[name]
	if !seeded {
		last = p.boot
	}
	since := now.Sub(last).Seconds()
	metrics.ObserveHealthCheck(name, ok, since)
}
