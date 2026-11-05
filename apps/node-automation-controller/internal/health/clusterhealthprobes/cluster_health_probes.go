// cluster_health_probes.go — in-process port of the five kuberhealthy
// "passive" HealthChecks that used to run as periodic checker Pods in
// the kuberhealthy namespace (infrastructure/base/kuberhealthy/checks/
// in passiontech-fluxcd). The sixth check in that dir,
// cronjob-checker, is deliberately NOT ported — cronjob-catchup
// already sweeps CronJobs cluster-wide.
//
// A sixth in-process check rides along on the same sweep:
// kcm-workqueue-watchdog (C6) detects a kube-controller-manager whose
// leader Lease still renews while its object controllers stop
// reconciling — a "gray" failure a dead-KCM check cannot see. It is
// not a ported HealthCheck but reuses the same probe plumbing,
// reporting FAIL on its own kuberhealthy_check series plus the
// dedicated node_automation_kcm_workqueue_frozen{reason} gauge.
//
// Three more self-healing checks ride the same plumbing:
//   - operator-workqueue-watchdog (W5.8) generalizes the C6 shape to
//     third-party operators — cilium/scylla/dragonfly/flux controllers
//     holding a renewing Lease while their target CRs stay
//     unreconciled past a stuck threshold. On top of the
//     node_automation_operator_workqueue_frozen{operator,reason}
//     gauge it AUTO-HEALS: outside a maintenance window the stuck
//     leader pod is deleted (1h cooldown, persisted on the Lease) to
//     force re-election.
//   - stateful-masterless-services (W6.2) flags a master-role
//     Service (role/redis-role/app.kubernetes.io/role ∈
//     {master,primary,leader}) backed by a ready StatefulSet whose
//     EndpointSlices report 0 Ready endpoints for >=3m — past 5m a
//     Dragonfly STS additionally triggers a dragonfly-operator
//     leader delete (30m cooldown) to force re-election.
//   - rabbitmq-suspended-listener (W6.4) deletes RabbitMQ pods stuck
//     >=10m in the suspended-listener wedge (Running, every container
//     started but never Ready — port 5672 refused) once all peer
//     replicas are Ready, so quorum survives the pod kill.
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
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

const clusterHealthQueue = "cluster-health-probes"

// Check names — the exact HealthCheck metadata.name values the
// replaced kuberhealthy checks carried; they are the `check` label
// values alerts and dashboards key on. kcm-workqueue-watchdog is the
// exception: not a ported HealthCheck, it is the C6 watchdog — it
// still reports on the same series under its own check name so the
// generic FAIL alerting path covers it too.
const (
	checkNameDNS           = "dns-status-internal"
	checkNameHTTPContent   = "http-content-check"
	checkNamePodRestarts   = "pod-restarts"
	checkNamePodStatus     = "pod-status-check"
	checkNameResourceQuota = "resource-quota-check"
	checkNameKCMWorkqueue  = "kcm-workqueue-watchdog"
	// W5.8/W6.2/W6.4 — the self-healing checks riding the same
	// plumbing; like the KCM watchdog they are not ported
	// HealthChecks but report under their own check names so the
	// generic FAIL alerting path covers them.
	checkNameOperatorWorkqueue  = "operator-workqueue-watchdog"
	checkNameStatefulMasterless = "stateful-masterless-services"
	checkNameRabbitMQSuspended  = "rabbitmq-suspended-listener"
	// W7 — same not-ported shape: the checks ride the generic FAIL
	// alerting path under their own check names.
	checkNameLocalPVStranded = "localpv-stranded-pods"
	checkNameOLMHealth       = "olm-subscription-health"
	// W10-CP4/W10-ST5 — Flux HelmRelease retry remediation and the
	// Percona cluster quorum watchdog live in this file; their
	// check-name constants sit here alongside the code. The nine
	// self-healing probes (W10-NM*/CP*/ST*/GI*) live one check per
	// file — cilium_bpf_map_pressure.go, linkerd_protocol_detection_
	// stall.go, coredns_upstream.go, cilium_node_ipam_exhaustion.go,
	// namespace_terminating_wedged.go, argocd_app_stuck.go,
	// rabbitmq_quorum_health.go, dragonfly_replica_sync_storm.go,
	// image_pull_storm.go — sharing self_healing_shared.go; their
	// check-name constants are declared in those files.
	checkNameFluxHRRetries = "flux-helmrelease-retries"
	checkNamePerconaQuorum = "percona-cluster-quorum"
	// W8/W9 — the Wave-8/9 checks live one check per file
	// (scheduler_watchdog.go, mesh_controlplane_watchdog.go,
	// node_hang_precordon.go, linkerd_endpoint_sync.go,
	// scylla_cluster_health.go); their check-name constants are
	// declared there alongside the code.
)

// healthListPageSize bounds the cluster-wide EndpointSlice list the
// masterless check pages through — same pagination posture as the
// webhook guard's census.
const healthListPageSize = 500

// healthProbeConfig carries the HEALTH_* env knobs the checker Pods
// read (HOSTNAME/TARGET_URL/MAX_FAILURES_ALLOWED/...), re-homed under
// a HEALTH_ prefix. Defaults match the live check manifests.
type healthProbeConfig struct {
	dnsHostnames        []string      // HEALTH_DNS_HOSTNAMES
	checkTimeout        time.Duration // HEALTH_CHECK_TIMEOUT
	httpURL             string        // HEALTH_HTTP_CONTENT_URL
	httpExpectedContent string        // HEALTH_HTTP_EXPECTED_CONTENT
	podCheckNamespace   string        // HEALTH_POD_CHECK_NAMESPACE
	maxPodRestarts      int32         // HEALTH_MAX_POD_RESTARTS
	podSkipDuration     time.Duration // HEALTH_POD_SKIP_DURATION
	quotaThreshold      float64       // HEALTH_RESOURCE_QUOTA_THRESHOLD
	kcmLeaseMaxAge      time.Duration // HEALTH_KCM_LEASE_MAX_AGE
	kcmFreezeMinAge     time.Duration // HEALTH_KCM_FREEZE_MIN_AGE
}

func healthEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// healthEnvDuration parses a duration env knob, warning + defaulting
// on two failure shapes: unparseable values (typos, unit-less numbers)
// and non-positive durations — a 0s/negative check timeout would make
// every probe fail instantly, and a 0s interval would panic the
// periodic ticker registration downstream.
func healthEnvDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		logf.Log.WithName(clusterHealthQueue).Info(
			"invalid env duration — using default", "key", key, "value", v,
			"default", def)
		return def
	}
	if d <= 0 {
		logf.Log.WithName(clusterHealthQueue).Info(
			"non-positive env duration — using default", "key", key,
			"value", v, "default", def)
		return def
	}
	return d
}

// healthEnvInt parses an integer env knob, warning + defaulting on
// unparseable values and negatives — e.g. HEALTH_MAX_POD_RESTARTS=-1
// would flag every container as over-limit.
func healthEnvInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		logf.Log.WithName(clusterHealthQueue).Info(
			"invalid env int — using default", "key", key, "value", v,
			"default", def)
		return def
	}
	if n < 0 {
		logf.Log.WithName(clusterHealthQueue).Info(
			"negative env int — using default", "key", key, "value", v,
			"default", def)
		return def
	}
	return n
}

// healthEnvFloat parses a float env knob, warning + defaulting on
// unparseable values (a garbage threshold string must not silently
// collapse to the default without an operator-visible note).
func healthEnvFloat(key string, def float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f <= 0 {
		// Non-positive thresholds are never meaningful (a <=0
		// quota threshold flags EVERYTHING); >1 is kept as the
		// operator's documented "disable this check" escape.
		logf.Log.WithName(clusterHealthQueue).Info(
			"invalid env float — using default", "key", key, "value", v,
			"default", def)
		return def
	}
	return f
}

// healthProbeConfigFromEnv resolves the check knobs once at Setup.
// The live manifests are the ground truth for the defaults (e.g.
// http-content-check TARGET_URL is the prometheus /-/healthy
// endpoint, not alertmanager).
func healthProbeConfigFromEnv() healthProbeConfig {
	// Second hostname is a ClusterIP Service (DNS record exists
	// regardless of backend pod readiness) — a headless service like
	// alertmanager-operated NXDOMAINs whenever its single pod is
	// recreating, which would flap the DNS check during every
	// alertmanager rollout despite CoreDNS being fine.
	hosts := strings.Split(healthEnv("HEALTH_DNS_HOSTNAMES",
		"kubernetes.default.svc.cluster.local,"+
			"kube-prometheus-stack-prometheus.prometheus-operator.svc.cluster.local"), ",")
	trimmed := hosts[:0]
	for _, h := range hosts {
		if h = strings.TrimSpace(h); h != "" {
			trimmed = append(trimmed, h)
		}
	}
	return healthProbeConfig{
		dnsHostnames:        trimmed,
		checkTimeout:        healthEnvDuration("HEALTH_CHECK_TIMEOUT", 30*time.Second),
		httpURL:             healthEnv("HEALTH_HTTP_CONTENT_URL", "http://kube-prometheus-stack-prometheus.prometheus-operator.svc:9090/-/healthy"),
		httpExpectedContent: healthEnv("HEALTH_HTTP_EXPECTED_CONTENT", "Healthy"),
		podCheckNamespace:   healthEnv("HEALTH_POD_CHECK_NAMESPACE", "kube-system"),
		maxPodRestarts:      int32(healthEnvInt("HEALTH_MAX_POD_RESTARTS", 10)),
		podSkipDuration:     healthEnvDuration("HEALTH_POD_SKIP_DURATION", 10*time.Minute),
		quotaThreshold:      healthEnvFloat("HEALTH_RESOURCE_QUOTA_THRESHOLD", 0.9),
		// KCM leader-election defaults are LeaseDuration 15s,
		// RenewDeadline 10s, RetryPeriod ~2s, so a live holder's
		// renewTime is never more than a few seconds old. 30s — 2×
		// the lease duration — bounds "still renewing" with margin
		// for apiserver latency; anything older means the holder is
		// gone (a dead KCM, not a frozen one).
		kcmLeaseMaxAge: healthEnvDuration("HEALTH_KCM_LEASE_MAX_AGE", 30*time.Second),
		// A freeze signature must persist this long before the gauge
		// fires — a healthy reconcile legitimately lags a spec write
		// by a sync period or two.
		kcmFreezeMinAge: healthEnvDuration("HEALTH_KCM_FREEZE_MIN_AGE", 10*time.Minute),
	}
}

// probeResult is one check's verdict. pass=false + infra=nil is an
// observed health failure (the metric's FAIL=1); infra!=nil is a
// client/apiserver error — the check is still marked FAIL (it did not
// succeed) but the error also counts against the queue run errors.
type probeResult struct {
	pass  bool
	why   string
	infra error
}

// deps carries the genuinely shared, read-mostly dependencies every
// check needs: the typed and dynamic clients, the resolved HEALTH_*
// config, and the test seams (lookupHost, httpClient, now). It also
// owns the two ledgers that outlive any single check: meshHealed,
// the shared self-heal cooldown stamp map, and ledger, the
// first-seen/emitted-gauge bookkeeping the self-healing checks share
// (formerly the package-level probeHealLedger — one prober per
// process means deps has the same lifetime). mu is the single lock
// the monolithic prober used for all check state: every check struct
// embeds *deps, so its maps stay under the same mutex.
type deps struct {
	cs kubernetes.Interface
	// dyn reads the CRD types the W5.8 stuck signatures scan
	// (gateway-api, scylladb, dragonflydb, flux) and the autopilot
	// Plan inside the maintenance mutex — no typed clients exist.
	dyn dynamic.Interface
	cfg healthProbeConfig
	// lookupHost is the DNS seam (tests inject a fake; production uses
	// the default resolver — in-cluster CoreDNS via /etc/resolv.conf).
	lookupHost func(ctx context.Context, host string) ([]string, error)
	httpClient *http.Client
	now        shared.Clock

	// mu guards meshHealed, ledger and every check's state maps —
	// the same single-lock posture the monolithic prober had.
	mu sync.Mutex

	// W8 watchdog state (under mu):
	//   - meshHealed: component → last control-plane pod delete —
	//     the W8-NM2 cilium-operator (1h) and W8-NM3 linkerd (30m)
	//     cooldowns, plus the W4 db-operator masterless heals.
	meshHealed map[string]time.Time

	// ledger is the shared first-seen streak + emitted-gauge
	// bookkeeping (see self_healing_shared.go).
	ledger healLedger
}

// checkEntry is one registry row: the check name — the
// kuberhealthy_check label value alerts key on — and the check's
// run func.
type checkEntry struct {
	name  string
	probe func(ctx context.Context) probeResult
}

// clusterHealthProber is the thin sweep runner: the shared deps, one
// instance per check (each colocating its own state with its logic
// in its own file), the kuberhealthy series reporter, and the check
// registry run() iterates. Check names are metric label values and
// must not change.
type clusterHealthProber struct {
	*deps

	// lastPass tracks the last OK per check name for the
	// seconds_since_success gauge — seeded to boot time so a check
	// that never passed still reports a growing staleness, matching
	// kuberhealthy (which counts from check creation).
	lastPass map[string]time.Time

	// One instance per check — the checks registry references these
	// same objects so per-check state persists across sweeps.
	dns             *dnsStatusCheck
	httpContent     *httpContentCheck
	podRestarts     *podRestartsCheck
	podStatus       *podStatusCheck
	resourceQuota   *resourceQuotaCheck
	kcm             *kcmWorkqueueCheck
	operator        *operatorWorkqueueCheck
	masterless      *statefulMasterlessCheck
	rabbitSuspended *rabbitMQSuspendedCheck
	localPV         *localPVStrandedCheck
	olm             *olmHealthCheck
	scheduler       *schedulerWatchdogCheck
	mesh            *meshControlPlaneCheck
	nodeHang        *nodeHangCheck
	linkerdSync     *linkerdEndpointSyncCheck
	scylla          *scyllaHealthCheck
	fluxHR          *fluxHRRetriesCheck
	percona         *perconaQuorumCheck
	ciliumBPF       *ciliumBPFMapPressureCheck
	linkerdStall    *linkerdProtocolDetectionStallCheck
	coreDNS         *coreDNSUpstreamCheck
	ciliumIPAM      *ciliumNodeIPAMExhaustionCheck
	nsWedged        *namespaceTerminatingWedgedCheck
	argoCD          *argoCDAppStuckCheck
	rabbitQuorum    *rabbitMQQuorumHealthCheck
	dragonflyStorm  *dragonflyReplicaSyncStormCheck
	imagePull       *imagePullStormCheck

	// checks is the run() registry — built once at construction in
	// the historical sweep order.
	checks []checkEntry
}

func newClusterHealthProber(cs kubernetes.Interface, dyn dynamic.Interface, cfg healthProbeConfig) *clusterHealthProber {
	boot := time.Now()
	d := &deps{
		cs:         cs,
		dyn:        dyn,
		cfg:        cfg,
		lookupHost: (&net.Resolver{}).LookupHost,
		httpClient: &http.Client{},
		now:        time.Now,
		meshHealed: map[string]time.Time{},
		ledger: healLedger{
			seen:    map[string]time.Time{},
			emitted: map[string]*shared.GaugeLedger[string]{},
		},
	}
	p := &clusterHealthProber{
		deps: d,
		lastPass: map[string]time.Time{
			checkNameDNS:                  boot,
			checkNameHTTPContent:          boot,
			checkNamePodRestarts:          boot,
			checkNamePodStatus:            boot,
			checkNameResourceQuota:        boot,
			checkNameKCMWorkqueue:         boot,
			checkNameOperatorWorkqueue:    boot,
			checkNameStatefulMasterless:   boot,
			checkNameRabbitMQSuspended:    boot,
			checkNameLocalPVStranded:      boot,
			checkNameOLMHealth:            boot,
			checkNameSchedulerWatchdog:    boot,
			checkNameMeshWatchdog:         boot,
			checkNameNodeHang:             boot,
			checkNameLinkerdEndpointSync:  boot,
			checkNameScyllaHealth:         boot,
			checkNameFluxHRRetries:        boot,
			checkNamePerconaQuorum:        boot,
			checkNameCiliumBPFMapPressure: boot,
			checkNameLinkerdOpaqueStall:   boot,
			checkNameCoreDNSUpstream:      boot,
			checkNameCiliumNodeIPAM:       boot,
			checkNameNamespaceWedged:      boot,
			checkNameArgoCDAppStuck:       boot,
			checkNameRabbitMQQuorum:       boot,
			checkNameDragonflySyncStorm:   boot,
			checkNameImagePullStorm:       boot,
		},
		dns:           &dnsStatusCheck{deps: d},
		httpContent:   &httpContentCheck{deps: d},
		podRestarts:   &podRestartsCheck{deps: d},
		podStatus:     &podStatusCheck{deps: d},
		resourceQuota: &resourceQuotaCheck{deps: d},
		kcm: &kcmWorkqueueCheck{deps: d,
			kcmFirstSeen:     map[string]time.Time{},
			kcmFrozenReasons: map[string]bool{},
		},
		operator: &operatorWorkqueueCheck{deps: d,
			opFirstSeen: map[string]time.Time{},
			opFrozen:    map[string]bool{},
			opHealed:    map[string]time.Time{},
		},
		masterless: &statefulMasterlessCheck{deps: d,
			stsZeroSince:   map[string]time.Time{},
			stsZeroEmitted: map[string]bool{},
			drHealed:       map[string]time.Time{},
			drPodHealed:    map[string]time.Time{},
		},
		rabbitSuspended: &rabbitMQSuspendedCheck{deps: d,
			rbSuspendedSince: map[string]time.Time{},
			rbHealed:         map[string]time.Time{},
		},
		localPV: &localPVStrandedCheck{deps: d,
			localPVEmitted:    map[string]bool{},
			pvcStalledEmitted: map[string]bool{},
			localPVHealed:     map[string]time.Time{},
			pvcProvHealed:     map[string]time.Time{},
		},
		olm: &olmHealthCheck{deps: d,
			olmFirstSeen: map[string]time.Time{},
			olmEmitted:   map[string]bool{},
			olmHealed:    map[string]time.Time{},
		},
		scheduler: &schedulerWatchdogCheck{deps: d},
		mesh:      &meshControlPlaneCheck{deps: d},
		nodeHang:  &nodeHangCheck{deps: d},
		linkerdSync: &linkerdEndpointSyncCheck{deps: d,
			linkerdDesyncSince:   map[string]time.Time{},
			linkerdDesyncEmitted: map[string]bool{},
			linkerdDesyncHealed:  map[string]time.Time{},
		},
		scylla: &scyllaHealthCheck{deps: d,
			scyllaFirstSeen: map[string]time.Time{},
			scyllaEmitted:   map[string]bool{},
		},
		fluxHR: &fluxHRRetriesCheck{deps: d,
			hrRetryHealed: map[string]time.Time{},
		},
		percona: &perconaQuorumCheck{deps: d,
			perconaInitSeen: map[string]time.Time{},
		},
		ciliumBPF:      &ciliumBPFMapPressureCheck{deps: d},
		linkerdStall:   &linkerdProtocolDetectionStallCheck{deps: d},
		coreDNS:        &coreDNSUpstreamCheck{deps: d},
		ciliumIPAM:     &ciliumNodeIPAMExhaustionCheck{deps: d},
		nsWedged:       &namespaceTerminatingWedgedCheck{deps: d},
		argoCD:         &argoCDAppStuckCheck{deps: d},
		rabbitQuorum:   &rabbitMQQuorumHealthCheck{deps: d},
		dragonflyStorm: &dragonflyReplicaSyncStormCheck{deps: d},
		imagePull:      &imagePullStormCheck{deps: d},
	}
	p.checks = []checkEntry{
		{checkNameDNS, p.dns.run},
		{checkNameHTTPContent, p.httpContent.run},
		{checkNamePodRestarts, p.podRestarts.run},
		{checkNamePodStatus, p.podStatus.run},
		{checkNameResourceQuota, p.resourceQuota.run},
		{checkNameKCMWorkqueue, p.kcm.run},
		{checkNameOperatorWorkqueue, p.operator.run},
		{checkNameStatefulMasterless, p.masterless.run},
		{checkNameRabbitMQSuspended, p.rabbitSuspended.run},
		{checkNameLocalPVStranded, p.localPV.run},
		{checkNameOLMHealth, p.olm.run},
		{checkNameSchedulerWatchdog, p.scheduler.run},
		{checkNameMeshWatchdog, p.mesh.run},
		{checkNameNodeHang, p.nodeHang.run},
		{checkNameLinkerdEndpointSync, p.linkerdSync.run},
		{checkNameScyllaHealth, p.scylla.run},
		{checkNameFluxHRRetries, p.fluxHR.run},
		{checkNamePerconaQuorum, p.percona.run},
		{checkNameCiliumBPFMapPressure, p.ciliumBPF.run},
		{checkNameLinkerdOpaqueStall, p.linkerdStall.run},
		{checkNameCoreDNSUpstream, p.coreDNS.run},
		{checkNameCiliumNodeIPAM, p.ciliumIPAM.run},
		{checkNameNamespaceWedged, p.nsWedged.run},
		{checkNameArgoCDAppStuck, p.argoCD.run},
		{checkNameRabbitMQQuorum, p.rabbitQuorum.run},
		{checkNameDragonflySyncStorm, p.dragonflyStorm.run},
		{checkNameImagePullStorm, p.imagePull.run},
	}
	return p
}

// Setup registers the 5-minute probe sweep. The
// kuberhealthy checks ran always-on, so the gate lives in
// CLUSTER_HEALTH_PROBES_ENABLED (default ON — explicit "false" opts
// out); disabled skips mgr.Add entirely, matching the
// cilium-taint-reaper pattern. dyn feeds the CRD scans inside the
// self-healing checks (W5.8/W6.2) — wired like every other
// dynamic-client module.
func Setup(d shared.Deps) error {
	if !shared.Gate("CLUSTER_HEALTH_PROBES_ENABLED", true) {
		logf.Log.WithName(clusterHealthQueue).Info("disabled — module not registered")
		return nil
	}
	p := newClusterHealthProber(d.CS, d.Dyn, healthProbeConfigFromEnv())
	interval := healthEnvDuration("CLUSTER_HEALTH_PROBES_INTERVAL", 5*time.Minute)
	// Surface the resolved HEALTH_* knobs once at registration so an
	// operator can tell from the logs which targets/thresholds the
	// checks run with (an unparseable env value silently falls back
	// to the default — the effective value is what matters here).
	logf.Log.WithName(clusterHealthQueue).Info("registered",
		"interval", interval, "dnsHostnames", p.cfg.dnsHostnames,
		"checkTimeout", p.cfg.checkTimeout, "httpURL", p.cfg.httpURL,
		"httpExpectedContent", p.cfg.httpExpectedContent,
		"podCheckNamespace", p.cfg.podCheckNamespace,
		"maxPodRestarts", p.cfg.maxPodRestarts,
		"podSkipDuration", p.cfg.podSkipDuration,
		"quotaThreshold", p.cfg.quotaThreshold,
		"kcmLeaseMaxAge", p.cfg.kcmLeaseMaxAge,
		"kcmFreezeMinAge", p.cfg.kcmFreezeMinAge)
	return shared.AddPeriodic(d.Mgr, clusterHealthQueue, interval, p.run)
}

func (p *clusterHealthProber) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	for _, c := range p.checks {
		res := c.probe(ctx)
		// A cancelled sweep context (SIGTERM during rollout/shutdown)
		// is not a health signal: emitting FAIL=1 or a run error now
		// would leave fake series behind on the dying pod. Bail out
		// silently — the surviving leader's next cycle reports.
		if ctx.Err() != nil {
			return nil
		}
		p.report(c.name, res.pass)
		// A check FAIL is the product — it is reported via metrics and
		// logged, never as a run error. Only apiserver/client failures
		// count against the queue's run-error counters.
		if res.infra != nil {
			metrics.IncError(clusterHealthQueue)
			log.Error(res.infra, "health check probe errored — marked FAIL",
				"check", c.name)
		} else if !res.pass {
			log.Info("health check FAIL", "check", c.name, "reason", res.why)
		}
	}
	return nil
}

// report updates the kuberhealthy-compatible series for one check.
func (p *clusterHealthProber) report(name string, ok bool) {
	p.mu.Lock()
	now := p.now()
	if ok {
		p.lastPass[name] = now
	}
	since := now.Sub(p.lastPass[name]).Seconds()
	p.mu.Unlock()
	metrics.ObserveHealthCheck(name, ok, since)
}
