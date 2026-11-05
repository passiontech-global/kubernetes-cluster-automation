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
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
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
	// Wave-10 probes live in cluster_health_wave10.go with their
	// constants declared there.
	checkNameFluxHRRetries = "flux-helmrelease-retries"
	checkNamePerconaQuorum = "percona-cluster-quorum"
	// W8/W9 — the Wave-8/9 checks live in cluster_health_wave8.go;
	// their check-name constants are declared there alongside the code.
)

// C6 watchdog knobs — the KCM leader Lease name and the
// node_automation_kcm_workqueue_frozen{reason} label values.
const (
	kcmLeaseName         = "kube-controller-manager"
	kcmReasonDesiredZero = "daemonset_desired_zero"
	kcmReasonStaleGen    = "stale_observed_generation"
)

// W5.8 — operator-workqueue-watchdog knobs.
const (
	// operatorLeaseMaxAge bounds "still renewing": operator
	// leader-election renews every ~2s inside a ~15s duration, so a
	// renewTime older than 2m means the holder is GONE — a dead
	// operator, not a frozen one (pod-status checks cover that
	// failure class).
	operatorLeaseMaxAge = 2 * time.Minute
	// operatorHealCooldown bounds leader-pod deletes to one per
	// operator per hour — the wider of the in-RAM ledger and the
	// persisted node.ops/last-operator-heal stamp on the Lease
	// (same wider-of-both shape as the helmrelease-unlocker).
	operatorHealCooldown = time.Hour
	// operatorHealAnno persists the last heal moment on the
	// operator's leader-election Lease — the restart-proof half of
	// the cooldown.
	operatorHealAnno = "node.ops/last-operator-heal"
	// ciliumStuckMinAge is the stuck window for the gateway-API
	// resources cilium-operator reconciles.
	ciliumStuckMinAge = 10 * time.Minute
	// operatorStuckMinAge is the default stuck window for the other
	// watched operators.
	operatorStuckMinAge = 20 * time.Minute
	// opReasonStaleGWStatus is the cilium signature: a gateway-API
	// object whose status.parents is empty/absent or whose
	// observedGeneration lags — the gateway controller never
	// attached it.
	opReasonStaleGWStatus = "stale_gateway_status"
	// ciliumGatewayController is the spec.controllerName a
	// GatewayClass carries when cilium's gateway-api controller
	// serves it — the ownership key for the gateway-API resources
	// in cilium-operator's target set.
	ciliumGatewayController = "io.cilium/gateway-controller"
	// opReasonNoConditions is the never-reconciled signature for CR
	// types that carry no observedGeneration — their controller
	// stamps status.conditions on the first reconcile pass, so an
	// absent/empty list means it never picked the object up (W7-C2).
	opReasonNoConditions = "no_status_conditions"
	// opReasonNoPhase is the same signature for CR types that report
	// a status.phase (argocd): an empty phase means the operator
	// never reconciled the object (W7-C2).
	opReasonNoPhase = "no_status_phase"
	// opReasonNoStatus is the medik8s variant: status.phase AND
	// status.conditions both absent — the operator never completed
	// a reconcile pass on either channel (W10-CP3).
	opReasonNoStatus = "no_status_at_all"
)

// W6.2 — stateful-masterless-services knobs.
const (
	// masterlessZeroMinAge: a master-role Service must report 0
	// Ready endpoints this long before the gauge fires.
	masterlessZeroMinAge = 3 * time.Minute
	// masterlessHealMinAge: the zero-endpoint streak must reach this
	// before the dragonfly-operator leader gets bounced (5m —
	// longer than the gauge so a flap doesn't kill the operator).
	masterlessHealMinAge  = 5 * time.Minute
	dragonflyHealCooldown = 30 * time.Minute
	// dragonflyOperatorNS/PodPrefix locate the operator pods the
	// heal deletes to force re-election.
	dragonflyOperatorNS        = "dragonfly-operator-system"
	dragonflyOperatorPodPrefix = "dragonfly-operator-controller-manager"
	// dragonflyHealAnno persists the last heal moment on the STS —
	// the restart-proof half of the cooldown.
	dragonflyHealAnno = "node.ops/last-dragonfly-operator-heal"

	// W7-C3 — dual-replica deadlock: past this zero-endpoint streak
	// the operator restart (step 1) demonstrably failed to re-elect
	// a master, so the STS ordinal-0 pod is deleted to force the
	// whole election from scratch.
	dragonflyReplicaDeadlockMinAge = 10 * time.Minute
	// dragonflyOperatorSettleMin bounds how fresh the operator heal
	// must be before the pod kill is allowed — step 1 needs a few
	// minutes to relabel the pods; deleting ordinal-0 while the new
	// operator is still reconciling reaps the pod pointlessly.
	dragonflyOperatorSettleMin = 3 * time.Minute
	// dragonflyPodHealCooldown bounds ordinal-0 pod deletes to one
	// per STS — wider of the in-RAM ledger and the persisted
	// node.ops/last-dragonfly-pod-heal stamp (same wider-of-both
	// shape as the operator heal above).
	dragonflyPodHealCooldown = 30 * time.Minute
	// dragonflyPodHealAnno persists the last ordinal-0 pod delete on
	// the STS — the restart-proof half of the cooldown.
	dragonflyPodHealAnno = "node.ops/last-dragonfly-pod-heal"
)

// W6.4 — rabbitmq-suspended-listener knobs.
const (
	rabbitComponentLabel  = "app.kubernetes.io/component=rabbitmq"
	rabbitSuspendedMinAge = 10 * time.Minute
	rabbitHealCooldown    = 30 * time.Minute
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

type clusterHealthProber struct {
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
	now        func() time.Time

	// lastPass tracks the last OK per check name for the
	// seconds_since_success gauge — seeded to boot time so a check
	// that never passed still reports a growing staleness, matching
	// kuberhealthy (which counts from check creation).
	mu       sync.Mutex
	lastPass map[string]time.Time

	// C6 watchdog state (under mu):
	//   - kcmFirstSeen: signature key "<reason>/<kind>/<name>" → the
	//     first sweep that observed it; a signature must persist
	//     kcmFreezeMinAge before the gauge fires. Pruned when the
	//     signature resolves — a later stall re-arms the window.
	//   - kcmFrozenReasons: reason labels currently held at 1, so a
	//     resolved signature flips its series back to 0 instead of
	//     leaking a stale 1 forever.
	kcmFirstSeen     map[string]time.Time
	kcmFrozenReasons map[string]bool

	// W5.8 watchdog state (under mu):
	//   - opFirstSeen: "operator/<gvr>/<ns>/<name>" → first sweep
	//     that saw the stuck signature; it must persist the
	//     operator's stuckMinAge before the gauge fires. Pruned when
	//     the object reconciles — a later stall re-arms the window.
	//   - opFrozen: "operator/reason" currently held at 1, so a
	//     resolved signature flips the series back to 0.
	//   - opHealed: operator → last leader-pod delete — the in-RAM
	//     half of the 1h heal cooldown (the Lease annotation is the
	//     durable half).
	opFirstSeen map[string]time.Time
	opFrozen    map[string]bool
	opHealed    map[string]time.Time

	// gwClassCtlr caches GatewayClass name → spec.controllerName for
	// ~a minute so the gateway-API ownership filter doesn't LIST the
	// class set once per stuck object (under mu).
	gwClassCtlr map[string]string
	gwClassAt   time.Time

	// W6.2 watchdog state (under mu):
	//   - stsZeroSince: "ns/svc/sts" → first sweep the master-role
	//     Service showed 0 Ready endpoints.
	//   - stsZeroEmitted: series ledger for
	//     StatefulServiceZeroEndpoints — a tuple not re-seen gets
	//     DeleteLabelValues, not a stale 1 (same hygiene as the
	//     webhook guard's brokenEmitted).
	//   - drHealed: operator pod "ns/name" → last delete — the
	//     in-RAM half of the 30m dragonfly heal cooldown (the STS
	//     annotation stamp is the durable half).
	//   - drPodHealed: "ns/sts" → last ordinal-0 pod delete — the
	//     in-RAM half of the 30m dual-replica-deadlock cooldown
	//     (W7-C3; the STS annotation is the durable half).
	stsZeroSince   map[string]time.Time
	stsZeroEmitted map[string]bool
	drHealed       map[string]time.Time
	drPodHealed    map[string]time.Time

	// W6.4 watchdog state (under mu):
	//   - rbSuspendedSince: "ns/pod/uid" → first sweep the pod
	//     showed the suspended-listener signature (uid in the key
	//     keeps a same-named replacement from inheriting the streak).
	//   - rbHealed: "ns/pod" → last delete — the 30m heal cooldown.
	rbSuspendedSince map[string]time.Time
	rbHealed         map[string]time.Time

	// W7-C4 watchdog state (under mu):
	//   - localPVEmitted: "ns/pod/pvc/node/reason" gauge tuples held
	//     at 1 — pruned via DeleteLabelValues when not re-seen (same
	//     hygiene as stsZeroEmitted).
	//   - pvcStalledEmitted: "ns/pvc/storageclass" gauge tuples held
	//     at 1 — same lifecycle.
	//   - localPVHealed: "ns/pvc" → last ephemeral-PVC heal — the
	//     30m cooldown (in-RAM: the PVC is deleted, nothing durable
	//     can carry the stamp).
	//   - pvcProvHealed: provisioner → last provisioner pod delete —
	//     the 1h cooldown.
	localPVEmitted    map[string]bool
	pvcStalledEmitted map[string]bool
	localPVHealed     map[string]time.Time
	pvcProvHealed     map[string]time.Time

	// W7-C5 watchdog state (under mu):
	//   - olmFirstSeen: "kind/ns/name/reason" → first sweep the
	//     unhealthy signature showed; it must persist
	//     olmUnhealthyMinAge before the gauge fires (>= olmHealMinAge
	//     for the CSV-triggered operator heal). Pruned on resolve.
	//   - olmEmitted: same keys held at gauge=1 — a tuple not
	//     re-seen gets DeleteLabelValues, not a stale 1.
	//   - olmHealed: reason → last olm-operator pod delete — the 1h
	//     cooldown (in-RAM: deleting the operator pod is the heal,
	//     nothing else can carry the stamp).
	olmFirstSeen map[string]time.Time
	olmEmitted   map[string]bool
	olmHealed    map[string]time.Time

	// W8 watchdog state (under mu):
	//   - meshHealed: component → last control-plane pod delete —
	//     the W8-NM2 cilium-operator (1h) and W8-NM3 linkerd (30m)
	//     cooldowns, plus the W4 db-operator masterless heals.
	meshHealed map[string]time.Time

	// W9-NM2 watchdog state (under mu):
	//   - linkerdDesyncSince: "ns/svc" → first sweep the headless
	//     Service's EndpointSlice diverged from its Ready pod IPs;
	//     pruned when the divergence resolves so a later desync
	//     re-arms the window.
	//   - linkerdDesyncEmitted: gauge tuples held at 1 — a tuple not
	//     re-seen gets DeleteLabelValues, not a stale 1.
	//   - linkerdDesyncHealed: "ns/svc" → last linkerd-destination
	//     bounce — the 1h per-service cooldown (in-RAM: the pod is
	//     the heal target, nothing else can carry the stamp).
	linkerdDesyncSince   map[string]time.Time
	linkerdDesyncEmitted map[string]bool
	linkerdDesyncHealed  map[string]time.Time

	// W9-ST1 watchdog state (under mu):
	//   - scyllaFirstSeen: "member/ns/svc" | "gossip/ns/pod/uid" →
	//     first sweep the signature showed; it must persist
	//     scyllaSignatureMinAge before the gauge fires (the
	//     degraded_condition reason carries its own clock — the CR
	//     condition's lastTransitionTime). Pruned on resolve.
	//   - scyllaEmitted: "ns/cluster/reason" gauge tuples held at 1 —
	//     same DeleteLabelValues hygiene as the other emitted sets.
	scyllaFirstSeen map[string]time.Time
	scyllaEmitted   map[string]bool

	// W10 watchdog state (under mu):
	//   - hrRetryHealed: "ns/name" → last reconcile-annotation patch —
	//     the 30m per-HelmRelease cooldown for the retries-exhausted
	//     remediator (W10-CP4). The requestedAt annotation we stamp is
	//     the durable half across restarts.
	//   - perconaInitSeen: "gvr/ns/name" → first sweep the Percona
	//     cluster read "initializing" — the 30m stuck-initializing
	//     window for checkPerconaClusterQuorum (W10-ST5). Pruned on
	//     resolve so a later re-init re-arms.
	hrRetryHealed   map[string]time.Time
	perconaInitSeen map[string]time.Time
}

func newClusterHealthProber(cs kubernetes.Interface, dyn dynamic.Interface, cfg healthProbeConfig) *clusterHealthProber {
	boot := time.Now()
	return &clusterHealthProber{
		cs:         cs,
		dyn:        dyn,
		cfg:        cfg,
		lookupHost: (&net.Resolver{}).LookupHost,
		httpClient: &http.Client{},
		now:        time.Now,
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
		kcmFirstSeen:         map[string]time.Time{},
		kcmFrozenReasons:     map[string]bool{},
		opFirstSeen:          map[string]time.Time{},
		opFrozen:             map[string]bool{},
		opHealed:             map[string]time.Time{},
		stsZeroSince:         map[string]time.Time{},
		stsZeroEmitted:       map[string]bool{},
		drHealed:             map[string]time.Time{},
		drPodHealed:          map[string]time.Time{},
		rbSuspendedSince:     map[string]time.Time{},
		rbHealed:             map[string]time.Time{},
		localPVEmitted:       map[string]bool{},
		pvcStalledEmitted:    map[string]bool{},
		localPVHealed:        map[string]time.Time{},
		pvcProvHealed:        map[string]time.Time{},
		olmFirstSeen:         map[string]time.Time{},
		olmEmitted:           map[string]bool{},
		olmHealed:            map[string]time.Time{},
		meshHealed:           map[string]time.Time{},
		linkerdDesyncSince:   map[string]time.Time{},
		linkerdDesyncEmitted: map[string]bool{},
		linkerdDesyncHealed:  map[string]time.Time{},
		scyllaFirstSeen:      map[string]time.Time{},
		scyllaEmitted:        map[string]bool{},
		hrRetryHealed:        map[string]time.Time{},
		perconaInitSeen:      map[string]time.Time{},
	}
}

// Setup registers the 5-minute probe sweep. The
// kuberhealthy checks ran always-on, so the gate lives in
// CLUSTER_HEALTH_PROBES_ENABLED (default ON — explicit "false" opts
// out); disabled skips mgr.Add entirely, matching the
// cilium-taint-reaper pattern. dyn feeds the CRD scans inside the
// self-healing checks (W5.8/W6.2) — wired like every other
// dynamic-client module.
func Setup(mgr ctrl.Manager, cs kubernetes.Interface, dyn dynamic.Interface, enabled bool) error {
	if !enabled {
		logf.Log.WithName(clusterHealthQueue).Info("disabled — module not registered")
		return nil
	}
	p := newClusterHealthProber(cs, dyn, healthProbeConfigFromEnv())
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
	return shared.AddPeriodic(mgr, clusterHealthQueue, interval, p.run)
}

func (p *clusterHealthProber) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	checks := []struct {
		name  string
		probe func(ctx context.Context) probeResult
	}{
		{checkNameDNS, p.probeDNS},
		{checkNameHTTPContent, p.probeHTTPContent},
		{checkNamePodRestarts, p.probePodRestarts},
		{checkNamePodStatus, p.probePodStatus},
		{checkNameResourceQuota, p.probeResourceQuota},
		{checkNameKCMWorkqueue, p.checkKCMWorkqueue},
		{checkNameOperatorWorkqueue, p.checkOperatorWorkqueues},
		{checkNameStatefulMasterless, p.checkStatefulMasterlessServices},
		{checkNameRabbitMQSuspended, p.checkRabbitMQSuspendedPods},
		{checkNameLocalPVStranded, p.checkLocalPVStrandedPods},
		{checkNameOLMHealth, p.checkOLMHealth},
		{checkNameSchedulerWatchdog, p.checkSchedulerFrozen},
		{checkNameMeshWatchdog, p.checkMeshControlPlane},
		{checkNameNodeHang, p.checkNodeHangPreCordon},
		{checkNameLinkerdEndpointSync, p.checkLinkerdEndpointSync},
		{checkNameScyllaHealth, p.checkScyllaHealth},
		{checkNameFluxHRRetries, p.checkFluxHelmReleaseRetries},
		{checkNamePerconaQuorum, p.checkPerconaClusterQuorum},
		{checkNameCiliumBPFMapPressure, p.checkCiliumBPFMapPressure},
		{checkNameLinkerdOpaqueStall, p.checkLinkerdProtocolDetectionStall},
		{checkNameCoreDNSUpstream, p.checkCoreDNSUpstream},
		{checkNameCiliumNodeIPAM, p.checkCiliumNodeIPAMExhaustion},
		{checkNameNamespaceWedged, p.checkNamespaceTerminatingWedged},
		{checkNameArgoCDAppStuck, p.checkArgoCDAppStuck},
		{checkNameRabbitMQQuorum, p.checkRabbitMQQuorumHealth},
		{checkNameDragonflySyncStorm, p.checkDragonflyReplicaSyncStorm},
		{checkNameImagePullStorm, p.checkImagePullStorm},
	}
	for _, c := range checks {
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

// probeDNS ports dns-resolution-check: every configured hostname must
// resolve. Per-check timeout comes from HEALTH_CHECK_TIMEOUT (the
// checker pod's TIMEOUT_DURATION was 30s).
func (p *clusterHealthProber) probeDNS(ctx context.Context) probeResult {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.checkTimeout)
	defer cancel()
	for _, host := range p.cfg.dnsHostnames {
		if _, err := p.lookupHost(ctx, host); err != nil {
			return probeResult{why: fmt.Sprintf("lookup %s: %v", host, err)}
		}
	}
	return probeResult{pass: true}
}

// probeHTTPContent ports http-content-check: GET must return 200 and
// a body containing the expected string (live check: prometheus
// /-/healthy answers "Prometheus Server is Healthy.", expected
// substring "Healthy").
func (p *clusterHealthProber) probeHTTPContent(ctx context.Context) probeResult {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.checkTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.httpURL, nil)
	if err != nil {
		return probeResult{why: fmt.Sprintf("build request: %v", err)}
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return probeResult{why: fmt.Sprintf("GET %s: %v", p.cfg.httpURL, err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return probeResult{why: fmt.Sprintf("GET %s: status %d, want 200",
			p.cfg.httpURL, resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return probeResult{why: fmt.Sprintf("read body: %v", err)}
	}
	if !strings.Contains(string(body), p.cfg.httpExpectedContent) {
		return probeResult{why: fmt.Sprintf("body missing %q",
			p.cfg.httpExpectedContent)}
	}
	return probeResult{pass: true}
}

// probePodRestarts ports pod-restarts-check: FAIL when any container
// status — app, init or ephemeral — in the target namespace has
// RestartCount over the limit (live check: kube-system, 10) AND the
// restarts are still live signal (W10-FIX5): a container that crossed
// the threshold weeks ago and has been stable since must not hold the
// check red forever — RestartCount is monotonic, so the raw count
// alone can never recover.
func (p *clusterHealthProber) probePodRestarts(ctx context.Context) probeResult {
	pods, err := p.cs.CoreV1().Pods(p.cfg.podCheckNamespace).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list pods in %s: %w",
			p.cfg.podCheckNamespace, err)}
	}
	now := p.now()
	var offenders []string
	for i := range pods.Items {
		pod := &pods.Items[i]
		for _, statuses := range [][]corev1.ContainerStatus{
			pod.Status.InitContainerStatuses,
			pod.Status.ContainerStatuses,
			pod.Status.EphemeralContainerStatuses,
		} {
			for _, s := range statuses {
				if s.RestartCount > p.cfg.maxPodRestarts &&
					restartRecentlyActive(s, now) {
					offenders = append(offenders,
						fmt.Sprintf("%s/%s=%d", pod.Name, s.Name, s.RestartCount))
				}
			}
		}
	}
	if len(offenders) > 0 {
		return probeResult{why: fmt.Sprintf("restarts>%d: %s",
			p.cfg.maxPodRestarts, strings.Join(offenders, ", "))}
	}
	return probeResult{pass: true}
}

// podRestartRecentWindow bounds how far back the last termination may
// sit before an over-threshold RestartCount reads as historical rather
// than live (W10-FIX5).
const podRestartRecentWindow = 24 * time.Hour

// restartRecentlyActive reports whether an over-threshold restart
// count still represents an ACTIVE failure: the last termination
// finished inside podRestartRecentWindow, or the container is
// currently Waiting (CrashLoopBackOff and friends — the kubelet only
// reports Waiting while the restart loop is live). A container that
// crossed the threshold and has run clean since reports neither and
// is ignored.
func restartRecentlyActive(s corev1.ContainerStatus, now time.Time) bool {
	if t := s.LastTerminationState.Terminated; t != nil &&
		!t.FinishedAt.IsZero() &&
		now.Sub(t.FinishedAt.Time) < podRestartRecentWindow {
		return true
	}
	return s.State.Waiting != nil
}

// probePodStatus ports pod-status-check: pods younger than
// SKIP_DURATION are ignored (fresh pods legitimately sit Pending while
// images pull); any older pod whose Phase is not Running or Succeeded
// is a FAIL (Failed/Unknown/stuck Pending).
func (p *clusterHealthProber) probePodStatus(ctx context.Context) probeResult {
	pods, err := p.cs.CoreV1().Pods(p.cfg.podCheckNamespace).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list pods in %s: %w",
			p.cfg.podCheckNamespace, err)}
	}
	var bad []string
	for i := range pods.Items {
		pod := &pods.Items[i]
		if p.now().Sub(pod.CreationTimestamp.Time) < p.cfg.podSkipDuration {
			continue // too young — still allowed to be Pending
		}
		if pod.Status.Phase != corev1.PodRunning &&
			pod.Status.Phase != corev1.PodSucceeded {
			bad = append(bad, fmt.Sprintf("%s=%s", pod.Name, pod.Status.Phase))
		}
	}
	if len(bad) > 0 {
		return probeResult{why: fmt.Sprintf("non-Running pods in %s: %s",
			p.cfg.podCheckNamespace, strings.Join(bad, ", "))}
	}
	return probeResult{pass: true}
}

// probeResourceQuota ports resource-quota-check: FAIL when any quota
// resource's used/hard ratio exceeds the threshold (live check:
// THRESHOLD=0.9 — strictly greater, so exactly-at-threshold passes).
// A resource absent from Status.Used counts as 0.
func (p *clusterHealthProber) probeResourceQuota(ctx context.Context) probeResult {
	quotas, err := p.cs.CoreV1().ResourceQuotas(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list resourcequotas: %w", err)}
	}
	var over []string
	for i := range quotas.Items {
		q := &quotas.Items[i]
		for name, hard := range q.Status.Hard {
			used, ok := q.Status.Used[name]
			if !ok {
				continue // no usage recorded — 0/hard is a pass
			}
			// hard=0 + used>0 divides to +Inf -> over; 0/0 is NaN
			// which compares false -> pass. Only `>` fails: exactly
			// at threshold is still a pass.
			ratio := used.AsApproximateFloat64() / hard.AsApproximateFloat64()
			if ratio > p.cfg.quotaThreshold {
				over = append(over, fmt.Sprintf("%s/%s %s=%s/%s",
					q.Namespace, q.Name, name, used.String(), hard.String()))
			}
		}
	}
	if len(over) > 0 {
		return probeResult{why: fmt.Sprintf("quota used/hard>%.2g: %s",
			p.cfg.quotaThreshold, strings.Join(over, ", "))}
	}
	return probeResult{pass: true}
}

// ---------------------------------------------------------------------------
// kcm-workqueue-watchdog (C6)
// ---------------------------------------------------------------------------

// checkKCMWorkqueue detects a kube-controller-manager workqueue
// freeze: the leader still renews its coordination.k8s.io Lease but
// the object controllers stop reconciling — a "gray" failure where
// /healthz and the leader lock stay green while cluster objects go
// stale (the incident class behind this watchdog).
//
// Preconditions, quiet on miss — the frozen-but-leader case is the
// ONLY thing this check flags:
//   - at least one Ready Node (the storm gate: with no Ready node a
//     desiredNumberScheduled==0 reading is ambiguous, and a dead
//     cluster is covered by other checks);
//   - the kube-system/kube-controller-manager Lease is still renewing
//     (renewTime no older than kcmLeaseMaxAge — KCM leader-election
//     renews every ~2s inside a 15s LeaseDuration). A stale or absent
//     Lease means the holder is GONE: a dead KCM is a different
//     failure pod-status/dead-node checks already cover, and flagging
//     it here would double-alert the wrong diagnosis.
//
// Freeze signatures (kube-system objects), each required to persist
// continuously for kcmFreezeMinAge via a per-object first-seen map:
//   - daemonset_desired_zero: a DaemonSet reports
//     status.desiredNumberScheduled==0 while pods are still
//     scheduled/ready — the DS controller stopped recomputing desired
//     from live nodes. desired==0 with zero pods anywhere is a
//     legitimately-empty selector, not a freeze, so it is excluded.
//   - stale_observed_generation: a Deployment or DaemonSet whose
//     status.observedGeneration lags metadata.generation — its
//     controller never processed the last spec write.
//
// On freeze the dedicated gauge
// node_automation_kcm_workqueue_frozen{reason} goes to 1; it flips
// back to 0 when the signature resolves (or when the preconditions
// stop holding — resetKCMWorkqueue re-arms tracking from scratch).
func (p *clusterHealthProber) checkKCMWorkqueue(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()

	nodes, err := shared.ListNodes(ctx, p.cs)
	if err != nil {
		return probeResult{infra: fmt.Errorf("list nodes: %w", err)}
	}
	ready := false
	for i := range nodes {
		if shared.NodeReady(&nodes[i]) {
			ready = true
			break
		}
	}
	if !ready {
		p.resetKCMWorkqueue()
		return probeResult{pass: true}
	}

	lease, err := p.cs.CoordinationV1().Leases(metav1.NamespaceSystem).
		Get(ctx, kcmLeaseName, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		// No leader Lease at all — no elected KCM to judge.
		p.resetKCMWorkqueue()
		return probeResult{pass: true}
	case err != nil:
		return probeResult{infra: fmt.Errorf("get lease %s/%s: %w",
			metav1.NamespaceSystem, kcmLeaseName, err)}
	case lease.Spec.RenewTime == nil ||
		now.Sub(lease.Spec.RenewTime.Time) > p.cfg.kcmLeaseMaxAge:
		// Stale renewTime = the holder is gone — a dead KCM, not a
		// frozen one. Stay quiet.
		p.resetKCMWorkqueue()
		return probeResult{pass: true}
	}

	dss, err := p.cs.AppsV1().DaemonSets(metav1.NamespaceSystem).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list daemonsets in %s: %w",
			metav1.NamespaceSystem, err)}
	}
	deps, err := p.cs.AppsV1().Deployments(metav1.NamespaceSystem).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list deployments in %s: %w",
			metav1.NamespaceSystem, err)}
	}

	// Candidate signatures keyed "<reason>/<kind>/<name>" so each
	// object's persistence window is tracked independently.
	sigs := map[string]string{}
	for i := range dss.Items {
		ds := &dss.Items[i]
		if ds.Status.DesiredNumberScheduled == 0 &&
			(ds.Status.CurrentNumberScheduled+
				ds.Status.UpdatedNumberScheduled+
				ds.Status.NumberReady+
				ds.Status.NumberMisscheduled) > 0 {
			sigs[kcmReasonDesiredZero+"/daemonset/"+ds.Name] = kcmReasonDesiredZero
		}
		if ds.Status.ObservedGeneration < ds.Generation {
			sigs[kcmReasonStaleGen+"/daemonset/"+ds.Name] = kcmReasonStaleGen
		}
	}
	for i := range deps.Items {
		dep := &deps.Items[i]
		if dep.Status.ObservedGeneration < dep.Generation {
			sigs[kcmReasonStaleGen+"/deployment/"+dep.Name] = kcmReasonStaleGen
		}
	}

	p.mu.Lock()
	frozen := map[string]bool{}
	for sig, reason := range sigs {
		if _, ok := p.kcmFirstSeen[sig]; !ok {
			p.kcmFirstSeen[sig] = now
			log.Info("KCM freeze signature — tracking first-seen",
				"signature", sig)
			continue
		}
		if now.Sub(p.kcmFirstSeen[sig]) >= p.cfg.kcmFreezeMinAge {
			frozen[reason] = true
		}
	}
	for sig := range p.kcmFirstSeen {
		if _, ok := sigs[sig]; !ok {
			delete(p.kcmFirstSeen, sig)
		}
	}
	for reason := range p.kcmFrozenReasons {
		if !frozen[reason] {
			metrics.KCMWorkqueueFrozen.WithLabelValues(reason).Set(0)
			delete(p.kcmFrozenReasons, reason)
		}
	}
	for reason := range frozen {
		metrics.KCMWorkqueueFrozen.WithLabelValues(reason).Set(1)
		p.kcmFrozenReasons[reason] = true
	}
	p.mu.Unlock()

	if len(frozen) == 0 {
		return probeResult{pass: true}
	}
	reasons := make([]string, 0, len(frozen))
	for r := range frozen {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	return probeResult{why: fmt.Sprintf(
		"KCM lease renews but kube-system objects unreconciled >=%s: %s",
		p.cfg.kcmFreezeMinAge, strings.Join(reasons, ", "))}
}

// resetKCMWorkqueue clears freeze tracking and drops any held gauge —
// called when the frozen-but-leader diagnosis cannot apply (no Ready
// nodes, absent/stale KCM Lease) so a signature that flaps around a
// precondition edge re-arms its persistence window from scratch.
func (p *clusterHealthProber) resetKCMWorkqueue() {
	p.mu.Lock()
	defer p.mu.Unlock()
	clear(p.kcmFirstSeen)
	for reason := range p.kcmFrozenReasons {
		metrics.KCMWorkqueueFrozen.WithLabelValues(reason).Set(0)
		delete(p.kcmFrozenReasons, reason)
	}
}

// ---------------------------------------------------------------------------
// operator-workqueue-watchdog (W5.8) — lease-holding zombie detector
// + auto-healer.
// ---------------------------------------------------------------------------

// opStuckResource binds a watched CRD GVR to its stall signature: the
// reason label reported on OperatorWorkqueueFrozen and the predicate
// deciding whether one object counts as unreconciled. owns optionally
// filters stuck objects down to those this operator is actually
// responsible for — required on resource types shared by several
// controllers (gateway-api objects on this cluster split between
// cilium-operator and the cloudflare-tunnel gateway controller, so a
// stuck route must not be blamed on — or healed by — the wrong
// operator). Nil means every stuck object counts.
type opStuckResource struct {
	gvr    schema.GroupVersionResource
	reason string
	stuck  func(o *unstructured.Unstructured) bool
	owns   func(ctx context.Context, p *clusterHealthProber, o *unstructured.Unstructured) bool
}

// operatorTarget is one watched operator: the leader-election Lease
// proving liveness, the pod label selector resolving the holder to a
// pod when holderIdentity parsing fails, the stuck persistence window
// and the CRD resources it is responsible for reconciling. A nil
// opStuckResource.owns means every stuck object counts.
//
// leaseNames lists every leader-election Lease id the operator may
// hold — upstream ships more than one across versions (Percona
// operators rotate their election ids, medik8s uses a fixed hash),
// so a single hardcoded name would silently disable the watch on the
// others. The first existing candidate wins.
//
// podNS overrides the namespace pods are looked up in when it differs
// from the Lease's namespace — the cert-manager chart elects leaders
// in kube-system while its pods live in cert-manager (W10-FIX2).
//
// leaseOptional marks operators that legitimately run without a
// leader-election Lease (external-secrets runs replicas:1 with
// leaderElect:false, dragonfly-operator has --leader-elect patched
// out — W10-FIX2): when no candidate Lease is found the watchdog
// falls back to a Running pod matching podSelector as the liveness
// proof — a live pod whose CRs still sit unreconciled is the same
// zombie shape the Lease renewTime proves for electing operators.
type operatorTarget struct {
	name          string
	leaseNS       string
	leaseNames    []string
	podNS         string
	podSelector   string
	leaseOptional bool
	stuckMinAge   time.Duration
	resources     []opStuckResource
}

// targetPodNS resolves the namespace operator pods live in: the
// explicit podNS override when set (lease and pods split across
// namespaces), else the Lease's own namespace.
func targetPodNS(t operatorTarget) string {
	if t.podNS != "" {
		return t.podNS
	}
	return t.leaseNS
}

// staleObservedGeneration is the canonical "controller never saw the
// last spec write" signature: status.observedGeneration lags
// metadata.generation. A missing observedGeneration reads as 0 — an
// object never touched by its controller is the strongest stuck
// signal there is (generation >= 1 for any real object).
func staleObservedGeneration(o *unstructured.Unstructured) bool {
	og, _, _ := unstructured.NestedInt64(o.Object, "status", "observedGeneration")
	return og < o.GetGeneration()
}

// fluxUnsuspendedStaleGen is staleObservedGeneration with the flux
// parking brake honored: a spec.suspend=true object is deliberately
// not reconciled — suspended work is parked, not stuck.
func fluxUnsuspendedStaleGen(o *unstructured.Unstructured) bool {
	if suspended, _, _ := unstructured.NestedBool(o.Object, "spec", "suspend"); suspended {
		return false
	}
	return staleObservedGeneration(o)
}

// helmRepoStaleGen is fluxUnsuspendedStaleGen plus the type=oci
// carve-out: since Flux v2.2 an OCI HelmRepository is a static
// reference — source-controller keeps no reconciler for it and never
// writes status, so observedGeneration stays absent forever and the
// generic signature would flag every healthy OCI repo (the actual
// OCI pull health lives on the generated HelmChart objects, which
// ARE watched by the helmcharts entry).
func helmRepoStaleGen(o *unstructured.Unstructured) bool {
	if t, _, _ := unstructured.NestedString(o.Object, "spec", "type"); t == "oci" {
		return false
	}
	return fluxUnsuspendedStaleGen(o)
}

// noStatusConditions is the "never reconciled" signature for CR
// types that lack a reliable observedGeneration (cert-manager
// Certificates, ExternalSecrets, KEDA ScaledObjects): the controller
// stamps status.conditions on its first reconcile pass, so an absent
// or empty list means it never picked the object up (W7-C2).
func noStatusConditions(o *unstructured.Unstructured) bool {
	conds, found, _ := unstructured.NestedSlice(o.Object, "status", "conditions")
	return !found || len(conds) == 0
}

// emptyStatusPhase is the same never-reconciled signature for CR
// types that report a status.phase (ArgoCD): an absent/empty phase
// means the operator never touched the object (W7-C2).
func emptyStatusPhase(o *unstructured.Unstructured) bool {
	phase, found, _ := unstructured.NestedString(o.Object, "status", "phase")
	return !found || phase == ""
}

// noStatusAtAll is the never-reconciled signature for CR types whose
// controllers write SPARSE status (medik8s NodeHealthCheck/
// SelfNodeRemediation): neither status.phase nor status.conditions
// means the operator never completed a reconcile pass. Either field
// alone can be legitimately absent on a healthy object — a paused
// NHC still carries phase=Paused, a finished SNR keeps its last
// phase — so only the both-absent shape proves "never reconciled".
func noStatusAtAll(o *unstructured.Unstructured) bool {
	if phase, found, _ := unstructured.NestedString(o.Object, "status", "phase"); found && phase != "" {
		return false
	}
	conds, found, _ := unstructured.NestedSlice(o.Object, "status", "conditions")
	return !found || len(conds) == 0
}

// perconaUnpausedStaleGen is staleObservedGeneration with the Percona
// pause brake honored: spec.pause=true (and psmdb's spec.mode=paused)
// parks reconciliation deliberately — paused clusters are parked,
// not stuck (W10-CP3).
func perconaUnpausedStaleGen(o *unstructured.Unstructured) bool {
	if paused, _, _ := unstructured.NestedBool(o.Object, "spec", "pause"); paused {
		return false
	}
	if mode, _, _ := unstructured.NestedString(o.Object, "spec", "mode"); mode == "paused" {
		return false
	}
	return staleObservedGeneration(o)
}

// condMaxObservedGeneration returns the largest observedGeneration
// carried inside a conditions list. Gateway-API resources report the
// generation their controller last processed inside each condition —
// there is no top-level status.observedGeneration on
// Gateway/HTTPRoute/GRPCRoute — so 0 means the attached controller
// has never reported a spec generation.
func condMaxObservedGeneration(conds []any) int64 {
	var max int64
	for _, c := range conds {
		m, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if og, _, _ := unstructured.NestedInt64(m, "observedGeneration"); og > max {
			max = og
		}
	}
	return max
}

// gatewayStatusStuck is the cilium-operator signature on the
// gateway-API route resources its gateway controller reconciles: an
// object reporting no status.parents (the controller attaches a
// parent status when it programs the route), or one whose parents'
// conditions still report only older observedGenerations — the
// controller attached once but never saw the last spec write.
func gatewayStatusStuck(o *unstructured.Unstructured) bool {
	parents, found, _ := unstructured.NestedSlice(o.Object, "status", "parents")
	if !found || len(parents) == 0 {
		return true
	}
	var maxOG int64
	for _, pr := range parents {
		m, ok := pr.(map[string]any)
		if !ok {
			continue
		}
		conds, _, _ := unstructured.NestedSlice(m, "conditions")
		if og := condMaxObservedGeneration(conds); og > maxOG {
			maxOG = og
		}
	}
	return maxOG < o.GetGeneration()
}

// gatewayObjectStuck is the same signature for the Gateway kind
// itself: Gateways carry status.listeners, not status.parents — the
// route predicate would flag every healthy Gateway forever. A
// programmed Gateway reports one status.listeners entry per
// spec.listeners entry; a spec with listeners but an empty/absent
// status.listeners means the controller never programmed it.
// Generation lag is judged from the conditions' observedGeneration
// (top-level status.conditions plus per-listener conditions) —
// Gateway status has no top-level observedGeneration field.
func gatewayObjectStuck(o *unstructured.Unstructured) bool {
	spec, found, _ := unstructured.NestedSlice(o.Object, "spec", "listeners")
	if !found || len(spec) == 0 {
		return false
	}
	status, found, _ := unstructured.NestedSlice(o.Object, "status", "listeners")
	if !found || len(status) == 0 {
		return true
	}
	var maxOG int64
	conds, _, _ := unstructured.NestedSlice(o.Object, "status", "conditions")
	maxOG = condMaxObservedGeneration(conds)
	for _, l := range status {
		m, ok := l.(map[string]any)
		if !ok {
			continue
		}
		conds, _, _ := unstructured.NestedSlice(m, "conditions")
		if og := condMaxObservedGeneration(conds); og > maxOG {
			maxOG = og
		}
	}
	return maxOG < o.GetGeneration()
}

// gatewayClassStuck is the signature for the GatewayClass kind
// itself: the class carries no top-level status.observedGeneration —
// the serving controller reports the last reconciled generation only
// inside status.conditions[type=Accepted].observedGeneration. No
// conditions, or none of them an Accepted entry, means the class was
// never picked up; an Accepted observedGeneration lagging
// metadata.generation means the last spec write was never seen. The
// Accepted status value (True/False) is irrelevant — a fresh
// rejection still proves the controller read the object.
func gatewayClassStuck(o *unstructured.Unstructured) bool {
	conds, found, _ := unstructured.NestedSlice(o.Object, "status", "conditions")
	if !found || len(conds) == 0 {
		return true
	}
	for _, c := range conds {
		m, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if t, _, _ := unstructured.NestedString(m, "type"); t != "Accepted" {
			continue
		}
		og, _, _ := unstructured.NestedInt64(m, "observedGeneration")
		return og < o.GetGeneration()
	}
	return true
}

// gatewayClassController resolves a GatewayClass name to its
// spec.controllerName, caching the class set for a minute so a
// stuck-object sweep doesn't LIST per object. ok=false means the
// class set is unavailable or the class is unknown — callers treat
// that as "cannot disprove ownership" and keep the object.
func (p *clusterHealthProber) gatewayClassController(ctx context.Context, class string) (string, bool) {
	p.mu.Lock()
	cached, at := p.gwClassCtlr, p.gwClassAt
	p.mu.Unlock()
	if cached == nil || p.now().Sub(at) > time.Minute {
		list, err := p.dyn.Resource(gwv1("gatewayclasses")).
			List(ctx, metav1.ListOptions{})
		if err != nil {
			return "", false
		}
		m := map[string]string{}
		for i := range list.Items {
			ctlr, _, _ := unstructured.NestedString(
				list.Items[i].Object, "spec", "controllerName")
			m[list.Items[i].GetName()] = ctlr
		}
		p.mu.Lock()
		p.gwClassCtlr, p.gwClassAt = m, p.now()
		p.mu.Unlock()
		cached = m
	}
	ctlr, ok := cached[class]
	return ctlr, ok
}

// ciliumOwnsGatewayObject is the ownership filter for the Gateways
// resource: only a Gateway whose class is served by cilium's gateway
// controller belongs in cilium-operator's stuck set. Unresolvable
// class data keeps the object — a Gateway whose class cannot be
// attributed is still worth flagging under the cluster's gateway-API
// watcher.
func ciliumOwnsGatewayObject(ctx context.Context, p *clusterHealthProber,
	o *unstructured.Unstructured) bool {
	class, _, _ := unstructured.NestedString(o.Object, "spec", "gatewayClassName")
	ctlr, ok := p.gatewayClassController(ctx, class)
	if !ok {
		return true
	}
	return ctlr == ciliumGatewayController
}

// ciliumOwnsGatewayClass attributes a GatewayClass to cilium
// directly — spec.controllerName sits on the object itself, so no
// lookup is needed. An absent controllerName keeps the object (a
// malformed class cannot disprove ownership, same rule as the other
// gateway-API filters); a PROVEN foreign controller drops it.
func ciliumOwnsGatewayClass(_ context.Context, _ *clusterHealthProber,
	o *unstructured.Unstructured) bool {
	ctlr, _, _ := unstructured.NestedString(o.Object, "spec", "controllerName")
	return ctlr == "" || ctlr == ciliumGatewayController
}

// ciliumOwnsRouteParent is the same filter for the route kinds: it
// resolves each spec.parentRefs[] entry to its Gateway and reports
// whether any parent's class is cilium's. Objects with no Gateway
// parents, or parents that fail to resolve, stay in the stuck set —
// an unattributable route is still a gateway-API-plane problem —
// while a route provably owned by another gateway controller is
// that controller's problem, not cilium-operator's.
func ciliumOwnsRouteParent(ctx context.Context, p *clusterHealthProber,
	o *unstructured.Unstructured) bool {
	refs, found, _ := unstructured.NestedSlice(o.Object, "spec", "parentRefs")
	if !found || len(refs) == 0 {
		return true
	}
	resolved := false
	for _, ref := range refs {
		m, ok := ref.(map[string]any)
		if !ok {
			continue
		}
		if k, _, _ := unstructured.NestedString(m, "kind"); k != "" && k != "Gateway" {
			continue
		}
		if g, _, _ := unstructured.NestedString(m, "group"); g != "" && g != "gateway.networking.k8s.io" {
			continue
		}
		name, _, _ := unstructured.NestedString(m, "name")
		if name == "" {
			continue
		}
		ns, _, _ := unstructured.NestedString(m, "namespace")
		if ns == "" {
			ns = o.GetNamespace()
		}
		gw, err := p.dyn.Resource(gwv1("gateways")).Namespace(ns).
			Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			continue
		}
		class, _, _ := unstructured.NestedString(gw.Object, "spec", "gatewayClassName")
		ctlr, ok := p.gatewayClassController(ctx, class)
		if !ok {
			continue
		}
		resolved = true
		if ctlr == ciliumGatewayController {
			return true
		}
	}
	return !resolved
}

// gwv1 is the gateway.networking.k8s.io/v1 group shared by the three
// resources the cilium signature scans.
func gwv1(resource string) schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group: "gateway.networking.k8s.io", Version: "v1", Resource: resource}
}

var operatorTargets = []operatorTarget{
	{
		name:        "cilium-operator",
		leaseNS:     "kube-system",
		leaseNames:  []string{"cilium-operator-resource-lock"},
		podSelector: "io.cilium/app=operator",
		stuckMinAge: ciliumStuckMinAge,
		resources: []opStuckResource{
			// GatewayClass has no top-level status.observedGeneration
			// — the serving controller stamps the reconciled
			// generation inside conditions[type=Accepted] only.
			{gvr: gwv1("gatewayclasses"), reason: opReasonStaleGWStatus,
				stuck: gatewayClassStuck, owns: ciliumOwnsGatewayClass},
			{gvr: gwv1("gateways"), reason: opReasonStaleGWStatus,
				stuck: gatewayObjectStuck, owns: ciliumOwnsGatewayObject},
			{gvr: gwv1("httproutes"), reason: opReasonStaleGWStatus,
				stuck: gatewayStatusStuck, owns: ciliumOwnsRouteParent},
			{gvr: gwv1("grpcroutes"), reason: opReasonStaleGWStatus,
				stuck: gatewayStatusStuck, owns: ciliumOwnsRouteParent},
		},
	},
	{
		name:        "scylla-operator",
		leaseNS:     "scylla-operator",
		leaseNames:  []string{"scylla-operator-lock"},
		podSelector: "app.kubernetes.io/name=scylla-operator",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr: schema.GroupVersionResource{
				Group: "scylla.scylladb.com", Version: "v1", Resource: "scyllaclusters"},
			reason: kcmReasonStaleGen, stuck: staleObservedGeneration,
		}},
	},
	{
		name:          "dragonfly-operator",
		leaseNS:       dragonflyOperatorNS,
		leaseNames:    []string{"7898635c.dragonflydb.io"},
		podSelector:   "control-plane=controller-manager",
		leaseOptional: true,
		stuckMinAge:   operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr: schema.GroupVersionResource{
				Group: "dragonflydb.io", Version: "v1alpha1", Resource: "dragonflies"},
			reason: kcmReasonStaleGen, stuck: staleObservedGeneration,
		}},
	},
	{
		name:        "helm-controller",
		leaseNS:     "flux-system",
		leaseNames:  []string{"helm-controller-leader-election"},
		podSelector: "app=helm-controller",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr: schema.GroupVersionResource{
				Group: "helm.toolkit.fluxcd.io", Version: "v2", Resource: "helmreleases"},
			reason: kcmReasonStaleGen, stuck: fluxUnsuspendedStaleGen,
		}},
	},
	{
		name:        "kustomize-controller",
		leaseNS:     "flux-system",
		leaseNames:  []string{"kustomize-controller-leader-election"},
		podSelector: "app=kustomize-controller",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr: schema.GroupVersionResource{
				Group: "kustomize.toolkit.fluxcd.io", Version: "v1", Resource: "kustomizations"},
			reason: kcmReasonStaleGen, stuck: fluxUnsuspendedStaleGen,
		}},
	},
	// W7-C2 — the ten additional leader-electing operators: every one
	// a controller-runtime leader whose zombie-leader gray failure
	// would wedge a whole slice of the stack (gitops sources, cert
	// issuance, secret sync, autoscaling, stateful operands).
	{
		name:        "source-controller",
		leaseNS:     "flux-system",
		leaseNames:  []string{"source-controller-leader-election"},
		podSelector: "app=source-controller",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{
			{gvr: schema.GroupVersionResource{
				Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "gitrepositories"},
				reason: kcmReasonStaleGen, stuck: fluxUnsuspendedStaleGen},
			{gvr: schema.GroupVersionResource{
				Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "helmrepositories"},
				reason: kcmReasonStaleGen, stuck: helmRepoStaleGen},
			{gvr: schema.GroupVersionResource{
				Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "helmcharts"},
				reason: kcmReasonStaleGen, stuck: fluxUnsuspendedStaleGen},
			{gvr: schema.GroupVersionResource{
				Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "ocirepositories"},
				reason: kcmReasonStaleGen, stuck: fluxUnsuspendedStaleGen},
			{gvr: schema.GroupVersionResource{
				Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "buckets"},
				reason: kcmReasonStaleGen, stuck: fluxUnsuspendedStaleGen},
		},
	},
	// notification-controller is deliberately absent: its v1beta3
	// Alert/Provider/Receiver are static objects — the API version
	// dropped their reconcilers, so no controller ever writes
	// status.observedGeneration or conditions on them and every
	// stuck signature flags healthy objects forever (the
	// passiontech-k0s-nonprod false-positive incident 2026-11-04).
	// Liveness stays covered by the pod/lease watches elsewhere.
	{
		name: "cert-manager",
		// The cert-manager helm chart elects leaders in kube-system
		// (global.leaderElection.namespace default) — the lease does
		// NOT live in the release namespace.
		leaseNS:    "kube-system",
		leaseNames: []string{"cert-manager-controller"},
		// The chart elects in kube-system but runs its pods in the
		// release namespace — pod lookups must not scan kube-system
		// (W10-FIX2).
		podNS:       "cert-manager",
		podSelector: "app.kubernetes.io/name=cert-manager",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{
			{gvr: schema.GroupVersionResource{
				Group: "cert-manager.io", Version: "v1", Resource: "certificates"},
				reason: opReasonNoConditions, stuck: noStatusConditions},
			// BUG-C5 — the same GVR additionally watched for
			// observedGeneration lag: a Certificate the controller
			// DID once reconcile can still be skipped by every
			// later spec write.
			{gvr: schema.GroupVersionResource{
				Group: "cert-manager.io", Version: "v1", Resource: "certificates"},
				reason: kcmReasonStaleGen, stuck: staleObservedGeneration},
		},
	},
	{
		name:    "external-secrets",
		leaseNS: "external-secrets",
		// Helm-default lease id — the deployment runs leaderElect:
		// false today (single replica), so the leaseOptional pod
		// fallback carries the liveness proof until HA is switched
		// on. externalsecret-operator-leader-election is the
		// OLM-installed name, not the helm chart's.
		leaseNames:    []string{"external-secrets-controller"},
		podSelector:   "app.kubernetes.io/name=external-secrets",
		leaseOptional: true,
		stuckMinAge:   operatorStuckMinAge,
		resources: []opStuckResource{
			{gvr: schema.GroupVersionResource{
				Group: "external-secrets.io", Version: "v1", Resource: "externalsecrets"},
				reason: opReasonNoConditions, stuck: noStatusConditions},
			{gvr: schema.GroupVersionResource{
				Group: "external-secrets.io", Version: "v1", Resource: "externalsecrets"},
				reason: kcmReasonStaleGen, stuck: staleObservedGeneration},
			{gvr: schema.GroupVersionResource{
				Group: "external-secrets.io", Version: "v1beta1", Resource: "externalsecrets"},
				reason: opReasonNoConditions, stuck: noStatusConditions},
			{gvr: schema.GroupVersionResource{
				Group: "external-secrets.io", Version: "v1beta1", Resource: "externalsecrets"},
				reason: kcmReasonStaleGen, stuck: staleObservedGeneration},
		},
	},
	{
		name:        "rabbitmq-cluster-operator",
		leaseNS:     "operators",
		leaseNames:  []string{"9c433e27.rabbitmq.com"},
		podSelector: "app.kubernetes.io/name=rabbitmq-cluster-operator",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr: schema.GroupVersionResource{
				Group: "rabbitmq.com", Version: "v1beta1", Resource: "rabbitmqclusters"},
			reason: kcmReasonStaleGen, stuck: staleObservedGeneration,
		}},
	},
	{
		name:        "keda-operator",
		leaseNS:     "operators",
		leaseNames:  []string{"operator.keda.sh"},
		podSelector: "app=keda-operator",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{
			{gvr: schema.GroupVersionResource{
				Group: "keda.sh", Version: "v1alpha1", Resource: "scaledobjects"},
				reason: opReasonNoConditions, stuck: noStatusConditions},
			{gvr: schema.GroupVersionResource{
				Group: "keda.sh", Version: "v1alpha1", Resource: "scaledobjects"},
				reason: kcmReasonStaleGen, stuck: staleObservedGeneration},
		},
	},
	{
		name: "argocd-operator",
		// The OLM Subscription sits in argocd-operator-system (see
		// infrastructure/base/operators/argocd-operator.yaml) — OLM
		// places the CSV deployment AND the leader-election lease
		// there, and the manager pods carry the kubebuilder
		// control-plane label, not name=argocd-operator.
		leaseNS:     "argocd-operator-system",
		leaseNames:  []string{"b23f6029.argoproj.io"},
		podSelector: "control-plane=controller-manager",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{
			{gvr: schema.GroupVersionResource{
				Group: "argoproj.io", Version: "v1beta1", Resource: "argocds"},
				reason: opReasonNoPhase, stuck: emptyStatusPhase},
			{gvr: schema.GroupVersionResource{
				Group: "argoproj.io", Version: "v1beta1", Resource: "argocds"},
				reason: kcmReasonStaleGen, stuck: staleObservedGeneration},
		},
	},
	{
		name:        "kargo-controller",
		leaseNS:     "kargo",
		leaseNames:  []string{"kargo-controller"},
		podSelector: "app.kubernetes.io/name=kargo,app.kubernetes.io/component=controller",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{
			{gvr: schema.GroupVersionResource{
				Group: "kargo.akuity.io", Version: "v1alpha1", Resource: "stages"},
				reason: kcmReasonStaleGen, stuck: staleObservedGeneration},
			{gvr: schema.GroupVersionResource{
				Group: "kargo.akuity.io", Version: "v1alpha1", Resource: "warehouses"},
				reason: kcmReasonStaleGen, stuck: staleObservedGeneration},
		},
	},
	{
		name:        "everest-operator",
		leaseNS:     "everest-system",
		leaseNames:  []string{"a8916322.percona.com"},
		podSelector: "control-plane=controller-manager",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr: schema.GroupVersionResource{
				Group: "everest.percona.com", Version: "v1alpha1", Resource: "databaseclusters"},
			reason: kcmReasonStaleGen, stuck: staleObservedGeneration,
		}},
	},
	{
		name:        "shipwright-build-controller",
		leaseNS:     "shipwright-build",
		leaseNames:  []string{"shipwright-build-controller"},
		podSelector: "app.kubernetes.io/name=shipwright-build-controller",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr: schema.GroupVersionResource{
				Group: "shipwright.io", Version: "v1beta1", Resource: "builds"},
			reason: kcmReasonStaleGen, stuck: staleObservedGeneration,
		}},
	},

	// ------------------------------------------------------------------
	// W10-CP3 — the remaining operators whose stuck queues still gate
	// the self-healing path. Lease ids, namespaces, pod selectors and
	// CRD anchors were verified against the cluster's Flux manifests
	// and upstream kubebuilder scaffolds (medik8s election ids
	// e1f13584/547f6cb6.medik8s.io, fluent 45c4fdd2.fluent.io,
	// shipwright 01a9b2d1.shipwright.io); where upstream can
	// legitimately run without a Lease (single replica or
	// leader-elect patched out) leaseOptional lets the Running-pod
	// fallback carry the liveness proof.
	// ------------------------------------------------------------------
	{
		// flux notification-controller: the v1beta3
		// Alert/Provider/Receiver objects are STATIC user config —
		// the controller reconciles no status into them, so there
		// is no CR signature to watch (the watchdog entry exists so
		// the Lease liveness signal is still covered).
		name:        "notification-controller",
		leaseNS:     "flux-system",
		leaseNames:  []string{"notification-controller-leader-election"},
		podSelector: "app=notification-controller",
		stuckMinAge: operatorStuckMinAge,
	},
	{
		name:        "node-healthcheck-operator",
		leaseNS:     "operators",
		leaseNames:  []string{"e1f13584.medik8s.io"},
		podSelector: "app.kubernetes.io/name=node-healthcheck-operator",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr: schema.GroupVersionResource{
				Group: "remediation.medik8s.io", Version: "v1alpha1",
				Resource: "nodehealthchecks"},
			reason: opReasonNoStatus, stuck: noStatusAtAll,
		}},
	},
	{
		name:        "self-node-remediation-operator",
		leaseNS:     "operators",
		leaseNames:  []string{"547f6cb6.medik8s.io"},
		podSelector: "control-plane=controller-manager,self-node-remediation-operator",
		stuckMinAge: operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr: schema.GroupVersionResource{
				Group: "self-node-remediation.medik8s.io", Version: "v1alpha1",
				Resource: "selfnoderemediations"},
			reason: opReasonNoStatus, stuck: noStatusAtAll,
		}},
	},
	{
		// Percona DB operators are installed by the everest
		// dbNamespace (openeverest values dbNamespace.
		// namespaceOverride: everest) — NOT everest-system, which
		// only runs the everest server + DatabaseCluster CRs.
		// Each ships multiple election-id generations across
		// releases, so leaseNames carries every candidate and
		// leaseOptional lets the pod fallback cover a total id
		// rotation (W10-CP3).
		name:          "percona-xtradb-cluster-operator",
		leaseNS:       "everest",
		leaseNames:    []string{"90888d0c.percona.com", "percona-xtradb-cluster-operator-lock"},
		podSelector:   "app.kubernetes.io/name=percona-xtradb-cluster-operator",
		leaseOptional: true,
		stuckMinAge:   operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr: schema.GroupVersionResource{
				Group: "pxc.percona.com", Version: "v1",
				Resource: "perconaxtradbclusters"},
			reason: kcmReasonStaleGen, stuck: perconaUnpausedStaleGen,
		}},
	},
	{
		name:          "percona-postgresql-operator",
		leaseNS:       "everest",
		leaseNames:    []string{"pgo-controller-lease", "percona-postgresql-operator-lock"},
		podSelector:   "app.kubernetes.io/name=percona-postgresql-operator",
		leaseOptional: true,
		stuckMinAge:   operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr: schema.GroupVersionResource{
				Group: "pgv2.percona.com", Version: "v2",
				Resource: "perconapgclusters"},
			reason: kcmReasonStaleGen, stuck: perconaUnpausedStaleGen,
		}},
	},
	{
		name:          "percona-server-mongodb-operator",
		leaseNS:       "everest",
		leaseNames:    []string{"087f5a08.percona.com", "percona-server-mongodb-operator-lock"},
		podSelector:   "app.kubernetes.io/name=percona-server-mongodb-operator",
		leaseOptional: true,
		stuckMinAge:   operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr: schema.GroupVersionResource{
				Group: "psmdb.percona.com", Version: "v1",
				Resource: "perconaservermongodbs"},
			reason: kcmReasonStaleGen, stuck: perconaUnpausedStaleGen,
		}},
	},
	{
		// fluent-operator (fluent-system): every fluentbit.fluent.io
		// CRD ships an EMPTY status struct — there is no status
		// channel to fingerprint, so the entry exists purely for
		// lease/pod liveness parity with the other operators.
		name:          "fluent-operator",
		leaseNS:       "fluent-system",
		leaseNames:    []string{"fluent-operator-leader-election", "45c4fdd2.fluent.io"},
		podSelector:   "app.kubernetes.io/name=fluent-operator",
		leaseOptional: true,
		stuckMinAge:   operatorStuckMinAge,
	},
	{
		name:          "tekton-pipelines-controller",
		leaseNS:       "tekton-pipelines",
		leaseNames:    []string{"tekton-pipelines-controller.tkn-leader-election", "tekton-pipelines-controller.pipelinerun.00-of-01"},
		podSelector:   "app.kubernetes.io/component=controller,app.kubernetes.io/part-of=tekton-pipelines",
		leaseOptional: true,
		stuckMinAge:   operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr: schema.GroupVersionResource{
				Group: "tekton.dev", Version: "v1", Resource: "pipelineruns"},
			reason: opReasonNoConditions, stuck: noStatusConditions,
		}},
	},
	{
		name:          "shipwright-operator",
		leaseNS:       "operators",
		leaseNames:    []string{"01a9b2d1.shipwright.io"},
		podSelector:   "app=shipwright-operator,control-plane=controller-manager",
		leaseOptional: true,
		stuckMinAge:   operatorStuckMinAge,
		resources: []opStuckResource{{
			gvr: schema.GroupVersionResource{
				Group: "operator.shipwright.io", Version: "v1alpha1",
				Resource: "shipwrightbuilds"},
			reason: opReasonNoConditions, stuck: noStatusConditions,
		}},
	},
}

// checkOperatorWorkqueues detects a lease-holding zombie operator:
// the leader still renews its coordination.k8s.io Lease while its
// target CRs sit unreconciled — the C6 gray-failure shape, but for
// the third-party operators whose stuck queues the flux/gitops stack
// depends on. Quiet on miss in the same cases as the KCM watchdog:
// no Lease or a stale renewTime means the holder is gone (a dead
// operator is a different failure pod-status checks already cover).
//
// Dual mechanism per stuck operator:
//
//	a) AUTO-HEAL — past the stuck window and outside maintenance,
//	   healOperatorLeader resolves the holderIdentity to the leader
//	   pod and deletes it (1h cooldown, persisted on the Lease),
//	   forcing re-election onto a fresh replica.
//	b) ALERTING — OperatorWorkqueueFrozen{operator,reason}=1 stays
//	   set while the CRs remain unreconciled, so a PrometheusRule
//	   fires if healing did not unstick the queue.
func (p *clusterHealthProber) checkOperatorWorkqueues(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	// The CR scans and the maintenance mutex both need dyn — a
	// missing client is a wiring bug, not "no signal".
	if p.dyn == nil {
		return probeResult{infra: fmt.Errorf(
			"no dynamic client — operator workqueue check unverifiable")}
	}
	now := p.now()
	p.mu.Lock()
	if p.opFirstSeen == nil {
		p.opFirstSeen = map[string]time.Time{}
	}
	if p.opFrozen == nil {
		p.opFrozen = map[string]bool{}
	}
	if p.opHealed == nil {
		p.opHealed = map[string]time.Time{}
	}
	p.mu.Unlock()

	frozen := map[string]string{} // "operator/reason" → reason, for the why line
	var firstErr error
	for _, op := range operatorTargets {
		lease, lerr := p.operatorLease(ctx, op)
		switch {
		case lerr != nil:
			if firstErr == nil {
				firstErr = lerr
			}
			continue
		case lease == nil && op.leaseOptional:
			// No candidate Lease by design (replicas:1 or
			// leader-elect patched out) — a Running pod under the
			// selector is the liveness proof a renewing Lease
			// provides elsewhere. lease stays nil:
			// healOperatorLeader/leaderPods both tolerate it
			// (selector fallback, no stamp persist).
			alive, aerr := p.operatorPodRunning(ctx, op)
			switch {
			case aerr != nil:
				if firstErr == nil {
					firstErr = fmt.Errorf("list pods %s selector %q (%s): %w",
						targetPodNS(op), op.podSelector, op.name, aerr)
				}
				continue
			case !alive:
				p.resetOperator(op.name)
				continue
			}
		case lease == nil:
			// No leader Lease — no elected operator to judge.
			p.resetOperator(op.name)
			continue
		case lease.Spec.RenewTime == nil ||
			now.Sub(lease.Spec.RenewTime.Time) > operatorLeaseMaxAge:
			// Stale renewTime = the holder is gone — a dead
			// operator, not a frozen one. Stay quiet.
			p.resetOperator(op.name)
			continue
		}

		// Collect this operator's live stuck signatures — keyed
		// "operator/<gvr>/<ns>/<name>" so each object's persistence
		// window is tracked independently. The list cache shares
		// one List across the resource entries that watch the same
		// GVR for different signatures (no_status_conditions +
		// stale_observed_generation, BUG-C5).
		live := map[string]bool{}
		reasonsFrozen := map[string]bool{}
		evalFailed := false
		lists := map[schema.GroupVersionResource]*unstructured.UnstructuredList{}
		for _, res := range op.resources {
			list, listed := lists[res.gvr]
			if !listed {
				l, err := p.dyn.Resource(res.gvr).List(ctx, metav1.ListOptions{})
				switch {
				case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
					lists[res.gvr] = &unstructured.UnstructuredList{}
					list = lists[res.gvr]
				case err != nil:
					evalFailed = true
					if firstErr == nil {
						firstErr = fmt.Errorf("list %s (%s): %w",
							res.gvr.Resource, op.name, err)
					}
					lists[res.gvr] = &unstructured.UnstructuredList{}
					list = lists[res.gvr]
				default:
					lists[res.gvr] = l
					list = l
				}
			}
			for i := range list.Items {
				o := &list.Items[i]
				if !res.stuck(o) {
					continue
				}
				// Shared-resource types: skip objects provably owned
				// by a different controller so the signature — and
				// the heal — lands on the right operator only.
				if res.owns != nil && !res.owns(ctx, p, o) {
					continue
				}
				key := op.name + "/" + res.gvr.Resource + "/" +
					o.GetNamespace() + "/" + o.GetName()
				live[key] = true
				p.mu.Lock()
				first, ok := p.opFirstSeen[key]
				if !ok {
					p.opFirstSeen[key] = now
				}
				p.mu.Unlock()
				if !ok {
					log.Info("operator stuck signature — tracking first-seen",
						"operator", op.name, "resource", res.gvr.Resource,
						"object", o.GetNamespace()+"/"+o.GetName())
					continue
				}
				if now.Sub(first) >= op.stuckMinAge {
					reasonsFrozen[res.reason] = true
				}
			}
		}
		if evalFailed {
			// An incomplete scan must not prune first-seen nor
			// clear held series — leave this operator's state as-is.
			continue
		}

		p.mu.Lock()
		for k := range p.opFirstSeen {
			if strings.HasPrefix(k, op.name+"/") && !live[k] {
				delete(p.opFirstSeen, k)
			}
		}
		for k := range p.opFrozen {
			if !strings.HasPrefix(k, op.name+"/") {
				continue
			}
			if reasonsFrozen[strings.TrimPrefix(k, op.name+"/")] {
				continue
			}
			metrics.OperatorWorkqueueFrozen.WithLabelValues(
				op.name, strings.TrimPrefix(k, op.name+"/")).Set(0)
			delete(p.opFrozen, k)
		}
		for r := range reasonsFrozen {
			metrics.OperatorWorkqueueFrozen.WithLabelValues(op.name, r).Set(1)
			p.opFrozen[op.name+"/"+r] = true
			frozen[op.name+"/"+r] = r
		}
		p.mu.Unlock()

		if len(reasonsFrozen) > 0 {
			reasons := make([]string, 0, len(reasonsFrozen))
			for r := range reasonsFrozen {
				reasons = append(reasons, r)
			}
			sort.Strings(reasons)
			p.healOperatorLeader(ctx, log, op, lease, reasons, now)
		}
	}

	if len(frozen) == 0 {
		if firstErr != nil {
			return probeResult{infra: firstErr}
		}
		return probeResult{pass: true}
	}
	keys := make([]string, 0, len(frozen))
	for k := range frozen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return probeResult{infra: firstErr, why: fmt.Sprintf(
		"operator lease renews but target CRs unreconciled: %s",
		strings.Join(keys, ", "))}
}

// operatorLease fetches the operator's leader-election Lease,
// trying each candidate name in op.leaseNames order — upstream
// ships more than one election id across versions, so a single
// hardcoded name would silently disable the watch on the others.
// Returns (nil, nil) when every candidate is absent; a non-NotFound
// error on any candidate is returned (errors are per-request, not
// per-name — RBAC/network failures hit all names equally).
func (p *clusterHealthProber) operatorLease(ctx context.Context, op operatorTarget) (*coordinationv1.Lease, error) {
	var firstErr error
	for _, name := range op.leaseNames {
		lease, err := p.cs.CoordinationV1().Leases(op.leaseNS).
			Get(ctx, name, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			continue
		case err != nil:
			if firstErr == nil {
				firstErr = fmt.Errorf("get lease %s/%s (%s): %w",
					op.leaseNS, name, op.name, err)
			}
			continue
		default:
			return lease, nil
		}
	}
	return nil, firstErr
}

// operatorPodRunning is the leaseOptional liveness fallback: at
// least one pod in the operator's pod namespace matching podSelector
// is Running — a live pod whose CRs sit unreconciled is the same
// zombie signature a renewing-lease zombie leader presents.
func (p *clusterHealthProber) operatorPodRunning(ctx context.Context, op operatorTarget) (bool, error) {
	pods, err := p.cs.CoreV1().Pods(targetPodNS(op)).List(ctx,
		metav1.ListOptions{LabelSelector: op.podSelector})
	if err != nil {
		return false, err
	}
	for i := range pods.Items {
		if pods.Items[i].Status.Phase == corev1.PodRunning &&
			pods.Items[i].DeletionTimestamp == nil {
			return true, nil
		}
	}
	return false, nil
}

// resetOperator clears one operator's tracking and flips its held
// frozen series back to 0 — called when the frozen-but-leader
// diagnosis cannot apply (absent/stale Lease) so a signature that
// flaps around a precondition edge re-arms from scratch.
func (p *clusterHealthProber) resetOperator(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k := range p.opFirstSeen {
		if strings.HasPrefix(k, name+"/") {
			delete(p.opFirstSeen, k)
		}
	}
	for k := range p.opFrozen {
		if !strings.HasPrefix(k, name+"/") {
			continue
		}
		metrics.OperatorWorkqueueFrozen.WithLabelValues(
			name, strings.TrimPrefix(k, name+"/")).Set(0)
		delete(p.opFrozen, k)
	}
}

// healOperatorLeader deletes the stuck operator's leader pod to force
// re-election — the same unsticking nudge a manual
// `kubectl delete pod` applies. Gates, in order: the 1h cooldown
// (wider of in-RAM ledger and the persisted Lease stamp), the
// maintenance mutex (never kill a leader mid-drain/upgrade), and a
// resolvable leader pod (holderIdentity "<pod>_<uuid>" first, then
// the label selector in the Lease's namespace). Every guard refusal
// is quiet — the frozen gauge + FAIL series already carry the alert.
func (p *clusterHealthProber) healOperatorLeader(ctx context.Context, log logr.Logger,
	op operatorTarget, lease *coordinationv1.Lease, reasons []string, now time.Time) {

	p.mu.Lock()
	last, ok := p.opHealed[op.name]
	p.mu.Unlock()
	if ok && now.Sub(last) < operatorHealCooldown {
		log.Info("skip heal: operator inside cooldown", "operator", op.name,
			"ago", now.Sub(last).Truncate(time.Minute))
		return
	}
	if lease != nil {
		if ts := lease.Annotations[operatorHealAnno]; ts != "" {
			if t, err := time.Parse(time.RFC3339, ts); err == nil &&
				now.Sub(t) < operatorHealCooldown {
				log.Info("skip heal: persisted stamp inside cooldown",
					"operator", op.name,
					"ago", now.Sub(t).Truncate(time.Minute))
				return
			}
		}
	}
	// Maintenance mutex — "cannot verify" fails closed like every
	// other caller: an unverifiable drain state defers the heal.
	held, why, err := shared.MaintenanceActive(ctx, p.cs, p.dyn)
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: maintenance check unverifiable — heal deferred (fail closed)",
			"operator", op.name, "error", err)
		return
	}
	if held {
		log.Info("maintenance in progress — heal deferred",
			"operator", op.name, "why", why)
		return
	}

	pods, err := p.leaderPods(ctx, op, lease)
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: leader pod resolution failed — heal deferred",
			"operator", op.name, "error", err)
		return
	}
	if len(pods) == 0 {
		log.Info("no leader pod resolvable for stuck operator — heal deferred",
			"operator", op.name)
		return
	}

	deleted := false
	for i := range pods {
		pod := &pods[i]
		// UID precondition closes the list→delete TOCTOU: a
		// same-named replacement pod is not ours to reap.
		uid := pod.UID
		if err := p.cs.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
			metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid},
			}); err != nil {
			metrics.IncError(clusterHealthQueue)
			log.Error(err, "stuck operator leader delete failed",
				"pod", pod.Namespace+"/"+pod.Name, "operator", op.name)
			continue
		}
		deleted = true
		log.Info("DELETE: stuck operator leader pod — forcing re-election",
			"operator", op.name, "pod", pod.Namespace+"/"+pod.Name,
			"reasons", strings.Join(reasons, ","))
	}
	if !deleted {
		return
	}
	for _, r := range reasons {
		metrics.OperatorWorkqueueHealsTotal.WithLabelValues(op.name, r).Inc()
	}
	p.mu.Lock()
	p.opHealed[op.name] = now
	p.mu.Unlock()
	// Persist the stamp on the Lease — the durable half of the
	// cooldown. A nil lease (leaseOptional operators healing through
	// the pod fallback) has nowhere to stamp; the in-RAM half is all
	// there is. A patch failure leaves the in-RAM half holding.
	if lease == nil {
		return
	}
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"annotations": map[string]any{
			operatorHealAnno: now.UTC().Format(time.RFC3339),
		}},
	})
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Error(err, "marshal heal stamp", "operator", op.name)
		return
	}
	if _, err := p.cs.CoordinationV1().Leases(lease.Namespace).Patch(ctx, lease.Name,
		types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Error(err, "persist heal stamp failed", "operator", op.name)
	}
}

// leaderPods resolves the operator's leader pod: holderIdentity is
// "<pod-name>_<uuid>" on client-go leader-election — the name prefix
// is tried first, then the verbatim identity (custom electors may
// not suffix); the operator's pod label selector inside the Lease's
// own namespace is the fallback when neither resolves.
func (p *clusterHealthProber) leaderPods(ctx context.Context, op operatorTarget,
	lease *coordinationv1.Lease) ([]corev1.Pod, error) {
	holder := ""
	// The pod namespace is the operator's own — podNS when the Lease
	// lives elsewhere (cert-manager elects in kube-system, runs in
	// cert-manager), else the Lease's namespace; for a nil lease
	// (leaseOptional operators) the selector scans targetPodNS(op).
	podNS := targetPodNS(op)
	if lease != nil {
		if lease.Spec.HolderIdentity != nil {
			holder = *lease.Spec.HolderIdentity
		}
	}
	if holder != "" {
		candidates := []string{holder}
		if i := strings.LastIndex(holder, "_"); i > 0 {
			candidates = append([]string{holder[:i]}, candidates...)
		}
		for _, name := range candidates {
			pod, err := p.cs.CoreV1().Pods(podNS).
				Get(ctx, name, metav1.GetOptions{})
			switch {
			case apierrors.IsNotFound(err):
				continue
			case err != nil:
				return nil, fmt.Errorf("get leader pod %s/%s: %w",
					podNS, name, err)
			default:
				return []corev1.Pod{*pod}, nil
			}
		}
	}
	pods, err := p.cs.CoreV1().Pods(podNS).List(ctx,
		metav1.ListOptions{LabelSelector: op.podSelector})
	if err != nil {
		return nil, fmt.Errorf("list operator pods in %s (selector %q): %w",
			podNS, op.podSelector, err)
	}
	// The selector fallback cannot tell the leader from its
	// standbys — deleting every matched replica wedges the operator
	// outright (the 2026-11-04 cilium-operator triple-delete). Cap
	// the blast radius at one pod, preferring the oldest (the
	// longest-running replica is the likelier wedged holder): if
	// the survivor was the real holder the signature stays up and
	// the next post-cooldown sweep deletes it.
	if len(pods.Items) > 1 {
		sort.Slice(pods.Items, func(i, j int) bool {
			return pods.Items[i].CreationTimestamp.
				Before(&pods.Items[j].CreationTimestamp)
		})
		return pods.Items[:1], nil
	}
	return pods.Items, nil
}

// ---------------------------------------------------------------------------
// W10-CP4 — flux HelmRelease retries-exhausted remediator.
// ---------------------------------------------------------------------------

const (
	// fluxHRStuckMinAge: a Ready=False HelmRelease must hold the
	// failure this long before it counts as stuck — transient helm
	// errors self-heal inside the controller's own retry backoff.
	fluxHRStuckMinAge = 15 * time.Minute
	// fluxHRHealCooldown bounds reconcile-annotation patches to one
	// per HelmRelease per 30m.
	fluxHRHealCooldown = 30 * time.Minute
	// fluxHRRequestedAtAnno / fluxHRForceAtAnno are the flux
	// reconcile-request annotations stamped with the SAME timestamp
	// token — requestedAt asks for a reconcile, forceAt skips the
	// artifact-cache freshness check (same pair the flux
	// CLI `reconcile --with-source` writes).
	fluxHRRequestedAtAnno = "reconcile.fluxcd.io/requestedAt"
	fluxHRForceAtAnno     = "reconcile.fluxcd.io/forceAt"
)

// helmReleaseRetryGVRs are the HelmRelease API versions the check
// probes — v2 is current, v2beta2 the previous storage version; the
// first List that succeeds wins.
var helmReleaseRetryGVRs = []schema.GroupVersionResource{
	{Group: "helm.toolkit.fluxcd.io", Version: "v2", Resource: "helmreleases"},
	{Group: "helm.toolkit.fluxcd.io", Version: "v2beta2", Resource: "helmreleases"},
}

// fluxHRFailureReasons are the Ready=False reasons that mean the
// helm action itself failed — combined with the "retries exhausted"
// message substring they cover every spelling helm-controller uses
// once spec.upgrade.remediation.retries is spent (W10-CP4).
var fluxHRFailureReasons = map[string]bool{
	"InstallFailed":    true,
	"UpgradeFailed":    true,
	"RetriesExhausted": true,
	"RetriesExceeded":  true,
}

// checkFluxHelmReleaseRetries detects HelmReleases parked at
// Ready=False past fluxHRStuckMinAge whose failure reads as
// retries-exhausted, and — when every spec.dependsOn HelmRelease is
// itself Ready — nudges the object back to work by stamping the
// reconcile.fluxcd.io/requestedAt+forceAt annotations (30m per-HR
// cooldown, wider of the in-RAM ledger and the requestedAt stamp we
// leave behind). The check FAILs while qualifying HRs exist —
// remediation is best-effort, detection is the contract.
func (p *clusterHealthProber) checkFluxHelmReleaseRetries(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	if p.dyn == nil {
		return probeResult{infra: fmt.Errorf(
			"no dynamic client — helmrelease retry check unverifiable")}
	}
	now := p.now()

	// Find the served HelmRelease version — try v2 then v2beta2.
	var gvr schema.GroupVersionResource
	var hrs *unstructured.UnstructuredList
	var listErr error
	for _, g := range helmReleaseRetryGVRs {
		l, err := p.dyn.Resource(g).List(ctx, metav1.ListOptions{})
		if err == nil {
			gvr, hrs = g, l
			break
		}
		if !apierrors.IsNotFound(err) && !meta.IsNoMatchError(err) {
			listErr = err
		}
	}
	if hrs == nil {
		if listErr != nil {
			return probeResult{infra: fmt.Errorf(
				"list helmreleases: %w", listErr)}
		}
		return probeResult{pass: true} // CRD not installed
	}

	var stuck []string
	for i := range hrs.Items {
		hr := &hrs.Items[i]
		if suspended, _, _ := unstructured.NestedBool(
			hr.Object, "spec", "suspend"); suspended {
			continue
		}
		status, reason, message, since, ok := fluxHRReadyCondition(hr)
		if !ok || status != "False" {
			continue
		}
		if !fluxHRFailureReasons[reason] &&
			!strings.Contains(strings.ToLower(message), "retries exhausted") {
			continue
		}
		// The failure must persist — a HR still inside its first
		// retry window is working as designed. No transition
		// timestamp → cannot prove the 15m window; stay quiet
		// rather than remediate blind.
		if since.IsZero() || now.Sub(since) < fluxHRStuckMinAge {
			continue
		}
		key := hr.GetNamespace() + "/" + hr.GetName()
		stuck = append(stuck, key)

		// Only remediate once every upstream dependsOn
		// HelmRelease is Ready — patching a HR whose dependency is
		// itself broken just re-fails on the same wall.
		if !p.fluxHRDepsReady(ctx, gvr, hr) {
			continue
		}
		p.maybePatchHRRetry(ctx, log, gvr, hr, key, now)
	}
	if len(stuck) > 0 {
		return probeResult{why: fmt.Sprintf(
			"helmreleases retries-exhausted >=%s: %s",
			fluxHRStuckMinAge, strings.Join(stuck, ", "))}
	}
	return probeResult{pass: true}
}

// fluxHRReadyCondition extracts the Ready condition's status, reason,
// message and lastTransitionTime from a HelmRelease. ok=false when no
// Ready condition exists at all.
func fluxHRReadyCondition(hr *unstructured.Unstructured) (status, reason, message string, since time.Time, ok bool) {
	for _, c := range shared.ReadyConds(hr) {
		if c["type"] != "Ready" {
			continue
		}
		status, _ = c["status"].(string)
		reason, _ = c["reason"].(string)
		message, _ = c["message"].(string)
		if ts, _ := c["lastTransitionTime"].(string); ts != "" {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				since = t
			}
		}
		return status, reason, message, since, true
	}
	return "", "", "", time.Time{}, false
}

// fluxHRDepsReady reports whether every spec.dependsOn HelmRelease
// reference resolves to a Ready=True object. A missing or unreadable
// dependency fails closed — never remediate on an unverifiable chain.
func (p *clusterHealthProber) fluxHRDepsReady(ctx context.Context,
	gvr schema.GroupVersionResource, hr *unstructured.Unstructured) bool {
	deps, found, err := unstructured.NestedSlice(hr.Object, "spec", "dependsOn")
	if err != nil || !found {
		return true // no dependsOn — vacuously ready
	}
	for _, d := range deps {
		m, ok := d.(map[string]any)
		if !ok {
			return false
		}
		name, _ := m["name"].(string)
		if name == "" {
			return false
		}
		ns, _ := m["namespace"].(string)
		if ns == "" {
			ns = hr.GetNamespace()
		}
		dep, err := p.dyn.Resource(gvr).Namespace(ns).
			Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false
		}
		if st, _, _ := fluxHRReadyStrings(dep); st != "True" {
			return false
		}
	}
	return true
}

// fluxHRReadyStrings is the status-only half of fluxHRReadyCondition
// for dependency checks.
func fluxHRReadyStrings(obj *unstructured.Unstructured) (status, reason, message string) {
	for _, c := range shared.ReadyConds(obj) {
		if c["type"] != "Ready" {
			continue
		}
		status, _ = c["status"].(string)
		reason, _ = c["reason"].(string)
		message, _ = c["message"].(string)
		return status, reason, message
	}
	return "", "", ""
}

// maybePatchHRRetry stamps the reconcile annotations on a stuck
// HelmRelease unless the 30m cooldown (in-RAM ledger OR the
// requestedAt stamp a previous patch — ours or an operator's —
// already left) is still warm.
func (p *clusterHealthProber) maybePatchHRRetry(ctx context.Context, log logr.Logger,
	gvr schema.GroupVersionResource, hr *unstructured.Unstructured,
	key string, now time.Time) {
	p.mu.Lock()
	last, ok := p.hrRetryHealed[key]
	p.mu.Unlock()
	if ok && now.Sub(last) < fluxHRHealCooldown {
		return
	}
	// The requestedAt annotation is the durable half: a stamp younger
	// than the cooldown — whether we wrote it or `flux reconcile`
	// did — means a reconcile is already queued.
	if v, found, _ := unstructured.NestedString(
		hr.Object, "metadata", "annotations", fluxHRRequestedAtAnno); found {
		if t, err := time.Parse(time.RFC3339, v); err == nil &&
			now.Sub(t) < fluxHRHealCooldown {
			return
		}
	}
	token := now.UTC().Format(time.RFC3339Nano)
	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]string{
				fluxHRRequestedAtAnno: token,
				fluxHRForceAtAnno:     token,
			},
		},
	})
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Error(err, "marshal hr retry patch failed", "hr", key)
		return
	}
	if _, err := p.dyn.Resource(gvr).Namespace(hr.GetNamespace()).
		Patch(ctx, hr.GetName(), types.MergePatchType, patch,
			metav1.PatchOptions{}); err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Error(err, "helmrelease retry patch failed", "hr", key)
		return
	}
	p.mu.Lock()
	p.hrRetryHealed[key] = now
	p.mu.Unlock()
	log.Info("patched helmrelease reconcile annotations",
		"hr", key, "requestedAt", token)
}

// ---------------------------------------------------------------------------
// W10-ST5 — percona-cluster-quorum.
// ---------------------------------------------------------------------------

const (
	// perconaInitMinAge bounds how long a Percona cluster may sit in
	// "initializing" before the quorum check calls it stuck — fresh
	// clusters legitimately take tens of minutes to bootstrap.
	perconaInitMinAge = 30 * time.Minute
)

// perconaClusterGVRs are the three Percona operator CRDs the quorum
// check sweeps cluster-wide; a cluster without a given operator
// simply has no objects (CRD absent → the List misses quietly).
var perconaClusterGVRs = []schema.GroupVersionResource{
	{Group: "pxc.percona.com", Version: "v1", Resource: "perconaxtradbclusters"},
	{Group: "pgv2.percona.com", Version: "v2", Resource: "perconapgclusters"},
	{Group: "psmdb.percona.com", Version: "v1", Resource: "perconaservermongodbs"},
}

// checkPerconaClusterQuorum flags Percona database clusters that
// report an error state, sit in "initializing" past
// perconaInitMinAge, or show fewer than one ready instance while not
// paused (W10-ST5). Suggested run() registration name:
// "percona-cluster-quorum".
func (p *clusterHealthProber) checkPerconaClusterQuorum(ctx context.Context) probeResult {
	if p.dyn == nil {
		return probeResult{infra: fmt.Errorf(
			"no dynamic client — percona quorum check unverifiable")}
	}
	now := p.now()
	p.mu.Lock()
	if p.perconaInitSeen == nil {
		p.perconaInitSeen = map[string]time.Time{}
	}
	p.mu.Unlock()

	var offenders []string
	live := map[string]bool{}
	var firstErr error
	for _, gvr := range perconaClusterGVRs {
		list, err := p.dyn.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) {
				continue // operator/CRD not installed on this cluster
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("list %s: %w", gvr.Resource, err)
			}
			continue
		}
		for i := range list.Items {
			o := &list.Items[i]
			key := gvr.Resource + "/" + o.GetNamespace() + "/" + o.GetName()
			live[key] = true
			if perconaClusterPaused(o) {
				p.clearPerconaInit(key)
				continue
			}
			state, _, _ := unstructured.NestedString(o.Object, "status", "state")
			statusField, _, _ := unstructured.NestedString(o.Object, "status", "status")
			switch {
			case strings.EqualFold(state, "error") ||
				strings.EqualFold(statusField, "error"):
				offenders = append(offenders, fmt.Sprintf(
					"%s/%s state=%s", o.GetNamespace(), o.GetName(),
					perconaStateLabel(state, statusField)))
				p.clearPerconaInit(key)
			case strings.EqualFold(state, "initializing") ||
				strings.EqualFold(statusField, "initializing"):
				// Initializing is checked BEFORE ready<1: a fresh
				// cluster's operator writes status.ready:0 while
				// bootstrapping — flagging it here would bypass
				// the perconaInitMinAge grace and flap new
				// clusters (W10-ST5 review).
				if p.perconaInitAge(key, now) >= perconaInitMinAge {
					offenders = append(offenders, fmt.Sprintf(
						"%s/%s initializing>%s", o.GetNamespace(),
						o.GetName(), perconaInitMinAge))
				}
			case perconaReadyBelowOne(o):
				offenders = append(offenders, fmt.Sprintf(
					"%s/%s ready<1", o.GetNamespace(), o.GetName()))
				p.clearPerconaInit(key)
			default:
				p.clearPerconaInit(key)
			}
		}
	}
	// Prune init timers for clusters that disappeared entirely.
	p.mu.Lock()
	for k := range p.perconaInitSeen {
		if !live[k] {
			delete(p.perconaInitSeen, k)
		}
	}
	p.mu.Unlock()

	if len(offenders) > 0 {
		return probeResult{why: fmt.Sprintf(
			"percona cluster quorum: %s", strings.Join(offenders, ", "))}
	}
	if firstErr != nil {
		return probeResult{infra: firstErr}
	}
	return probeResult{pass: true}
}

// perconaClusterPaused reports spec.pause==true or spec.mode=="paused"
// — a deliberately parked cluster is not a quorum failure.
func perconaClusterPaused(o *unstructured.Unstructured) bool {
	if paused, _, _ := unstructured.NestedBool(o.Object, "spec", "pause"); paused {
		return true
	}
	if mode, _, _ := unstructured.NestedString(o.Object, "spec", "mode"); mode == "paused" {
		return true
	}
	return false
}

// perconaReadyBelowOne reads the ready-instance count across the
// Percona status shapes: top-level status.ready (PXC, PSMDB) or the
// nested status.postgres.ready (PGv2 keeps readiness under the
// postgres component). Absent fields read as "unknown", not zero —
// an operator that never wrote a count must not false-positive.
func perconaReadyBelowOne(o *unstructured.Unstructured) bool {
	if ready, found, _ := unstructured.NestedInt64(o.Object, "status", "ready"); found {
		return ready < 1
	}
	if ready, found, _ := unstructured.NestedInt64(o.Object, "status", "postgres", "ready"); found {
		return ready < 1
	}
	return false
}

// perconaStateLabel picks the non-empty state/status string for the
// offender message.
func perconaStateLabel(state, statusField string) string {
	if state != "" {
		return state
	}
	return statusField
}

// perconaInitAge records (or returns the age of) the first sweep this
// cluster was seen initializing — the 30m stuck-initializing clock.
func (p *clusterHealthProber) perconaInitAge(key string, now time.Time) time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	since, ok := p.perconaInitSeen[key]
	if !ok {
		p.perconaInitSeen[key] = now
		return 0
	}
	return now.Sub(since)
}

// clearPerconaInit drops a cluster's initializing timer — resolved,
// errored or otherwise no longer initializing.
func (p *clusterHealthProber) clearPerconaInit(key string) {
	p.mu.Lock()
	delete(p.perconaInitSeen, key)
	p.mu.Unlock()
}

// ---------------------------------------------------------------------------
// stateful-masterless-services (W6.2) — masterless service guard +
// dragonfly auto-heal.
// ---------------------------------------------------------------------------

// masterlessRoleKeys are the label keys marking a Service that routes
// only to the master/primary of a stateful set — 0 Ready endpoints on
// it means the workload is leaderless.
var masterlessRoleKeys = []string{"role", "redis-role", "app.kubernetes.io/role"}

// masterlessRoleValues are the role values identifying the master
// side of a replicated stateful service.
var masterlessRoleValues = []string{"master", "primary", "leader"}

// masterRoleService reports whether svc carries a master-role key —
// in its selector (selects only the leader pods) or its own labels
// (the Service is labeled as the master endpoint).
func masterRoleService(svc *corev1.Service) bool {
	for _, k := range masterlessRoleKeys {
		if v := svc.Spec.Selector[k]; slices.Contains(masterlessRoleValues, v) {
			return true
		}
	}
	for _, k := range masterlessRoleKeys {
		if v := svc.Labels[k]; slices.Contains(masterlessRoleValues, v) {
			return true
		}
	}
	return false
}

// selectorMatchesSTS reports whether the Service routes to the
// StatefulSet's pods: every NON-role key in svc.Spec.Selector must
// appear in the STS pod-template labels. Role keys are stripped —
// operators write role=master/replica onto the POD at runtime, never
// into the template, so a literal subset match would never fire for
// exactly the services this check exists to watch (dragonfly/redis
// master services). A selector that carries nothing but role keys
// cannot be attributed to one STS — it matches every workload, so it
// is excluded.
func selectorMatchesSTS(svc *corev1.Service, podLabels map[string]string) bool {
	nonRole := map[string]string{}
	for k, v := range svc.Spec.Selector {
		if slices.Contains(masterlessRoleKeys, k) {
			continue
		}
		nonRole[k] = v
	}
	if len(nonRole) == 0 {
		return false
	}
	return labels.SelectorFromSet(nonRole).Matches(labels.Set(podLabels))
}

// masterSvc pairs a master-role Service with the ready StatefulSet
// whose pod labels its selector matches.
type masterSvc struct {
	ns, svc string
	sts     *appsv1.StatefulSet
}

// masterlessDue pairs a master-role service past the heal window
// with the moment its zero-endpoint streak began — the W7-C3
// deadlock heal needs the streak length, not just "past 5m".
type masterlessDue struct {
	svc   masterSvc
	since time.Time
}

// dragonflyOwned reports whether the StatefulSet is managed by the
// dragonfly-operator — via app.kubernetes.io/part-of=dragonfly or
// app.kubernetes.io/created-by=dragonfly-operator on the STS metadata
// or its pod template.
func dragonflyOwned(sts *appsv1.StatefulSet) bool {
	for _, lbls := range []map[string]string{sts.Labels, sts.Spec.Template.Labels} {
		if lbls["app.kubernetes.io/part-of"] == "dragonfly" ||
			lbls["app.kubernetes.io/created-by"] == "dragonfly-operator" {
			return true
		}
	}
	return false
}

// checkStatefulMasterlessServices detects a masterless stateful
// service: a non-headless Service routing to a ready StatefulSet's
// pods under a master-role key whose EndpointSlices report 0 Ready
// endpoints — the STS is alive but clients have no master to reach
// (the operator that assigns the role wedged).
//
// Past masterlessZeroMinAge the gauge
// node_automation_stateful_service_zero_endpoints{ns,svc,sts} goes to
// 1 and the check FAILs; past masterlessHealMinAge a Dragonfly-owned
// STS additionally triggers a dragonfly-operator leader delete (30m
// cooldown) — a wedged operator is the common cause of a missing
// master label/election.
func (p *clusterHealthProber) checkStatefulMasterlessServices(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()
	p.mu.Lock()
	if p.stsZeroSince == nil {
		p.stsZeroSince = map[string]time.Time{}
	}
	if p.stsZeroEmitted == nil {
		p.stsZeroEmitted = map[string]bool{}
	}
	if p.drHealed == nil {
		p.drHealed = map[string]time.Time{}
	}
	if p.drPodHealed == nil {
		p.drPodHealed = map[string]time.Time{}
	}
	p.mu.Unlock()

	stsList, err := p.cs.AppsV1().StatefulSets(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list statefulsets: %w", err)}
	}
	svcList, err := p.cs.CoreV1().Services(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list services: %w", err)}
	}
	// Ready-endpoint census per ns/service — same source as the
	// webhook guard (paged, service-name label binding, nil ready
	// counts as ready). A list error skips the whole check: "0
	// ready" is indistinguishable from "no data".
	ready := map[string]int{}
	sliceOpts := metav1.ListOptions{Limit: healthListPageSize}
	for {
		sliceList, err := p.cs.DiscoveryV1().EndpointSlices(metav1.NamespaceAll).
			List(ctx, sliceOpts)
		if err != nil {
			return probeResult{infra: fmt.Errorf("list endpointslices: %w", err)}
		}
		for _, s := range sliceList.Items {
			svc := s.Labels[discoveryv1.LabelServiceName]
			if svc == "" {
				continue
			}
			key := s.Namespace + "/" + svc
			for _, ep := range s.Endpoints {
				if ep.Conditions.Ready == nil || *ep.Conditions.Ready {
					ready[key]++
				}
			}
		}
		if sliceList.Continue == "" {
			break
		}
		sliceOpts.Continue = sliceList.Continue
	}

	// Candidates: a ready STS paired with a master-role Service
	// routing to its pods.
	var candidates []masterSvc
	for i := range stsList.Items {
		sts := &stsList.Items[i]
		if sts.Status.ReadyReplicas == 0 {
			continue
		}
		for j := range svcList.Items {
			svc := &svcList.Items[j]
			if svc.Namespace != sts.Namespace ||
				svc.Spec.ClusterIP == "" ||
				svc.Spec.ClusterIP == corev1.ClusterIPNone {
				continue // headless services are deliberately per-pod
			}
			if !masterRoleService(svc) ||
				!selectorMatchesSTS(svc, sts.Spec.Template.Labels) {
				continue
			}
			candidates = append(candidates,
				masterSvc{ns: svc.Namespace, svc: svc.Name, sts: sts})
		}
	}

	seen := map[string]bool{}    // tuples observed at 0 ready this sweep
	emitted := map[string]bool{} // tuples past the gauge window
	var due []masterlessDue      // past the heal window
	for _, c := range candidates {
		key := c.ns + "/" + c.svc + "/" + c.sts.Name
		if ready[c.ns+"/"+c.svc] > 0 {
			continue // master reachable — drop any streak
		}
		seen[key] = true
		p.mu.Lock()
		first, ok := p.stsZeroSince[key]
		if !ok {
			p.stsZeroSince[key] = now
		}
		p.mu.Unlock()
		if !ok {
			log.Info("master-role service at 0 ready endpoints — tracking first-seen",
				"service", c.ns+"/"+c.svc, "statefulset", c.sts.Name)
			continue
		}
		if now.Sub(first) < masterlessZeroMinAge {
			continue
		}
		emitted[key] = true
		metrics.StatefulServiceZeroEndpoints.
			WithLabelValues(c.ns, c.svc, c.sts.Name).Set(1)
		if now.Sub(first) >= masterlessHealMinAge {
			due = append(due, masterlessDue{svc: c, since: first})
		}
	}

	p.mu.Lock()
	for k := range p.stsZeroSince {
		if !seen[k] {
			delete(p.stsZeroSince, k)
		}
	}
	for k := range p.stsZeroEmitted {
		if emitted[k] {
			continue
		}
		if parts := strings.SplitN(k, "/", 3); len(parts) == 3 {
			metrics.StatefulServiceZeroEndpoints.
				DeleteLabelValues(parts[0], parts[1], parts[2])
		}
		delete(p.stsZeroEmitted, k)
	}
	maps.Copy(p.stsZeroEmitted, emitted)
	p.mu.Unlock()

	// Dragonfly auto-heal — a masterless dragonfly past the heal
	// window bounces the operator leader to force re-election (step
	// 1); past the deadlock window and >=3m after that bounce the
	// dual-replica heal deletes the lowest-ordinal pod to restart
	// the election from scratch (step 2, W7-C3). A non-dragonfly
	// masterless STS gets per-pod role diagnostics instead — its
	// election contract is operand-specific and a generic pod kill
	// is not safe to automate.
	for _, d := range due {
		if !dragonflyOwned(d.svc.sts) {
			// W4: a masterless stateful service owned by a known db
			// operator gets the operator pod bounced to force
			// re-election — the same re-election nudge as the
			// dragonfly heal, on its own per-operator 30m cooldown.
			if op := dbOperatorFor(d.svc.sts); op != "" {
				p.healDBOperator(ctx, log, d.svc, op, now)
			} else {
				p.logStatefulPodRoles(ctx, log, d.svc)
			}
			continue
		}
		p.healDragonflyOperator(ctx, log, d.svc, now)
		if now.Sub(d.since) >= dragonflyReplicaDeadlockMinAge {
			p.healDragonflyReplicaDeadlock(ctx, log, d.svc, now)
		}
	}

	if len(emitted) == 0 {
		return probeResult{pass: true}
	}
	keys := make([]string, 0, len(emitted))
	for k := range emitted {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return probeResult{why: fmt.Sprintf(
		"master-role services at 0 ready endpoints >=%s: %s",
		masterlessZeroMinAge, strings.Join(keys, ", "))}
}

// healDragonflyOperator deletes the dragonfly-operator controller
// pod(s) — the same re-election nudge the operator watchdog applies,
// keyed on its own 30m cooldown so the leader is never churned. The
// cooldown is the wider of the in-RAM ledger and the
// node.ops/last-dragonfly-operator-heal stamp persisted on the STS
// that triggered it (survives operator restarts).
func (p *clusterHealthProber) healDragonflyOperator(ctx context.Context, log logr.Logger,
	sig masterSvc, now time.Time) {
	// Maintenance mutex — never kill an operator mid-drain/upgrade;
	// "cannot verify" fails closed like healOperatorLeader (W5.8).
	held, why, err := shared.MaintenanceActive(ctx, p.cs, p.dyn)
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: maintenance check unverifiable — heal deferred (fail closed)",
			"statefulset", sig.sts.Namespace+"/"+sig.sts.Name, "error", err)
		return
	}
	if held {
		log.Info("maintenance in progress — heal deferred",
			"statefulset", sig.sts.Namespace+"/"+sig.sts.Name, "why", why)
		return
	}
	if ts := sig.sts.Annotations[dragonflyHealAnno]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil &&
			now.Sub(t) < dragonflyHealCooldown {
			log.Info("skip heal: persisted stamp inside cooldown",
				"statefulset", sig.sts.Namespace+"/"+sig.sts.Name,
				"ago", now.Sub(t).Truncate(time.Minute))
			return
		}
	}
	pods, err := p.cs.CoreV1().Pods(dragonflyOperatorNS).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: list dragonfly-operator pods failed — heal deferred",
			"error", err)
		return
	}
	deleted := false
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !strings.HasPrefix(pod.Name, dragonflyOperatorPodPrefix) {
			continue
		}
		key := pod.Namespace + "/" + pod.Name
		p.mu.Lock()
		last, ok := p.drHealed[key]
		p.mu.Unlock()
		if ok && now.Sub(last) < dragonflyHealCooldown {
			log.Info("skip heal: dragonfly operator inside cooldown",
				"pod", key, "ago", now.Sub(last).Truncate(time.Minute))
			continue
		}
		uid := pod.UID
		if err := p.cs.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
			metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid},
			}); err != nil {
			metrics.IncError(clusterHealthQueue)
			log.Error(err, "dragonfly operator delete failed", "pod", key)
			continue
		}
		p.mu.Lock()
		p.drHealed[key] = now
		p.mu.Unlock()
		deleted = true
		log.Info("DELETE: dragonfly operator pod — masterless service, forcing re-election",
			"pod", key, "service", sig.ns+"/"+sig.svc,
			"statefulset", sig.sts.Name)
	}
	if !deleted {
		return
	}
	// Persist the stamp on the STS — the durable half of the
	// cooldown. A patch failure leaves the in-RAM half holding.
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"annotations": map[string]any{
			dragonflyHealAnno: now.UTC().Format(time.RFC3339),
		}},
	})
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Error(err, "marshal dragonfly heal stamp", "statefulset", sig.sts.Name)
		return
	}
	if _, err := p.cs.AppsV1().StatefulSets(sig.sts.Namespace).Patch(ctx,
		sig.sts.Name, types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Error(err, "persist dragonfly heal stamp failed",
			"statefulset", sig.sts.Namespace+"/"+sig.sts.Name)
	}
}

// dragonflyOperatorHealedAt returns the most recent moment a
// dragonfly-operator leader pod was deleted by step 1 — the wider
// of the persisted node.ops/last-dragonfly-operator-heal stamp on
// this STS and the in-RAM per-pod ledger (which survives an STS
// patch failure). ok=false means no heal has landed yet: the
// dual-replica heal must not skip ahead of step 1.
func (p *clusterHealthProber) dragonflyOperatorHealedAt(sig masterSvc) (time.Time, bool) {
	var latest time.Time
	if ts := sig.sts.Annotations[dragonflyHealAnno]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil && t.After(latest) {
			latest = t
		}
	}
	p.mu.Lock()
	for _, t := range p.drHealed {
		if t.After(latest) {
			latest = t
		}
	}
	p.mu.Unlock()
	return latest, !latest.IsZero()
}

// podMasterRole reports whether the pod carries a master/primary/
// leader value under any master-role label key — the positive form
// of the dual-replica deadlock check (a pod already holding the
// master role means the election produced a winner and a pod kill
// would fight it).
func podMasterRole(pod *corev1.Pod) bool {
	for _, k := range masterlessRoleKeys {
		if slices.Contains(masterlessRoleValues, pod.Labels[k]) {
			return true
		}
	}
	return false
}

// smallestOrdinalPod returns the pod with the lowest StatefulSet
// ordinal — "<sts>-0" in the common case — or nil when none of the
// pods match the "<sts>-<n>" naming. StatefulSet pod names are the
// only source of truth for the ordinal (there is no field for it).
func smallestOrdinalPod(pods []corev1.Pod, stsName string) *corev1.Pod {
	var best *corev1.Pod
	bestOrd := -1
	for i := range pods {
		name := pods[i].Name
		if !strings.HasPrefix(name, stsName+"-") {
			continue
		}
		ord, err := strconv.Atoi(name[len(stsName)+1:])
		if err != nil {
			continue
		}
		if bestOrd < 0 || ord < bestOrd {
			bestOrd = ord
			best = &pods[i]
		}
	}
	return best
}

// dbOperatorNames are the operators whose role-assignment wedge this
// check heals — matched against the StatefulSet's labels, pod-template
// labels and ownerReferences. The long Percona deployment names sit
// alongside the short chart aliases (W10-FIX4): an STS owned by the
// percona-xtradb-cluster-operator Deployment labels itself with the
// long name, while older charts/labels still carry pxc-operator.
var dbOperatorNames = []string{
	"mariadb-operator", "pxc-operator", "psmdb-operator",
	"pg-operator", "scylla-operator",
	"percona-xtradb-cluster-operator", "percona-server-mongodb-operator",
	"percona-postgresql-operator",
}

// dbOperatorDeploymentAliases groups the Deployment/pod-name spellings
// one logical db operator answers to (W10-FIX4): the short chart alias
// (pxc-operator) and the long upstream Deployment name
// (percona-xtradb-cluster-operator) produce DIFFERENT pod name
// prefixes, so a heal keyed on whichever spelling dbOperatorFor
// matched would miss the real pods.
var dbOperatorDeploymentAliases = map[string][]string{
	"percona-xtradb-cluster-operator": {"percona-xtradb-cluster-operator", "pxc-operator"},
	"percona-server-mongodb-operator": {"percona-server-mongodb-operator", "psmdb-operator"},
	"percona-postgresql-operator":     {"percona-postgresql-operator", "pg-operator"},
}

// dbOperatorPodPrefixes returns every pod-name prefix the logical
// operator may deploy under — the alias group when one exists, else
// the bare operator name. Order is stable: the canonical (key) name
// first, then aliases.
func dbOperatorPodPrefixes(operator string) []string {
	if aliases, ok := dbOperatorDeploymentAliases[operator]; ok {
		return aliases
	}
	for _, aliases := range dbOperatorDeploymentAliases {
		for _, a := range aliases {
			if a == operator {
				return aliases
			}
		}
	}
	return []string{operator}
}

// dbOperatorFor returns the db operator name owning this StatefulSet,
// or "" — matching any label value on the STS or its pod template
// containing the operator name (managed-by/part-of/created-by and
// operator-specific labels all end up containing it), plus
// ownerReference names.
func dbOperatorFor(sts *appsv1.StatefulSet) string {
	for _, lbls := range []map[string]string{sts.Labels, sts.Spec.Template.Labels} {
		for _, v := range lbls {
			for _, op := range dbOperatorNames {
				if strings.Contains(v, op) {
					return op
				}
			}
		}
	}
	for _, ref := range sts.OwnerReferences {
		for _, op := range dbOperatorNames {
			if strings.Contains(ref.Name, op) {
				return op
			}
		}
	}
	return ""
}

// healDBOperator deletes a pod of the responsible db operator to
// force master re-election — only fires while !MaintenanceActive
// (the caller guarantees the >=5m zero-endpoint streak and
// sts.Status.ReadyReplicas > 0; the check itself only reaches here
// for ready STS). 30m per-operator cooldown on the in-RAM ledger.
func (p *clusterHealthProber) healDBOperator(ctx context.Context, log logr.Logger,
	sig masterSvc, operator string, now time.Time) {
	const dbOperatorHealCooldown = 30 * time.Minute
	p.mu.Lock()
	last, ok := p.meshHealed[operator]
	p.mu.Unlock()
	if ok && now.Sub(last) < dbOperatorHealCooldown {
		log.Info("skip heal: db operator inside cooldown", "operator", operator,
			"ago", now.Sub(last).Truncate(time.Minute))
		return
	}
	held, why, err := shared.MaintenanceActive(ctx, p.cs, p.dyn)
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: maintenance check unverifiable — heal deferred (fail closed)",
			"operator", operator, "error", err)
		return
	}
	if held {
		log.Info("maintenance in progress — heal deferred", "operator", operator, "why", why)
		return
	}
	pods, err := p.cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: list pods failed — db operator heal deferred", "error", err)
		return
	}
	// Find the oldest Running pod of the operator — its namespace is
	// not fixed across installs, so the prefix match runs
	// cluster-wide and the blast radius is capped at one pod. The
	// Percona operators answer to two Deployment spellings (W10-FIX4)
	// — every alias prefix is tried so a short-name match still finds
	// the long-named pods.
	prefixes := dbOperatorPodPrefixes(operator)
	var target *corev1.Pod
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.Status.Phase != corev1.PodRunning ||
			pod.DeletionTimestamp != nil {
			continue
		}
		matched := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(pod.Name, prefix+"-") {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if target == nil || pod.CreationTimestamp.Before(&target.CreationTimestamp) {
			target = pod
		}
	}
	if target == nil {
		log.Info("no running pod found for db operator — heal deferred",
			"operator", operator)
		return
	}
	uid := target.UID
	if err := p.cs.CoreV1().Pods(target.Namespace).Delete(ctx, target.Name,
		metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid},
		}); err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Error(err, "db operator pod delete failed",
			"pod", target.Namespace+"/"+target.Name, "operator", operator)
		return
	}
	p.mu.Lock()
	p.meshHealed[operator] = now
	p.mu.Unlock()
	metrics.ControlPlanePodHealsTotal.WithLabelValues(operator).Inc()
	log.Info("DELETE: db operator pod — masterless service, forcing re-election",
		"operator", operator, "pod", target.Namespace+"/"+target.Name,
		"service", sig.ns+"/"+sig.svc, "statefulset", sig.sts.Name)
}

// logStatefulPodRoles dumps per-pod role-label diagnostics for a
// masterless non-dragonfly StatefulSet — the W7-C3 pod-delete heal
// is dragonfly-only (its election contract is operator-driven), so
// for Percona/PostgreSQL/NATS the check leaves this evidence trail
// for the on-call engineer instead of acting on it. Diagnostics
// only: a list failure must not escalate into a run error.
func (p *clusterHealthProber) logStatefulPodRoles(ctx context.Context, log logr.Logger, sig masterSvc) {
	sel, err := metav1.LabelSelectorAsSelector(sig.sts.Spec.Selector)
	if err != nil {
		return
	}
	pods, err := p.cs.CoreV1().Pods(sig.sts.Namespace).List(ctx,
		metav1.ListOptions{LabelSelector: sel.String()})
	if err != nil {
		return
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		roles := map[string]string{}
		for _, k := range masterlessRoleKeys {
			if v := pod.Labels[k]; v != "" {
				roles[k] = v
			}
		}
		log.Info("masterless service — pod role diagnostic",
			"service", sig.ns+"/"+sig.svc,
			"statefulset", sig.sts.Namespace+"/"+sig.sts.Name,
			"pod", pod.Name,
			"ready", shared.PodReadyCond(pod),
			"roles", fmt.Sprintf("%v", roles))
	}
}

// healDragonflyReplicaDeadlock is the W7-C3 step-2 heal: the
// dragonfly-operator leader was already bounced (step 1, W6.2) but
// the masterless streak outlived it — the dual-replica deadlock
// where every pod holds role=replica (each still executing
// REPLICAOF <old-dead-ip>) and an operator restart alone cannot
// re-elect. Deleting the lowest-ordinal pod forces the election
// from scratch.
//
// Gates, in order:
//  1. the operator heal must have actually landed >=
//     dragonflyOperatorSettleMin ago — deleting a pod before the new
//     leader had time to relabel reaps it pointlessly, and no heal
//     record at all means step 1 never ran: keep waiting rather
//     than skipping to pod kills;
//  2. the deadlock itself: every STS pod Ready AND zero pods
//     carrying a master-role label — an unready pod or an existing
//     master means the wedge sits elsewhere and a pod kill helps
//     nothing;
//  3. the 30m cooldown (wider of in-RAM ledger and persisted STS
//     stamp) and the maintenance mutex — the same shape every
//     pod-delete heal in this package carries.
func (p *clusterHealthProber) healDragonflyReplicaDeadlock(ctx context.Context, log logr.Logger,
	sig masterSvc, now time.Time) {

	stsKey := sig.sts.Namespace + "/" + sig.sts.Name

	// Gate 1 — the operator heal must have settled first.
	opHealedAt, healed := p.dragonflyOperatorHealedAt(sig)
	switch {
	case !healed:
		log.Info("dual-replica deadlock: no operator heal recorded — waiting for step 1",
			"statefulset", stsKey)
		return
	case now.Sub(opHealedAt) < dragonflyOperatorSettleMin:
		log.Info("dual-replica deadlock: operator heal still settling — waiting",
			"statefulset", stsKey,
			"ago", now.Sub(opHealedAt).Truncate(time.Minute))
		return
	}

	sel, err := metav1.LabelSelectorAsSelector(sig.sts.Spec.Selector)
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: statefulset selector unparseable — deadlock heal deferred",
			"statefulset", stsKey, "error", err)
		return
	}
	pods, err := p.cs.CoreV1().Pods(sig.sts.Namespace).List(ctx,
		metav1.ListOptions{LabelSelector: sel.String()})
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: list statefulset pods failed — deadlock heal deferred",
			"statefulset", stsKey, "error", err)
		return
	}

	// Gate 2 — confirm the deadlock shape: all replicas Ready but
	// nobody holds the master role.
	if len(pods.Items) == 0 {
		return // no pods — nothing safe to delete
	}
	allReady := true
	hasMaster := false
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !shared.PodReadyCond(pod) {
			allReady = false
		}
		if podMasterRole(pod) {
			hasMaster = true
		}
	}
	switch {
	case !allReady:
		log.Info("dual-replica deadlock not confirmed: unready pod — heal deferred",
			"statefulset", stsKey)
		return
	case hasMaster:
		// A pod already carries the master role — endpoints will
		// follow; a pod kill now would fight a live re-election.
		return
	}

	// Gate 3 — the 30m cooldown (wider of in-RAM + persisted), then
	// the maintenance mutex.
	p.mu.Lock()
	last, ok := p.drPodHealed[stsKey]
	p.mu.Unlock()
	if ok && now.Sub(last) < dragonflyPodHealCooldown {
		log.Info("skip heal: dragonfly pod inside cooldown",
			"statefulset", stsKey, "ago", now.Sub(last).Truncate(time.Minute))
		return
	}
	if ts := sig.sts.Annotations[dragonflyPodHealAnno]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil &&
			now.Sub(t) < dragonflyPodHealCooldown {
			log.Info("skip heal: persisted stamp inside cooldown",
				"statefulset", stsKey,
				"ago", now.Sub(t).Truncate(time.Minute))
			return
		}
	}
	// Maintenance mutex — never kill a stateful pod mid-drain/
	// upgrade; "cannot verify" fails closed like every other caller.
	held, why, err := shared.MaintenanceActive(ctx, p.cs, p.dyn)
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: maintenance check unverifiable — heal deferred (fail closed)",
			"statefulset", stsKey, "error", err)
		return
	}
	if held {
		log.Info("maintenance in progress — heal deferred",
			"statefulset", stsKey, "why", why)
		return
	}

	target := smallestOrdinalPod(pods.Items, sig.sts.Name)
	if target == nil {
		return // no STS-named pod found — nothing safe to delete
	}
	// UID precondition closes the list→delete TOCTOU: a same-named
	// replacement pod is not ours to reap.
	uid := target.UID
	if err := p.cs.CoreV1().Pods(target.Namespace).Delete(ctx, target.Name,
		metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{UID: &uid},
		}); err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Error(err, "dragonfly dual-replica pod delete failed",
			"pod", target.Namespace+"/"+target.Name)
		return
	}
	metrics.DragonflyMasterlessPodHealsTotal.
		WithLabelValues(sig.sts.Namespace, sig.sts.Name).Inc()
	p.mu.Lock()
	p.drPodHealed[stsKey] = now
	p.mu.Unlock()
	log.Info("DELETE: dragonfly dual-replica deadlock — lowest-ordinal pod deleted to force master re-election",
		"pod", target.Namespace+"/"+target.Name,
		"statefulset", stsKey, "service", sig.ns+"/"+sig.svc)

	// Persist the stamp on the STS — the durable half of the
	// cooldown. A patch failure leaves the in-RAM half holding.
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"annotations": map[string]any{
			dragonflyPodHealAnno: now.UTC().Format(time.RFC3339),
		}},
	})
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Error(err, "marshal dragonfly pod heal stamp", "statefulset", stsKey)
		return
	}
	if _, err := p.cs.AppsV1().StatefulSets(sig.sts.Namespace).Patch(ctx,
		sig.sts.Name, types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Error(err, "persist dragonfly pod heal stamp failed",
			"statefulset", stsKey)
	}
}

// ---------------------------------------------------------------------------
// rabbitmq-suspended-listener (W6.4) — suspended listener healer.
// ---------------------------------------------------------------------------

// rabbitSuspended reports the suspended-listener signature: the pod
// is Running and every container Started (kubelet launched them) but
// none ever went Ready — the rabbit listener sits on the
// ranch:suspended branch refusing port 5672 while the pod looks
// "almost healthy" to every coarse check.
func rabbitSuspended(pod *corev1.Pod) bool {
	if pod.Status.Phase != corev1.PodRunning || pod.DeletionTimestamp != nil {
		return false
	}
	if len(pod.Status.ContainerStatuses) == 0 {
		return false
	}
	for _, s := range pod.Status.ContainerStatuses {
		if s.Started == nil || !*s.Started || s.Ready {
			return false
		}
	}
	return true
}

// rabbitQuorumSafe verifies deleting the suspended pod cannot break
// the cluster quorum: the pod must be owned by a StatefulSet whose
// every OTHER replica is Ready — a peer that is itself suspended or
// down means the delete could take the cluster below quorum, so the
// heal stands down and the FAIL series keeps alerting instead.
func (p *clusterHealthProber) rabbitQuorumSafe(ctx context.Context, pod *corev1.Pod) (bool, error) {
	owner := metav1.GetControllerOf(pod)
	if owner == nil || owner.Kind != "StatefulSet" {
		return false, nil // cannot verify peers — do not touch
	}
	sts, err := p.cs.AppsV1().StatefulSets(pod.Namespace).
		Get(ctx, owner.Name, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("get statefulset %s/%s: %w",
			pod.Namespace, owner.Name, err)
	}
	sel, err := metav1.LabelSelectorAsSelector(sts.Spec.Selector)
	if err != nil {
		return false, fmt.Errorf("statefulset selector %s/%s: %w",
			pod.Namespace, owner.Name, err)
	}
	peers, err := p.cs.CoreV1().Pods(pod.Namespace).List(ctx,
		metav1.ListOptions{LabelSelector: sel.String()})
	if err != nil {
		return false, fmt.Errorf("list peer pods of %s/%s: %w",
			pod.Namespace, owner.Name, err)
	}
	// BUG-C2: quorum must be verified against the DESIRED membership,
	// not just "every listed peer is Ready" — a scaled-down or
	// mid-churn set where fewer than spec.replicas pods even exist
	// cannot prove the delete leaves quorum intact. Require the full
	// pod count AND replicas-1 READY peers (the suspended pod itself
	// holds the remaining vote).
	if sts.Spec.Replicas == nil {
		return false, nil
	}
	want := int(*sts.Spec.Replicas)
	if len(peers.Items) < want {
		return false, nil
	}
	readyPeers := 0
	for i := range peers.Items {
		peer := &peers.Items[i]
		if peer.UID == pod.UID {
			continue
		}
		if shared.PodReadyCond(peer) {
			readyPeers++
		}
	}
	if readyPeers < want-1 {
		return false, nil
	}
	return true, nil
}

// checkRabbitMQSuspendedPods heals the RabbitMQ suspended-listener
// wedge: a pod whose containers all started but never went Ready is
// partitioned from its own cluster while holding a peer slot. Stuck
// >=10m AND all other replicas Ready (quorum survives) → delete the
// pod so the StatefulSet controller brings up a clean replica; the
// RabbitMQSuspendedHealsTotal counter records each heal.
func (p *clusterHealthProber) checkRabbitMQSuspendedPods(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()
	p.mu.Lock()
	if p.rbSuspendedSince == nil {
		p.rbSuspendedSince = map[string]time.Time{}
	}
	if p.rbHealed == nil {
		p.rbHealed = map[string]time.Time{}
	}
	p.mu.Unlock()

	pods, err := p.cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx,
		metav1.ListOptions{LabelSelector: rabbitComponentLabel})
	if err != nil {
		return probeResult{infra: fmt.Errorf("list rabbitmq pods: %w", err)}
	}

	live := map[string]bool{} // "ns/pod/uid" suspended signatures this sweep
	var due []corev1.Pod
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !rabbitSuspended(pod) {
			continue
		}
		key := pod.Namespace + "/" + pod.Name + "/" + string(pod.UID)
		live[key] = true
		p.mu.Lock()
		first, ok := p.rbSuspendedSince[key]
		if !ok {
			p.rbSuspendedSince[key] = now
		}
		p.mu.Unlock()
		if !ok {
			log.Info("rabbitmq suspended-listener signature — tracking first-seen",
				"pod", pod.Namespace+"/"+pod.Name)
			continue
		}
		if now.Sub(first) >= rabbitSuspendedMinAge {
			due = append(due, *pod)
		}
	}
	p.mu.Lock()
	for k := range p.rbSuspendedSince {
		if !live[k] {
			delete(p.rbSuspendedSince, k)
		}
	}
	p.mu.Unlock()

	// Maintenance mutex — evaluated once per sweep and only when
	// there is something to delete: pod kills during a drain/upgrade
	// are exactly what the mutex exists to prevent; "cannot verify"
	// fails closed.
	var maintHeld bool
	var maintWhy string
	var maintErr error
	if len(due) > 0 {
		maintHeld, maintWhy, maintErr = shared.MaintenanceActive(ctx, p.cs, p.dyn)
		if maintErr != nil {
			metrics.IncError(clusterHealthQueue)
			log.Info("WARN: maintenance check unverifiable — heals deferred (fail closed)",
				"error", maintErr)
		}
	}
	for i := range due {
		pod := &due[i]
		key := pod.Namespace + "/" + pod.Name
		if maintErr != nil || maintHeld {
			log.Info("maintenance gate — suspended rabbitmq pod kept",
				"pod", key, "why", maintWhy)
			continue
		}
		p.mu.Lock()
		last, ok := p.rbHealed[key]
		p.mu.Unlock()
		if ok && now.Sub(last) < rabbitHealCooldown {
			log.Info("skip heal: rabbitmq pod inside cooldown",
				"pod", key, "ago", now.Sub(last).Truncate(time.Minute))
			continue
		}
		safe, err := p.rabbitQuorumSafe(ctx, pod)
		if err != nil {
			metrics.IncError(clusterHealthQueue)
			log.Info("WARN: quorum check failed — heal deferred",
				"pod", key, "error", err)
			continue
		}
		if !safe {
			log.Info("quorum unsafe — suspended rabbitmq pod kept (peers not all Ready)",
				"pod", key)
			continue
		}
		uid := pod.UID
		if err := p.cs.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
			metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid},
			}); err != nil {
			metrics.IncError(clusterHealthQueue)
			log.Error(err, "suspended rabbitmq pod delete failed", "pod", key)
			continue
		}
		p.mu.Lock()
		p.rbHealed[key] = now
		p.mu.Unlock()
		metrics.RabbitMQSuspendedHealsTotal.
			WithLabelValues(pod.Namespace, pod.Name).Inc()
		log.Info("DELETE: suspended-listener rabbitmq pod — quorum verified",
			"pod", key)
	}

	if len(due) == 0 {
		return probeResult{pass: true}
	}
	names := make([]string, 0, len(due))
	for i := range due {
		names = append(names, due[i].Namespace+"/"+due[i].Name)
	}
	sort.Strings(names)
	return probeResult{why: fmt.Sprintf(
		"rabbitmq pods running suspended >=%s: %s",
		rabbitSuspendedMinAge, strings.Join(names, ", "))}
}

// ---------------------------------------------------------------------------
// localpv-stranded-pods (W7-C4) — local-PV dead-node diagnostics +
// ephemeral-PVC rescue + provisioner watchdog.
// ---------------------------------------------------------------------------

// W7-C4 — localpv-stranded-pods knobs.
const (
	// localPVStrandedMinAge: a Pending pod must be this old before
	// its bound PV's node gets audited — younger pods may still be
	// pulling images or waiting on the scheduler, not stranded.
	localPVStrandedMinAge = 5 * time.Minute
	// localPVEphemeralHealMinAge: a stranded ephemeral pod must
	// persist this long before the PVC+pod delete fires — longer
	// than the gauge window so a flap cannot reap a volume.
	localPVEphemeralHealMinAge   = 10 * time.Minute
	localPVEphemeralHealCooldown = 30 * time.Minute
	// localPVEphemeralAnno opts any workload into the disposable-
	// volume heal — set on the pod or its PVC.
	localPVEphemeralAnno = "node.ops/ephemeral-localpv"
	// concourseWorkerNS/PodPrefix name the workload whose local
	// workdir is disposable by design — losing it on a dead node is
	// the exact rescue the concourse janitor already performs while
	// the node lives.
	concourseWorkerNS        = "concourse"
	concourseWorkerPodPrefix = "concourse-worker"
	// pvcStalledMinAge is the pending window for the provisioner
	// watchdog: a PVC pending this long on the hostpath class while
	// Ready workers exist means the provisioner wedged.
	pvcStalledMinAge           = 15 * time.Minute
	pvcProvisionerHealCooldown = time.Hour
	openebsHostpathSC          = "openebs-hostpath"
	openebsProvisionerNS       = "openebs"
	openebsProvisionerPrefix   = "openebs-localpv-provisioner"
	openebsProvisionerName     = "openebs-localpv-provisioner"
	// Stranded-reason gauge label values.
	strandedReasonMissingNode  = "missing_node"
	strandedReasonOutOfService = "out_of_service"
	strandedReasonNotReady     = "not_ready"
	strandedReasonCordoned     = "cordoned"
)

// strandedHeal is one pod+PVC pair eligible for the ephemeral-volume
// rescue — carried out of the pod scan so the maintenance mutex is
// evaluated once per sweep.
type strandedHeal struct {
	pod    *corev1.Pod
	pvc    *corev1.PersistentVolumeClaim
	node   string
	reason string
}

// localPVNodeNames extracts the hostnames a PV's required
// nodeAffinity pins it to — the local volume can only ever exist on
// those nodes.
func localPVNodeNames(pv *corev1.PersistentVolume) []string {
	na := pv.Spec.NodeAffinity
	if na == nil || na.Required == nil {
		return nil
	}
	var out []string
	for _, term := range na.Required.NodeSelectorTerms {
		for _, expr := range term.MatchExpressions {
			if expr.Key != corev1.LabelHostname ||
				expr.Operator != corev1.NodeSelectorOpIn {
				continue
			}
			out = append(out, expr.Values...)
		}
	}
	return out
}

// strandedNodeReason classifies a PV-pinned node that can never host
// the pod again — "" when the node is fine (the pod pends for some
// other reason: CPU, scheduling, image).
func strandedNodeReason(nodes map[string]*corev1.Node, name string) string {
	n := nodes[name]
	if n == nil {
		return strandedReasonMissingNode
	}
	if shared.HasTaint(n.Spec.Taints, corev1.TaintNodeOutOfService) {
		return strandedReasonOutOfService
	}
	if !shared.NodeReady(n) {
		return strandedReasonNotReady
	}
	if n.Spec.Unschedulable {
		return strandedReasonCordoned
	}
	return ""
}

// ephemeralLocalPV reports whether the workload's local volume is
// disposable: concourse-worker workdirs (rebuilt by the init
// container on the new node) or anything explicitly annotated
// node.ops/ephemeral-localpv on the pod or the PVC.
func ephemeralLocalPV(pod *corev1.Pod, pvc *corev1.PersistentVolumeClaim) bool {
	if pod.Namespace == concourseWorkerNS &&
		strings.HasPrefix(pod.Name, concourseWorkerPodPrefix) {
		return true
	}
	return pod.Annotations[localPVEphemeralAnno] == "true" ||
		pvc.Annotations[localPVEphemeralAnno] == "true"
}

// checkLocalPVStrandedPods covers the two local-PV failure shapes
// that leave workloads Pending forever with no signal:
//
//	a) STRANDED — a Pending pod's bound PVC points at a PV whose
//	   nodeAffinity pins it to a node that is missing, out-of-
//	   service, NotReady or cordoned. The volume can never follow
//	   the pod to a new node, so the pod pends forever. Every such
//	   pod emits localpv_stranded_pods=1 — and for workloads whose
//	   volume is disposable (concourse-worker, or pod/PVC annotated
//	   node.ops/ephemeral-localpv) stranded on a confirmed-gone
//	   node (missing or out-of-service) the heal deletes PVC+pod so
//	   the StatefulSet rebinds on a live node while the Released PV
//	   gets swept by the node-host-agent. Database volumes are
//	   NEVER touched — alerting only.
//	b) STALLED — a Pending pod waits on a Pending openebs-hostpath
//	   PVC while Ready+schedulable workers exist: the localpv
//	   provisioner wedged. pvc_provisioning_stalled=1 fires and —
//	   outside maintenance, past the 1h cooldown — the provisioner
//	   pod is deleted to force a resync.
func (p *clusterHealthProber) checkLocalPVStrandedPods(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	now := p.now()
	p.mu.Lock()
	if p.localPVEmitted == nil {
		p.localPVEmitted = map[string]bool{}
	}
	if p.pvcStalledEmitted == nil {
		p.pvcStalledEmitted = map[string]bool{}
	}
	if p.localPVHealed == nil {
		p.localPVHealed = map[string]time.Time{}
	}
	if p.pvcProvHealed == nil {
		p.pvcProvHealed = map[string]time.Time{}
	}
	p.mu.Unlock()

	nodes, err := shared.ListNodes(ctx, p.cs)
	if err != nil {
		return probeResult{infra: fmt.Errorf("list nodes: %w", err)}
	}
	nodesByName := make(map[string]*corev1.Node, len(nodes))
	hasSchedulableWorker := false
	for i := range nodes {
		nodesByName[nodes[i].Name] = &nodes[i]
		if shared.NodeReady(&nodes[i]) && !nodes[i].Spec.Unschedulable &&
			!shared.IsControlPlane(&nodes[i]) {
			hasSchedulableWorker = true
		}
	}

	// Paged cluster-wide reads — the same full-truth posture as the
	// masterless EndpointSlice census: a partial read cannot tell
	// "stranded" from "no data", so a list error aborts the check.
	pvsByName := map[string]*corev1.PersistentVolume{}
	pvOpts := metav1.ListOptions{Limit: healthListPageSize}
	for {
		page, err := p.cs.CoreV1().PersistentVolumes().List(ctx, pvOpts)
		if err != nil {
			return probeResult{infra: fmt.Errorf("list persistentvolumes: %w", err)}
		}
		for i := range page.Items {
			pvsByName[page.Items[i].Name] = &page.Items[i]
		}
		if page.Continue == "" {
			break
		}
		pvOpts.Continue = page.Continue
	}
	pvcsByKey := map[string]*corev1.PersistentVolumeClaim{}
	pvcOpts := metav1.ListOptions{Limit: healthListPageSize}
	for {
		page, err := p.cs.CoreV1().PersistentVolumeClaims(metav1.NamespaceAll).
			List(ctx, pvcOpts)
		if err != nil {
			return probeResult{infra: fmt.Errorf("list persistentvolumeclaims: %w", err)}
		}
		for i := range page.Items {
			pvcsByKey[page.Items[i].Namespace+"/"+page.Items[i].Name] = &page.Items[i]
		}
		if page.Continue == "" {
			break
		}
		pvcOpts.Continue = page.Continue
	}

	emitted := map[string]bool{} // "ns/pod/pvc/node/reason" this sweep
	stalled := map[string]bool{} // "ns/pvc/storageclass" this sweep
	var heals []strandedHeal

	podOpts := metav1.ListOptions{
		FieldSelector: "status.phase=Pending",
		Limit:         healthListPageSize,
	}
	for {
		page, err := p.cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx, podOpts)
		if err != nil {
			return probeResult{infra: fmt.Errorf("list pods: %w", err)}
		}
		for i := range page.Items {
			pod := &page.Items[i]
			if pod.Status.Phase != corev1.PodPending {
				continue // mirrors the FieldSelector for fake clients
			}
			age := now.Sub(pod.CreationTimestamp.Time)
			if age < localPVStrandedMinAge {
				continue
			}
			for _, vol := range pod.Spec.Volumes {
				claim := vol.PersistentVolumeClaim
				if claim == nil {
					continue
				}
				pvc := pvcsByKey[pod.Namespace+"/"+claim.ClaimName]
				if pvc == nil {
					continue
				}
				// Branch A — bound local PV on an unavailable node.
				if pvc.Status.Phase == corev1.ClaimBound &&
					pvc.Spec.VolumeName != "" {
					if pv := pvsByName[pvc.Spec.VolumeName]; pv != nil {
						for _, node := range localPVNodeNames(pv) {
							reason := strandedNodeReason(nodesByName, node)
							if reason == "" {
								continue
							}
							key := pod.Namespace + "/" + pod.Name + "/" +
								pvc.Name + "/" + node + "/" + reason
							emitted[key] = true
							metrics.LocalPVStrandedPods.WithLabelValues(
								pod.Namespace, pod.Name, pvc.Name, node, reason).Set(1)
							// Confirmed-gone nodes only: NotReady/
							// cordoned can come back — a missing or
							// fenced (out-of-service) node cannot.
							if ephemeralLocalPV(pod, pvc) &&
								(reason == strandedReasonMissingNode ||
									reason == strandedReasonOutOfService) &&
								age >= localPVEphemeralHealMinAge {
								heals = append(heals, strandedHeal{
									pod: pod, pvc: pvc, node: node, reason: reason})
							}
						}
					}
				}
				// Branch B — claim still Pending on the hostpath
				// provisioner while schedulable workers exist.
				if pvc.Status.Phase == corev1.ClaimPending &&
					hasSchedulableWorker &&
					pvc.Spec.StorageClassName != nil &&
					*pvc.Spec.StorageClassName == openebsHostpathSC &&
					age >= pvcStalledMinAge {
					key := pod.Namespace + "/" + pvc.Name + "/" + openebsHostpathSC
					stalled[key] = true
					metrics.PVCProvisioningStalled.WithLabelValues(
						pod.Namespace, pvc.Name, openebsHostpathSC).Set(1)
				}
			}
		}
		if page.Continue == "" {
			break
		}
		podOpts.Continue = page.Continue
	}

	// Prune the gauges' series for tuples not re-seen — same
	// DeleteLabelValues hygiene as stsZeroEmitted.
	p.mu.Lock()
	for k := range p.localPVEmitted {
		if emitted[k] {
			continue
		}
		if parts := strings.SplitN(k, "/", 5); len(parts) == 5 {
			metrics.LocalPVStrandedPods.DeleteLabelValues(
				parts[0], parts[1], parts[2], parts[3], parts[4])
		}
		delete(p.localPVEmitted, k)
	}
	maps.Copy(p.localPVEmitted, emitted)
	for k := range p.pvcStalledEmitted {
		if stalled[k] {
			continue
		}
		if parts := strings.SplitN(k, "/", 3); len(parts) == 3 {
			metrics.PVCProvisioningStalled.DeleteLabelValues(
				parts[0], parts[1], parts[2])
		}
		delete(p.pvcStalledEmitted, k)
	}
	maps.Copy(p.pvcStalledEmitted, stalled)
	p.mu.Unlock()

	// The maintenance mutex is evaluated once per sweep and only
	// when there is something to delete — pod/PVC kills during a
	// drain are exactly what it exists to prevent; "cannot verify"
	// fails closed.
	var maintHeld bool
	var maintWhy string
	var maintErr error
	if len(heals) > 0 || len(stalled) > 0 {
		maintHeld, maintWhy, maintErr = shared.MaintenanceActive(ctx, p.cs, p.dyn)
		if maintErr != nil {
			metrics.IncError(clusterHealthQueue)
			log.Info("WARN: maintenance check unverifiable — localpv heals deferred (fail closed)",
				"error", maintErr)
		}
	}
	for i := range heals {
		h := &heals[i]
		pvcKey := h.pvc.Namespace + "/" + h.pvc.Name
		if maintErr != nil || maintHeld {
			log.Info("maintenance gate — stranded ephemeral pvc kept",
				"pvc", pvcKey, "why", maintWhy)
			continue
		}
		p.mu.Lock()
		last, ok := p.localPVHealed[pvcKey]
		p.mu.Unlock()
		if ok && now.Sub(last) < localPVEphemeralHealCooldown {
			log.Info("skip heal: ephemeral localpv inside cooldown",
				"pvc", pvcKey, "ago", now.Sub(last).Truncate(time.Minute))
			continue
		}
		// PVC first, then the pod — the claim release flips the PV
		// to Released so the node-host-agent sweeps it, and the pod
		// delete lets the StatefulSet rebind onto a live node. UID
		// preconditions close the list→delete TOCTOU on both.
		pvcUID := h.pvc.UID
		pvcErr := p.cs.CoreV1().PersistentVolumeClaims(h.pvc.Namespace).
			Delete(ctx, h.pvc.Name, metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &pvcUID},
			})
		switch {
		case pvcErr == nil || apierrors.IsNotFound(pvcErr):
			// NotFound: the claim vanished between list and heal —
			// the release half is already done, still free the pod.
		case apierrors.IsForbidden(pvcErr):
			// RBAC-denied is permanent (PVC delete is only granted
			// via the concourse Role — an ephemeral-localpv opt-in
			// elsewhere can never succeed). Stamp the cooldown so
			// the check doesn't error-loop every sweep, keep the
			// pod, and surface once.
			metrics.IncError(clusterHealthQueue)
			log.Error(pvcErr, "ephemeral localpv pvc delete forbidden — RBAC scope blocks the heal; stamping cooldown",
				"pvc", pvcKey)
			p.mu.Lock()
			p.localPVHealed[pvcKey] = now
			p.mu.Unlock()
			continue
		default:
			metrics.IncError(clusterHealthQueue)
			log.Error(pvcErr, "ephemeral localpv pvc delete failed", "pvc", pvcKey)
			continue
		}
		podUID := h.pod.UID
		if err := p.cs.CoreV1().Pods(h.pod.Namespace).Delete(ctx, h.pod.Name,
			metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &podUID},
			}); err != nil && !apierrors.IsNotFound(err) {
			metrics.IncError(clusterHealthQueue)
			log.Error(err, "stranded pod delete failed",
				"pod", h.pod.Namespace+"/"+h.pod.Name)
			continue
		}
		p.mu.Lock()
		p.localPVHealed[pvcKey] = now
		p.mu.Unlock()
		metrics.LocalPVEphemeralHealsTotal.
			WithLabelValues(h.pvc.Namespace, h.pvc.Name, h.node).Inc()
		log.Info("DELETE: ephemeral localpv pvc+pod stranded on a confirmed-dead node — StatefulSet rebinds on a live node",
			"pvc", pvcKey, "pod", h.pod.Namespace+"/"+h.pod.Name,
			"node", h.node, "reason", h.reason)
	}
	if len(stalled) > 0 && maintErr == nil && !maintHeld {
		p.healLocalPVProvisioner(ctx, log, now)
	}

	if len(emitted) == 0 && len(stalled) == 0 {
		return probeResult{pass: true}
	}
	keys := make([]string, 0, len(emitted)+len(stalled))
	for k := range emitted {
		keys = append(keys, k)
	}
	for k := range stalled {
		keys = append(keys, "stalled:"+k)
	}
	sort.Strings(keys)
	return probeResult{why: fmt.Sprintf(
		"localpv-stranded/stalled volumes: %s", strings.Join(keys, ", "))}
}

// healLocalPVProvisioner deletes the openebs-localpv-provisioner
// pod(s) — the same re-sync nudge every operator heal here applies.
// Pending hostpath claims while Ready workers exist mean the
// provisioner missed a watch event; a restart makes it re-list and
// provision. 1h cooldown (in-RAM — the pod itself is the heal
// target, nothing else can carry the stamp).
func (p *clusterHealthProber) healLocalPVProvisioner(ctx context.Context,
	log logr.Logger, now time.Time) {

	p.mu.Lock()
	last, ok := p.pvcProvHealed[openebsProvisionerName]
	p.mu.Unlock()
	if ok && now.Sub(last) < pvcProvisionerHealCooldown {
		log.Info("skip heal: localpv provisioner inside cooldown",
			"ago", now.Sub(last).Truncate(time.Minute))
		return
	}
	pods, err := p.cs.CoreV1().Pods(openebsProvisionerNS).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: list provisioner pods failed — heal deferred",
			"error", err)
		return
	}
	deleted := false
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !strings.HasPrefix(pod.Name, openebsProvisionerPrefix) {
			continue
		}
		uid := pod.UID
		if err := p.cs.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
			metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid},
			}); err != nil {
			metrics.IncError(clusterHealthQueue)
			log.Error(err, "localpv provisioner delete failed",
				"pod", pod.Namespace+"/"+pod.Name)
			continue
		}
		deleted = true
		log.Info("DELETE: wedged localpv provisioner — stalled claims need a resync",
			"pod", pod.Namespace+"/"+pod.Name)
	}
	if !deleted {
		return
	}
	p.mu.Lock()
	p.pvcProvHealed[openebsProvisionerName] = now
	p.mu.Unlock()
	metrics.PVCProvisionerHealsTotal.
		WithLabelValues(openebsProvisionerName).Inc()
}

// ---------------------------------------------------------------------------
// olm-subscription-health (W7-C5) — OLM CSV / webhook cert /
// subscription guard + olm-operator auto-heal.
// ---------------------------------------------------------------------------

// W7-C5 — olm-subscription-health knobs.
const (
	// olmUnhealthyMinAge: an unhealthy CSV/Subscription signature
	// must persist this long before the gauge fires — CSVs
	// legitimately sit in Installing/Replacing during upgrades.
	olmUnhealthyMinAge = 15 * time.Minute
	// olmHealMinAge: a CSV stuck or overdue on webhook cert
	// rotation this long triggers the olm-operator pod delete.
	olmHealMinAge   = 20 * time.Minute
	olmHealCooldown = time.Hour
	// olmOperatorNS/PodPrefix locate the operator pods the heal
	// deletes to force CSV/webhook-cert reconciliation.
	olmOperatorNS        = "olm"
	olmOperatorPodPrefix = "olm-operator"
	// OLM kind label values for the gauge.
	olmKindCSV          = "ClusterServiceVersion"
	olmKindSubscription = "Subscription"
	// Unhealthy-reason gauge label values.
	olmReasonCSVStuck         = "csv_not_succeeded"
	olmReasonCertOverdue      = "cert_rotation_overdue"
	olmReasonCatalogUnhealthy = "catalog_sources_unhealthy"
	olmReasonResolutionFailed = "resolution_failed"
)

// OLM GVRs — dynamic-client reads, skipped gracefully when the CRDs
// are not installed on a cluster.
var (
	olmCSVGVR = schema.GroupVersionResource{
		Group: "operators.coreos.com", Version: "v1alpha1",
		Resource: "clusterserviceversions"}
	olmSubGVR = schema.GroupVersionResource{
		Group: "operators.coreos.com", Version: "v1alpha1",
		Resource: "subscriptions"}
)

// checkOLMHealth audits the OLM control plane's two user-visible
// surfaces — ClusterServiceVersions and Subscriptions. Unlike
// cert-manager operators, OLM manages and rotates its operands'
// webhook TLS itself via the CSV, so a wedged olm-operator silently
// expires every admission webhook it owns (the NHC/SNR paralysis
// scenario: the remediation operator's webhook dies exactly when a
// node needs fencing):
//
//   - CSV status.phase != "Succeeded" — an install wedged mid-flight;
//   - CSV status.certsRotateAt in the past — the webhook cert
//     rotation OLM owes the operand never landed;
//   - Subscription conditions CatalogSourcesUnhealthy=True /
//     ResolutionFailed=True — a subscription that can no longer
//     resolve its package.
//
// A signature must persist olmUnhealthyMinAge before
// olm_unhealthy_resources=1 fires; a CSV stuck or cert-overdue past
// olmHealMinAge additionally deletes the olm-operator pod (outside
// maintenance, 1h cooldown) to force the missed reconciliation.
func (p *clusterHealthProber) checkOLMHealth(ctx context.Context) probeResult {
	log := logf.FromContext(ctx)
	// The CR scans and the maintenance mutex both need dyn — a
	// missing client is a wiring bug, not "no signal".
	if p.dyn == nil {
		return probeResult{infra: fmt.Errorf(
			"no dynamic client — olm health check unverifiable")}
	}
	now := p.now()
	p.mu.Lock()
	if p.olmFirstSeen == nil {
		p.olmFirstSeen = map[string]time.Time{}
	}
	if p.olmEmitted == nil {
		p.olmEmitted = map[string]bool{}
	}
	if p.olmHealed == nil {
		p.olmHealed = map[string]time.Time{}
	}
	p.mu.Unlock()

	// live signatures keyed "kind/ns/name/reason".
	live := map[string]bool{}
	csvs, err := p.dyn.Resource(olmCSVGVR).List(ctx, metav1.ListOptions{})
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		// OLM not installed on this cluster — nothing to audit.
	case err != nil:
		return probeResult{infra: fmt.Errorf("list clusterserviceversions: %w", err)}
	default:
		for i := range csvs.Items {
			csv := &csvs.Items[i]
			obj := olmKindCSV + "/" + csv.GetNamespace() + "/" + csv.GetName()
			phase, _, _ := unstructured.NestedString(csv.Object, "status", "phase")
			if phase != "Succeeded" {
				live[obj+"/"+olmReasonCSVStuck] = true
			}
			if ts, found, _ := unstructured.NestedString(
				csv.Object, "status", "certsRotateAt"); found && ts != "" {
				if t, err := time.Parse(time.RFC3339, ts); err == nil && now.After(t) {
					live[obj+"/"+olmReasonCertOverdue] = true
				}
			}
		}
	}
	subs, err := p.dyn.Resource(olmSubGVR).List(ctx, metav1.ListOptions{})
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
	case err != nil:
		return probeResult{infra: fmt.Errorf("list subscriptions: %w", err)}
	default:
		for i := range subs.Items {
			sub := &subs.Items[i]
			obj := olmKindSubscription + "/" +
				sub.GetNamespace() + "/" + sub.GetName()
			for _, c := range shared.ReadyConds(sub) {
				ctype, _ := c["type"].(string)
				cstatus, _ := c["status"].(string)
				if cstatus != "True" {
					continue
				}
				switch ctype {
				case "CatalogSourcesUnhealthy":
					live[obj+"/"+olmReasonCatalogUnhealthy] = true
				case "ResolutionFailed":
					live[obj+"/"+olmReasonResolutionFailed] = true
				}
			}
		}
	}

	emitted := map[string]bool{}     // keys past the gauge window
	healReasons := map[string]bool{} // reasons past the heal window (CSV only)
	p.mu.Lock()
	for k := range p.olmFirstSeen {
		if !live[k] {
			delete(p.olmFirstSeen, k)
		}
	}
	for k := range live {
		first, ok := p.olmFirstSeen[k]
		if !ok {
			p.olmFirstSeen[k] = now
			log.Info("olm unhealthy signature — tracking first-seen",
				"signature", k)
			continue
		}
		if now.Sub(first) < olmUnhealthyMinAge {
			continue
		}
		emitted[k] = true
		parts := strings.SplitN(k, "/", 4)
		metrics.OLMUnhealthyResources.
			WithLabelValues(parts[0], parts[1], parts[2], parts[3]).Set(1)
		// The heal is CSV-scoped: a subscription failure is the
		// catalog's problem, not olm-operator's queue.
		if parts[0] == olmKindCSV && now.Sub(first) >= olmHealMinAge {
			healReasons[parts[3]] = true
		}
	}
	for k := range p.olmEmitted {
		if emitted[k] {
			continue
		}
		if parts := strings.SplitN(k, "/", 4); len(parts) == 4 {
			metrics.OLMUnhealthyResources.DeleteLabelValues(
				parts[0], parts[1], parts[2], parts[3])
		}
		delete(p.olmEmitted, k)
	}
	maps.Copy(p.olmEmitted, emitted)
	p.mu.Unlock()

	if len(healReasons) > 0 {
		reasons := make([]string, 0, len(healReasons))
		for r := range healReasons {
			reasons = append(reasons, r)
		}
		sort.Strings(reasons)
		p.healOLMOperator(ctx, log, reasons, now)
	}

	if len(emitted) == 0 {
		return probeResult{pass: true}
	}
	keys := make([]string, 0, len(emitted))
	for k := range emitted {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return probeResult{why: fmt.Sprintf(
		"olm resources unhealthy >=%s: %s",
		olmUnhealthyMinAge, strings.Join(keys, ", "))}
}

// healOLMOperator deletes the olm-operator pod(s) — a wedged
// operator stops reconciling CSVs and stops rotating the webhook
// certificates it owns, so a restart forces both queues to re-list.
// Gates: the 1h in-RAM cooldown (the pod is the heal target —
// nothing else can carry the stamp) and the maintenance mutex, same
// shape as every pod-delete heal in this package.
func (p *clusterHealthProber) healOLMOperator(ctx context.Context,
	log logr.Logger, reasons []string, now time.Time) {

	p.mu.Lock()
	last, ok := p.olmHealed[olmOperatorPodPrefix]
	p.mu.Unlock()
	if ok && now.Sub(last) < olmHealCooldown {
		log.Info("skip heal: olm-operator inside cooldown",
			"ago", now.Sub(last).Truncate(time.Minute))
		return
	}
	held, why, err := shared.MaintenanceActive(ctx, p.cs, p.dyn)
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: maintenance check unverifiable — heal deferred (fail closed)",
			"error", err)
		return
	}
	if held {
		log.Info("maintenance in progress — heal deferred", "why", why)
		return
	}
	pods, err := p.cs.CoreV1().Pods(olmOperatorNS).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		metrics.IncError(clusterHealthQueue)
		log.Info("WARN: list olm-operator pods failed — heal deferred",
			"error", err)
		return
	}
	deleted := false
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !strings.HasPrefix(pod.Name, olmOperatorPodPrefix) {
			continue
		}
		uid := pod.UID
		if err := p.cs.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name,
			metav1.DeleteOptions{
				Preconditions: &metav1.Preconditions{UID: &uid},
			}); err != nil {
			metrics.IncError(clusterHealthQueue)
			log.Error(err, "olm-operator delete failed",
				"pod", pod.Namespace+"/"+pod.Name)
			continue
		}
		deleted = true
		log.Info("DELETE: wedged olm-operator — stuck CSV/cert-rotation queues need a resync",
			"pod", pod.Namespace+"/"+pod.Name,
			"reasons", strings.Join(reasons, ","))
	}
	if !deleted {
		return
	}
	p.mu.Lock()
	p.olmHealed[olmOperatorPodPrefix] = now
	p.mu.Unlock()
	for _, r := range reasons {
		metrics.OLMOperatorHealsTotal.WithLabelValues(r).Inc()
	}
}
