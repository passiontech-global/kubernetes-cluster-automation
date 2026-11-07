// Package probefw is the framework half of the cluster-health probe
// sweep: the dependencies every check shares (Deps), the resolved
// HEALTH_* knobs (Config), the per-check verdict (Result) and the
// uniform Check shape the root clusterhealthprobes registry sweeps.
//
// Each check lives in a domain subpackage under internal/health and
// exposes a New(*Deps) Check constructor; the registry's health
// CheckReg rows (collected into shared.Deps.CheckRegs) are the
// single sweep-order list.
package probefw

import (
	"context"
	"net"
	"net/http"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

// HealthListPageSize bounds the cluster-wide EndpointSlice list the
// masterless check pages through — same pagination posture as the
// webhook guard's census. Kept as an exported alias of the shared
// page bound so the domain checks' spelling stays stable.
const HealthListPageSize = kube.DefaultListPageSize

// Result is one check's verdict. Pass=false + Infra=nil is an
// observed health failure (the metric's FAIL=1); Infra!=nil is a
// client/apiserver error — the check is still marked FAIL (it did not
// succeed) but the error also counts against the queue run errors.
type Result struct {
	Pass  bool
	Why   string
	Infra error
}

// Check is the uniform shape every sweep check satisfies — the
// per-check types each carry a Run method with this signature, so
// the registry needs no per-check adapter.
type Check interface {
	Run(ctx context.Context) Result
}

// Deps carries the genuinely shared, read-mostly dependencies every
// check needs: the module's ops/queue name, the typed and dynamic
// clients, the resolved HEALTH_* config, and the test seams
// (LookupHost, HTTPClient, Now). It also owns the state that outlives
// any single check: Heals, the shared self-heal cooldown ledger every
// pod-delete heal stamps, and Prom, the Prometheus instant-query
// client the metrics-backed checks share. The sweep runs serially
// inside one shared.Periodic goroutine — nothing locks.
type Deps struct {
	// Name is the module's ops/queue name — shared.Deps.Name stamped
	// by the module registry; it labels the run-error counters and
	// the registered periodic.
	Name string
	CS   kubernetes.Interface
	// NodeReader is the informer-cache reader AllNodes prefers —
	// mgr.GetClient() in production, nil in tests (falls back to the
	// direct ListNodes). Read-only censuses only; destructive acts
	// still confirm on CS.
	NodeReader kube.CachedNodeReader
	// Dyn reads the CRD types the W5.8 stuck signatures scan
	// (gateway-api, scylladb, dragonflydb, flux) and the autopilot
	// Plan inside the maintenance mutex — no typed clients exist.
	Dyn dynamic.Interface
	Cfg Config
	// LookupHost is the DNS seam (tests inject a fake; production
	// uses the default resolver — in-cluster CoreDNS via
	// /etc/resolv.conf).
	LookupHost func(ctx context.Context, host string) ([]string, error)
	HTTPClient *http.Client
	Now        shared.Clock

	// Heals is the shared heal-cooldown ledger. DeletePodHeal keys
	// "selfheal/<check>/<target>"; the mesh watchdog keys bare
	// component names (cilium-operator, linkerd-destination/-identity)
	// and the db-operator masterless heals key operator names — one
	// keyspace so a heal under any spelling honors the same stamp
	// (the former deps.meshHealed map).
	Heals state.CooldownSet

	// verdict memoizes the maintenance-mutex evaluation every heal
	// preamble in the sweep shares — DeletePodHeal plus every check
	// gating through HealAllowed — one evaluation per Verdict TTL
	// across the whole serial sweep instead of three API reads per
	// target per check.
	verdict kube.Verdict

	// Prom is the shared Prometheus instant-query client the
	// metrics-backed checks run through PromQuery; Timeout bounds
	// each query below the check's own deadline.
	Prom promq.Client
}

// NewDeps builds the production-wired shared dependencies from the
// module's registry-stamped shared.Deps: the ops name and the clients
// pass through, and the test seams take their production defaults —
// the system DNS resolver, a plain http.Client, the real clock.
// NodeReader is the manager's cached client; a nil Mgr (the
// literally-constructed test Deps shape shared.Deps documents)
// leaves it nil, the documented fall-back-to-ListNodes posture.
//
// Prom deliberately shares the HTTPClient POINTER: tests swap
// d.HTTPClient post-construction and PromQuery re-reads the field per
// call, so the one seam serves both the plain-HTTP checks and the
// PromQL-backed ones. Timeout bounds each query by the check timeout
// — the posture the retired promInstantQuery encoded inline.
func NewDeps(d shared.Deps, cfg Config) *Deps {
	deps := &Deps{
		Name:       d.Name,
		CS:         d.CS,
		Dyn:        d.Dyn,
		Cfg:        cfg,
		LookupHost: (&net.Resolver{}).LookupHost,
		HTTPClient: &http.Client{},
		Now:        time.Now,
	}
	if d.Mgr != nil {
		deps.NodeReader = d.Mgr.GetClient()
	}
	deps.Prom = promq.Client{HTTP: deps.HTTPClient, Timeout: cfg.Timeouts.Check}
	return deps
}

// Config carries the HEALTH_* env knobs the checker Pods read
// (HOSTNAME/TARGET_URL/MAX_FAILURES_ALLOWED/...), re-homed under a
// HEALTH_ prefix and grouped by the check (or check family) that
// consumes them. Defaults match the live check manifests.
type Config struct {
	Timeouts    TimeoutsConfig
	DNS         DNSConfig
	HTTPContent HTTPContentConfig
	Pods        PodsConfig
	Quota       QuotaConfig
	KCM         KCMConfig
	Cilium      CiliumConfig
	Datastore   DatastoreConfig
	Linkerd     LinkerdConfig
}

// TimeoutsConfig bounds remote calls at two levels: Check is the
// per-request deadline the ported checks (and the shared Prometheus
// client) wrap each remote call in; PerCheck bounds one check's whole
// share of the serial sweep.
type TimeoutsConfig struct {
	Check    time.Duration // HEALTH_CHECK_TIMEOUT
	PerCheck time.Duration // HEALTH_PER_CHECK_TIMEOUT
}

// DNSConfig — dns-status-internal (the ported dns-resolution-check):
// every hostname must resolve.
type DNSConfig struct {
	Hostnames []string // HEALTH_DNS_HOSTNAMES
}

// HTTPContentConfig — http-content-check: GET must return 200 with a
// body containing the expected string.
type HTTPContentConfig struct {
	URL      string // HEALTH_HTTP_CONTENT_URL
	Expected string // HEALTH_HTTP_EXPECTED_CONTENT
}

// PodsConfig — the pod-restarts and pod-status checks: which
// namespace to census, the restart ceiling and the young-pod grace.
type PodsConfig struct {
	Namespace    string        // HEALTH_POD_CHECK_NAMESPACE
	MaxRestarts  int32         // HEALTH_MAX_POD_RESTARTS
	SkipDuration time.Duration // HEALTH_POD_SKIP_DURATION
}

// QuotaConfig — resource-quota-check: the used/hard ceiling.
type QuotaConfig struct {
	Threshold float64 // HEALTH_RESOURCE_QUOTA_THRESHOLD
}

// KCMConfig — kcm-workqueue-watchdog (C6): how fresh the leader
// Lease's renewTime must read, and how long a freeze signature must
// persist before the gauge fires.
type KCMConfig struct {
	LeaseMaxAge  time.Duration // HEALTH_KCM_LEASE_MAX_AGE
	FreezeMinAge time.Duration // HEALTH_KCM_FREEZE_MIN_AGE
}

// CiliumConfig — the cilium nethealth knobs: the BPF map fill-ratio
// ceiling for cilium-bpf-map-pressure and the node pod-IP free-ratio
// floor for cilium-node-ipam-exhaustion. The env names carry no
// HEALTH_ prefix — they predate the port and the ops contract keeps
// them byte-stable.
type CiliumConfig struct {
	BPFMapPressureThreshold float64 // CILIUM_BPF_MAP_PRESSURE_THRESHOLD
	NodeIPAMMinFreeRatio    float64 // CILIUM_NODE_IPAM_MIN_FREE_RATIO
}

// DatastoreConfig — the datastore checks' persistence windows:
// postgres-wal-archive-guard's cnpg-health CloudNativePG signatures and
// the pvc-resize-stall-guard's stall window.
type DatastoreConfig struct {
	CNPGUnhealthyMinAge  time.Duration // HEALTH_CNPG_UNHEALTHY_MIN_AGE
	PVCResizeStallMinAge time.Duration // HEALTH_PVC_RESIZE_STALL_MIN_AGE
}

// LinkerdConfig — the linkerd nethealth knobs:
// linkerd-outlier-guard's evict kill-switch (linkerd-outlier). The env name
// carries no HEALTH_ prefix — it is an ops lever on the flags
// ConfigMap like the other sub-feature gates.
type LinkerdConfig struct {
	OutlierEvictEnabled bool // LINKERD_OUTLIER_EVICT_ENABLED
}
