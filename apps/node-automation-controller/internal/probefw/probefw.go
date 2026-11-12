// Package probefw is the framework half of the cluster-health probe
// sweep: the dependencies every check shares (Deps), the resolved
// HEALTH_* knobs (Config), the per-check verdict (Result) and the
// uniform Check shape the root clusterhealthprobes registry sweeps.
//
// Each check lives in a domain subpackage under internal/health and
// exposes a New(*Deps) Check constructor; the registry's health
// CheckReg rows (collected into shared.Deps.CheckRegs) are the
// single sweep-order list. probefw sits at internal/ top level — a
// leaf like platform/metrics/promq — because shared.CheckReg.New is
// typed `func(*probefw.Deps) probefw.Check`: the package must be
// importable by the shared contract layer, which the health domain
// tree can never be (depguard + the import cycle probefw → shared
// it would force). NewDeps takes the dependency fields verbatim
// (not shared.Deps) for the same reason.
package probefw

import (
	"context"
	"net"
	"net/http"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/maintenance"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
	hosthttpx "github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/httpx"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// HealthListPageSize bounds the cluster-wide EndpointSlice list the
// masterless check pages through — same pagination posture as the
// webhook guard's census. Kept as an exported alias of the shared
// page bound so the domain checks' spelling stays stable.
const HealthListPageSize = kube.DefaultListPageSize

// HeavyScanCycles is the internal cadence divider for the cluster's
// heaviest censuses — the checks that page EVERY ConfigMap/Secret
// (or the full pull-secret reference set) cluster-wide cannot afford
// a fresh read every 5m sweep. A check counts its Runs and audits on
// cycles 1, 1+HeavyScanCycles, … — every 6th sweep ≈ 30m at the
// default interval — carrying its last emitted tuples and findings
// forward between audits (state.GaugeLedger.Last + a stored finding
// slice) so neither the gauge nor the verdict flaps on "not
// evaluated this cycle". Bloat/secret-hygiene drift is slow; a
// 30-minute detection bound is the right cost/benefit.
const HeavyScanCycles = 6

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
// client the metrics-backed checks share. The sweep drives checks
// serially inside one shared.Periodic goroutine; per-check bodies may
// fan out into bounded worker pools, which is why the sweep snapshot
// carries a per-kind mutex per memoized read (see snapshot.go).
type Deps struct {
	// Name is the module's ops/queue name — the module's registry row
	// name, stamped by newClusterHealthProber; it labels the
	// run-error counters and the registered periodic.
	Name string
	CS   kubernetes.Interface
	// Meta is the metadata-only client ListPartialOrFallback prefers
	// for census reads that only need ObjectMeta (ReplicaSets today)
	// — nil in tests, where the CS/Dyn fallbacks serve the same
	// objects heavier but identically.
	Meta metadata.Interface
	// NodeReader is the informer-cache reader AllNodes prefers —
	// mgr.GetClient() in production, nil in tests (falls back to the
	// direct ListNodes). Read-only censuses only; destructive acts
	// still confirm on CS.
	NodeReader kube.CachedNodeReader
	// Dyn reads the CRD types the operator-workqueue-watchdog stuck signatures scan
	// (gateway-api, scylladb, dragonflydb, flux) and the autopilot
	// Plan inside the maintenance mutex — no typed clients exist.
	Dyn dynamic.Interface
	Cfg Config
	// LookupHost is the DNS seam (tests inject a fake; production
	// uses the default resolver — in-cluster CoreDNS via
	// /etc/resolv.conf).
	LookupHost func(ctx context.Context, host string) ([]string, error)
	HTTPClient *http.Client
	Now        timex.Clock

	// Heals is the shared heal-cooldown ledger. DeletePodHeal keys
	// "selfheal/<check>/<target>"; the mesh watchdog keys bare
	// component names (cilium-operator, linkerd-destination/-identity)
	// and the db-operator masterless heals key operator names — one
	// keyspace so a heal under any spelling honors the same stamp
	// (the former deps.meshHealed map).
	Heals state.CooldownSet

	// Maintenance is the shared maintenance-mutex verdict every heal
	// gate in the sweep memoizes on — wired from
	// shared.Deps.Maintenance by the sweep module so ALL checks pay
	// one mutex evaluation per Verdict TTL across the whole sweep
	// instead of three API reads per target per check. Nil
	// (literally-constructed test Deps) falls back to the per-Deps
	// verdictFallback — same memoization, just not shared across
	// modules.
	Maintenance     *maintenance.Verdict
	verdictFallback maintenance.Verdict

	// Prom is the shared Prometheus instant-query client the
	// metrics-backed checks run through PromQuery; Timeout bounds
	// each query below the check's own deadline.
	Prom promq.Client

	// promEndpointOverride is the HEALTH_PROMETHEUS_QUERY_URL env
	// knob resolved ONCE in NewDeps — reading env inside a run is a
	// bug, so the override freezes at construction. The endpoint
	// itself still derives per call from Cfg.HTTPContent.URL (plain
	// resolved config, mutated by no production path) when no
	// override was set; "" means no override.
	promEndpointOverride string
}

// NewDeps builds the production-wired shared dependencies from the
// fields the sweep module stamps: the ops name and the clients pass
// through, and the test seams take their production defaults — the
// system DNS resolver, a plain http.Client, the real clock. The
// signature is primitives, not shared.Deps — probefw is a leaf the
// shared contract layer itself names (CheckReg.New's type), so it
// may not import shared back. nodeReader is the manager's cached
// client; nil (the literally-constructed test Deps shape) leaves the
// documented fall-back-to-ListNodes posture.
//
// Prom deliberately shares the HTTPClient POINTER: tests swap
// d.HTTPClient post-construction and PromQuery re-read the field per
// call, so the one seam serves both the plain-HTTP checks and the
// PromQL-backed ones. Timeout bounds each query by the check timeout
// — the posture the retired promInstantQuery encoded inline. The
// HEALTH_PROMETHEUS_QUERY_URL env override resolves ONCE here —
// reading env inside a run is a bug; the fallback derivation from
// Cfg.HTTPContent.URL stays live because Cfg is resolved config,
// not env.
func NewDeps(name string, cs kubernetes.Interface, dyn dynamic.Interface,
	nodeReader kube.CachedNodeReader, cfg Config) *Deps {
	deps := &Deps{
		Name:       name,
		CS:         cs,
		Dyn:        dyn,
		NodeReader: nodeReader,
		Cfg:        cfg,
		LookupHost: (&net.Resolver{}).LookupHost,
		HTTPClient: &http.Client{Transport: hosthttpx.PooledTransport(16, nil)},
		Now:        time.Now,
	}
	deps.Prom = promq.Client{HTTP: deps.HTTPClient, Timeout: cfg.Timeouts.Check}
	deps.promEndpointOverride = envx.Getenv("HEALTH_PROMETHEUS_QUERY_URL", "")
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
