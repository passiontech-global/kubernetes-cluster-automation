// Package probefw is the framework half of the cluster-health probe
// sweep: the dependencies every check shares (Deps), the resolved
// HEALTH_* knobs (Config), the per-check verdict (Result) and the
// uniform Check shape the root clusterhealthprobes registry sweeps.
//
// Each check lives in a domain subpackage under internal/health and
// exposes a New(*Deps) Check constructor; the root package's
// checkDefs roster is the single sweep-order list.
package probefw

import (
	"context"
	"net/http"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/promq"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

// HealthListPageSize bounds the cluster-wide EndpointSlice list the
// masterless check pages through — same pagination posture as the
// webhook guard's census.
const HealthListPageSize = 500

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

	// Prom is the shared Prometheus instant-query client the
	// metrics-backed checks run through PromQuery; Timeout bounds
	// each query below the check's own deadline.
	Prom promq.Client
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
