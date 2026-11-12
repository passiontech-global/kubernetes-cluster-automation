// Package apiprober ports api-backend-guard.sh
// (passiontech-fluxcd infrastructure/base/node-ops/api-lb-guard/) into
// a continuous in-agent loop, adapted to the node-local api-local-lb
// HAProxy sidecar that fronts the cluster's apiservers.
//
// Problem (incident 2026-09-17): an apiserver can be TCP+/readyz
// healthy while its watch-cache is wedged ("required revision has been
// compacted" loop) → LIST/WATCH return stale data forever. HAProxy's
// tcp-check cannot see it, so traffic keeps round-robining onto a
// poisoned backend.
//
// Functional check = two independent signals per backend (direct to
// the backend, never through the VIP):
//
//	rv_now   = consistent LIST (goes to etcd)
//	rv_cache = LIST ?resourceVersion=0 (served from watch-cache)
//
// A backend is wedged when either:
//  1. rv-gap: rv_now - rv_cache > GapMin for FailCycles consecutive
//     cycles — a long-accumulated wedge (~55k rev when observed).
//  2. frozen: rv_cache bit-identical to the previous cycle while
//     rv_now keeps advancing, for FrozenCycles consecutive cycles —
//     the early wedge signature (a fresh wedge grows ~1 rev/s and
//     takes hours to reach GapMin). An idle cluster (rv_now <=
//     rv_cache) resets the counter — standing still while idle is
//     not wedge evidence.
//
// Action: `disable server <backend>/<name>` over the HAProxy admin
// socket on wedge; `enable` after RecoverCycles consecutive fresh
// cycles. When CompanionBackends is set the action is applied on
// EVERY backend in [BackendName]+CompanionBackends (api-backend-
// guard.sh parity: a wedged controller poisons the konnectivity lane
// too — incident 2026-10-07); a "No such server" reply on a companion
// backend is a no-op, not an error.
//
// StaticBackends merges the api-backend-guard.sh API_BACKENDS model:
// "name=ip:port" entries probed directly — covers external API LB VMs
// whose `show stat` rows carry no addr (the server line uses the name
// as the address) and adds apiservers the local HAProxy does not list
// at all. Discovered servers with an empty addr resolve their Addr
// from StaticBackends by name; static entries absent from discovery
// are appended as UP servers.
//
// SAFETY FENCES (ported 1:1):
//   - NEVER disable the last usable backend — at least one backend
//     fresh this cycle must remain taking traffic.
//   - A TCP-unreachable backend is left alone (HAProxy's tcp-check
//     already marked it DOWN). But a TCP-alive backend whose queries
//     fail FailCycles in a row is an apiserver stall/wedge — worse
//     than DOWN — and is drained like a wedge. Failures classified
//     probe-side (credential file unreadable, auth 401/403, TLS
//     trust, request build) are NOT apiserver evidence — the cycle
//     is inconclusive for that backend, counts neither fresh nor
//     stale, and can never reach the DEAD verdict.
//   - Mode=dry-run (default) logs "would disable/enable" only.
//     Switch to enforce after the detection loop is verified.
package apiprober

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
)

// Mode values — the shell script's dry-run default is preserved.
const (
	ModeDryRun  = "dry-run"
	ModeEnforce = "enforce"
)

// Defaults mirror the shell script + the api-local-lb sidecar.
const (
	defaultSocketPath    = "/run/api-local-lb-admin.sock"
	defaultBackendName   = "api_local_back"
	defaultInterval      = 30 * time.Second
	defaultGapMin        = int64(10000)
	defaultFailCycles    = 2
	defaultFrozenCycles  = 2
	defaultRecoverCycles = 3
	defaultTCPTimeout    = 5 * time.Second  // `timeout 5 /dev/tcp` preflight
	defaultQueryTimeout  = 12 * time.Second // curl --max-time 12 — generous: the
	// inter-DC probe path over nebula is ~ms RTT, so a timeout class
	// failure is genuine apiserver stall evidence, not WAN latency.
	defaultTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	// LivePath is a consistent (etcd) read — no resourceVersion. The
	// nodes list is used because the SA has nodes get,list and
	// /api/v1 has no leases resource (Lease is coordination.k8s.io).
	defaultLivePath = "/api/v1/nodes?limit=1"
	// CachePath is served from the apiserver watch-cache (rv=0).
	defaultCachePath = "/api/v1/nodes?limit=1&resourceVersion=0"
	// WatchdogStateDir is the node-watchdog state dir (host mount)
	// holding the backward-compat files module 34-apiserver-backends
	// wrote: apibe-gap-<ip-dashed> (rv gap per backend, read by
	// prom_emit for node_watchdog_apiserver_backend_gap) and
	// state-apiserver-backend-stale-<ip-dashed> (read by
	// 06-kubelet-watch-wedge to gate k0sworker restarts).
	defaultWatchdogStateDir = "/host/var/lib/node-watchdog"
	// defaultGuardConfPath mirrors cmd/agent's
	// NODE_HOST_AGENT_API_GUARD_CONF default.
	defaultGuardConfPath = "/etc/api-backend-guard.conf"
)

// StaticBackend is an API_BACKENDS-style entry — an apiserver to
// probe by name + ip:port independent of `show stat` (external API LB
// VMs where the server line has no explicit address, or controllers
// missing from the local HAProxy config).
type StaticBackend struct {
	Name string
	Addr string // ip:port for direct API queries
}

// Config carries the prober's knobs — all test-injectable.
type Config struct {
	// Base is the shared watchdog-subsystem block — the probe
	// cadence, WatchdogStateDir (the apibe-*/state-apiserver-
	// backend-stale-* compat files land there) and WatchdogSrc
	// (re-reads node-watchdog.conf every cycle and merges its
	// API_BACKENDS into the static set — hostconfig rewrites the
	// conf mid-run, so a backend joining/leaving the list must
	// apply next cycle, not next agent restart) splice
	// (subframe.FromDeps). The rest of the block (clock, host root,
	// systemd, watchdog log) is carried but unused — the prober
	// writes its own apibe-* files directly, not through a
	// hoststate store.
	subframe.Base
	SocketPath  string // HAProxy admin unix socket
	BackendName string // HAProxy backend holding the apiservers
	// CompanionBackends are extra HAProxy backends that receive the
	// same enable/disable actions (shell HAPROXY_BACKENDS parity) —
	// "No such server" replies on them are ignored.
	CompanionBackends []string
	// StaticBackends are API_BACKENDS-style name=ip:port entries
	// merged into the probe set (see package doc).
	StaticBackends []StaticBackend
	// GuardSrc, when set, re-reads api-backend-guard.conf every
	// cycle and overlays the keys it carries onto the
	// startup-resolved knobs (SocketPath/BackendName/
	// CompanionBackends/StaticBackends/Mode/TokenFile/CAFile and the
	// GAP_MIN/FAIL_CYCLES/FROZEN_CYCLES/RECOVER_CYCLES thresholds).
	// The conf is the managed contract on api-lb VMs — hostconfig
	// owns the file — so a key it sets wins over the Config field;
	// keys it does not set fall through. Required, not optional:
	// an agent that started BEFORE hostconfig's first conf render
	// otherwise pins the compile-time fallbacks forever (incident
	// shape: TokenFile stuck on the nonexistent SA path → every
	// probe qfailed → an enforce-mode guard would drain a healthy
	// backend ~60s post-rollout). New() auto-wires a
	// GuardReloader on NODE_HOST_AGENT_API_GUARD_CONF (default
	// /etc/api-backend-guard.conf) when GuardSrc is nil; set an
	// explicit GuardSrc to point elsewhere or at a path that never
	// exists to disable the overlay.
	GuardSrc *GuardReloader
	// envSet records which conf-overlappable knobs env explicitly
	// carried at ConfigFromEnv time — the documented precedence is
	// env > guard.conf > default, so refreshGuard's live conf
	// overlay must not shadow an env-provided field (it used to
	// shadow it outright — precedence inversion). The zero value
	// means "nothing env-protected", so hand-built Configs keep
	// the old conf-wins-everything behavior.
	envSet        guardEnvSet
	Mode          string        // dry-run | enforce
	GapMin        int64         // rv-gap wedge threshold
	FailCycles    int           // consecutive gap>GapMin OR query-fail → drain
	FrozenCycles  int           // consecutive frozen rv_cache → drain
	RecoverCycles int           // consecutive fresh → re-enable
	TCPTimeout    time.Duration // TCP preflight deadline
	QueryTimeout  time.Duration // per-query deadline
	TokenFile     string        // bearer token for API queries ("" = none)
	CAFile        string        // CA bundle for backend TLS verification
	InsecureTLS   bool          // skip backend cert verification (mirrors curl -sk)
	LivePath      string        // consistent-read URL path+query
	CachePath     string        // cached-read URL path+query
	// Base.WatchdogStateDir, when non-empty and present on disk,
	// receives the apibe-gap-*/state-apiserver-backend-stale-*
	// compat files.

	// HTTPClient, when set, is used for all API queries and overrides
	// TokenFile/CAFile/InsecureTLS — the test seam (httptest clients).
	HTTPClient *http.Client
	// DialSocket overrides the unix-socket dialer — the test seam for
	// a fake HAProxy admin socket.
	DialSocket func(ctx context.Context, path string) (net.Conn, error)
	// TCPCheck overrides the TCP preflight — the test seam for
	// reachability control per backend.
	TCPCheck func(ctx context.Context, addr string) error
}

func (c *Config) applyDefaults() {
	if c.SocketPath == "" {
		c.SocketPath = defaultSocketPath
	}
	if c.BackendName == "" {
		c.BackendName = defaultBackendName
	}
	if c.Interval <= 0 {
		c.Interval = defaultInterval
	}
	if c.Mode == "" {
		c.Mode = ModeDryRun
	}
	if c.GapMin <= 0 {
		c.GapMin = defaultGapMin
	}
	if c.FailCycles <= 0 {
		c.FailCycles = defaultFailCycles
	}
	if c.FrozenCycles <= 0 {
		c.FrozenCycles = defaultFrozenCycles
	}
	if c.RecoverCycles <= 0 {
		c.RecoverCycles = defaultRecoverCycles
	}
	if c.TCPTimeout <= 0 {
		c.TCPTimeout = defaultTCPTimeout
	}
	if c.QueryTimeout <= 0 {
		c.QueryTimeout = defaultQueryTimeout
	}
	if c.TokenFile == "" {
		c.TokenFile = defaultTokenFile
	}
	if c.CAFile == "" {
		c.CAFile = defaultCAFile
	}
	if c.LivePath == "" {
		c.LivePath = defaultLivePath
	}
	if c.CachePath == "" {
		c.CachePath = defaultCachePath
	}
	if c.WatchdogStateDir == "" {
		c.WatchdogStateDir = defaultWatchdogStateDir
	}
}

// Prober runs the wedge-detection loop.
type Prober struct {
	cfg    Config
	client *http.Client
	caKey  string // cache key of the CA bundle p.client was built with
	// caStat is the fsx.FileStatKey of the CA file p.client was
	// built with — refreshClient stats before paying caClient's
	// read+PEM-parse+sha256, which used to run every cycle even when
	// the bundle never moved.
	caStat string
	// cycleToken/cycleTokenErr/cycleTokenLoaded carry the SA bearer
	// token read ONCE per Cycle — the projected token only rotates
	// on pod restart, so listRV's per-query os.ReadFile multiplied a
	// syscall by 2×backends×cycles for nothing. Outside Cycle
	// (tests calling listRV directly) bearerToken reads fresh.
	cycleToken       string
	cycleTokenErr    error
	cycleTokenLoaded bool
	states           map[string]*backendState
	// eff is the per-cycle effective view of the knobs the guard
	// conf may carry — refreshGuard() re-derives it from GuardSrc
	// every Cycle (and once in New so unit-test entry points that
	// call Cycle internals directly still see sane values). Only
	// the Cycle goroutine reads/writes it — never exported.
	eff guardEff
	// socketAbsent is the log-once latch for the missing-socket
	// gate: the absent state logs a single informational line on
	// the transition (and one more when the socket appears), not
	// an ERROR per cycle. Only the Cycle goroutine touches it.
	socketAbsent bool
	// cycleStatics is the per-cycle snapshot of the merged static
	// backend set — resolved once in Cycle. statics() re-parses
	// node-watchdog.conf on every call (WatchdogSrc.Get re-reads
	// the file each Get), so discover's per-row staticAddr lookups
	// must not each trigger a conf parse. Nil outside Cycle →
	// staticAddr resolves fresh (direct discover calls in tests).
	cycleStatics []StaticBackend

	rvGap         *prometheus.GaugeVec
	enabled       *prometheus.GaugeVec
	probeFailures *prometheus.CounterVec // phase: tcp|query
	actions       *prometheus.CounterVec // action: disable|enable|fence_skip|dryrun_disable|dryrun_enable
	cycles        *prometheus.CounterVec // result: ok|discover_fail
	backendCount  prometheus.Gauge
	duration      prometheus.Gauge
}

// New returns a Prober, building the TLS client from the credential
// config unless Config.HTTPClient is injected, and registers metrics.
func New(cfg Config, reg prometheus.Registerer) (*Prober, error) {
	cfg.applyDefaults()
	if cfg.Mode != ModeDryRun && cfg.Mode != ModeEnforce {
		return nil, fmt.Errorf("invalid mode %q (want %q or %q)",
			cfg.Mode, ModeDryRun, ModeEnforce)
	}
	if cfg.GuardSrc == nil {
		// Auto-wire the conf cmd/agent parses once at startup: a
		// reloader keeps that layer live per cycle (hostconfig's
		// first render lands AFTER the agent starts on api-lb VMs).
		cfg.GuardSrc = NewGuardReloader(guardConfPath(), GuardDefaults{})
	}
	p := &Prober{cfg: cfg, states: map[string]*backendState{}}

	if cfg.HTTPClient != nil {
		p.client = cfg.HTTPClient
	} else if cfg.InsecureTLS {
		// explicit opt-in, mirrors curl -sk
		p.client = &http.Client{Transport: baseTransport(
			&tls.Config{InsecureSkipVerify: true})}
	} else {
		cl, key, err := caClient(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		p.client, p.caKey = cl, key
	}
	// Seed the effective knobs (and pick up any GuardSrc-carried
	// CA that differs from the startup one) so every method sees a
	// resolved view before the first Cycle.
	p.refreshGuard()

	p.rvGap = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_host_agent_apiprober_backend_rv_gap",
		Help: "rv consistent(etcd) - rv watch-cache per apiserver backend.",
	}, []string{"backend"})
	p.enabled = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "node_host_agent_apiprober_backend_enabled",
		Help: "1 = backend UP in HAProxy and not drained by this prober.",
	}, []string{"backend"})
	p.probeFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_apiprober_probe_failures_total",
		Help: "Backend probe failures by phase (tcp|query|probe_error). " +
			"probe_error = the fault is probe-side (credential/TLS), not apiserver evidence.",
	}, []string{"backend", "phase"})
	p.actions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_apiprober_actions_total",
		Help: "Guard actions per backend: disable|enable|fence_skip|dryrun_disable|dryrun_enable.",
	}, []string{"backend", "action"})
	p.cycles = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_apiprober_cycles_total",
		Help: "Probe cycles by result (ok|no_socket|discover_fail).",
	}, []string{"result"})
	p.backendCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_apiprober_backends",
		Help: "Backends discovered in the HAProxy backend last cycle.",
	})
	p.duration = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_apiprober_cycle_duration_seconds",
		Help: "Duration of the last probe cycle.",
	})

	if err := subframe.RegisterAll(reg,
		p.rvGap, p.enabled, p.probeFailures, p.actions, p.cycles,
		p.backendCount, p.duration); err != nil {
		return nil, fmt.Errorf("register apiprober metrics: %w", err)
	}
	return p, nil
}

// Name identifies the subsystem for logging.
func (p *Prober) Name() string { return "apiprober" }

// Run probes immediately, then every Interval until ctx is cancelled.
func (p *Prober) Run(ctx context.Context) {
	cycle.Every("apiprober", p.cfg.Interval, p.Cycle).Run(ctx)
}

// baseTransport clones http.DefaultTransport with our TLS config —
// cloning rather than hand-rolling a bare &http.Transport{} keeps
// the dialer/keep-alive defaults (IdleConnTimeout=0 would pin TLS
// buffers on every idle conn forever, ForceAttemptHTTP2=false falls
// back to HTTP/1.1).
func baseTransport(tlsCfg *tls.Config) *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	tr.IdleConnTimeout = 90 * time.Second
	return tr
}

func caPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates in %s", path)
	}
	return pool, nil
}

// caClient builds the probe http.Client for a CA path and returns a
// cache key (path + content hash) refreshClient compares to decide
// whether the effective CA changed. caFile="" → system roots.
func caClient(caFile string) (*http.Client, string, error) {
	tlsCfg := &tls.Config{}
	key := caFile
	if caFile != "" {
		pool, err := caPool(caFile)
		if err != nil {
			return nil, "", fmt.Errorf("load CA %s: %w", caFile, err)
		}
		tlsCfg.RootCAs = pool
		pem, _ := os.ReadFile(caFile) // caPool already read it OK
		sum := sha256.Sum256(pem)
		key = caFile + "@" + hex.EncodeToString(sum[:])
	}
	return &http.Client{Transport: baseTransport(tlsCfg)}, key, nil
}

// guardEnvSet marks the conf-overlappable knobs env explicitly set
// — refreshGuard consults it per field (env > guard.conf > default).
type guardEnvSet struct {
	socket, backend, companions          bool
	mode, tokenFile, caFile              bool
	gapMin, failCycles, frozen, recoverC bool
}

// guardEff is the per-cycle effective view of the knobs
// api-backend-guard.conf may carry (see Config.GuardSrc) — the
// startup-resolved Config value overlaid by the live conf.
type guardEff struct {
	socket     string
	backend    string
	companions []string
	statics    []StaticBackend
	mode       string
	tokenFile  string
	caFile     string
	gapMin     int64
	failCycles int
	frozen     int
	recoverC   int
}
