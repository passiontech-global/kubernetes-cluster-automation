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
//     than DOWN — and is drained like a wedge.
//   - Mode=dry-run (default) logs "would disable/enable" only.
//     Switch to enforce after the detection loop is verified.
package apiprober

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/watchdogconf"
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
	defaultQueryTimeout  = 12 * time.Second // curl --max-time 12
	defaultTokenFile     = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultCAFile        = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
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

// Config carries the prober's knobs — all test-injectable.
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
	SocketPath  string // HAProxy admin unix socket
	BackendName string // HAProxy backend holding the apiservers
	// CompanionBackends are extra HAProxy backends that receive the
	// same enable/disable actions (shell HAPROXY_BACKENDS parity) —
	// "No such server" replies on them are ignored.
	CompanionBackends []string
	// StaticBackends are API_BACKENDS-style name=ip:port entries
	// merged into the probe set (see package doc).
	StaticBackends []StaticBackend
	// WatchdogSrc, when set, re-reads node-watchdog.conf every cycle
	// and merges its API_BACKENDS into the static set — hostconfig
	// rewrites the conf mid-run, so a backend joining/leaving the
	// list must apply next cycle, not next agent restart.
	WatchdogSrc *watchdogconf.Reloader
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
	GuardSrc      *GuardReloader
	Interval      time.Duration // probe cycle
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
	// WatchdogStateDir, when non-empty and present on disk, receives
	// the apibe-gap-*/state-apiserver-backend-stale-* compat files.
	WatchdogStateDir string

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

// backend is one server row discovered from `show stat`.
type backend struct {
	Name   string
	Addr   string // ip:port for direct API queries
	Status string // haproxy-reported status (UP, DOWN, MAINT, ...)
}

// up reports whether HAProxy considers the backend usable. An
// admin-disabled server reports MAINT — it must not count toward the
// drain fence even if its API probes are fresh.
func (b backend) up() bool { return strings.HasPrefix(b.Status, "UP") }

// maint reports an admin-disabled server (disable via socket, or the
// disable restored from server-state-file after a HAProxy restart).
// Treated like a drain for the recovery path: a backend stays
// re-enableable after RecoverCycles fresh probes even when the
// process-memory drained flag was lost to an agent restart — the
// alternative is a healthy apiserver stranded in MAINT forever.
// Caveat: this also undoes deliberate manual drains (the shell guard
// used on-disk drained-* marker files for that distinction).
func (b backend) maint() bool { return strings.HasPrefix(b.Status, "MAINT") }

// vip reports a load-balancer VIP server entry (suffix "_lb", e.g.
// api_datahub_lb in worker api-local-lb). VIP entries round-robin
// across multiple controllers, so their cached/live queries can land on
// different backends and must not be probed directly or counted toward
// the drain fence. Instead they follow sig14b semantics: disabled when
// any direct controller is wedged while >=1 direct controller remains
// fresh, and re-enabled when all controllers are healthy or when no
// direct controller is usable (least-bad).
func (b backend) vip() bool { return strings.HasSuffix(b.Name, "_lb") }

// backendState tracks per-backend consecutive-cycle counters — the
// in-memory equivalent of the shell script's $STATE_DIR files
// (qfail-, frozen-, fail-, ok-, drained-).
type backendState struct {
	qfail     int   // consecutive query failures (TCP alive)
	frozen    int   // consecutive identical rv_cache while rv_now grows
	fail      int   // consecutive gap > GapMin
	ok        int   // consecutive fully-fresh cycles
	prevCache int64 // last observed rv_cache
	hasPrev   bool
	drained   bool // we issued disable (or are tracking it)
}

// Prober runs the wedge-detection loop.
type Prober struct {
	cfg    Config
	client *http.Client
	caKey  string // cache key of the CA bundle p.client was built with
	states map[string]*backendState
	// eff is the per-cycle effective view of the knobs the guard
	// conf may carry — refreshGuard() re-derives it from GuardSrc
	// every Cycle (and once in New so unit-test entry points that
	// call Cycle internals directly still see sane values). Only
	// the Cycle goroutine reads/writes it — never exported.
	eff guardEff

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
		//nolint:gosec // explicit opt-in, mirrors curl -sk
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
		Help: "Backend probe failures by phase (tcp|query).",
	}, []string{"backend", "phase"})
	p.actions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_apiprober_actions_total",
		Help: "Guard actions per backend: disable|enable|fence_skip|dryrun_disable|dryrun_enable.",
	}, []string{"backend", "action"})
	p.cycles = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "node_host_agent_apiprober_cycles_total",
		Help: "Probe cycles by result (ok|discover_fail).",
	}, []string{"result"})
	p.backendCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_apiprober_backends",
		Help: "Backends discovered in the HAProxy backend last cycle.",
	})
	p.duration = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "node_host_agent_apiprober_cycle_duration_seconds",
		Help: "Duration of the last probe cycle.",
	})

	if reg != nil {
		for _, c := range []prometheus.Collector{
			p.rvGap, p.enabled, p.probeFailures, p.actions, p.cycles,
			p.backendCount, p.duration,
		} {
			if err := reg.Register(c); err != nil {
				return nil, fmt.Errorf("register apiprober metrics: %w", err)
			}
		}
	}
	return p, nil
}

// Name identifies the subsystem for logging.
func (p *Prober) Name() string { return "apiprober" }

// Run probes immediately, then every Interval until ctx is cancelled.
func (p *Prober) Run(ctx context.Context) {
	p.Cycle(ctx)
	t := time.NewTicker(p.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.Cycle(ctx)
		}
	}
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

// refreshGuard re-reads the guard conf (GuardSrc) and re-derives
// p.eff. Called once per Cycle — a conf written by hostconfig's
// first converge, or edited later via api_lb_guard_vms, applies on
// the NEXT cycle, not the next agent restart (the incident shape:
// an agent booted before the conf existed pinned the SA-path token
// fallback → every probe qfailed → enforce-mode drain ~60s in).
//
// Overlay rule: a key the conf carries wins over the startup Config
// value (the conf is the managed contract — hostconfig owns it);
// keys absent from the conf fall through to Config. A garbage MODE
// degrades to the non-enforce (dry-run) paths — fail-safe.
func (p *Prober) refreshGuard() {
	var g GuardDefaults
	if p.cfg.GuardSrc != nil {
		g = p.cfg.GuardSrc.Get()
	}
	e := &p.eff
	e.socket = firstNonEmpty(g.SocketPath, p.cfg.SocketPath)
	e.backend = firstNonEmpty(g.BackendName, p.cfg.BackendName)
	e.mode = firstNonEmpty(g.Mode, p.cfg.Mode)
	e.tokenFile = firstNonEmpty(g.TokenFile, p.cfg.TokenFile)
	e.caFile = firstNonEmpty(g.CAFile, p.cfg.CAFile)
	if len(g.CompanionBackends) > 0 {
		e.companions = g.CompanionBackends
	} else {
		e.companions = p.cfg.CompanionBackends
	}
	// Conf entries first so a same-name edit wins the dedup — a
	// mid-run API_BACKENDS change must REPLACE the startup value,
	// not be shadowed by it.
	e.statics = dedupStatic(append(
		append([]StaticBackend{}, g.StaticBackends...),
		p.cfg.StaticBackends...))
	e.gapMin = p.cfg.GapMin
	if g.GapMin > 0 {
		e.gapMin = g.GapMin
	}
	e.failCycles = p.cfg.FailCycles
	if g.FailCycles > 0 {
		e.failCycles = g.FailCycles
	}
	e.frozen = p.cfg.FrozenCycles
	if g.FrozenCycles > 0 {
		e.frozen = g.FrozenCycles
	}
	e.recoverC = p.cfg.RecoverCycles
	if g.RecoverCycles > 0 {
		e.recoverC = g.RecoverCycles
	}
	p.refreshClient()
}

// refreshClient rebuilds the TLS client when the effective CA
// changed (conf edit or bundle rotation). Skipped entirely for an
// injected HTTPClient or InsecureTLS — the -sk client never consults
// the CA. An unreadable/invalid CA keeps the last-good client and
// retries next cycle.
func (p *Prober) refreshClient() {
	if p.cfg.HTTPClient != nil || p.cfg.InsecureTLS {
		return
	}
	cl, key, err := caClient(p.eff.caFile)
	if err != nil {
		slog.Error("apiprober: CA load failed — keeping previous TLS client",
			"ca", p.eff.caFile, "error", err, "subsystem", "apiprober")
		return
	}
	if key != p.caKey {
		p.client, p.caKey = cl, key
		slog.Info("apiprober: rebuilt TLS client — effective CA changed",
			"ca", p.eff.caFile, "subsystem", "apiprober")
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// dedupStatic keeps the first entry per name — later duplicates are
// dropped (a same-named entry present in both the startup config and
// the live guard conf must not be double-probed; ordering decides
// precedence, see refreshGuard).
func dedupStatic(in []StaticBackend) []StaticBackend {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, sb := range in {
		if sb.Name == "" || seen[sb.Name] {
			continue
		}
		seen[sb.Name] = true
		out = append(out, sb)
	}
	return out
}

// guardConfPath resolves the conf path the same way cmd/agent does —
// NODE_HOST_AGENT_API_GUARD_CONF, default /etc/api-backend-guard.conf.
func guardConfPath() string {
	return firstNonEmpty(os.Getenv("NODE_HOST_AGENT_API_GUARD_CONF"),
		defaultGuardConfPath)
}

// dial connects to the HAProxy admin socket.
func (p *Prober) dial(ctx context.Context) (net.Conn, error) {
	if p.cfg.DialSocket != nil {
		return p.cfg.DialSocket(ctx, p.eff.socket)
	}
	d := net.Dialer{Timeout: p.cfg.TCPTimeout}
	return d.DialContext(ctx, "unix", p.eff.socket)
}

// socketCmd sends one admin command and returns the response body.
// HAProxy runtime commands are newline-terminated and the server
// closes the connection after answering.
func (p *Prober) socketCmd(ctx context.Context, cmd string) (string, error) {
	conn, err := p.dial(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	deadline := time.Now().Add(p.cfg.TCPTimeout)
	_ = conn.SetDeadline(deadline)
	if _, err := io.WriteString(conn, cmd+"\n"); err != nil {
		return "", err
	}
	out, err := io.ReadAll(conn)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// discover lists servers of the configured HAProxy backend via
// `show stat` (CSV). The first line carries the column names; rows are
// matched on pxname==BackendName with svname != BACKEND/FRONTEND.
func (p *Prober) discover(ctx context.Context) ([]backend, error) {
	out, err := p.socketCmd(ctx, "show stat")
	if err != nil {
		return nil, fmt.Errorf("show stat: %w", err)
	}
	var header map[string]int
	var backends []backend
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			cols := strings.Split(strings.TrimPrefix(strings.TrimSpace(line), "# "), ",")
			header = make(map[string]int, len(cols))
			for i, c := range cols {
				header[strings.TrimSpace(c)] = i
			}
			continue
		}
		if header == nil {
			return nil, fmt.Errorf("show stat: data row before header")
		}
		fields := strings.Split(line, ",")
		get := func(col string) string {
			i, ok := header[col]
			if !ok || i >= len(fields) {
				return ""
			}
			return fields[i]
		}
		if get("pxname") != p.eff.backend {
			continue
		}
		svname := get("svname")
		if svname == "" || svname == "BACKEND" || svname == "FRONTEND" {
			continue
		}
		addr := get("addr")
		if addr == "" {
			// External API LB VMs run `server <name>` lines without an
			// addr — resolve it from StaticBackends (API_BACKENDS) by
			// name, api-backend-guard.sh parity.
			if sa := p.staticAddr(svname); sa != "" {
				addr = sa
			} else {
				// One unresolvable row must not fail the WHOLE
				// cycle — the other servers still probe/drain
				// normally (a stray server line is an ops config
				// bug, not an apiserver outage).
				slog.Warn("show stat: server has no addr column value and no API_BACKENDS match — skipping it",
					"server", svname, "subsystem", "apiprober")
				continue
			}
		}
		// svname is a substring of the whole `show stat` buffer —
		// clone it before it becomes a p.states map key / Prometheus
		// label value, or every unique name pins the multi-KB CSV on
		// the heap forever.
		backends = append(backends, backend{
			Name: strings.Clone(svname), Addr: addr, Status: get("status"),
		})
	}
	if header == nil {
		return nil, fmt.Errorf("show stat: no CSV header found")
	}
	return backends, nil
}

// tcpPreflight mirrors `timeout 5 bash -c "echo >/dev/tcp/$h/$p"`.
func (p *Prober) tcpPreflight(ctx context.Context, addr string) error {
	if p.cfg.TCPCheck != nil {
		return p.cfg.TCPCheck(ctx, addr)
	}
	cctx, cancel := context.WithTimeout(ctx, p.cfg.TCPTimeout)
	defer cancel()
	d := net.Dialer{}
	conn, err := d.DialContext(cctx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

// listRV returns the LIST-level resourceVersion of one apiserver
// endpoint. ok=false on any transport/HTTP/parse failure — the caller
// treats it as a query failure, same as the shell version's "empty or
// non-numeric" check.
func (p *Prober) listRV(ctx context.Context, addr, path string) (rv int64, ok bool) {
	qctx, cancel := context.WithTimeout(ctx, p.cfg.QueryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(qctx, http.MethodGet,
		"https://"+addr+path, nil)
	if err != nil {
		return 0, false
	}
	// Ask for object metadata only — both probe paths are nodes LISTs,
	// and with resourceVersion=0 the watch-cache ignores limit=1, so
	// without this header every cycle decodes the entire NodeList
	// (and truncates at the read cap once it exceeds 1 MiB).
	req.Header.Set("Accept",
		"application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1")
	// Token re-read per query — the SA token is projected and rotates.
	if p.eff.tokenFile != "" && p.cfg.HTTPClient == nil {
		tok, err := os.ReadFile(p.eff.tokenFile)
		if err != nil {
			return 0, false
		}
		req.Header.Set("Authorization",
			"Bearer "+strings.TrimSpace(string(tok)))
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	// A metadata-only list is a few hundred bytes — the 1 MiB cap is
	// a safety bound only. Drain any tail to EOF so keep-alive can
	// reuse the connection.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, false
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return 0, false
	}
	var list struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return 0, false
	}
	rv, err = strconv.ParseInt(list.Metadata.ResourceVersion, 10, 64)
	if err != nil {
		return 0, false
	}
	return rv, true
}

// statics returns the effective static backend set: the
// guard-conf-overlaid set (eff.statics, already deduped by name —
// conf first) plus, when WatchdogSrc is wired, node-watchdog.conf's
// API_BACKENDS re-read this call (the runner re-sourced the conf
// every run).
func (p *Prober) statics() []StaticBackend {
	out := append([]StaticBackend{}, p.eff.statics...)
	if p.cfg.WatchdogSrc != nil {
		for _, b := range p.cfg.WatchdogSrc.Get().APIBackends {
			out = append(out, StaticBackend{Name: b.Name, Addr: b.Addr})
		}
	}
	return out
}

// staticAddr resolves a server name to its static-backend Addr ("" =
// not configured), normalized with the bash default port.
func (p *Prober) staticAddr(name string) string {
	for _, sb := range p.statics() {
		if sb.Name == name {
			return withDefaultPort(sb.Addr)
		}
	}
	return ""
}

// withDefaultPort fills the port on a bare-IP/-host backend address
// — api-backend-guard.sh defaulted API_BACKENDS entries without a
// port to 443. A missing port made every TCP preflight fail with
// "missing port in address" → the backend counted unreachable
// forever, never probed.
func withDefaultPort(addr string) string {
	if addr == "" {
		return addr
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(strings.Trim(addr, "[]"), "443")
}

// mergeStatic appends StaticBackends entries missing from discovery
// as UP servers — they take traffic via their LB so they count toward
// the drain fence like any discovered UP backend. Entries whose name
// discovery already returned are skipped (discovery wins — it carries
// the live HAProxy status), and so are names already appended from
// the static set itself — the same name in both confs must not be
// probed twice.
func mergeStatic(backends []backend, static []StaticBackend) []backend {
	seen := make(map[string]bool, len(backends))
	for _, b := range backends {
		seen[b.Name] = true
	}
	for _, sb := range static {
		if sb.Name == "" || sb.Addr == "" || seen[sb.Name] {
			continue
		}
		// Char-spray guard: a jinja-scalar var that resolved to a
		// STRING reaches the caller as rune-by-rune elements — skip
		// anything that can't be a real backend name/addr.
		if len(sb.Name) < 2 ||
			strings.ContainsAny(sb.Name+sb.Addr, " \t'\"[]{}(),") {
			continue
		}
		seen[sb.Name] = true
		backends = append(backends, backend{
			Name: sb.Name, Addr: withDefaultPort(sb.Addr), Status: "UP",
		})
	}
	return backends
}

// haproxyServer issues "<action> server <backend>/<name>" on the admin
// socket for every backend in [BackendName]+CompanionBackends —
// api-backend-guard.sh's haproxy_srv parity (a wedged controller is
// drained on every lane it serves). A "No such server" reply on a
// companion backend is ignored (the server simply doesn't exist
// there); an error on the primary backend always propagates.
func (p *Prober) haproxyServer(ctx context.Context, action, name string) error {
	backends := append([]string{p.eff.backend}, p.eff.companions...)
	var firstErr error
	for i, be := range backends {
		out, err := p.socketCmd(ctx,
			fmt.Sprintf("%s server %s/%s", action, be, name))
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		// "No such server" or permission errors come back as text —
		// an empty reply means success on HAProxy >= 2.x. Companions
		// may legitimately not carry this server (no-op in the shell).
		if s := strings.TrimSpace(out); s != "" {
			if i > 0 && strings.Contains(s, "No such server") {
				continue
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("%s server %s/%s: %s", action, be, name, s)
			}
		}
	}
	return firstErr
}

// --- watchdog state files (module 34 parity) ---
// The host node-watchdog stack reads these: 06-kubelet-watch-wedge
// gates k0sworker restarts on state-apiserver-backend-stale-<ip>, and
// lib.sh prom_emit turns apibe-gap-<ip> into
// node_watchdog_apiserver_backend_gap{backend="<ip-dashed>"}. The
// suffix is the backend IP with dots replaced by dashes
// (shell ${beh//./-}) — NOT the server name.

// watchdogDir returns the configured state dir when it exists on disk
// this cycle, else "". An empty/missing dir disables all file ops
// silently — test environments and non-watchdog nodes.
func (p *Prober) watchdogDir() string {
	d := p.cfg.WatchdogStateDir
	if d == "" {
		return ""
	}
	if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
		return ""
	}
	return d
}

// dashedIP maps a backend addr to the watchdog file suffix:
// "10.0.0.1:6443" → "10-0-0-1".
func dashedIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr // Addr without a port — use it raw
	}
	return strings.ReplaceAll(host, ".", "-")
}

// writeFileAtomic writes path via tmp+rename — the same atomic-copy
// contract the watchdog prom files rely on (no torn reads mid-write).
// The tmp name deliberately breaks the state-*/apibe-gap-* prefixes —
// hostmetrics scans the dir for state-* files and a
// "state-foo-<ip>.tmp" would surface as a phantom watchdog_state
// series ("<ip>.tmp") that then persists at 0 forever.
func writeFileAtomic(path string, data []byte) error {
	tmp := filepath.Join(filepath.Dir(path), ".tmp-"+filepath.Base(path))
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// writeGapFile records the last measured rv gap for prom_emit.
// Best-effort: a write failure is logged, never fatal.
func (p *Prober) writeGapFile(dir string, b backend, gap int64) {
	f := dir + "/apibe-gap-" + dashedIP(b.Addr)
	if err := writeFileAtomic(f, []byte(strconv.FormatInt(gap, 10)+"\n")); err != nil {
		slog.Info("watchdog gap file write failed", "file", f, "error", err)
	}
}

// latchStale creates state-apiserver-backend-stale-<ip> — state_enter
// semantics: create only if absent, content = current epoch.
func (p *Prober) latchStale(dir string, b backend) {
	f := dir + "/state-apiserver-backend-stale-" + dashedIP(b.Addr)
	if _, err := os.Stat(f); err == nil {
		return
	}
	if err := writeFileAtomic(f,
		[]byte(strconv.FormatInt(time.Now().Unix(), 10)+"\n")); err != nil {
		slog.Info("watchdog stale latch write failed", "file", f, "error", err)
	}
}

// clearStale removes the stale latch — state_exit semantics, called
// only on a fully-fresh cycle (hysteresis: inconclusive cycles keep
// whatever exists). not-exist is ignored.
func (p *Prober) clearStale(dir string, b backend) {
	f := dir + "/state-apiserver-backend-stale-" + dashedIP(b.Addr)
	if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
		slog.Info("watchdog stale latch remove failed", "file", f, "error", err)
	}
}

// pruneWatchdogFiles deletes apibe-gap-* and state-apiserver-backend-
// stale-* files whose dashed-IP is no longer among the discovered
// direct backends — a backend retired from api-local-lb would
// otherwise leave its latch/gap file latched forever (false NPD/prom
// signal, the shell's prune block parity). Only runs when discovery
// returned rows — never on discover failure or an empty backend list.
func (p *Prober) pruneWatchdogFiles(dir string, backends []backend) {
	keep := make(map[string]bool, len(backends))
	for _, b := range backends {
		if !b.vip() {
			keep[dashedIP(b.Addr)] = true
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		var suffix string
		switch {
		case strings.HasPrefix(name, "apibe-gap-"):
			suffix = strings.TrimPrefix(name, "apibe-gap-")
		case strings.HasPrefix(name, "state-apiserver-backend-stale-"):
			suffix = strings.TrimPrefix(name, "state-apiserver-backend-stale-")
		default:
			continue
		}
		if !keep[suffix] {
			_ = os.Remove(dir + "/" + name)
		}
	}
}

func (p *Prober) stateFor(name string) *backendState {
	st, ok := p.states[name]
	if !ok {
		st = &backendState{}
		p.states[name] = st
	}
	return st
}

// pruneStaleBackends drops in-memory probe state and every
// per-backend metric series for names no longer present in
// discovery — a backend retired from api-local-lb would otherwise
// pin its p.states entry and its label values on the registry
// forever. Only runs when discovery returned rows — never on
// discover failure or an empty backend list.
func (p *Prober) pruneStaleBackends(backends []backend) {
	live := make(map[string]bool, len(backends))
	for _, b := range backends {
		live[b.Name] = true
	}
	for name := range p.states {
		if live[name] {
			continue
		}
		delete(p.states, name)
		p.rvGap.DeleteLabelValues(name)
		p.enabled.DeleteLabelValues(name)
		// probeFailures/actions carry a second label (phase|action)
		// — drop every series whose backend label matches.
		p.probeFailures.DeletePartialMatch(prometheus.Labels{"backend": name})
		p.actions.DeletePartialMatch(prometheus.Labels{"backend": name})
	}
}

// Cycle runs one detection+guard round — the shell script body.
func (p *Prober) Cycle(ctx context.Context) {
	log := slog.With("subsystem", "apiprober")
	start := time.Now()
	defer func() { p.duration.Set(time.Since(start).Seconds()) }()

	// Re-read the guard conf every cycle — a conf written or edited
	// by hostconfig mid-run applies NOW, not after a restart.
	p.refreshGuard()

	backends, err := p.discover(ctx)
	if err != nil {
		log.Error("cannot discover backends from HAProxy socket",
			"socket", p.eff.socket, "error", err)
		p.cycles.WithLabelValues("discover_fail").Inc()
		return
	}
	// Merge API_BACKENDS-style static entries — covers backends whose
	// `show stat` addr column is empty (external API LB VMs) and
	// apiservers the local HAProxy does not list.
	backends = mergeStatic(backends, p.statics())
	p.backendCount.Set(float64(len(backends)))
	p.cycles.WithLabelValues("ok").Inc()

	// Resolved once per cycle: "" disables every watchdog file op.
	wdir := p.watchdogDir()

	fresh := 0                 // direct backends fresh AND usable this cycle (drain fence)
	stale := map[string]bool{} // name → wedged/dead this cycle
	statusByName := make(map[string]backend, len(backends))
	var vips []backend

	for _, b := range backends {
		if ctx.Err() != nil {
			return
		}
		statusByName[b.Name] = b
		st := p.stateFor(b.Name)
		if b.vip() {
			vips = append(vips, b)
			continue
		}

		// TCP preflight: unreachable → HAProxy tcp-check owns the
		// verdict; we neither count it fresh nor stale.
		if err := p.tcpPreflight(ctx, b.Addr); err != nil {
			log.Info("probe: unreachable — skip (haproxy health-check owns it)",
				"backend", b.Name, "addr", b.Addr)
			p.probeFailures.WithLabelValues(b.Name, "tcp").Inc()
			continue
		}

		rvCache, okC := p.listRV(ctx, b.Addr, p.cfg.CachePath)
		rvNow, okN := p.listRV(ctx, b.Addr, p.cfg.LivePath)
		if !okC || !okN {
			// TCP alive but queries fail = apiserver stall/wedge —
			// worse than DOWN (L7 /readyz may still pass while
			// storage is wedged, incident 2026-10-07).
			st.qfail++
			st.frozen = 0
			st.ok = 0
			p.probeFailures.WithLabelValues(b.Name, "query").Inc()
			if st.qfail >= p.eff.failCycles {
				stale[b.Name] = true
				log.Info("DEAD: API queries failing — apiserver stall/wedge, drain from VIP",
					"backend", b.Name, "addr", b.Addr,
					"cacheOK", okC, "liveOK", okN, "qfail", st.qfail)
			} else {
				log.Info("probe: query failed — not draining yet",
					"backend", b.Name, "qfail", st.qfail,
					"failCycles", p.eff.failCycles)
			}
			continue
		}
		st.qfail = 0
		gap := rvNow - rvCache
		p.rvGap.WithLabelValues(b.Name).Set(float64(gap))
		if wdir != "" {
			p.writeGapFile(wdir, b, gap)
		}

		// Frozen signal: rv_cache bit-identical while rv_now advances
		// → watch-cache stopped updating (early wedge signature).
		// rv_cache advancing (cache alive) or rv_now <= rv_cache
		// (cluster idle) resets the counter.
		if st.hasPrev && rvCache == st.prevCache && rvNow > rvCache {
			st.frozen++
		} else {
			st.frozen = 0
		}
		st.prevCache = rvCache
		st.hasPrev = true

		// Gap signal: rv_now - rv_cache > GapMin accumulates.
		if gap > p.eff.gapMin {
			st.fail++
		} else {
			st.fail = 0
		}

		switch {
		case st.frozen >= p.eff.frozen || st.fail >= p.eff.failCycles:
			stale[b.Name] = true
			st.ok = 0
			if st.frozen >= p.eff.frozen {
				log.Info("FROZEN: rv_cache unchanged while rv_now advances — watch-cache wedge",
					"backend", b.Name, "rvCache", rvCache, "rvNow", rvNow,
					"frozen", st.frozen)
			} else {
				log.Info("STALE: backend serving old watch-cache",
					"backend", b.Name, "gap", gap, "fail", st.fail)
			}
		case gap > p.eff.gapMin:
			st.ok = 0
			log.Info("probe: gap above threshold — not draining yet",
				"backend", b.Name, "gap", gap, "fail", st.fail,
				"failCycles", p.eff.failCycles)
		case st.frozen > 0:
			st.ok = 0
			log.Info("probe: rv_cache frozen while rv_now advances — accumulating",
				"backend", b.Name, "rvCache", rvCache, "rvNow", rvNow,
				"frozen", st.frozen, "frozenCycles", p.eff.frozen)
		default:
			st.ok++
			if wdir != "" && st.ok >= p.eff.recoverC {
				// state_exit parity: the shell needed RECOVER_CYCLES
				// consecutive fully-fresh runs before clearing the
				// latch — one lucky probe must not unblock
				// 06-kubelet-watch-wedge's upstream gate. The
				// inconclusive paths above (TCP-unreachable,
				// under-threshold qfail/frozen/gap) keep whatever
				// latch exists.
				p.clearStale(wdir, b)
			}
			if st.drained || b.maint() {
				// Re-enable only after RecoverCycles consecutive
				// fresh cycles (drained by us, or admin-disabled
				// externally — reconciled the same way).
				if st.ok >= p.eff.recoverC {
					if p.eff.mode == ModeEnforce {
						if err := p.haproxyServer(ctx, "enable", b.Name); err != nil {
							log.Error("enable via HAProxy socket failed",
								"backend", b.Name, "error", err)
						} else {
							st.drained = false
							st.ok = 0
							p.actions.WithLabelValues(b.Name, "enable").Inc()
							if b.up() {
								fresh++
							}
							log.Info("ACTION: enabled backend — fresh again",
								"backend", b.Name, "backend", p.eff.backend,
								"ok", p.eff.recoverC, "gap", gap)
						}
					} else {
						log.Info("DRY-RUN: would enable backend",
							"backend", b.Name, "ok", st.ok, "gap", gap)
						p.actions.WithLabelValues(b.Name, "dryrun_enable").Inc()
					}
				}
			} else if b.up() {
				fresh++
			}
		}
	}

	// Drain phase — after the fresh count for this cycle is final.
	// usableFresh snapshots the pre-drain count: every backend in it
	// stays enabled through the drain (drains only remove stale
	// backends), so it is the RIGHT basis for the VIP bypass decision
	// — unlike the decremented fence budget below.
	usableFresh := fresh
	names := make([]string, 0, len(stale))
	for n := range stale {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		st := p.states[name]
		b := statusByName[name]
		if wdir != "" {
			// Wedged/dead this cycle → state_enter parity (the latch
			// gates 06-kubelet-watch-wedge's k0sworker restart).
			p.latchStale(wdir, b)
		}
		if st.drained {
			// Already drained — but a HAProxy restart forgets runtime
			// disables (socket state is not persistent). Re-apply
			// while HAProxy reports the server usable again; the
			// recovery path above re-enables via the drained flag.
			if p.eff.mode == ModeEnforce && b.up() {
				if err := p.haproxyServer(ctx, "disable", name); err != nil {
					log.Error("re-apply disable failed",
						"backend", name, "error", err)
				} else {
					log.Info("ACTION: re-applied disable — HAProxy forgot drained server",
						"backend", name)
					p.actions.WithLabelValues(name, "disable").Inc()
				}
			}
			continue
		}
		// FENCE: never disable the last usable backend. If every other
		// backend is stale/unreachable this cycle, draining more only
		// takes the VIP down with them — keep it, escalate via log.
		if fresh < 1 {
			log.Info("FENCE: backend wedged but no fresh backend remains — not draining, manual action needed",
				"backend", name)
			p.actions.WithLabelValues(name, "fence_skip").Inc()
			continue
		}
		if p.eff.mode == ModeEnforce {
			if err := p.haproxyServer(ctx, "disable", name); err != nil {
				log.Error("disable via HAProxy socket failed",
					"backend", name, "error", err)
				continue
			}
			st.drained = true
			// Staged drain (shell `fresh=$((fresh - 1))` parity):
			// every successful disable spends one fresh slot, so a
			// run drains at most `fresh` stale backends — the fence
			// above then still has a usable backend to protect.
			fresh--
			p.actions.WithLabelValues(name, "disable").Inc()
			log.Info("ACTION: disabled backend — watch-cache wedge",
				"backend", name, "haproxyBackend", p.eff.backend,
				"freshRemaining", fresh)
		} else {
			log.Info("DRY-RUN: would disable backend — watch-cache wedge",
				"backend", name, "freshRemaining", fresh)
			p.actions.WithLabelValues(name, "dryrun_disable").Inc()
		}
	}

	// VIP phase (sig14b): *_lb entries round-robin across controllers,
	// so when any direct controller is wedged/drained AND >=1 direct
	// controller is fresh, disable the VIP entry so traffic goes
	// straight to the healthy controller(s). Re-enable when all direct
	// controllers are healthy again, or when fresh == 0 (least-bad).
	staleCtrlCount := 0
	for _, b := range backends {
		if b.vip() {
			continue
		}
		if stale[b.Name] || p.states[b.Name].drained {
			staleCtrlCount++
		}
	}
	wantVIPDisable := staleCtrlCount > 0 && usableFresh > 0
	for _, vip := range vips {
		st := p.states[vip.Name]
		if wantVIPDisable {
			if p.eff.mode == ModeEnforce {
				if !st.drained || vip.up() {
					if err := p.haproxyServer(ctx, "disable", vip.Name); err != nil {
						log.Error("disable VIP via HAProxy socket failed",
							"backend", vip.Name, "error", err)
						continue
					}
					st.drained = true
					p.actions.WithLabelValues(vip.Name, "disable").Inc()
					log.Info("ACTION: disabled VIP backend — direct controller wedged while fresh controller available",
						"backend", vip.Name, "staleCtrls", staleCtrlCount, "freshCtrls", fresh)
				}
			} else if !st.drained {
				st.drained = true
				log.Info("DRY-RUN: would disable VIP backend — direct controller wedged",
					"backend", vip.Name, "staleCtrls", staleCtrlCount, "freshCtrls", fresh)
				p.actions.WithLabelValues(vip.Name, "dryrun_disable").Inc()
			}
		} else if st.drained || vip.maint() {
			if p.eff.mode == ModeEnforce {
				if err := p.haproxyServer(ctx, "enable", vip.Name); err != nil {
					log.Error("enable VIP via HAProxy socket failed",
						"backend", vip.Name, "error", err)
					continue
				}
				st.drained = false
				p.actions.WithLabelValues(vip.Name, "enable").Inc()
				log.Info("ACTION: enabled VIP backend",
					"backend", vip.Name, "staleCtrls", staleCtrlCount, "freshCtrls", fresh)
			} else {
				st.drained = false
				log.Info("DRY-RUN: would enable VIP backend",
					"backend", vip.Name, "staleCtrls", staleCtrlCount, "freshCtrls", fresh)
				p.actions.WithLabelValues(vip.Name, "dryrun_enable").Inc()
			}
		}
	}

	// Export per-backend enabled state after all transitions.
	for _, b := range backends {
		v := 0.0
		if b.up() && !p.states[b.Name].drained {
			v = 1
		}
		p.enabled.WithLabelValues(b.Name).Set(v)
	}

	// Prune state for backends that left discovery — only when
	// discover returned rows (never on discover_fail/empty: a failed
	// or empty scan must not wipe latches/counters/metric series the
	// next good scan still needs).
	if len(backends) > 0 {
		p.pruneStaleBackends(backends)
		if wdir != "" {
			p.pruneWatchdogFiles(wdir, backends)
		}
	}
}

// --- /etc/api-backend-guard.conf (standalone api-lb-vm defaults) ---
//
// hostconfig renders a KEY=VALUE shell-env conf on api-lb VMs (the
// file the retired api-backend-guard.sh sourced). The standalone
// agent feeds it as the fallback layer below the env knobs — env →
// guard.conf → compiled defaults — and (via Config.GuardSrc) as a
// per-cycle live overlay so conf writes/edits take effect without
// an agent restart. Keys:
//
//	HAPROXY_SOCKET   admin unix socket → SocketPath
//	HAPROXY_BACKEND  primary backend   → BackendName
//	HAPROXY_BACKENDS full action set   → CompanionBackends (minus the primary)
//	API_BACKENDS     "name=ip:port" list → StaticBackends
//	MODE             dry-run|enforce   → Mode
//	API_TOKEN_FILE/API_CA_FILE         → TokenFile/CAFile
//	TOKEN_FILE/CA_FILE                 → short-spelling fallback for the same
//	GAP_MIN/FAIL_CYCLES/FROZEN_CYCLES/RECOVER_CYCLES → thresholds
//
// (STATE_DIR is intentionally unmapped — the Go port keeps per-
// backend counters in memory; the watchdog compat files live in
// WatchdogStateDir, a different dir with different contents.)
//
// GuardDefaults is the parsed api-backend-guard.conf — every field
// zero means "fall through to the compiled default".
type GuardDefaults struct {
	SocketPath        string
	BackendName       string
	CompanionBackends []string
	StaticBackends    []StaticBackend
	Mode              string
	TokenFile         string
	CAFile            string
	GapMin            int64 // GAP_MIN
	FailCycles        int   // FAIL_CYCLES
	FrozenCycles      int   // FROZEN_CYCLES
	RecoverCycles     int   // RECOVER_CYCLES
}

// GuardReloader re-reads the conf on every Get — the mtime-check-
// free equivalent of watchdogconf.Reloader (the file is a few
// hundred bytes; a plain re-read is the simplest correct semantics).
// A missing file yields the zero GuardDefaults (no overlay), an
// unreadable one keeps the last good parse — the shell `source`
// semantics were "read fresh each run". Get is safe for concurrent
// use.
type GuardReloader struct {
	Path string

	mu  sync.Mutex
	cur GuardDefaults
}

// NewGuardReloader seeds the reloader with an initial parse (the
// zero value is fine — the first Get re-reads anyway).
func NewGuardReloader(path string, initial GuardDefaults) *GuardReloader {
	return &GuardReloader{Path: path, cur: initial}
}

// Get returns the freshest parse of Path, falling back to the last
// good one on read/parse errors.
func (r *GuardReloader) Get() GuardDefaults {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Path == "" {
		return r.cur
	}
	if g, err := LoadGuardConf(r.Path); err == nil {
		r.cur = g
	}
	return r.cur
}

// LoadGuardConf parses the conf at path. A missing file is NOT an
// error (pods and non-api-lb hosts never carry it) — it returns the
// zero GuardDefaults and nil so callers can chain env → conf →
// default unconditionally.
//
// Credential keys accept BOTH spellings: API_TOKEN_FILE/API_CA_FILE
// is the original contract (the ansible api-backend-guard.conf.j2
// template — deployed api-lb VMs still carry it and the retired
// shell guard sourced exactly these), TOKEN_FILE/CA_FILE the short
// spelling the Go port's first conf renders used. The API_-
// prefixed (original) spelling wins when both are present — it is
// the documented contract and the one converge manages.
func LoadGuardConf(path string) (GuardDefaults, error) {
	var g GuardDefaults
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return g, nil
		}
		return g, fmt.Errorf("read %s: %w", path, err)
	}
	vars := parseShellKV(string(data))
	g.SocketPath = vars["HAPROXY_SOCKET"]
	g.BackendName = vars["HAPROXY_BACKEND"]
	g.Mode = vars["MODE"]
	g.TokenFile = firstNonEmpty(vars["API_TOKEN_FILE"], vars["TOKEN_FILE"])
	g.CAFile = firstNonEmpty(vars["API_CA_FILE"], vars["CA_FILE"])
	g.GapMin, _ = strconv.ParseInt(vars["GAP_MIN"], 10, 64)
	g.FailCycles = atoiOr(vars["FAIL_CYCLES"])
	g.FrozenCycles = atoiOr(vars["FROZEN_CYCLES"])
	g.RecoverCycles = atoiOr(vars["RECOVER_CYCLES"])
	// HAPROXY_BACKENDS names the whole action set INCLUDING the
	// primary backend (shell parity: `for b in $HAPROXY_BACKENDS`) —
	// the primary already acts via BackendName, so only the rest are
	// companions (double-applying an enable/disable is a no-op but
	// logs and metrics would double-count it).
	for _, b := range strings.Fields(vars["HAPROXY_BACKENDS"]) {
		if b == "" || b == g.BackendName {
			continue
		}
		g.CompanionBackends = append(g.CompanionBackends, b)
	}
	for _, e := range strings.Fields(vars["API_BACKENDS"]) {
		if sb, ok := parseStaticBackend(e); ok {
			g.StaticBackends = append(g.StaticBackends, sb)
		}
	}
	return g, nil
}

// atoiOr parses a small integer conf value; empty/garbage → 0
// (fall through to the caller's default).
func atoiOr(v string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(v))
	return n
}

// parseStaticBackend parses one API_BACKENDS element "name=ip:port"
// (or bare "ip:port" — Name falls back to Addr), 1:1 with
// watchdogconf's APIBackends entries.
func parseStaticBackend(entry string) (StaticBackend, bool) {
	name, addr, hasEq := strings.Cut(entry, "=")
	if !hasEq {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return StaticBackend{}, false
		}
		return StaticBackend{Name: entry, Addr: entry}, true
	}
	name, addr = strings.TrimSpace(name), strings.TrimSpace(addr)
	if name == "" || addr == "" {
		return StaticBackend{}, false
	}
	return StaticBackend{Name: name, Addr: addr}, true
}

// parseShellKV parses shell-style KEY=VALUE lines (the same grammar
// watchdogconf uses — quotes honoured, `#` comments, `export `
// prefixes tolerated). Duplicated here because watchdogconf's parser
// is package-private and the guard conf is an apiprober input.
func parseShellKV(data string) map[string]string {
	vars := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if v, ok := strings.CutPrefix(line, "export "); ok {
			line = strings.TrimSpace(v)
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		vars[key] = guardScalar(guardValue(strings.TrimSpace(val)))
	}
	return vars
}

// guardScalar strips surrounding single/double quotes.
func guardScalar(v string) string {
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') ||
			(v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}

// guardValue cuts a raw VALUE at the first `#` that opens a bash
// comment — outside quotes and at a word boundary. A `#` inside
// quotes or glued to the previous word is literal (bash `source`
// parity — same semantics as watchdogconf's parser).
func guardValue(val string) string {
	var out strings.Builder
	out.Grow(len(val))
	var quote byte
	wordStart := true
	for i := 0; i < len(val); i++ {
		ch := val[i]
		if quote != 0 {
			out.WriteByte(ch)
			if ch == quote {
				quote = 0
			}
			continue
		}
		switch ch {
		case '"', '\'':
			quote = ch
			wordStart = false
			out.WriteByte(ch)
		case ' ', '\t':
			wordStart = true
			out.WriteByte(ch)
		case '#':
			if wordStart {
				return strings.TrimSpace(out.String())
			}
			out.WriteByte(ch)
		default:
			wordStart = false
			out.WriteByte(ch)
		}
	}
	return strings.TrimSpace(out.String())
}
