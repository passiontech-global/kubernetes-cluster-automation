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
// cycles.
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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
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
)

// Config carries the prober's knobs — all test-injectable.
type Config struct {
	SocketPath    string        // HAProxy admin unix socket
	BackendName   string        // HAProxy backend holding the apiservers
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
	states map[string]*backendState

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
	p := &Prober{cfg: cfg, states: map[string]*backendState{}}

	if cfg.HTTPClient != nil {
		p.client = cfg.HTTPClient
	} else {
		tlsCfg := &tls.Config{InsecureSkipVerify: cfg.InsecureTLS} //nolint:gosec // explicit opt-in, mirrors curl -sk
		if !cfg.InsecureTLS && cfg.CAFile != "" {
			pool, err := caPool(cfg.CAFile)
			if err != nil {
				return nil, fmt.Errorf("load CA %s: %w", cfg.CAFile, err)
			}
			tlsCfg.RootCAs = pool
		}
		p.client = &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		}
	}

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

// dial connects to the HAProxy admin socket.
func (p *Prober) dial(ctx context.Context) (net.Conn, error) {
	if p.cfg.DialSocket != nil {
		return p.cfg.DialSocket(ctx, p.cfg.SocketPath)
	}
	d := net.Dialer{Timeout: p.cfg.TCPTimeout}
	return d.DialContext(ctx, "unix", p.cfg.SocketPath)
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
		if get("pxname") != p.cfg.BackendName {
			continue
		}
		svname := get("svname")
		if svname == "" || svname == "BACKEND" || svname == "FRONTEND" {
			continue
		}
		addr := get("addr")
		if addr == "" {
			return nil, fmt.Errorf("show stat: server %s has no addr column value", svname)
		}
		backends = append(backends, backend{
			Name: svname, Addr: addr, Status: get("status"),
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
	// Token re-read per query — the SA token is projected and rotates.
	if p.cfg.TokenFile != "" && p.cfg.HTTPClient == nil {
		tok, err := os.ReadFile(p.cfg.TokenFile)
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, false
	}
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

// haproxyServer issues "<action> server <backend>/<name>" on the admin
// socket.
func (p *Prober) haproxyServer(ctx context.Context, action, name string) error {
	out, err := p.socketCmd(ctx,
		fmt.Sprintf("%s server %s/%s", action, p.cfg.BackendName, name))
	if err != nil {
		return err
	}
	// "No such server" or permission errors come back as text — an
	// empty reply means success on HAProxy >= 2.x.
	if s := strings.TrimSpace(out); s != "" {
		return fmt.Errorf("%s server %s/%s: %s", action, p.cfg.BackendName, name, s)
	}
	return nil
}

func (p *Prober) stateFor(name string) *backendState {
	st, ok := p.states[name]
	if !ok {
		st = &backendState{}
		p.states[name] = st
	}
	return st
}

// Cycle runs one detection+guard round — the shell script body.
func (p *Prober) Cycle(ctx context.Context) {
	log := slog.With("subsystem", "apiprober")
	start := time.Now()
	defer func() { p.duration.Set(time.Since(start).Seconds()) }()

	backends, err := p.discover(ctx)
	if err != nil {
		log.Error("cannot discover backends from HAProxy socket",
			"socket", p.cfg.SocketPath, "error", err)
		p.cycles.WithLabelValues("discover_fail").Inc()
		return
	}
	p.backendCount.Set(float64(len(backends)))
	p.cycles.WithLabelValues("ok").Inc()

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
			if st.qfail >= p.cfg.FailCycles {
				stale[b.Name] = true
				log.Info("DEAD: API queries failing — apiserver stall/wedge, drain from VIP",
					"backend", b.Name, "addr", b.Addr,
					"cacheOK", okC, "liveOK", okN, "qfail", st.qfail)
			} else {
				log.Info("probe: query failed — not draining yet",
					"backend", b.Name, "qfail", st.qfail,
					"failCycles", p.cfg.FailCycles)
			}
			continue
		}
		st.qfail = 0
		gap := rvNow - rvCache
		p.rvGap.WithLabelValues(b.Name).Set(float64(gap))

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
		if gap > p.cfg.GapMin {
			st.fail++
		} else {
			st.fail = 0
		}

		switch {
		case st.frozen >= p.cfg.FrozenCycles || st.fail >= p.cfg.FailCycles:
			stale[b.Name] = true
			st.ok = 0
			if st.frozen >= p.cfg.FrozenCycles {
				log.Info("FROZEN: rv_cache unchanged while rv_now advances — watch-cache wedge",
					"backend", b.Name, "rvCache", rvCache, "rvNow", rvNow,
					"frozen", st.frozen)
			} else {
				log.Info("STALE: backend serving old watch-cache",
					"backend", b.Name, "gap", gap, "fail", st.fail)
			}
		case gap > p.cfg.GapMin:
			st.ok = 0
			log.Info("probe: gap above threshold — not draining yet",
				"backend", b.Name, "gap", gap, "fail", st.fail,
				"failCycles", p.cfg.FailCycles)
		case st.frozen > 0:
			st.ok = 0
			log.Info("probe: rv_cache frozen while rv_now advances — accumulating",
				"backend", b.Name, "rvCache", rvCache, "rvNow", rvNow,
				"frozen", st.frozen, "frozenCycles", p.cfg.FrozenCycles)
		default:
			st.ok++
			if st.drained || b.maint() {
				// Re-enable only after RecoverCycles consecutive
				// fresh cycles (drained by us, or admin-disabled
				// externally — reconciled the same way).
				if st.ok >= p.cfg.RecoverCycles {
					if p.cfg.Mode == ModeEnforce {
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
								"backend", b.Name, "backend", p.cfg.BackendName,
								"ok", p.cfg.RecoverCycles, "gap", gap)
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
	names := make([]string, 0, len(stale))
	for n := range stale {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		st := p.states[name]
		b := statusByName[name]
		if st.drained {
			// Already drained — but a HAProxy restart forgets runtime
			// disables (socket state is not persistent). Re-apply
			// while HAProxy reports the server usable again; the
			// recovery path above re-enables via the drained flag.
			if p.cfg.Mode == ModeEnforce && b.up() {
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
		if p.cfg.Mode == ModeEnforce {
			if err := p.haproxyServer(ctx, "disable", name); err != nil {
				log.Error("disable via HAProxy socket failed",
					"backend", name, "error", err)
				continue
			}
			st.drained = true
			p.actions.WithLabelValues(name, "disable").Inc()
			log.Info("ACTION: disabled backend — watch-cache wedge",
				"backend", name, "haproxyBackend", p.cfg.BackendName,
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
	wantVIPDisable := staleCtrlCount > 0 && fresh > 0
	for _, vip := range vips {
		st := p.states[vip.Name]
		if wantVIPDisable {
			if p.cfg.Mode == ModeEnforce {
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
			if p.cfg.Mode == ModeEnforce {
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
}
