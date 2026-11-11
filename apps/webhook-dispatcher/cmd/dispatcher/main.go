// webhook-dispatcher — receives GitHub org webhook deliveries and
// fans out instant resource checks to a Concourse ATC, replacing
// per-resource polling latency with push-driven checks.
//
// Flow: POST /webhook -> verify X-Hub-Signature-256 (HMAC-SHA256 over
// the raw request body) -> resolve repository.full_name against the
// cached Concourse pipeline/resource index (~60s TTL) -> answer 202
// and POST each matching resource's check webhook on a detached,
// bounded fan-out (16 workers, 15s per target):
//
//	push              -> git resources
//	pull_request      -> github-pr resources
//	release (publish) -> git resources
//	create (tag)      -> git resources
//
// Other events are acknowledged with 202 so GitHub does not retry.
// A single resource failure never fails the delivery — GitHub
// redelivery would re-trigger every resource, not just the failed one.
//
// Two listeners, deliberately split: the public one (:8080, LISTEN_ADDR)
// serves only what GitHub needs — POST /webhook, GET /healthz (the
// liveness probe, manifest-compatible), GET /readyz (readiness). The
// internal one (:9115, METRICS_ADDR) serves GET /metrics (from a
// dedicated Prometheus registry) and net/http/pprof under
// /debug/pprof/ — operational endpoints that must never be reachable
// from GitHub's side. Both listeners are BOUND before the process
// waits on signals, so a port collision or typo'd address aborts boot
// instead of surfacing asynchronously.
//
// Shutdown contract: on SIGINT/SIGTERM the public listener drains for
// at most 10s, then the in-flight fan-out wait gets at most 15s
// (Handler.Wait logs abandoned fan-outs) — ~25s worst case, under the
// pod's 30s SIGKILL grace period.
//
// Env contract:
//
//	GITHUB_WEBHOOK_SECRET  (required) HMAC key configured on the org webhook
//	CI_WEBHOOK_TOKEN       (required) Concourse check webhook token
//	LOCAL_USERS            (required) Concourse basic auth "user:password"
//	CONCOURSE_URL          (default http://concourse-web:8080)
//	CONCOURSE_TEAM         (default main)
//	LISTEN_ADDR            (default :8080)
//	METRICS_ADDR           (default :9115)
//
// See docs/env.md for the full catalog.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof" // handlers wired explicitly below (Index, Profile, ...) — never on DefaultServeMux
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/webhook-dispatcher/internal/concourse"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/webhook-dispatcher/internal/handler"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/httpx"
)

var version = "dev"

// parseLocalUsers splits Concourse basic auth "user:password" on the
// first colon so passwords may contain colons.
func parseLocalUsers(s string) (user, password string, ok bool) {
	user, password, ok = strings.Cut(s, ":")
	return user, password, ok && user != "" && password != ""
}

func main() {
	var showVersion bool
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Printf("webhook-dispatcher %s\n", version)
		return
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	// Required env — fail fast instead of booting into guaranteed
	// 401s (missing webhook secret/token) or 502s (missing ATC creds).
	var missing []string
	for _, key := range []string{
		"GITHUB_WEBHOOK_SECRET", "CI_WEBHOOK_TOKEN", "LOCAL_USERS",
	} {
		if os.Getenv(key) == "" {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		logger().Error("missing required environment variables", "vars", missing)
		os.Exit(1)
	}

	// LOCAL_USERS carries Concourse basic auth as "user:password".
	user, password, ok := parseLocalUsers(os.Getenv("LOCAL_USERS"))
	if !ok {
		logger().Error("LOCAL_USERS must be in 'user:password' form")
		os.Exit(1)
	}

	// Connection pool tuned for the fan-out shape: 16 check-webhook
	// workers + 8 index workers all share this client, so idle conns
	// must cover the burst or every POST re-dials the ATC.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = 64
	transport.MaxIdleConnsPerHost = 32
	transport.MaxConnsPerHost = 32
	transport.IdleConnTimeout = 90 * time.Second

	client := &concourse.Client{
		BaseURL:      envx.String("CONCOURSE_URL", "http://concourse-web:8080"),
		Team:         envx.String("CONCOURSE_TEAM", "main"),
		User:         user,
		Password:     password,
		WebhookToken: os.Getenv("CI_WEBHOOK_TOKEN"),
		HTTP:         &http.Client{Timeout: 15 * time.Second, Transport: transport},
		IndexTTL:     time.Minute,
	}

	wh := handler.New(os.Getenv("GITHUB_WEBHOOK_SECRET"), client)

	// All Prometheus metrics register on this dedicated registry,
	// served by the internal listener only — the public listener faces
	// GitHub and must not expose index/fan-out internals.
	reg := prometheus.NewRegistry()
	handler.RegisterMetrics(reg)
	concourse.RegisterMetrics(reg)

	// Internal listener: metrics scrape + pprof. Trusted-network
	// surface — keep everything operational off LISTEN_ADDR.
	internalMux := http.NewServeMux()
	internalMux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	internalMux.HandleFunc("/debug/pprof/", pprof.Index)
	internalMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	internalMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	internalMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	internalMux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	publicMux := http.NewServeMux()
	publicMux.Handle("POST /webhook", wh)
	publicMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	// Readiness mirrors liveness for the split-listener contract: both
	// listeners are bound (and serving) before this flag is set, so a
	// request here implies the process is serving — the flag still
	// gates it honestly across the bind→serve window.
	var ready atomic.Bool
	publicMux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	listenAddr := envx.String("LISTEN_ADDR", ":8080")
	metricsAddr := envx.String("METRICS_ADDR", ":9115")

	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Bind BEFORE entering the wait-on-signal loop: a port collision
	// or typo'd address must abort boot (log + exit), not surface
	// asynchronously from a goroutine after readiness. httpx.New does
	// the same bind-then-serve for the internal server.
	publicLn, err := net.Listen("tcp", listenAddr)
	if err != nil {
		logger().Error("binding public listener", "addr", listenAddr, "error", err)
		os.Exit(1)
	}
	publicSrv := &http.Server{
		Addr:    listenAddr,
		Handler: publicMux,
		// ReadTimeout covers the whole request incl. the body (bounded
		// by MaxBytesReader at 8 MiB) — without it a slow-drip client
		// outlives ReadHeaderTimeout and holds the conn forever.
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		// WriteTimeout must cover the handler's 30s index-fetch budget
		// (fan-out itself is async — the response is a fast 202).
		WriteTimeout: 45 * time.Second,
		IdleTimeout:  60 * time.Second,
		// GitHub sends a handful of modest headers; the tight cap keeps
		// a hostile peer from parking large header buffers per conn.
		MaxHeaderBytes: 64 << 10,
	}
	internalSrv, err := httpx.New(metricsAddr, internalMux, httpx.Opts{})
	if err != nil {
		logger().Error("binding metrics listener", "addr", metricsAddr, "error", err)
		os.Exit(1)
	}

	// Serve both. A serve-loop failure (accept error) is fatal — same
	// as the old single ListenAndServe: log and exit non-zero.
	publicErr := make(chan error, 1)
	go func() {
		if err := publicSrv.Serve(publicLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			publicErr <- err
		}
	}()
	internalErr := internalSrv.Serve() // <-chan error; ErrServerClosed folded
	ready.Store(true)

	logger().Info("starting webhook-dispatcher",
		"version", version, "addr", listenAddr,
		"routes", "POST /webhook, GET /healthz, GET /readyz",
		"metrics_addr", metricsAddr,
		"internal_routes", "GET /metrics, /debug/pprof/*",
		"concourse_url", client.BaseURL, "concourse_team", client.Team)

	select {
	case err := <-publicErr:
		logger().Error("server exited", "error", err)
		os.Exit(1)
	case err := <-internalErr:
		logger().Error("metrics server exited", "error", err)
		os.Exit(1)
	case <-ctx.Done():
	}

	// Shutdown: drain both listeners (10s), then the fan-out wait
	// (Handler.waitBudget, 15s). Total ~25s worst case — under the
	// pod's 30s SIGKILL grace period, so the process exits on its own
	// terms instead of being killed with check POSTs half-written.
	logger().Info("shutdown signal received — draining connections")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := publicSrv.Shutdown(shutdownCtx); err != nil {
		logger().Warn("graceful shutdown failed — connections dropped",
			"error", err)
	}
	if err := internalSrv.Shutdown(shutdownCtx); err != nil {
		logger().Warn("metrics server shutdown failed", "error", err)
	}
	cancel()
	// srv.Shutdown only drains listeners and request handlers — the
	// detached fan-out goroutines outlive the requests that spawned
	// them. Wait (budgeted) for the last check POST to land before
	// exiting; Wait logs any fan-outs abandoned at budget expiry.
	logger().Info("connections drained — waiting for in-flight fan-outs")
	waitCtx, waitCancel := context.WithTimeout(context.Background(), handler.WaitBudget)
	wh.Wait(waitCtx)
	waitCancel()
	// Fan-outs are done (or abandoned) — drop the keep-alive
	// connections the ATC client pooled during dispatch so the process
	// exits without lingering sockets.
	client.HTTP.CloseIdleConnections()
}
