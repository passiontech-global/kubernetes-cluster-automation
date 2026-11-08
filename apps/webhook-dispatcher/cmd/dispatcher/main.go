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
// GET /metrics exposes the Prometheus counters/histogram; GET /healthz
// is the liveness probe.
//
// Env contract:
//
//	GITHUB_WEBHOOK_SECRET  (required) HMAC key configured on the org webhook
//	CI_WEBHOOK_TOKEN       (required) Concourse check webhook token
//	LOCAL_USERS            (required) Concourse basic auth "user:password"
//	CONCOURSE_URL          (default http://concourse-web:8080)
//	CONCOURSE_TEAM         (default main)
//	LISTEN_ADDR            (default :8080)
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/webhook-dispatcher/internal/concourse"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/webhook-dispatcher/internal/handler"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
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

	client := &concourse.Client{
		BaseURL:      envx.String("CONCOURSE_URL", "http://concourse-web:8080"),
		Team:         envx.String("CONCOURSE_TEAM", "main"),
		User:         user,
		Password:     password,
		WebhookToken: os.Getenv("CI_WEBHOOK_TOKEN"),
		HTTP:         &http.Client{Timeout: 15 * time.Second},
		IndexTTL:     time.Minute,
	}

	wh := handler.New(os.Getenv("GITHUB_WEBHOOK_SECRET"), client)

	mux := http.NewServeMux()
	mux.Handle("POST /webhook", wh)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("GET /metrics", promhttp.Handler())

	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{
		Addr:    envx.String("LISTEN_ADDR", ":8080"),
		Handler: mux,
		// ReadTimeout covers the whole request incl. the body (bounded
		// by MaxBytesReader at 8 MiB) — without it a slow-drip client
		// outlives ReadHeaderTimeout and holds the conn forever.
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		// WriteTimeout must cover the handler's 30s index-fetch budget
		// (fan-out itself is async — the response is a fast 202).
		WriteTimeout: 45 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	// shutdownDone closes when BOTH the HTTP drain and the fan-out
	// wait have finished — main must block on it after ListenAndServe
	// returns or it would exit while detached check POSTs are still
	// in flight.
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		logger().Info("shutdown signal received — draining connections")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger().Warn("graceful shutdown failed — connections dropped",
				"error", err)
		}
		// srv.Shutdown only drains listeners and request handlers —
		// the detached fan-out goroutines outlive the requests that
		// spawned them. Wait for the last check POST to land (each is
		// bounded by the per-target fan-out timeout) before exiting.
		logger().Info("connections drained — waiting for in-flight fan-outs")
		wh.Wait()
		// Fan-outs are done — drop the keep-alive connections the ATC
		// client pooled during dispatch so the process exits without
		// lingering sockets.
		client.HTTP.CloseIdleConnections()
	}()

	logger().Info("starting webhook-dispatcher",
		"version", version, "addr", srv.Addr,
		"routes", "POST /webhook, GET /healthz, GET /metrics",
		"concourse_url", client.BaseURL, "concourse_team", client.Team)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger().Error("server exited", "error", err)
		os.Exit(1)
	}
	<-shutdownDone
}
