// webhook-dispatcher — receives GitHub org webhook deliveries and
// fans out instant resource checks to a Concourse ATC, replacing
// per-resource polling latency with push-driven checks.
//
// Flow: POST /webhook -> verify X-Hub-Signature-256 (HMAC-SHA256 over
// the raw request body) -> resolve repository.full_name against the
// cached Concourse pipeline/resource index (~60s TTL) -> POST each
// matching resource's check webhook:
//
//	push         -> git resources
//	pull_request -> github-pr resources
//
// Other events are acknowledged with 202 so GitHub does not retry.
// A single resource failure never fails the delivery — GitHub
// redelivery would re-trigger every resource, not just the failed one.
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

	"github.com/passiontech-global/kubernetes-node-automation/apps/webhook-dispatcher/internal/concourse"
	"github.com/passiontech-global/kubernetes-node-automation/apps/webhook-dispatcher/internal/handler"
)

var version = "dev"

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

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
		BaseURL:      getenv("CONCOURSE_URL", "http://concourse-web:8080"),
		Team:         getenv("CONCOURSE_TEAM", "main"),
		User:         user,
		Password:     password,
		WebhookToken: os.Getenv("CI_WEBHOOK_TOKEN"),
		HTTP:         &http.Client{Timeout: 15 * time.Second},
		IndexTTL:     time.Minute,
	}

	mux := http.NewServeMux()
	mux.Handle("POST /webhook",
		handler.New(os.Getenv("GITHUB_WEBHOOK_SECRET"), client))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{
		Addr:              getenv("LISTEN_ADDR", ":8080"),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		// WriteTimeout must cover the handler's 30s fan-out budget.
		WriteTimeout: 45 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		logger().Info("shutdown signal received — draining connections")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger().Warn("graceful shutdown failed — connections dropped",
				"error", err)
		}
	}()

	logger().Info("starting webhook-dispatcher",
		"version", version, "addr", srv.Addr,
		"routes", "POST /webhook, GET /healthz",
		"concourse_url", client.BaseURL, "concourse_team", client.Team)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger().Error("server exited", "error", err)
		os.Exit(1)
	}
}
