// config_test.go — env→agent.Config wiring: env warns and the per-subsystem enable/disable set.

package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// Env-parse semantics live in libs/hostkit/envx (envx_test.go
// covers them); only the warn behaviour cmd/agent operators see is
// still asserted here.

// captureSlog swaps the default slog logger for a text handler
// writing to the returned buffer — restored on cleanup.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// An unparseable env duration falls back to the default — but warns:
// a typo'd knob silently pinned to the default is impossible to spot
// from the outside. envx.Duration emits the same message through the
// "envx" logger; logx.For resolves slog.Default() per call so the
// captured handler still sees it.
func TestEnvDurationWarnsOnUnparseable(t *testing.T) {
	const key = "TEST_NHA_DURATION_WARN"
	buf := captureSlog(t)

	t.Setenv(key, "bogus!")
	if got := envx.Duration(key, time.Second); got != time.Second {
		t.Fatalf("envx.Duration(invalid)=%v want default 1s", got)
	}
	logs := buf.String()
	if !strings.Contains(logs, "unparseable env duration") ||
		!strings.Contains(logs, key) {
		t.Fatalf("missing unparseable-duration warn:\n%s", logs)
	}

	// Parseable values warn nothing.
	buf.Reset()
	t.Setenv(key, "30s")
	if got := envx.Duration(key, time.Second); got != 30*time.Second {
		t.Fatalf("envx.Duration(30s)=%v want 30s", got)
	}
	if strings.Contains(buf.String(), "env duration") {
		t.Fatalf("parseable value warned:\n%s", buf.String())
	}
}

// TestBuildAgentConfigSubsystems exercises the env→Config wiring:
// enable/disable envs control which subsystems are constructed.
func TestBuildAgentConfigSubsystems(t *testing.T) {
	// Force the out-of-cluster path deterministically for every
	// subtest — kubeClient must not find an in-cluster config or a
	// stray user KUBECONFIG unless the subtest sets one.
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	t.Setenv("KUBECONFIG", "")

	t.Run("all disabled", func(t *testing.T) {
		disableAllSubsystems(t)
		cfg, report := testBuildAgentConfig("n", "p", false)
		if len(cfg.Subsystems) != 0 {
			t.Fatalf("subsystems=%d want 0", len(cfg.Subsystems))
		}
		if !slices.Contains(report.Off, "apiprober") {
			t.Fatalf("report.Off=%v missing apiprober", report.Off)
		}
		if cfg.Registry == nil {
			t.Fatal("Registry is nil")
		}
		if cfg.MetricsAddr != "127.0.0.1:0" || cfg.ProbeAddr != "127.0.0.1:0" {
			t.Fatalf("addrs not carried through: %+v", cfg)
		}
	})

	t.Run("sweeper omitted without kubeconfig is not fatal", func(t *testing.T) {
		disableAllSubsystems(t)
		t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "absent"))
		t.Setenv(envnames.EnvEnableSweeper, "true")
		cfg, _ := testBuildAgentConfig("n", "p", false)
		if len(cfg.Subsystems) != 0 {
			t.Fatalf("subsystems=%d want 0 (sweeper skipped, not fatal)", len(cfg.Subsystems))
		}
	})

	t.Run("sweeper built with kubeconfig", func(t *testing.T) {
		disableAllSubsystems(t)
		kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
		content := `apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: https://127.0.0.1:6443
    insecure-skip-tls-verify: true
contexts:
- name: test
  context:
    cluster: test
    user: test
current-context: test
users:
- name: test
  user:
    token: test-token
`
		if err := os.WriteFile(kubeconfig, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Setenv("KUBECONFIG", kubeconfig)
		t.Setenv(envnames.EnvEnableSweeper, "true")
		cfg, _ := testBuildAgentConfig("n", "p", false)
		// hubsync joins: with a working client it is always wired in
		// pod mode (it polls for the converge key itself).
		if names := subsystemNames(cfg); len(names) != 2 ||
			names[0] != "sweeper" || names[1] != "hubsync" {
			t.Fatalf("subsystems=%v want [sweeper hubsync]", names)
		}
	})

	t.Run("apiprober default enabled", func(t *testing.T) {
		disableAllSubsystems(t)
		// "auto" is the production default — the prober enables
		// itself without a socket gate.
		t.Setenv(envnames.EnvEnableApiprober, "auto")
		cfg, report := testBuildAgentConfig("n", "p", false)
		if slices.Contains(report.Off, "apiprober") {
			t.Fatalf("apiprober resolved off want on (auto default): %+v", report)
		}
		if names := subsystemNames(cfg); len(names) != 1 || names[0] != "apiprober" {
			t.Fatalf("subsystems=%v want [apiprober]", names)
		}
	})

	t.Run("hostmetrics default enabled registers collector", func(t *testing.T) {
		disableAllSubsystems(t)
		// HOSTMETRICS default true; it registers on the registry AND
		// (BUG-H5) runs as a subsystem driving the latch ticker —
		// latches can't ride scrape-time Collect() when Prometheus
		// goes dark.
		t.Setenv(envnames.EnvEnableHostmetrics, "true")
		cfg, _ := testBuildAgentConfig("n", "p", false)
		if len(cfg.Subsystems) != 1 || cfg.Subsystems[0].Name() != "hostmetrics" {
			t.Fatalf("subsystems=%v want [hostmetrics]", subsystemNames(cfg))
		}
		if _, err := cfg.Registry.Gather(); err != nil {
			t.Fatalf("Gather on shared registry failed: %v", err)
		}
	})

	t.Run("apiprober invalid mode is not fatal", func(t *testing.T) {
		disableAllSubsystems(t)
		t.Setenv(envnames.EnvEnableApiprober, "auto")
		t.Setenv(envnames.EnvApiproberMode, "bogus")
		cfg, report := testBuildAgentConfig("n", "p", false)
		// Resolved ON (auto) but Build failed — that is exactly the
		// skipped bucket the startup log reports.
		if !slices.Contains(report.Skipped, "apiprober") {
			t.Fatalf("report.Skipped=%v missing apiprober", report.Skipped)
		}
		if len(cfg.Subsystems) != 0 {
			t.Fatalf("subsystems=%d want 0 (apiprober setup failed, not fatal)", len(cfg.Subsystems))
		}
	})

	t.Run("concourse-cache default enabled without kube client", func(t *testing.T) {
		disableAllSubsystems(t)
		// CONCOURSE_CACHE default true; pure host-fs, no kube client
		// required.
		t.Setenv(envnames.EnvEnableConcourseCache, "true")
		cfg, _ := testBuildAgentConfig("n", "p", false)
		if names := subsystemNames(cfg); len(names) != 1 || names[0] != "concourse-cache" {
			t.Fatalf("subsystems=%v want [concourse-cache]", names)
		}
	})

	t.Run("nethealth default enabled without kube client", func(t *testing.T) {
		disableAllSubsystems(t)
		// NETHEALTH default true; no kube client required.
		t.Setenv(envnames.EnvEnableNethealth, "true")
		cfg, _ := testBuildAgentConfig("n", "p", false)
		if names := subsystemNames(cfg); len(names) != 1 || names[0] != "nethealth" {
			t.Fatalf("subsystems=%v want [nethealth]", names)
		}
	})

	t.Run("controllerhygiene auto disables on non-controller", func(t *testing.T) {
		disableAllSubsystems(t)
		// "auto" is the production default; no k0scontroller.service
		// under the test host root → stays off.
		t.Setenv(envnames.EnvEnableControllerhygiene, "auto")
		cfg, _ := testBuildAgentConfig("n", "p", false)
		if len(cfg.Subsystems) != 0 {
			t.Fatalf("subsystems=%v want [] (no k0scontroller unit)", subsystemNames(cfg))
		}
	})

	t.Run("hostconfig auto disables without vars dir", func(t *testing.T) {
		disableAllSubsystems(t)
		// "auto" is the production default; the default vars dir
		// carries no defaults.yaml in the test environment → off.
		t.Setenv(envnames.EnvEnableHostconfig, "auto")
		cfg, _ := testBuildAgentConfig("n", "p", false)
		if len(cfg.Subsystems) != 0 {
			t.Fatalf("subsystems=%v want [] (no vars dir)", subsystemNames(cfg))
		}
	})

	t.Run("hostconfig auto enables when defaults.yaml present", func(t *testing.T) {
		disableAllSubsystems(t)
		varsDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(varsDir, "defaults.yaml"),
			[]byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Setenv(envnames.EnvEnableHostconfig, "auto")
		t.Setenv(envnames.EnvHostconfigVarsDir, varsDir)
		cfg, _ := testBuildAgentConfig("n", "p", false)
		if names := subsystemNames(cfg); len(names) != 1 || names[0] != "hostconfig" {
			t.Fatalf("subsystems=%v want [hostconfig]", names)
		}
	})
}
