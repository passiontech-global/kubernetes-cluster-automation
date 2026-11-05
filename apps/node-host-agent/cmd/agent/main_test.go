package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/agent"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/platform/watchdogconf"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/subsystem/apiprober"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/subsystem/hostconfig"
)

func TestGetenv(t *testing.T) {
	const key = "TEST_NHA_GETENV"

	t.Run("unset returns default", func(t *testing.T) {
		if got := getenv(key, "def"); got != "def" {
			t.Fatalf("getenv unset=%q want %q", got, "def")
		}
	})
	t.Run("empty returns default", func(t *testing.T) {
		t.Setenv(key, "")
		if got := getenv(key, "def"); got != "def" {
			t.Fatalf("getenv empty=%q want %q", got, "def")
		}
	})
	t.Run("set returns value", func(t *testing.T) {
		t.Setenv(key, "val")
		if got := getenv(key, "def"); got != "val" {
			t.Fatalf("getenv set=%q want %q", got, "val")
		}
	})
}

func TestEnvBool(t *testing.T) {
	const key = "TEST_NHA_BOOL"

	// Truthy and falsy spellings must round-trip regardless of the
	// default — mirroring the shell knobs they replace.
	for _, v := range []string{"1", "true", "yes", "on"} {
		t.Run("truthy/"+v, func(t *testing.T) {
			t.Setenv(key, v)
			if !envBool(key, false) {
				t.Fatalf("envBool(%q) with default=false want true", v)
			}
			if !envBool(key, true) {
				t.Fatalf("envBool(%q) with default=true want true", v)
			}
		})
	}
	for _, v := range []string{"0", "false", "no", "off"} {
		t.Run("falsy/"+v, func(t *testing.T) {
			t.Setenv(key, v)
			if envBool(key, true) {
				t.Fatalf("envBool(%q) with default=true want false", v)
			}
			if envBool(key, false) {
				t.Fatalf("envBool(%q) with default=false want false", v)
			}
		})
	}
	// Invalid/empty fall through to the default — both directions.
	for _, def := range []bool{true, false} {
		t.Setenv(key, "bogus")
		if got := envBool(key, def); got != def {
			t.Fatalf("envBool(invalid)=%v want default %v", got, def)
		}
		t.Setenv(key, "")
		if got := envBool(key, def); got != def {
			t.Fatalf("envBool(empty)=%v want default %v", got, def)
		}
	}
}

func TestEnvInt(t *testing.T) {
	const key = "TEST_NHA_INT"

	t.Setenv(key, "42")
	if got := envInt(key, 7); got != 42 {
		t.Fatalf("envInt=%d want 42", got)
	}
	t.Setenv(key, "notanint")
	if got := envInt(key, 7); got != 7 {
		t.Fatalf("envInt(invalid)=%d want default 7", got)
	}
	t.Setenv(key, "")
	if got := envInt(key, 7); got != 7 {
		t.Fatalf("envInt(empty)=%d want default 7", got)
	}
}

func TestEnvInt64(t *testing.T) {
	const key = "TEST_NHA_INT64"

	t.Setenv(key, "9876543210")
	if got := envInt64(key, 5); got != 9876543210 {
		t.Fatalf("envInt64=%d want 9876543210", got)
	}
	t.Setenv(key, "notanint")
	if got := envInt64(key, 5); got != 5 {
		t.Fatalf("envInt64(invalid)=%d want default 5", got)
	}
	t.Setenv(key, "")
	if got := envInt64(key, 5); got != 5 {
		t.Fatalf("envInt64(empty)=%d want default 5", got)
	}
}

func TestEnvDuration(t *testing.T) {
	const key = "TEST_NHA_DURATION"

	// Go duration strings parse normally.
	t.Setenv(key, "1h")
	if got := envDuration(key, time.Second); got != time.Hour {
		t.Fatalf("envDuration(1h)=%v want 1h", got)
	}
	t.Setenv(key, "30s")
	if got := envDuration(key, time.Second); got != 30*time.Second {
		t.Fatalf("envDuration(30s)=%v want 30s", got)
	}
	// A bare integer means seconds — parity with the shell knobs.
	t.Setenv(key, "90")
	if got := envDuration(key, time.Second); got != 90*time.Second {
		t.Fatalf("envDuration(90)=%v want 90s", got)
	}
	t.Setenv(key, "bogus!")
	if got := envDuration(key, time.Second); got != time.Second {
		t.Fatalf("envDuration(invalid)=%v want default 1s", got)
	}
	t.Setenv(key, "")
	if got := envDuration(key, time.Second); got != time.Second {
		t.Fatalf("envDuration(empty)=%v want default 1s", got)
	}
}

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

// An unparseable env duration falls back to the default — but warns,
// like the ≤0 path does: a typo'd knob silently pinned to the
// default is impossible to spot from the outside.
func TestEnvDurationWarnsOnUnparseable(t *testing.T) {
	const key = "TEST_NHA_DURATION_WARN"
	buf := captureSlog(t)

	t.Setenv(key, "bogus!")
	if got := envDuration(key, time.Second); got != time.Second {
		t.Fatalf("envDuration(invalid)=%v want default 1s", got)
	}
	logs := buf.String()
	if !strings.Contains(logs, "unparseable env duration") ||
		!strings.Contains(logs, key) {
		t.Fatalf("missing unparseable-duration warn:\n%s", logs)
	}

	// Parseable values warn nothing.
	buf.Reset()
	t.Setenv(key, "30s")
	if got := envDuration(key, time.Second); got != 30*time.Second {
		t.Fatalf("envDuration(30s)=%v want 30s", got)
	}
	if strings.Contains(buf.String(), "env duration") {
		t.Fatalf("parseable value warned:\n%s", buf.String())
	}
}

// TestKubeClientOutOfCluster exercises the KUBECONFIG fallback. The
// in-cluster env vars are forced empty so rest.InClusterConfig fails
// deterministically; the assertion still tolerates either outcome
// (error, or a client if the environment somehow resolves one).
func TestKubeClientOutOfCluster(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	t.Run("missing kubeconfig file errors", func(t *testing.T) {
		t.Setenv("KUBECONFIG", "/nonexistent/kubeconfig")
		cs, err := kubeClient()
		if err == nil && cs == nil {
			t.Fatal("kubeClient returned nil client and nil error")
		}
	})
	t.Run("empty kubeconfig errors", func(t *testing.T) {
		t.Setenv("KUBECONFIG", "")
		cs, err := kubeClient()
		if err == nil && cs == nil {
			t.Fatal("kubeClient returned nil client and nil error")
		}
	})
}

// TestKubeClientKubeconfigSuccess exercises the $KUBECONFIG fallback
// success path: a real kubeconfig file pointing at a (never-dialled)
// server must produce a non-nil clientset — NewForConfig only builds
// the REST client, no connection is attempted.
func TestKubeClientKubeconfigSuccess(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

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

	cs, err := kubeClient()
	if err != nil {
		t.Fatalf("kubeClient with valid KUBECONFIG err=%v want nil", err)
	}
	if cs == nil {
		t.Fatal("kubeClient with valid KUBECONFIG returned nil client")
	}
}

// TestMainVersionFlag runs main() in a helper subprocess (the standard
// re-exec pattern): the -version flag must print the build version and
// exit 0 before any listener is bound.
func TestMainVersionFlag(t *testing.T) {
	if os.Getenv("GO_HELPER_PROCESS") == "1" {
		// Inside the helper: rebuild the flagset the testing binary
		// already consumed, then run main with -version.
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		os.Args = []string{"node-host-agent", "-version"}
		main()
		// main() returned (the -version early-return) — exit before
		// the test framework's PASS banner pollutes stdout.
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestMainVersionFlag$")
	cmd.Env = append(os.Environ(), "GO_HELPER_PROCESS=1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("helper process failed: %v\noutput: %s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != version {
		t.Fatalf("-version output=%q want %q", got, version)
	}
}

// TestMainRunShutsDownOnSIGTERM runs the full main() path in a helper
// subprocess: listeners bind on ephemeral ports, then SIGTERM drives
// the signal context to a clean exit — covering everything between
// the -version early-return and a.Run.
func TestMainRunShutsDownOnSIGTERM(t *testing.T) {
	if os.Getenv("GO_HELPER_PROCESS_RUN") == "1" {
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		os.Args = []string{
			"node-host-agent",
			"-metrics-bind-address=127.0.0.1:0",
			"-health-probe-bind-address=127.0.0.1:0",
		}
		main()
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestMainRunShutsDownOnSIGTERM$")
	cmd.Env = append(os.Environ(),
		"GO_HELPER_PROCESS_RUN=1",
		// Hermetic: no kube client attempts, no host-path probes.
		"NODE_HOST_AGENT_ENABLE_SWEEPER=false",
		"NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE=false",
		"NODE_HOST_AGENT_ENABLE_APIPROBER=false",
		"NODE_HOST_AGENT_ENABLE_HOSTMETRICS=false",
		"NODE_HOST_AGENT_ENABLE_HYGIENE=false",
		"NODE_HOST_AGENT_ENABLE_NETHEALTH=false",
		"NODE_HOST_AGENT_ENABLE_REPORTER=false",
		"NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE=false",
		"NODE_HOST_AGENT_ENABLE_HOSTCONFIG=false",
		"NODE_HOST_AGENT_ENABLE_JANITOR=false",
		"KUBERNETES_SERVICE_HOST=",
		"KUBERNETES_SERVICE_PORT=",
		"KUBECONFIG=",
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	// Both servers log "listening" once bound — that's the readiness
	// signal; SIGTERM before it could land before the notify context.
	listening := make(chan struct{})
	go func() {
		defer close(listening)
		sc := bufio.NewScanner(stdout)
		n := 0
		for sc.Scan() {
			if strings.Contains(sc.Text(), `"msg":"listening"`) {
				n++
				if n == 2 {
					return
				}
			}
		}
	}()

	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()
	select {
	case <-listening:
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			_ = cmd.Process.Kill()
			t.Fatalf("could not signal helper: %v", err)
		}
	case <-timeout.C:
		_ = cmd.Process.Kill()
		t.Fatal("helper never reached the listening state")
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper did not shut down cleanly: %v", err)
	}
}

// TestMainRunListenerError exercises the a.Run failure tail of
// main(): an unbindable metrics address exits the process with
// status 1.
func TestMainRunListenerError(t *testing.T) {
	if os.Getenv("GO_HELPER_PROCESS_BADADDR") == "1" {
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		os.Args = []string{
			"node-host-agent",
			"-metrics-bind-address=bad addr",
			"-health-probe-bind-address=127.0.0.1:0",
		}
		main()
		os.Exit(0) // unreachable: main exits 1 on Run error
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestMainRunListenerError$")
	cmd.Env = append(os.Environ(),
		"GO_HELPER_PROCESS_BADADDR=1",
		"NODE_HOST_AGENT_ENABLE_SWEEPER=false",
		"NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE=false",
		"NODE_HOST_AGENT_ENABLE_APIPROBER=false",
		"NODE_HOST_AGENT_ENABLE_HOSTMETRICS=false",
		"NODE_HOST_AGENT_ENABLE_HYGIENE=false",
		"NODE_HOST_AGENT_ENABLE_NETHEALTH=false",
		"NODE_HOST_AGENT_ENABLE_REPORTER=false",
		"NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE=false",
		"NODE_HOST_AGENT_ENABLE_HOSTCONFIG=false",
		"NODE_HOST_AGENT_ENABLE_JANITOR=false",
		"KUBERNETES_SERVICE_HOST=",
		"KUBERNETES_SERVICE_PORT=",
		"KUBECONFIG=",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("helper should exit non-zero on listener error:\n%s", out)
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("helper exit=%v want exit code 1:\n%s", err, out)
	}
	if !strings.Contains(string(out), "agent exited") {
		t.Fatalf("helper output missing 'agent exited' log:\n%s", out)
	}
}

// disableAllSubsystems switches every default-on subsystem off —
// each subtest then re-enables only what it exercises.
func disableAllSubsystems(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"NODE_HOST_AGENT_ENABLE_SWEEPER",
		"NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE",
		"NODE_HOST_AGENT_ENABLE_APIPROBER",
		"NODE_HOST_AGENT_ENABLE_HOSTMETRICS",
		"NODE_HOST_AGENT_ENABLE_HYGIENE",
		"NODE_HOST_AGENT_ENABLE_NETHEALTH",
		"NODE_HOST_AGENT_ENABLE_REPORTER",
		"NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE",
		"NODE_HOST_AGENT_ENABLE_HOSTCONFIG",
		"NODE_HOST_AGENT_ENABLE_JANITOR",
	} {
		t.Setenv(k, "false")
	}
}

func subsystemNames(cfg agent.Config) []string {
	names := []string{}
	for _, s := range cfg.Subsystems {
		names = append(names, s.Name())
	}
	return names
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
		cfg, apiproberOn := buildAgentConfig("n", "p", "ns", "v",
			"127.0.0.1:0", "127.0.0.1:0", false)
		if len(cfg.Subsystems) != 0 {
			t.Fatalf("subsystems=%d want 0", len(cfg.Subsystems))
		}
		if apiproberOn {
			t.Fatal("apiproberEnabled=true want false")
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
		t.Setenv("NODE_HOST_AGENT_ENABLE_SWEEPER", "true")
		cfg, _ := buildAgentConfig("n", "p", "ns", "v", "127.0.0.1:0", "127.0.0.1:0", false)
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
		t.Setenv("NODE_HOST_AGENT_ENABLE_SWEEPER", "true")
		cfg, _ := buildAgentConfig("n", "p", "ns", "v", "127.0.0.1:0", "127.0.0.1:0", false)
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
		t.Setenv("NODE_HOST_AGENT_ENABLE_APIPROBER", "auto")
		cfg, apiproberOn := buildAgentConfig("n", "p", "ns", "v",
			"127.0.0.1:0", "127.0.0.1:0", false)
		if !apiproberOn {
			t.Fatal("apiproberEnabled=false want true (auto default)")
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
		t.Setenv("NODE_HOST_AGENT_ENABLE_HOSTMETRICS", "true")
		cfg, _ := buildAgentConfig("n", "p", "ns", "v",
			"127.0.0.1:0", "127.0.0.1:0", false)
		if len(cfg.Subsystems) != 1 || cfg.Subsystems[0].Name() != "hostmetrics" {
			t.Fatalf("subsystems=%v want [hostmetrics]", subsystemNames(cfg))
		}
		if _, err := cfg.Registry.Gather(); err != nil {
			t.Fatalf("Gather on shared registry failed: %v", err)
		}
	})

	t.Run("apiprober invalid mode is not fatal", func(t *testing.T) {
		disableAllSubsystems(t)
		t.Setenv("NODE_HOST_AGENT_ENABLE_APIPROBER", "auto")
		t.Setenv("NODE_HOST_AGENT_APIPROBER_MODE", "bogus")
		cfg, apiproberOn := buildAgentConfig("n", "p", "ns", "v",
			"127.0.0.1:0", "127.0.0.1:0", false)
		if !apiproberOn {
			t.Fatal("apiproberEnabled=false want true")
		}
		if len(cfg.Subsystems) != 0 {
			t.Fatalf("subsystems=%d want 0 (apiprober setup failed, not fatal)", len(cfg.Subsystems))
		}
	})

	t.Run("concourse-cache default enabled without kube client", func(t *testing.T) {
		disableAllSubsystems(t)
		// CONCOURSE_CACHE default true; pure host-fs, no kube client
		// required.
		t.Setenv("NODE_HOST_AGENT_ENABLE_CONCOURSE_CACHE", "true")
		cfg, _ := buildAgentConfig("n", "p", "ns", "v",
			"127.0.0.1:0", "127.0.0.1:0", false)
		if names := subsystemNames(cfg); len(names) != 1 || names[0] != "concourse-cache" {
			t.Fatalf("subsystems=%v want [concourse-cache]", names)
		}
	})

	t.Run("nethealth default enabled without kube client", func(t *testing.T) {
		disableAllSubsystems(t)
		// NETHEALTH default true; no kube client required.
		t.Setenv("NODE_HOST_AGENT_ENABLE_NETHEALTH", "true")
		cfg, _ := buildAgentConfig("n", "p", "ns", "v",
			"127.0.0.1:0", "127.0.0.1:0", false)
		if names := subsystemNames(cfg); len(names) != 1 || names[0] != "nethealth" {
			t.Fatalf("subsystems=%v want [nethealth]", names)
		}
	})

	t.Run("controllerhygiene auto disables on non-controller", func(t *testing.T) {
		disableAllSubsystems(t)
		// "auto" is the production default; no k0scontroller.service
		// under the test host root → stays off.
		t.Setenv("NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE", "auto")
		cfg, _ := buildAgentConfig("n", "p", "ns", "v",
			"127.0.0.1:0", "127.0.0.1:0", false)
		if len(cfg.Subsystems) != 0 {
			t.Fatalf("subsystems=%v want [] (no k0scontroller unit)", subsystemNames(cfg))
		}
	})

	t.Run("hostconfig auto disables without vars dir", func(t *testing.T) {
		disableAllSubsystems(t)
		// "auto" is the production default; the default vars dir
		// carries no defaults.yaml in the test environment → off.
		t.Setenv("NODE_HOST_AGENT_ENABLE_HOSTCONFIG", "auto")
		cfg, _ := buildAgentConfig("n", "p", "ns", "v",
			"127.0.0.1:0", "127.0.0.1:0", false)
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
		t.Setenv("NODE_HOST_AGENT_ENABLE_HOSTCONFIG", "auto")
		t.Setenv("NODE_HOST_AGENT_HOSTCONFIG_VARS_DIR", varsDir)
		cfg, _ := buildAgentConfig("n", "p", "ns", "v",
			"127.0.0.1:0", "127.0.0.1:0", false)
		if names := subsystemNames(cfg); len(names) != 1 || names[0] != "hostconfig" {
			t.Fatalf("subsystems=%v want [hostconfig]", names)
		}
	})
}

// stubKubeClient swaps the package-level client factory for a counter
// stub — csOnce's shared-build behaviour is only observable through it.
func stubKubeClient(t *testing.T,
	fn func() (kubernetes.Interface, error)) *int {
	t.Helper()
	calls := new(int)
	orig := kubeClient
	kubeClient = func() (kubernetes.Interface, error) {
		(*calls)++
		return fn()
	}
	t.Cleanup(func() { kubeClient = orig })
	return calls
}

// enableBothKubeConsumers is the env set where sweeper AND
// workerhygiene each reach their csOnce call.
func enableBothKubeConsumers(t *testing.T) {
	t.Helper()
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	t.Setenv("KUBECONFIG", "")
	disableAllSubsystems(t)
	t.Setenv("NODE_HOST_AGENT_ENABLE_SWEEPER", "true")
	t.Setenv("NODE_HOST_AGENT_ENABLE_HYGIENE", "true")
}

// TestCsOnceSharesOneClientset: sweeper and workerhygiene both consume
// csOnce — the clientset is built exactly once for the process.
func TestCsOnceSharesOneClientset(t *testing.T) {
	calls := stubKubeClient(t, func() (kubernetes.Interface, error) {
		return fake.NewSimpleClientset(), nil
	})
	enableBothKubeConsumers(t)

	cfg, _ := buildAgentConfig("node-a", "p", "ns", "v",
		"127.0.0.1:0", "127.0.0.1:0", false)

	if *calls != 1 {
		t.Fatalf("kubeClient calls=%d want 1 (shared clientset)", *calls)
	}
	names := []string{}
	for _, s := range cfg.Subsystems {
		names = append(names, s.Name())
	}
	if len(names) != 3 || names[0] != "sweeper" || names[1] != "workerhygiene" ||
		names[2] != "hubsync" {
		t.Fatalf("subsystems=%v want [sweeper workerhygiene hubsync]", names)
	}
}

// TestCsOnceErrorRetried: only a successful build is cached — each
// consumer re-attempts after a failure so one transient error cannot
// disable every kube subsystem for the process lifetime (and neither
// subsystem aborts the agent).
func TestCsOnceErrorRetried(t *testing.T) {
	calls := stubKubeClient(t, func() (kubernetes.Interface, error) {
		return nil, errors.New("no config")
	})
	enableBothKubeConsumers(t)

	cfg, _ := buildAgentConfig("node-a", "p", "ns", "v",
		"127.0.0.1:0", "127.0.0.1:0", false)

	// sweeper + workerhygiene + hubsync each re-attempt once.
	if *calls != 3 {
		t.Fatalf("kubeClient calls=%d want 3 (error retried per consumer)", *calls)
	}
	if len(cfg.Subsystems) != 0 {
		t.Fatalf("subsystems=%d want 0 (client build failed)", len(cfg.Subsystems))
	}
}

// --- standalone mode ---

// TestStandaloneDefaultFlips verifies the standalone enable-set
// inversion: with a working kube client stub and a node name, pod
// mode builds the kube-dependent subsystems by default while
// standalone does not — and an explicit env override still wins.
func TestStandaloneDefaultFlips(t *testing.T) {
	stubKubeClient(t, func() (kubernetes.Interface, error) {
		return fake.NewSimpleClientset(), nil
	})
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	t.Setenv("KUBECONFIG", "")
	t.Setenv("NODE_HOST_AGENT_NODE_NAME", "node-a")
	t.Setenv("NODE_HOST_AGENT_WATCHDOG_CONF",
		filepath.Join(t.TempDir(), "absent.conf"))
	t.Setenv("NODE_HOST_AGENT_API_GUARD_CONF",
		filepath.Join(t.TempDir(), "absent-guard.conf"))
	t.Setenv("NODE_HOST_AGENT_HOSTCONFIG_VARS_DIR", t.TempDir())
	t.Setenv("NODE_HOST_AGENT_CONVERGE_SSH_KEY",
		filepath.Join(t.TempDir(), "absent-key"))
	t.Setenv("NODE_HOST_AGENT_ENABLE_KINEDB", "false")
	t.Setenv("NODE_HOST_AGENT_ENABLE_CONTROLLERHYGIENE", "false")
	t.Setenv("NODE_HOST_AGENT_ENABLE_HOSTCONFIG", "false")

	t.Run("standalone flips kube-dependent defaults off", func(t *testing.T) {
		cfg, _ := buildAgentConfig("node-a", "p", "ns", "v",
			"127.0.0.1:0", "127.0.0.1:0", true)
		names := subsystemNames(cfg)
		want := map[string]bool{
			"apiprober": true, "hostmetrics": true,
			"hostmetrics-textfile": true,
			"nethealth":            true, "janitor": true,
		}
		for _, n := range names {
			if !want[n] {
				t.Fatalf("standalone subsystem %q not in want-set %v", n, names)
			}
			delete(want, n)
		}
		if len(want) != 0 {
			t.Fatalf("standalone missing subsystems %v (got %v)", want, names)
		}
	})

	t.Run("pod mode keeps kube-dependent defaults on", func(t *testing.T) {
		cfg, _ := buildAgentConfig("node-a", "p", "ns", "v",
			"127.0.0.1:0", "127.0.0.1:0", false)
		got := map[string]bool{}
		for _, n := range subsystemNames(cfg) {
			got[n] = true
		}
		for _, n := range []string{
			"sweeper", "concourse-cache", "workerhygiene", "nodereporter",
		} {
			if !got[n] {
				t.Fatalf("pod mode missing %q (got %v)", n, subsystemNames(cfg))
			}
		}
		if got["hostmetrics-textfile"] {
			t.Fatal("hostmetrics-textfile must not run in pod mode")
		}
	})

	t.Run("env override still wins in standalone", func(t *testing.T) {
		t.Setenv("NODE_HOST_AGENT_ENABLE_HYGIENE", "true")
		cfg, _ := buildAgentConfig("node-a", "p", "ns", "v",
			"127.0.0.1:0", "127.0.0.1:0", true)
		got := map[string]bool{}
		for _, n := range subsystemNames(cfg) {
			got[n] = true
		}
		if !got["workerhygiene"] {
			t.Fatalf("ENABLE_HYGIENE=true ignored in standalone (got %v)",
				subsystemNames(cfg))
		}
	})

	t.Run("NODE_HOST_AGENT_STANDALONE env selects standalone", func(t *testing.T) {
		t.Setenv("NODE_HOST_AGENT_STANDALONE", "1")
		cfg, _ := buildAgentConfig("node-a", "p", "ns", "v",
			"127.0.0.1:0", "127.0.0.1:0", false)
		got := map[string]bool{}
		for _, n := range subsystemNames(cfg) {
			got[n] = true
		}
		if got["sweeper"] || got["workerhygiene"] || got["nodereporter"] {
			t.Fatalf("STANDALONE=1 did not flip defaults (got %v)",
				subsystemNames(cfg))
		}
		if !got["hostmetrics-textfile"] {
			t.Fatal("STANDALONE=1 did not enable the textfile writer")
		}
	})
}

// --- subcommand dispatch (arg-parse level) ---

func TestDispatchDaemonArgs(t *testing.T) {
	for _, argv := range [][]string{
		{"node-host-agent"},
		{"node-host-agent", "-version"},
		{"node-host-agent", "--standalone", "--node-name=x"},
	} {
		if code, handled := dispatch(argv); handled {
			t.Fatalf("dispatch(%v)=(%d,true) want (0,false)", argv, code)
		}
	}
}

func TestDispatchUnknownSubcommand(t *testing.T) {
	code, handled := dispatch([]string{"node-host-agent", "bogus"})
	if !handled || code != 2 {
		t.Fatalf("dispatch(bogus)=(%d,%v) want (2,true)", code, handled)
	}
}

func TestDispatchRuncArgv0(t *testing.T) {
	// argv[0] "runc" selects the wrapper; runc.real does not exist in
	// the test env so exec fails → non-zero, but dispatch handled it.
	code, handled := dispatch([]string{"/concourse-runc/runc", "state"})
	if !handled {
		t.Fatal("argv0 runc was not handled")
	}
	if code == 0 {
		t.Fatal("runc wrapper returned 0 without runc.real — unexpected")
	}
}

func TestDispatchConvergeOnceArgParsing(t *testing.T) {
	// Bad flag → exit 2; -h/--help → exit 0 (flag.ErrHelp is not an
	// error — a user asking for usage must not fail CI/wrappers).
	if code, handled := dispatch([]string{"nha", "converge-once", "--bogus"}); !handled || code != 2 {
		t.Fatalf("converge-once --bogus=(%d,%v) want (2,true)", code, handled)
	}
	for _, h := range []string{"-h", "--help"} {
		if code, handled := dispatch([]string{"nha", "converge-once", h}); !handled || code != 0 {
			t.Fatalf("converge-once %s=(%d,%v) want (0,true)", h, code, handled)
		}
	}
	// A vars dir without the topology files → the cycle counts the
	// load error and the command exits 1 (converge-once reports
	// errs > 0 — same contract as nebula-sign on missing vars).
	dir := t.TempDir()
	code, handled := dispatch([]string{"nha", "converge-once",
		"--vars-dir=" + dir, "--node-name=testnode"})
	if !handled || code != 1 {
		t.Fatalf("converge-once=(%d,%v) want (1,true)", code, handled)
	}
}

// quietRunner answers every host command with empty output + nil
// error — the scriptedRunner equivalent for the converge-once clean
// path (a node absent from the registry self-gates every group).
type quietRunner struct{}

func (quietRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	return "", nil
}

func TestDispatchConvergeOnceCleanExit0(t *testing.T) {
	// Stub the host seams: a tempdir host root + a runner that never
	// fails, so a fully self-gating converge reports errs==0 and the
	// command exits 0 (the timer/CI "converged" contract).
	oldRoot, oldRunner := convergeHostRoot, convergeRunner
	defer func() { convergeHostRoot, convergeRunner = oldRoot, oldRunner }()
	convergeHostRoot = t.TempDir()
	convergeRunner = func() hostconfig.Runner { return quietRunner{} }

	dir := t.TempDir()
	for name, content := range map[string]string{
		"interdc_nodes.yaml": "{}\n",
		"cluster.yaml":       "{}\n",
		"defaults.yaml":      "interdc_nebula_enabled: false\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	code, handled := dispatch([]string{"nha", "converge-once",
		"--vars-dir=" + dir, "--node-name=testnode"})
	if !handled || code != 0 {
		t.Fatalf("converge-once clean=(%d,%v) want (0,true)", code, handled)
	}
}

func TestDispatchNebulaSignArgParsing(t *testing.T) {
	// --ca-dir is required.
	if code, handled := dispatch([]string{"nha", "nebula-sign"}); !handled || code != 2 {
		t.Fatalf("nebula-sign (no ca-dir)=(%d,%v) want (2,true)", code, handled)
	}
	// -h exits 0 — help is a clean exit, not a usage error.
	if code, handled := dispatch([]string{"nha", "nebula-sign", "-h"}); !handled || code != 0 {
		t.Fatalf("nebula-sign -h=(%d,%v) want (0,true)", code, handled)
	}
	// Missing vars files → error exit 1 (topology.Load fails before
	// any signing).
	dir := t.TempDir()
	code, handled := dispatch([]string{"nha", "nebula-sign",
		"--vars-dir=" + dir, "--ca-dir=" + dir})
	if !handled || code != 1 {
		t.Fatalf("nebula-sign missing vars=(%d,%v) want (1,true)", code, handled)
	}
}

func TestDispatchConcourseWorkerInitArgParsing(t *testing.T) {
	if code, handled := dispatch([]string{"nha", "concourse-worker-init", "--bogus"}); !handled || code != 2 {
		t.Fatalf("concourse-worker-init --bogus=(%d,%v) want (2,true)", code, handled)
	}
	if code, handled := dispatch([]string{"nha", "concourse-worker-init", "-h"}); !handled || code != 0 {
		t.Fatalf("concourse-worker-init -h=(%d,%v) want (0,true)", code, handled)
	}
	// --wrapper-source pointing at a missing binary fails the
	// install (copyFileAtomic errors) → exit 1, proving the flag
	// reached cfg.WrapperSource. The other flags get temp dirs and a
	// temp runc source so everything before the wrapper copy works.
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	runcDir := filepath.Join(dir, "runc")
	runcSrc := filepath.Join(dir, "runc-real")
	for _, d := range []string{work, runcDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(runcSrc, []byte("fake-runc"), 0o755); err != nil {
		t.Fatal(err)
	}
	code, handled := dispatch([]string{"nha", "concourse-worker-init",
		"--work-dir=" + work, "--runc-dir=" + runcDir,
		"--runc-source=" + runcSrc,
		"--wrapper-source=" + filepath.Join(dir, "no-such-binary")})
	if !handled || code != 1 {
		t.Fatalf("concourse-worker-init bad wrapper-source=(%d,%v) want (1,true)",
			code, handled)
	}
}

func TestDispatchPurgeEventsArgParsing(t *testing.T) {
	if code, handled := dispatch([]string{"nha", "purge-events", "--bogus"}); !handled || code != 2 {
		t.Fatalf("purge-events --bogus=(%d,%v) want (2,true)", code, handled)
	}
	if code, handled := dispatch([]string{"nha", "purge-events", "-h"}); !handled || code != 0 {
		t.Fatalf("purge-events -h=(%d,%v) want (0,true)", code, handled)
	}
	// A malformed cutoff is a usage error before any TLS/dial work.
	for _, argv := range [][]string{
		{"nha", "purge-events", "not-a-timestamp"},
		{"nha", "purge-events", "--before=not-a-timestamp"},
	} {
		if code, handled := dispatch(argv); !handled || code != 2 {
			t.Fatalf("purge-events %v=(%d,%v) want (2,true)", argv[2:], code, handled)
		}
	}
	// Missing PKI files → Run fails building the client → exit 1.
	code, handled := dispatch([]string{"nha", "purge-events",
		"--ca=/nonexistent/ca.crt", "2026-08-23T04:27:00Z"})
	if !handled || code != 1 {
		t.Fatalf("purge-events missing CA=(%d,%v) want (1,true)", code, handled)
	}
}

// The positional-cutoff scan works on a clone — the compacting
// appends must not corrupt the caller's slice (which aliases the
// os.Args backing array in production).
func TestPurgeEventsDoesNotMutateArgs(t *testing.T) {
	for _, args := range [][]string{
		// Positional first: without the clone the compaction shifts
		// the flag left over it inside the shared backing array.
		{"2026-08-23T04:27:00Z", "--ca=/nonexistent/ca.crt"},
		// The `--` branch drops the element after it in place.
		{"--", "not-a-timestamp", "--ca=/nonexistent/ca.crt"},
	} {
		want := slices.Clone(args)
		if code := purgeEventsCmd(context.Background(), args); code != 1 && code != 2 {
			t.Fatalf("purge-events %v=%d want 1 or 2", args, code)
		}
		if !slices.Equal(args, want) {
			t.Fatalf("args mutated in place: got %v want %v", args, want)
		}
	}
}

func TestDispatchCheckKineDBArgParsing(t *testing.T) {
	if code, handled := dispatch([]string{"nha", "check-kine-db", "--bogus"}); !handled || code != 2 {
		t.Fatalf("check-kine-db --bogus=(%d,%v) want (2,true)", code, handled)
	}
	if code, handled := dispatch([]string{"nha", "check-kine-db", "-h"}); !handled || code != 0 {
		t.Fatalf("check-kine-db -h=(%d,%v) want (0,true)", code, handled)
	}
}

func TestDispatchCheckK0sDriftArgParsing(t *testing.T) {
	if code, handled := dispatch([]string{"nha", "check-k0s-drift", "--bogus"}); !handled || code != 2 {
		t.Fatalf("check-k0s-drift --bogus=(%d,%v) want (2,true)", code, handled)
	}
	if code, handled := dispatch([]string{"nha", "check-k0s-drift", "-h"}); !handled || code != 0 {
		t.Fatalf("check-k0s-drift -h=(%d,%v) want (0,true)", code, handled)
	}
	// A nonexistent unit file gates the check off → clean exit 0 on
	// any host (the "not a k0s controller" skip).
	code, handled := dispatch([]string{"nha", "check-k0s-drift",
		"--unit-file=" + filepath.Join(t.TempDir(), "no-such.service")})
	if !handled || code != 0 {
		t.Fatalf("check-k0s-drift no unit=(%d,%v) want (0,true)", code, handled)
	}
	// Missing config + present unit → unreadable drift → exit 1.
	dir := t.TempDir()
	unit := filepath.Join(dir, "k0scontroller.service")
	if err := os.WriteFile(unit, []byte("[Unit]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, handled = dispatch([]string{"nha", "check-k0s-drift",
		"--unit-file=" + unit,
		"--config=" + filepath.Join(dir, "no-such.yaml")})
	if !handled || code != 1 {
		t.Fatalf("check-k0s-drift missing config=(%d,%v) want (1,true)", code, handled)
	}
}

func TestDispatchRescueEtcdArgParsing(t *testing.T) {
	if code, handled := dispatch([]string{"nha", "rescue-etcd", "--bogus"}); !handled || code != 2 {
		t.Fatalf("rescue-etcd --bogus=(%d,%v) want (2,true)", code, handled)
	}
	if code, handled := dispatch([]string{"nha", "rescue-etcd", "-h"}); !handled || code != 0 {
		t.Fatalf("rescue-etcd -h=(%d,%v) want (0,true)", code, handled)
	}
	// A missing k0s dir → the etcdctl exec fails on the very first
	// endpoint status → exit 1.
	code, handled := dispatch([]string{"nha", "rescue-etcd",
		"--k0s-dir=" + filepath.Join(t.TempDir(), "no-such")})
	if !handled || code != 1 {
		t.Fatalf("rescue-etcd missing k0s-dir=(%d,%v) want (1,true)", code, handled)
	}
}

// --- apiprober guard-conf precedence (env → conf → default) ---

func TestResolveProberInputs(t *testing.T) {
	wdCfg, _ := watchdogconf.Parse([]byte(
		`API_BACKENDS="wd1=10.1.0.1:6443"`))
	guard := apiprober.GuardDefaults{
		SocketPath:        "/run/haproxy-admin/admin.sock",
		BackendName:       "kubeAPI_backend",
		CompanionBackends: []string{"konnectivity_back"},
		StaticBackends: []apiprober.StaticBackend{
			{Name: "hub1", Addr: "10.0.0.1:6443"},
		},
		Mode:      "enforce",
		TokenFile: "/etc/api-backend-guard/token",
		CAFile:    "/etc/api-backend-guard/ca.crt",
	}

	t.Run("defaults without env or conf", func(t *testing.T) {
		pi := resolveProberInputs(wdCfg, apiprober.GuardDefaults{})
		if pi.socket != "/run/api-local-lb-admin.sock" ||
			pi.backend != "api_local_back" ||
			pi.mode != apiprober.ModeDryRun ||
			pi.tokenFile != "/var/run/secrets/kubernetes.io/serviceaccount/token" ||
			pi.caFile != "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt" {
			t.Fatalf("defaults=%+v", pi)
		}
		// wdCfg API_BACKENDS feed StaticBackends as before.
		if len(pi.static) != 1 || pi.static[0].Name != "wd1" {
			t.Fatalf("static=%v want wdCfg backends", pi.static)
		}
	})

	t.Run("guard conf fills below env", func(t *testing.T) {
		pi := resolveProberInputs(wdCfg, guard)
		if pi.socket != guard.SocketPath || pi.backend != guard.BackendName ||
			pi.mode != "enforce" || pi.tokenFile != guard.TokenFile ||
			pi.caFile != guard.CAFile {
			t.Fatalf("guard fallback=%+v", pi)
		}
		if len(pi.companions) != 1 || pi.companions[0] != "konnectivity_back" {
			t.Fatalf("companions=%v", pi.companions)
		}
		// Guard API_BACKENDS win over the watchdog conf's.
		if len(pi.static) != 1 || pi.static[0].Name != "hub1" {
			t.Fatalf("static=%v want guard backends", pi.static)
		}
	})

	t.Run("env beats guard conf", func(t *testing.T) {
		t.Setenv("NODE_HOST_AGENT_APIPROBER_SOCKET", "/custom.sock")
		t.Setenv("NODE_HOST_AGENT_APIPROBER_MODE", "dry-run")
		t.Setenv("NODE_HOST_AGENT_APIPROBER_COMPANION_BACKENDS", "extra1,extra2")
		pi := resolveProberInputs(wdCfg, guard)
		if pi.socket != "/custom.sock" || pi.mode != "dry-run" {
			t.Fatalf("env override=%+v", pi)
		}
		if len(pi.companions) != 2 || pi.companions[0] != "extra1" {
			t.Fatalf("env companions=%v", pi.companions)
		}
		// Untouched envs still see the conf layer.
		if pi.backend != guard.BackendName || pi.tokenFile != guard.TokenFile {
			t.Fatalf("conf layer lost under env=%+v", pi)
		}
	})
}

// --- kubeletWatchdogHosts ---

func TestKubeletWatchdogHosts(t *testing.T) {
	t.Run("env list wins", func(t *testing.T) {
		t.Setenv("NODE_HOST_AGENT_KUBELET_WATCHDOG_HOSTS", "a , b")
		got := kubeletWatchdogHosts(t.TempDir(), "n")
		if len(got) != 2 || got[0] != "a" || got[1] != "b" {
			t.Fatalf("env hosts=%v", got)
		}
	})

	t.Run("systemd_watchdog_hosts from vars dir", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "interdc_nodes.yaml"),
			[]byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cluster.yaml"),
			[]byte("systemd_watchdog_hosts:\n  - node-x\n  - node-y\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		got := kubeletWatchdogHosts(dir, "node-a")
		if len(got) != 2 || got[0] != "node-x" || got[1] != "node-y" {
			t.Fatalf("vars hosts=%v", got)
		}
	})

	t.Run("missing vars dir is nil not error", func(t *testing.T) {
		if got := kubeletWatchdogHosts(t.TempDir(), "n"); got != nil {
			t.Fatalf("hosts=%v want nil", got)
		}
	})
}

// --- resolveLocalBinary ---

func TestResolveLocalBinary(t *testing.T) {
	orig := osExecutable
	t.Cleanup(func() { osExecutable = orig })

	t.Run("env override wins", func(t *testing.T) {
		t.Setenv("NODE_HOST_AGENT_HUBSYNC_LOCAL_BINARY", "/custom/bin")
		if got := resolveLocalBinary(); got != "/custom/bin" {
			t.Fatalf("env override=%q want /custom/bin", got)
		}
	})

	t.Run("deleted suffix stripped", func(t *testing.T) {
		real := filepath.Join(t.TempDir(), "node-host-agent")
		if err := os.WriteFile(real, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
		osExecutable = func() (string, error) { return real + " (deleted)", nil }
		if got := resolveLocalBinary(); got != real {
			t.Fatalf("deleted-suffix resolve=%q want %q", got, real)
		}
	})

	t.Run("nonexistent resolved path falls back", func(t *testing.T) {
		osExecutable = func() (string, error) {
			return filepath.Join(t.TempDir(), "gone") + " (deleted)", nil
		}
		if got := resolveLocalBinary(); got != "/node-host-agent" {
			t.Fatalf("missing-path resolve=%q want /node-host-agent", got)
		}
	})

	t.Run("os.Executable error falls back", func(t *testing.T) {
		osExecutable = func() (string, error) { return "", errors.New("noexe") }
		if got := resolveLocalBinary(); got != "/node-host-agent" {
			t.Fatalf("error resolve=%q want /node-host-agent", got)
		}
	})
}

// --- kinedb / hubsync gating ---

func writeEd25519Key(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestKineDBGating(t *testing.T) {
	disableAllSubsystems(t)
	sandboxed := t.TempDir()
	t.Setenv("NODE_HOST_AGENT_WATCHDOG_CONF", filepath.Join(sandboxed, "no.conf"))
	t.Setenv("NODE_HOST_AGENT_API_GUARD_CONF", filepath.Join(sandboxed, "no.conf"))
	t.Setenv("NODE_HOST_AGENT_HOSTCONFIG_VARS_DIR", sandboxed)
	t.Setenv("NODE_HOST_AGENT_CONVERGE_SSH_KEY", filepath.Join(sandboxed, "no-key"))
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	t.Setenv("KUBECONFIG", "")

	t.Run("auto + no detect → off", func(t *testing.T) {
		cfg, _ := buildAgentConfig("n", "p", "ns", "v",
			"127.0.0.1:0", "127.0.0.1:0", false)
		for _, n := range subsystemNames(cfg) {
			if n == "kinedb" {
				t.Fatal("kinedb enabled without Detect match")
			}
		}
	})
	t.Run("true forces on", func(t *testing.T) {
		t.Setenv("NODE_HOST_AGENT_ENABLE_KINEDB", "true")
		cfg, _ := buildAgentConfig("n", "p", "ns", "v",
			"127.0.0.1:0", "127.0.0.1:0", false)
		got := subsystemNames(cfg)
		if len(got) != 1 || got[0] != "kinedb" {
			t.Fatalf("subsystems=%v want [kinedb]", got)
		}
	})
}

func TestHubsyncGating(t *testing.T) {
	disableAllSubsystems(t)
	sandboxed := t.TempDir()
	t.Setenv("NODE_HOST_AGENT_WATCHDOG_CONF", filepath.Join(sandboxed, "no.conf"))
	t.Setenv("NODE_HOST_AGENT_API_GUARD_CONF", filepath.Join(sandboxed, "no.conf"))
	t.Setenv("NODE_HOST_AGENT_HOSTCONFIG_VARS_DIR", sandboxed)
	t.Setenv("NODE_HOST_AGENT_ENABLE_KINEDB", "false")
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	t.Setenv("KUBECONFIG", "")

	t.Run("no key → registered, polls for key", func(t *testing.T) {
		stubKubeClient(t, func() (kubernetes.Interface, error) {
			return fake.NewSimpleClientset(), nil
		})
		t.Setenv("NODE_HOST_AGENT_CONVERGE_SSH_KEY",
			filepath.Join(sandboxed, "absent"))
		cfg, _ := buildAgentConfig("n", "pod-a", "ns", "v",
			"127.0.0.1:0", "127.0.0.1:0", false)
		// The absent key is NOT a permanent gate — the secret mounts
		// optional:true and may land after pod start; the Syncer
		// re-checks on every trigger (skip-cycle-and-poll).
		got := subsystemNames(cfg)
		if len(got) != 1 || got[0] != "hubsync" {
			t.Fatalf("subsystems=%v want [hubsync] (key-waiting mode)", got)
		}
	})

	t.Run("key + kube client → on", func(t *testing.T) {
		stubKubeClient(t, func() (kubernetes.Interface, error) {
			return fake.NewSimpleClientset(), nil
		})
		t.Setenv("NODE_HOST_AGENT_CONVERGE_SSH_KEY", writeEd25519Key(t))
		cfg, _ := buildAgentConfig("n", "pod-a", "ns", "v",
			"127.0.0.1:0", "127.0.0.1:0", false)
		got := subsystemNames(cfg)
		if len(got) != 1 || got[0] != "hubsync" {
			t.Fatalf("subsystems=%v want [hubsync]", got)
		}
	})

	t.Run("key + client error → skipped not fatal", func(t *testing.T) {
		stubKubeClient(t, func() (kubernetes.Interface, error) {
			return nil, errors.New("no config")
		})
		t.Setenv("NODE_HOST_AGENT_CONVERGE_SSH_KEY", writeEd25519Key(t))
		cfg, _ := buildAgentConfig("n", "pod-a", "ns", "v",
			"127.0.0.1:0", "127.0.0.1:0", false)
		for _, n := range subsystemNames(cfg) {
			if n == "hubsync" {
				t.Fatal("hubsync enabled despite client error")
			}
		}
	})

	t.Run("standalone never runs hubsync", func(t *testing.T) {
		stubKubeClient(t, func() (kubernetes.Interface, error) {
			return fake.NewSimpleClientset(), nil
		})
		t.Setenv("NODE_HOST_AGENT_CONVERGE_SSH_KEY", writeEd25519Key(t))
		cfg, _ := buildAgentConfig("n", "pod-a", "ns", "v",
			"127.0.0.1:0", "127.0.0.1:0", true)
		for _, n := range subsystemNames(cfg) {
			if n == "hubsync" {
				t.Fatal("hubsync ran in standalone mode")
			}
		}
	})
}
