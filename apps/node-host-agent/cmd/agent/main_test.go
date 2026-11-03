package main

import (
	"bufio"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
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
		"NODE_HOST_AGENT_ENABLE_APIPROBER=false",
		"NODE_HOST_AGENT_ENABLE_HOSTMETRICS=false",
		"NODE_HOST_AGENT_ENABLE_HYGIENE=false",
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
		"NODE_HOST_AGENT_ENABLE_APIPROBER=false",
		"NODE_HOST_AGENT_ENABLE_HOSTMETRICS=false",
		"NODE_HOST_AGENT_ENABLE_HYGIENE=false",
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
		t.Setenv("NODE_HOST_AGENT_ENABLE_SWEEPER", "false")
		t.Setenv("NODE_HOST_AGENT_ENABLE_APIPROBER", "false")
		t.Setenv("NODE_HOST_AGENT_ENABLE_HOSTMETRICS", "false")
		cfg, apiproberOn := buildAgentConfig("n", "p", "ns", "v",
			"127.0.0.1:0", "127.0.0.1:0")
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
		t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "absent"))
		t.Setenv("NODE_HOST_AGENT_ENABLE_SWEEPER", "true")
		t.Setenv("NODE_HOST_AGENT_ENABLE_APIPROBER", "false")
		t.Setenv("NODE_HOST_AGENT_ENABLE_HOSTMETRICS", "false")
		cfg, _ := buildAgentConfig("n", "p", "ns", "v", "127.0.0.1:0", "127.0.0.1:0")
		if len(cfg.Subsystems) != 0 {
			t.Fatalf("subsystems=%d want 0 (sweeper skipped, not fatal)", len(cfg.Subsystems))
		}
	})

	t.Run("sweeper built with kubeconfig", func(t *testing.T) {
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
		t.Setenv("NODE_HOST_AGENT_ENABLE_APIPROBER", "false")
		t.Setenv("NODE_HOST_AGENT_ENABLE_HOSTMETRICS", "false")
		t.Setenv("NODE_HOST_AGENT_ENABLE_HYGIENE", "false")
		cfg, _ := buildAgentConfig("n", "p", "ns", "v", "127.0.0.1:0", "127.0.0.1:0")
		if len(cfg.Subsystems) != 1 || cfg.Subsystems[0].Name() != "sweeper" {
			names := []string{}
			for _, s := range cfg.Subsystems {
				names = append(names, s.Name())
			}
			t.Fatalf("subsystems=%v want [sweeper]", names)
		}
	})

	t.Run("apiprober default enabled", func(t *testing.T) {
		t.Setenv("NODE_HOST_AGENT_ENABLE_SWEEPER", "false")
		t.Setenv("NODE_HOST_AGENT_ENABLE_HOSTMETRICS", "false")
		// NODE_HOST_AGENT_ENABLE_APIPROBER unset → "auto" → enabled.
		cfg, apiproberOn := buildAgentConfig("n", "p", "ns", "v",
			"127.0.0.1:0", "127.0.0.1:0")
		if !apiproberOn {
			t.Fatal("apiproberEnabled=false want true (auto default)")
		}
		if len(cfg.Subsystems) != 1 || cfg.Subsystems[0].Name() != "apiprober" {
			names := []string{}
			for _, s := range cfg.Subsystems {
				names = append(names, s.Name())
			}
			t.Fatalf("subsystems=%v want [apiprober]", names)
		}
	})

	t.Run("hostmetrics default enabled registers collector", func(t *testing.T) {
		t.Setenv("NODE_HOST_AGENT_ENABLE_APIPROBER", "false")
		// SWEEPER/HOSTMETRICS unset → default true. Sweeper's client
		// build fails (no kubeconfig) → skipped, not fatal;
		// hostmetrics is a scrape-time collector, not a subsystem.
		cfg, _ := buildAgentConfig("n", "p", "ns", "v",
			"127.0.0.1:0", "127.0.0.1:0")
		if len(cfg.Subsystems) != 0 {
			t.Fatalf("subsystems=%d want 0 (hostmetrics registers on the registry)", len(cfg.Subsystems))
		}
		if _, err := cfg.Registry.Gather(); err != nil {
			t.Fatalf("Gather on shared registry failed: %v", err)
		}
	})

	t.Run("apiprober invalid mode is not fatal", func(t *testing.T) {
		t.Setenv("NODE_HOST_AGENT_ENABLE_SWEEPER", "false")
		t.Setenv("NODE_HOST_AGENT_ENABLE_HOSTMETRICS", "false")
		t.Setenv("NODE_HOST_AGENT_APIPROBER_MODE", "bogus")
		cfg, apiproberOn := buildAgentConfig("n", "p", "ns", "v",
			"127.0.0.1:0", "127.0.0.1:0")
		if !apiproberOn {
			t.Fatal("apiproberEnabled=false want true")
		}
		if len(cfg.Subsystems) != 0 {
			t.Fatalf("subsystems=%d want 0 (apiprober setup failed, not fatal)", len(cfg.Subsystems))
		}
	})
}

// stubKubeClient swaps the package-level client factory for a counter
// stub — csOnce's single-build behaviour is only observable through it.
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
	t.Setenv("NODE_HOST_AGENT_ENABLE_SWEEPER", "true")
	t.Setenv("NODE_HOST_AGENT_ENABLE_APIPROBER", "false")
	t.Setenv("NODE_HOST_AGENT_ENABLE_HOSTMETRICS", "false")
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
		"127.0.0.1:0", "127.0.0.1:0")

	if *calls != 1 {
		t.Fatalf("kubeClient calls=%d want 1 (shared clientset)", *calls)
	}
	names := []string{}
	for _, s := range cfg.Subsystems {
		names = append(names, s.Name())
	}
	if len(names) != 2 || names[0] != "sweeper" || names[1] != "workerhygiene" {
		t.Fatalf("subsystems=%v want [sweeper workerhygiene]", names)
	}
}

// TestCsOnceErrorNotRetried: a failed first build is cached — the
// second consumer sees the same error without re-attempting (and
// neither subsystem aborts the agent).
func TestCsOnceErrorNotRetried(t *testing.T) {
	calls := stubKubeClient(t, func() (kubernetes.Interface, error) {
		return nil, errors.New("no config")
	})
	enableBothKubeConsumers(t)

	cfg, _ := buildAgentConfig("node-a", "p", "ns", "v",
		"127.0.0.1:0", "127.0.0.1:0")

	if *calls != 1 {
		t.Fatalf("kubeClient calls=%d want 1 (error cached, not retried)", *calls)
	}
	if len(cfg.Subsystems) != 0 {
		t.Fatalf("subsystems=%d want 0 (client build failed)", len(cfg.Subsystems))
	}
}
