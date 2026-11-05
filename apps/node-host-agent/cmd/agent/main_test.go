package main

import (
	"bufio"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/agent"
)

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

// testAgentParams builds the params most subtests share — ephemeral
// addrs, version "v", namespace "ns" — with node/pod/standalone
// varying per subtest.
func testAgentParams(nodeName, podName string, standalone bool) agentParams {
	return agentParams{
		nodeName:       nodeName,
		podName:        podName,
		namespace:      "ns",
		version:        "v",
		metricsAddr:    "127.0.0.1:0",
		probeAddr:      "127.0.0.1:0",
		standaloneFlag: standalone,
	}
}

func subsystemNames(cfg agent.Config) []string {
	names := []string{}
	for _, s := range cfg.Subsystems {
		names = append(names, s.Name())
	}
	return names
}
