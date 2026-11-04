package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/recorder"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/conversion"
)

func TestGetenv(t *testing.T) {
	const key = "NAC_TEST_GETENV"

	t.Run("unset returns default", func(t *testing.T) {
		t.Setenv(key, "")
		if got := getenv(key, "def"); got != "def" {
			t.Fatalf("getenv=%q, want %q", got, "def")
		}
	})

	t.Run("set returns value", func(t *testing.T) {
		t.Setenv(key, "/custom/labels.txt")
		if got := getenv(key, "def"); got != "/custom/labels.txt" {
			t.Fatalf("getenv=%q, want %q", got, "/custom/labels.txt")
		}
	})
}

func TestGetenvInt(t *testing.T) {
	const key = "NAC_TEST_GETENV_INT"

	t.Run("unset returns default", func(t *testing.T) {
		t.Setenv(key, "")
		if got := getenvInt(key, 4); got != 4 {
			t.Fatalf("getenvInt=%d, want 4", got)
		}
	})
	t.Run("valid returns value", func(t *testing.T) {
		t.Setenv(key, "7")
		if got := getenvInt(key, 4); got != 7 {
			t.Fatalf("getenvInt=%d, want 7", got)
		}
	})
	t.Run("zero and negative are honored", func(t *testing.T) {
		// minReplicas<=0 is the documented "disable the pin" setting —
		// getenvInt must not clamp it away.
		for v, want := range map[string]int{"0": 0, "-2": -2} {
			t.Setenv(key, v)
			if got := getenvInt(key, 4); got != want {
				t.Fatalf("getenvInt(%q)=%d, want %d", v, got, want)
			}
		}
	})
	t.Run("unparseable falls back to default", func(t *testing.T) {
		t.Setenv(key, "not-a-number")
		if got := getenvInt(key, 4); got != 4 {
			t.Fatalf("getenvInt=%d, want 4", got)
		}
	})
}

func TestGetenvDuration(t *testing.T) {
	const key = "NAC_TEST_GETENV_DURATION"

	t.Run("unset returns default", func(t *testing.T) {
		t.Setenv(key, "")
		if got := getenvDuration(key, 5*time.Minute); got != 5*time.Minute {
			t.Fatalf("getenvDuration=%s, want 5m", got)
		}
	})
	t.Run("valid returns value", func(t *testing.T) {
		t.Setenv(key, "10m")
		if got := getenvDuration(key, 5*time.Minute); got != 10*time.Minute {
			t.Fatalf("getenvDuration=%s, want 10m", got)
		}
	})
	// Every duration knob feeds a ticker interval — <=0 would panic
	// time.NewTicker and a sub-second one would hot-loop the sweep,
	// so both must fall back to the default, not be honored.
	t.Run("non-positive falls back to default", func(t *testing.T) {
		for _, v := range []string{"0s", "-5m"} {
			t.Setenv(key, v)
			if got := getenvDuration(key, 5*time.Minute); got != 5*time.Minute {
				t.Fatalf("getenvDuration(%q)=%s, want 5m", v, got)
			}
		}
	})
	t.Run("sub-second falls back to default", func(t *testing.T) {
		for _, v := range []string{"1ns", "500ms", "999ms"} {
			t.Setenv(key, v)
			if got := getenvDuration(key, 5*time.Minute); got != 5*time.Minute {
				t.Fatalf("getenvDuration(%q)=%s, want 5m", v, got)
			}
		}
	})
	t.Run("one second is honored", func(t *testing.T) {
		t.Setenv(key, "1s")
		if got := getenvDuration(key, 5*time.Minute); got != time.Second {
			t.Fatalf("getenvDuration=%s, want 1s", got)
		}
	})
	t.Run("unparseable falls back to default", func(t *testing.T) {
		t.Setenv(key, "not-a-duration")
		if got := getenvDuration(key, 5*time.Minute); got != 5*time.Minute {
			t.Fatalf("getenvDuration=%s, want 5m", got)
		}
	})
}

// ---- subprocess tests for main() -------------------------------------
//
// main() terminates via os.Exit on both the happy version path and
// every failure path, so it can only be exercised by re-executing the
// test binary (the standard helper-process pattern) and observing the
// child's exit code + captured output.

// TestHelperProcess is the helper entry point re-executed by the
// TestMain* tests below — it is skipped on the parent run and calls
// main() in the child so os.Exit surfaces as the process exit code.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_HELPER_PROCESS") != "1" {
		return
	}
	// main() calls flag.Parse() on flag.CommandLine, which in this
	// re-executed test binary already carries the -test.* flags.
	// Rebuild the FlagSet and cut argv at "--" so main() sees exactly
	// the arguments the parent passed after it.
	sep := slices.Index(os.Args, "--")
	if sep < 0 {
		os.Exit(2) // parent contract violation: no "--" separator
	}
	os.Args = append([]string{os.Args[0]}, os.Args[sep+1:]...)
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	main()
	// Reached only when main() returns normally (graceful shutdown —
	// every other path os.Exits itself). An explicit os.Exit matters:
	// the coverage runtime only flushes counters to GOCOVERDIR via its
	// exit hook, which a plain test-binary completion does not trigger.
	os.Exit(0)
}

// kubeScrubbedEnv returns the process environment minus every variable
// that could make ctrl.GetConfigOrDie succeed (or fail differently) —
// kubeconfig paths and in-cluster service discovery.
func kubeScrubbedEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		switch key {
		case "KUBECONFIG", "KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT":
			continue
		}
		env = append(env, kv)
	}
	return env
}

// runMainInSubprocess re-executes the test binary; the helper inside
// runs main() with args as argv. Returns captured stdout, stderr and
// the process exit code (0 when the child exits cleanly).
func runMainInSubprocess(t *testing.T, args []string, extraEnv ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmdArgs := append([]string{"-test.run=TestHelperProcess", "--"}, args...)
	cmd := exec.Command(os.Args[0], cmdArgs...)
	cmd.Env = append(kubeScrubbedEnv(), append([]string{"GO_HELPER_PROCESS=1"}, extraEnv...)...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	switch {
	case err == nil:
		code = 0
	default:
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("subprocess did not run: %v", err)
		}
		code = exitErr.ExitCode()
	}
	return outBuf.String(), errBuf.String(), code
}

// -version must print "node-automation-controller <version>" and exit
// 0 before any cluster connection is attempted.
func TestMainVersionFlag(t *testing.T) {
	stdout, _, code := runMainInSubprocess(t, []string{"-version"})
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if want := "node-automation-controller dev\n"; stdout != want {
		t.Fatalf("stdout = %q, want %q", stdout, want)
	}
}

// With no kubeconfig anywhere (no flag, no KUBECONFIG env, no
// in-cluster service vars, empty $HOME/.kube) ctrl.GetConfigOrDie must
// log "unable to get kubeconfig" and exit 1.
func TestMainNoKubeconfig(t *testing.T) {
	// Redirect HOME so the loading-rules precedence ($HOME/.kube/
	// config) finds nothing even on a machine with a real kubeconfig.
	emptyHome := t.TempDir()
	stdout, stderr, code := runMainInSubprocess(t, nil, "HOME="+emptyHome)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (stdout=%q stderr=%q)", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "unable to get kubeconfig") {
		t.Fatalf("stderr missing %q, got %q", "unable to get kubeconfig", stderr)
	}
}

// lockedBuffer is an io.Writer whose contents can be polled while the
// child process is still writing to it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// fakeDiscoveryAPIServer is the minimal apiserver needed for main() to
// complete its full boot path: it answers the discovery documents
// ctrl.NewManager's ByObject cache setup needs for namespacedness
// lookups, serves empty lists to the informers and holds watch
// requests open until canceled — so mgr.Start reaches steady state
// without a real cluster. Everything else gets a 404 Status.
func fakeDiscoveryAPIServer(t *testing.T) *httptest.Server {
	t.Helper()
	const resourcesV1 = `{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"v1","resources":[` +
		`{"name":"configmaps","singularName":"","namespaced":true,"kind":"ConfigMap","verbs":["get","list","watch"]},` +
		`{"name":"endpoints","singularName":"","namespaced":true,"kind":"Endpoints","verbs":["get","list","watch"]},` +
		`{"name":"nodes","singularName":"","namespaced":false,"kind":"Node","verbs":["get","list","watch"]},` +
		`{"name":"pods","singularName":"","namespaced":true,"kind":"Pod","verbs":["get","list","watch"]},` +
		`{"name":"secrets","singularName":"","namespaced":true,"kind":"Secret","verbs":["get","list","watch"]}]}`

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"kind":"APIVersions","apiVersion":"v1","versions":["v1"]}`)
	})
	mux.HandleFunc("GET /apis", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"kind":"APIGroupList","apiVersion":"v1","groups":[`+
			`{"name":"apps","versions":[{"groupVersion":"apps/v1","version":"v1"}],`+
			`"preferredVersion":{"groupVersion":"apps/v1","version":"v1"}}]}`)
	})
	mux.HandleFunc("GET /api/v1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, resourcesV1)
	})
	mux.HandleFunc("GET /apis/apps/v1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"apps/v1","resources":[`+
			`{"name":"daemonsets","singularName":"","namespaced":true,"kind":"DaemonSet","verbs":["get","list","watch"]},`+
			`{"name":"deployments","singularName":"","namespaced":true,"kind":"Deployment","verbs":["get","list","watch"]}]}`)
	})
	// Informer List/Watch traffic — the only other calls the manager
	// makes (all module work is tick-gated well past the test window).
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var apiVersion, kind string
		switch {
		case strings.HasSuffix(r.URL.Path, "/daemonsets"):
			apiVersion, kind = "apps/v1", "DaemonSetList"
		case strings.HasSuffix(r.URL.Path, "/deployments"):
			apiVersion, kind = "apps/v1", "DeploymentList"
		case strings.HasSuffix(r.URL.Path, "/secrets"):
			apiVersion, kind = "v1", "SecretList"
		case strings.HasSuffix(r.URL.Path, "/configmaps"):
			apiVersion, kind = "v1", "ConfigMapList"
		case strings.HasSuffix(r.URL.Path, "/nodes"):
			apiVersion, kind = "v1", "NodeList"
		default:
			http.Error(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound"}`,
				http.StatusNotFound)
			return
		}
		if r.URL.Query().Get("watch") == "true" {
			// Empty watch stream held open: the informer stays synced
			// until the shutdown cancels the request context.
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			<-r.Context().Done()
			return
		}
		fmt.Fprintf(w, `{"apiVersion":%q,"kind":%q,"metadata":{"resourceVersion":"1"},"items":[]}`,
			apiVersion, kind)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// With a kubeconfig pointing at the fake apiserver, main() must run the
// entire boot path — GetConfigOrDie, NewManager, clientset + dynamic
// client, all 27 module setups, health probes, "starting manager" —
// then block in mgr.Start. SIGINT (what SetupSignalHandler maps to ctx
// cancel on pod termination) must unwind it to a clean exit 0.
func TestMainStartsManagerUntilSignal(t *testing.T) {
	srv := fakeDiscoveryAPIServer(t)
	kubeconfig := writeKubeconfig(t, srv.URL)

	stderr := &lockedBuffer{}
	var stdout bytes.Buffer
	cmd := exec.Command(os.Args[0],
		"-test.run=TestHelperProcess", "--",
		// :0 picks ephemeral ports so the child cannot collide with a
		// real listener on :9115/:8081.
		"-metrics-bind-address=:0", "-health-probe-bind-address=:0")
	cmd.Env = append(kubeScrubbedEnv(), "GO_HELPER_PROCESS=1", "KUBECONFIG="+kubeconfig)
	cmd.Stdout = &stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}

	// Wait until the child logs "starting manager" — proof the full
	// wiring path ran — before interrupting.
	deadline := time.Now().Add(60 * time.Second)
	for !strings.Contains(stderr.String(), "starting manager") {
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("manager never started; stderr=%q", stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Let SetupSignalHandler install its handler and the informers
	// settle before signaling.
	time.Sleep(500 * time.Millisecond)
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("signal child: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("exit = %v, want clean shutdown; stderr=%q", err, stderr.String())
		}
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("child did not exit after SIGINT; stderr=%q", stderr.String())
	}
}

// writeKubeconfig materializes a minimal kubeconfig pointing at url.
func writeKubeconfig(t *testing.T, url string) string {
	t.Helper()
	kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
	content := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: %s
contexts:
- name: test
  context:
    cluster: test
    user: test
current-context: test
users:
- name: test
  user:
    token: fake
`, url)
	if err := os.WriteFile(kubeconfig, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return kubeconfig
}

// A kubeconfig that loads but points at an unreachable apiserver fails
// inside ctrl.NewManager (its ByObject cache setup resolves
// namespacedness via discovery) — expect "unable to create manager"
// and exit 1.
func TestMainManagerCreationFails(t *testing.T) {
	kubeconfig := writeKubeconfig(t, "https://127.0.0.1:1")
	stdout, stderr, code := runMainInSubprocess(t, nil, "KUBECONFIG="+kubeconfig)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (stdout=%q stderr=%q)", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "unable to create manager") {
		t.Fatalf("stderr missing %q, got %q", "unable to create manager", stderr)
	}
}

// With a working (fake) apiserver but an unbindable metrics address,
// mgr.Start fails immediately — expect "manager exited" and exit 1.
func TestMainManagerStartFails(t *testing.T) {
	srv := fakeDiscoveryAPIServer(t)
	kubeconfig := writeKubeconfig(t, srv.URL)
	stdout, stderr, code := runMainInSubprocess(t,
		[]string{"-metrics-bind-address=bad-address", "-health-probe-bind-address=:0"},
		"KUBECONFIG="+kubeconfig)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (stdout=%q stderr=%q)", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "manager exited") {
		t.Fatalf("stderr missing %q, got %q", "manager exited", stderr)
	}
}

// ---- moduleConfigFromEnv / setupModules ------------------------------

func TestModuleConfigFromEnv(t *testing.T) {
	keys := []string{
		"CILIUM_TAINT_REAPER_ENABLED",
		"FLUENTBIT_ROLLER_ENABLED",
		"CERTMANAGER_REAPER_ENABLED",
		"CILIUM_IDENTITY_AUDITOR_ENABLED",
		"EXTERNALSECRET_NUDGE_ENABLED",
		"CSR_APPROVER_ENABLED",
		"HELM_STALL_UNWEDGE_ENABLED",
		"CONCOURSE_JANITOR_ENABLED",
		"NODE_LABELER_CONFIG_PATH",
		"COREDNS_PATCHER_ENABLED",
		"COREDNS_PATCHER_ZONE_WHEN",
		"COREDNS_PATCHER_ZONE_MIN_DOMAINS",
		"COREDNS_MIN_REPLICAS",
		"COREDNS_NODES_PER_REPLICA",
		"METRICS_SERVER_PATCHER_ENABLED",
		"METRICS_SERVER_MIN_REPLICAS",
		"METRICS_SERVER_NODES_PER_REPLICA",
		"CF_TUNNEL_WATCHDOG_ENABLED",
		"CF_TUNNEL_WATCHDOG_NAMESPACE",
		"CF_TUNNEL_WATCHDOG_INTERVAL",
		"CLUSTER_HEALTH_PROBES_ENABLED",
		"VOLUMEATTACHMENT_CLEANER_ENABLED",
		"PDB_WATCHDOG_ENABLED",
		"CERT_DRIFT_AUDITOR_ENABLED",
		"APISERVICE_GUARD_ENABLED",
		"ZOMBIE_SIDECAR_REAPER_ENABLED",
		"ORPHAN_ENDPOINTSLICE_CLEANER_ENABLED",
		"STATEFULSET_ONDELETE_ROLLER_ENABLED",
		"VELERO_BACKUP_AUDITOR_ENABLED",
	}
	clear := func(t *testing.T) {
		for _, k := range keys {
			t.Setenv(k, "")
		}
	}

	t.Run("defaults", func(t *testing.T) {
		clear(t)
		mc := moduleConfigFromEnv()
		if mc.ciliumEnabled || mc.fluentbitEnabled || mc.certReaperEnabled ||
			mc.ciliumAuditEnabled || mc.esNudgeEnabled || mc.csrApproveEnabled ||
			mc.helmStallUnwedgeEnabled || mc.concourseJanitorEnabled {
			t.Fatalf("expected all gates disabled, got %+v", mc)
		}
		if mc.labelerPath != "/etc/node-labeler/labels.txt" {
			t.Fatalf("labelerPath = %q, want default", mc.labelerPath)
		}
		// The ported patcher/watchdog/prober modules default ON — only
		// an explicit "false" opts a cluster out.
		if !mc.corednsPatcherEnabled || !mc.metricsServerPatcherEnabled ||
			!mc.cfTunnelWatchdogEnabled || !mc.clusterHealthProbesEnabled {
			t.Fatalf("expected ported modules default-on, got %+v", mc)
		}
		if !mc.volumeAttachmentCleanerEnabled || !mc.pdbWatchdogEnabled ||
			!mc.certDriftAuditorEnabled {
			t.Fatalf("expected self-healing modules default-on, got %+v", mc)
		}
		// The wave 1-3 operations modules default ON the same way.
		if !mc.apiServiceGuardEnabled || !mc.zombieSidecarReaperEnabled ||
			!mc.orphanEndpointSliceEnabled || !mc.statefulSetRollerEnabled ||
			!mc.veleroBackupAuditorEnabled {
			t.Fatalf("expected wave 1-3 modules default-on, got %+v", mc)
		}
		if mc.corednsZoneWhen != "DoNotSchedule" {
			t.Fatalf("corednsZoneWhen = %q, want DoNotSchedule", mc.corednsZoneWhen)
		}
		if mc.corednsZoneMinDomains != 2 {
			t.Fatalf("corednsZoneMinDomains = %d, want 2", mc.corednsZoneMinDomains)
		}
		// Proportional replica pins default to the multi-zone values
		// the cluster-proportional-autoscaler carried.
		if mc.corednsMinReplicas != 4 {
			t.Fatalf("corednsMinReplicas = %d, want 4", mc.corednsMinReplicas)
		}
		if mc.corednsNodesPerReplica != 1 {
			t.Fatalf("corednsNodesPerReplica = %d, want 1", mc.corednsNodesPerReplica)
		}
		if mc.metricsServerMinReplicas != 3 {
			t.Fatalf("metricsServerMinReplicas = %d, want 3", mc.metricsServerMinReplicas)
		}
		if mc.metricsServerNodesPerReplica != 1 {
			t.Fatalf("metricsServerNodesPerReplica = %d, want 1",
				mc.metricsServerNodesPerReplica)
		}
		if mc.cfTunnelWatchdogNamespace != "cloudflare-tunnel-system" {
			t.Fatalf("cfTunnelWatchdogNamespace = %q, want default",
				mc.cfTunnelWatchdogNamespace)
		}
		if mc.cfTunnelWatchdogInterval != 5*time.Minute {
			t.Fatalf("cfTunnelWatchdogInterval = %s, want 5m",
				mc.cfTunnelWatchdogInterval)
		}
	})

	t.Run("all enabled", func(t *testing.T) {
		clear(t)
		t.Setenv("CILIUM_TAINT_REAPER_ENABLED", "true")
		t.Setenv("FLUENTBIT_ROLLER_ENABLED", "true")
		t.Setenv("CERTMANAGER_REAPER_ENABLED", "true")
		t.Setenv("CILIUM_IDENTITY_AUDITOR_ENABLED", "true")
		t.Setenv("EXTERNALSECRET_NUDGE_ENABLED", "true")
		t.Setenv("CSR_APPROVER_ENABLED", "true")
		t.Setenv("HELM_STALL_UNWEDGE_ENABLED", "true")
		t.Setenv("CONCOURSE_JANITOR_ENABLED", "true")
		t.Setenv("NODE_LABELER_CONFIG_PATH", "/custom/labels.txt")
		mc := moduleConfigFromEnv()
		if !mc.ciliumEnabled || !mc.fluentbitEnabled || !mc.certReaperEnabled ||
			!mc.ciliumAuditEnabled || !mc.esNudgeEnabled || !mc.csrApproveEnabled ||
			!mc.helmStallUnwedgeEnabled || !mc.concourseJanitorEnabled {
			t.Fatalf("expected all gates enabled, got %+v", mc)
		}
		if mc.labelerPath != "/custom/labels.txt" {
			t.Fatalf("labelerPath = %q, want /custom/labels.txt", mc.labelerPath)
		}
	})

	t.Run("ported module overrides", func(t *testing.T) {
		clear(t)
		t.Setenv("COREDNS_PATCHER_ENABLED", "false")
		t.Setenv("COREDNS_PATCHER_ZONE_WHEN", "ScheduleAnyway")
		t.Setenv("COREDNS_PATCHER_ZONE_MIN_DOMAINS", "0")
		// cicd single-zone pin + an explicit 0 disable (a cluster
		// re-enabling standalone CPA sets minReplicas<=0).
		t.Setenv("COREDNS_MIN_REPLICAS", "1")
		t.Setenv("COREDNS_NODES_PER_REPLICA", "2")
		t.Setenv("METRICS_SERVER_PATCHER_ENABLED", "false")
		t.Setenv("METRICS_SERVER_MIN_REPLICAS", "0")
		t.Setenv("METRICS_SERVER_NODES_PER_REPLICA", "5")
		t.Setenv("CF_TUNNEL_WATCHDOG_ENABLED", "false")
		t.Setenv("CF_TUNNEL_WATCHDOG_NAMESPACE", "custom-ns")
		t.Setenv("CF_TUNNEL_WATCHDOG_INTERVAL", "10m")
		t.Setenv("CLUSTER_HEALTH_PROBES_ENABLED", "false")
		t.Setenv("VOLUMEATTACHMENT_CLEANER_ENABLED", "false")
		t.Setenv("PDB_WATCHDOG_ENABLED", "false")
		t.Setenv("CERT_DRIFT_AUDITOR_ENABLED", "false")
		t.Setenv("APISERVICE_GUARD_ENABLED", "false")
		t.Setenv("ZOMBIE_SIDECAR_REAPER_ENABLED", "false")
		t.Setenv("ORPHAN_ENDPOINTSLICE_CLEANER_ENABLED", "false")
		t.Setenv("STATEFULSET_ONDELETE_ROLLER_ENABLED", "false")
		t.Setenv("VELERO_BACKUP_AUDITOR_ENABLED", "false")
		mc := moduleConfigFromEnv()
		if mc.corednsPatcherEnabled || mc.metricsServerPatcherEnabled ||
			mc.cfTunnelWatchdogEnabled || mc.clusterHealthProbesEnabled {
			t.Fatalf("explicit false must disable the ported modules, got %+v", mc)
		}
		if mc.volumeAttachmentCleanerEnabled || mc.pdbWatchdogEnabled ||
			mc.certDriftAuditorEnabled {
			t.Fatalf("explicit false must disable the self-healing modules, got %+v", mc)
		}
		if mc.apiServiceGuardEnabled || mc.zombieSidecarReaperEnabled ||
			mc.orphanEndpointSliceEnabled || mc.statefulSetRollerEnabled ||
			mc.veleroBackupAuditorEnabled {
			t.Fatalf("explicit false must disable the wave 1-3 modules, got %+v", mc)
		}
		if mc.corednsZoneWhen != "ScheduleAnyway" || mc.corednsZoneMinDomains != 0 {
			t.Fatalf("zone override not applied: %q/%d",
				mc.corednsZoneWhen, mc.corednsZoneMinDomains)
		}
		if mc.corednsMinReplicas != 1 || mc.corednsNodesPerReplica != 2 {
			t.Fatalf("coredns proportional override not applied: %d/%d",
				mc.corednsMinReplicas, mc.corednsNodesPerReplica)
		}
		if mc.metricsServerMinReplicas != 0 || mc.metricsServerNodesPerReplica != 5 {
			t.Fatalf("metrics-server proportional override not applied: %d/%d",
				mc.metricsServerMinReplicas, mc.metricsServerNodesPerReplica)
		}
		if mc.cfTunnelWatchdogNamespace != "custom-ns" {
			t.Fatalf("cfTunnelWatchdogNamespace = %q, want custom-ns",
				mc.cfTunnelWatchdogNamespace)
		}
		if mc.cfTunnelWatchdogInterval != 10*time.Minute {
			t.Fatalf("cfTunnelWatchdogInterval = %s, want 10m",
				mc.cfTunnelWatchdogInterval)
		}
	})
}

// stubManager mirrors testutil.StubManager:
// Add appends to `added` (addErr injects a registration failure), and
// only GetScheme/GetControllerOptions/GetLogger return anything
// meaningful because those are the only getters the builder and
// AddPeriodic call — source.TypedKind only stores the cache until
// Start (never invoked), so nil cache/client/mapper are safe, but the
// scheme MUST be real: apiutil.GVKForObject resolves at build time.
var _ manager.Manager = (*stubManager)(nil)

type stubManager struct {
	added  []manager.Runnable
	addErr error
	scheme *runtime.Scheme
}

func newStubManager() *stubManager {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		panic(err)
	}
	return &stubManager{scheme: scheme}
}

func (m *stubManager) Add(r manager.Runnable) error {
	if m.addErr != nil {
		return m.addErr
	}
	m.added = append(m.added, r)
	return nil
}

// GetControllerOptions disables the process-global controller-name
// uniqueness check — all modules are built in one test binary, which
// would otherwise collide on repeated runs.
func (m *stubManager) GetControllerOptions() config.Controller {
	return config.Controller{SkipNameValidation: ptr.To(true)}
}

func (m *stubManager) GetScheme() *runtime.Scheme                      { return m.scheme }
func (m *stubManager) GetLogger() logr.Logger                          { return logr.Discard() }
func (m *stubManager) GetCache() cache.Cache                           { return nil }
func (m *stubManager) GetClient() client.Client                        { return nil }
func (m *stubManager) GetFieldIndexer() client.FieldIndexer            { return nil }
func (m *stubManager) GetRESTMapper() meta.RESTMapper                  { return nil }
func (m *stubManager) GetAPIReader() client.Reader                     { return nil }
func (m *stubManager) GetHTTPClient() *http.Client                     { return nil }
func (m *stubManager) GetConfig() *rest.Config                         { return nil }
func (m *stubManager) GetEventRecorderFor(string) record.EventRecorder { return nil }
func (m *stubManager) GetEventRecorder(string) recorder.EventRecorder  { return nil }
func (m *stubManager) GetWebhookServer() webhook.Server                { return nil }
func (m *stubManager) GetConverterRegistry() conversion.Registry       { return nil }
func (m *stubManager) Start(context.Context) error                     { return nil }
func (m *stubManager) Elected() <-chan struct{}                        { return nil }
func (m *stubManager) AddHealthzCheck(string, healthz.Checker) error   { return nil }
func (m *stubManager) AddReadyzCheck(string, healthz.Checker) error    { return nil }

func (m *stubManager) AddMetricsServerExtraHandler(string, http.Handler) error {
	return nil
}

func stubDyn() *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
}

// Every module registers exactly one runnable on the manager — 32 in
// the map — except the sixteen gate-skippers (certmanager-reaper,
// cilium-identity-auditor, cilium-taint-reaper, fluent-bit-config-roller,
// coredns-patcher, metrics-server-patcher, cf-tunnel-proxy-watchdog,
// statefulset-ondelete-roller, cluster-health-probes,
// pdb-deadlock-watchdog, volumeattachment-cleaner,
// zombie-sidecar-reaper, orphan-endpointslice-cleaner,
// cert-drift-auditor, apiservice-guard, velero-backup-auditor), which
// skip mgr.Add entirely while disabled (16 runnables then). The other
// feature flags only gate the tick body, not registration.
func TestSetupModules(t *testing.T) {
	t.Run("all gates enabled", func(t *testing.T) {
		m := newStubManager()
		mc := moduleConfig{
			ciliumEnabled:                  true,
			fluentbitEnabled:               true,
			certReaperEnabled:              true,
			ciliumAuditEnabled:             true,
			esNudgeEnabled:                 true,
			csrApproveEnabled:              true,
			concourseJanitorEnabled:        true,
			labelerPath:                    filepath.Join(t.TempDir(), "labels.txt"),
			corednsPatcherEnabled:          true,
			corednsZoneWhen:                "DoNotSchedule",
			corednsZoneMinDomains:          2,
			metricsServerPatcherEnabled:    true,
			cfTunnelWatchdogEnabled:        true,
			cfTunnelWatchdogNamespace:      "cloudflare-tunnel-system",
			cfTunnelWatchdogInterval:       5 * time.Minute,
			clusterHealthProbesEnabled:     true,
			volumeAttachmentCleanerEnabled: true,
			pdbWatchdogEnabled:             true,
			certDriftAuditorEnabled:        true,
			apiServiceGuardEnabled:         true,
			zombieSidecarReaperEnabled:     true,
			orphanEndpointSliceEnabled:     true,
			statefulSetRollerEnabled:       true,
			veleroBackupAuditorEnabled:     true,
		}
		if err := setupModules(m, fake.NewSimpleClientset(), stubDyn(), mc); err != nil {
			t.Fatalf("setupModules: %v", err)
		}
		if len(m.added) != 32 {
			t.Fatalf("registered %d runnables, want 32", len(m.added))
		}
		for i, r := range m.added {
			if r == nil {
				t.Fatalf("runnable %d is nil", i)
			}
		}
	})

	t.Run("all gates disabled", func(t *testing.T) {
		m := newStubManager()
		if err := setupModules(m, fake.NewSimpleClientset(), stubDyn(), moduleConfig{}); err != nil {
			t.Fatalf("setupModules: %v", err)
		}
		if len(m.added) != 16 {
			t.Fatalf("registered %d runnables, want 16", len(m.added))
		}
	})
}

// The DefaultTransform wired into cache.Options must strip
// managedFields on every cached type and additionally nil
// .Status.Images on Nodes — the two biggest informer-memory items
// no module reads. Other objects pass through otherwise untouched.
func TestDefaultCacheTransform(t *testing.T) {
	t.Run("node loses images and managedFields", func(t *testing.T) {
		n := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:          "n1",
				ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubelet"}},
			},
			Status: corev1.NodeStatus{
				Images: []corev1.ContainerImage{{Names: []string{"img:latest"}}},
				Conditions: []corev1.NodeCondition{
					{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
				},
			},
		}
		out, err := defaultCacheTransform(n)
		if err != nil {
			t.Fatalf("transform: %v", err)
		}
		got, ok := out.(*corev1.Node)
		if !ok {
			t.Fatalf("transformed object is %T, want *corev1.Node", out)
		}
		if got.Status.Images != nil {
			t.Fatalf("Status.Images not stripped: %+v", got.Status.Images)
		}
		if got.GetManagedFields() != nil {
			t.Fatalf("managedFields not stripped: %+v", got.GetManagedFields())
		}
		if got.Name != "n1" || len(got.Status.Conditions) != 1 {
			t.Fatalf("transform mangled the node: %+v", got)
		}
	})

	t.Run("non-node keeps its fields, loses managedFields", func(t *testing.T) {
		s := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:          "passiontech-pipeline",
				Namespace:     "fluent-system",
				ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "fluent-operator"}},
			},
			Data: map[string][]byte{"k": []byte("v")},
		}
		out, err := defaultCacheTransform(s)
		if err != nil {
			t.Fatalf("transform: %v", err)
		}
		got, ok := out.(*corev1.Secret)
		if !ok {
			t.Fatalf("transformed object is %T, want *corev1.Secret", out)
		}
		if string(got.Data["k"]) != "v" {
			t.Fatal("transform mangled secret data")
		}
		if got.GetManagedFields() != nil {
			t.Fatal("managedFields not stripped on a non-Node object")
		}
	})
}

// A manager.Add failure must abort boot — setupModules propagates the
// first setup error instead of silently losing a module.
func TestSetupModulesErrorPropagates(t *testing.T) {
	want := errors.New("manager rejected runnable")
	m := newStubManager()
	m.addErr = want
	err := setupModules(m, fake.NewSimpleClientset(), stubDyn(), moduleConfig{})
	if !errors.Is(err, want) {
		t.Fatalf("setupModules error = %v, want %v", err, want)
	}
	if len(m.added) != 0 {
		t.Fatalf("registered %d runnables, want 0", len(m.added))
	}
}
