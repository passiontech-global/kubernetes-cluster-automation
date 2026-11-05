package main

import (
	"bytes"
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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/testutil"
)

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
// client, all module setups, health probes, "starting manager" —
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

// ---- setupModules ----------------------------------------------------
//
// Registration gates live on the shared.Module rows now — setupModules
// resolves each GateEnv and stamps Deps.Disabled before calling Setup,
// so these tests drive the whole fleet through t.Setenv + a
// shared.Deps exactly like boot does.

// moduleGateEnvs derives the registration-gate env vars from the
// registry itself — a hand-maintained list could drift from modules
// silently. Setting every GateEnv "true" enables every gate (opt-in
// and default-on alike); "false" disables them all. Sub-feature gates
// (CSR_APPROVER_ENABLED, HELM_STALL_UNWEDGE_ENABLED, ...) are
// deliberately absent — they alter run behavior, not runnable counts.
func moduleGateEnvs() []string {
	var envs []string
	for _, m := range modules {
		if m.GateEnv != "" {
			envs = append(envs, m.GateEnv)
		}
	}
	return envs
}

// The registry is the contract every other piece keys on: names must
// be non-empty and unique (they label metric series and boot logs —
// a dup would merge two modules' error accounting) and every row must
// carry a Setup — a nil one would nil-call at boot.
func TestModuleRegistry(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range modules {
		if m.Name == "" {
			t.Fatal("module row with empty Name")
		}
		if seen[m.Name] {
			t.Fatalf("duplicate module name %q", m.Name)
		}
		seen[m.Name] = true
		if m.Setup == nil {
			t.Fatalf("module %q has nil Setup", m.Name)
		}
	}
}

func testDeps(m *testutil.StubManager) shared.Deps {
	return shared.Deps{
		Mgr: m,
		CS:  fake.NewSimpleClientset(),
		Dyn: testutil.StubDyn(),
		Log: m.GetLogger(),
	}
}

// filterModules is the -modules allowlist: unset means the full
// registry; a set value returns exactly the named modules in
// registry order regardless of argv order; an unknown name is an
// error that names the offender (fail fast — a silently skipped typo
// would run the wrong subset).
func TestFilterModules(t *testing.T) {
	t.Run("empty means full registry", func(t *testing.T) {
		got, err := filterModules(nil)
		if err != nil {
			t.Fatalf("filterModules(nil): %v", err)
		}
		if len(got) != len(modules) {
			t.Fatalf("got %d modules, want all %d", len(got), len(modules))
		}
		for i := range got {
			if got[i].Name != modules[i].Name {
				t.Fatalf("got[%d] = %q, want %q", i, got[i].Name, modules[i].Name)
			}
		}
	})

	t.Run("subset keeps registry order", func(t *testing.T) {
		// argv order reversed vs the registry — the result must still
		// follow the registry so boot order stays deterministic.
		got, err := filterModules([]string{"csr-watcher", "node-labeler"})
		if err != nil {
			t.Fatalf("filterModules: %v", err)
		}
		var names []string
		for _, m := range got {
			names = append(names, m.Name)
		}
		if want := []string{"node-labeler", "csr-watcher"}; !slices.Equal(names, want) {
			t.Fatalf("names = %v, want %v", names, want)
		}
	})

	t.Run("unknown name fails", func(t *testing.T) {
		_, err := filterModules([]string{"node-labeler", "no-such-module"})
		if err == nil {
			t.Fatal("filterModules accepted an unknown name")
		}
		if !strings.Contains(err.Error(), "no-such-module") {
			t.Fatalf("error missing the bad name: %v", err)
		}
		if !strings.Contains(err.Error(), "node-labeler") {
			t.Fatalf("error missing the valid-name list: %v", err)
		}
	})
}

// parseModulesFlag is whitespace-tolerant and drops empty entries —
// " a, ,b " is exactly ["a","b"], and an all-whitespace value is
// "unset" rather than a bogus name.
func TestParseModulesFlag(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"  ", nil},
		{"a", []string{"a"}},
		{"a,b", []string{"a", "b"}},
		{" a , b,", []string{"a", "b"}},
	} {
		if got := parseModulesFlag(tc.in); !slices.Equal(got, tc.want) {
			t.Fatalf("parseModulesFlag(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// Every module registers exactly one runnable on the manager — 32 in
// the registry — except the gate-skippers, which setupModules hands
// Deps.Disabled and which then skip mgr.Add entirely. Modules whose
// flag only gates the tick body (csr-watcher approve mode,
// helmrelease-unlocker stall-unwedge, externalsecret-nudge,
// webhookguard, and the no-gate always-on modules) still register.
func TestSetupModules(t *testing.T) {
	t.Run("all gates enabled", func(t *testing.T) {
		for _, k := range moduleGateEnvs() {
			t.Setenv(k, "true")
		}
		t.Setenv("NODE_LABELER_CONFIG_PATH",
			filepath.Join(t.TempDir(), "labels.txt"))
		m := testutil.NewStubManager()
		if err := setupModules(testDeps(m), modules); err != nil {
			t.Fatalf("setupModules: %v", err)
		}
		if len(m.Added) != 32 {
			t.Fatalf("registered %d runnables, want 32", len(m.Added))
		}
		for i, r := range m.Added {
			if r == nil {
				t.Fatalf("runnable %d is nil", i)
			}
		}
	})

	t.Run("all gates disabled", func(t *testing.T) {
		for _, k := range moduleGateEnvs() {
			t.Setenv(k, "false")
		}
		m := testutil.NewStubManager()
		if err := setupModules(testDeps(m), modules); err != nil {
			t.Fatalf("setupModules: %v", err)
		}
		// 32 modules minus the 17 gate-skippers = 15 runnables.
		if len(m.Added) != 15 {
			t.Fatalf("registered %d runnables, want 15", len(m.Added))
		}
	})

	// The -modules allowlist narrows what Setup runs: two gateless
	// always-on modules → exactly two runnables, no matter what the
	// gate envs say.
	t.Run("allowlist subset", func(t *testing.T) {
		mods, err := filterModules([]string{"node-labeler", "csr-watcher"})
		if err != nil {
			t.Fatalf("filterModules: %v", err)
		}
		m := testutil.NewStubManager()
		if err := setupModules(testDeps(m), mods); err != nil {
			t.Fatalf("setupModules: %v", err)
		}
		if len(m.Added) != 2 {
			t.Fatalf("registered %d runnables, want 2", len(m.Added))
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
	m := testutil.NewStubManager()
	m.AddErr = want
	err := setupModules(testDeps(m), modules)
	if !errors.Is(err, want) {
		t.Fatalf("setupModules error = %v, want %v", err, want)
	}
	if len(m.Added) != 0 {
		t.Fatalf("registered %d runnables, want 0", len(m.Added))
	}
}
