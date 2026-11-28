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
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/httpx"
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
		case "KUBECONFIG", "KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT",
			"NODE_AUTOMATION_PPROF_BIND_ADDRESS":
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
	switch err {
	case nil:
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
		_, _ = fmt.Fprint(w, `{"kind":"APIVersions","apiVersion":"v1","versions":["v1"]}`)
	})
	mux.HandleFunc("GET /apis", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"kind":"APIGroupList","apiVersion":"v1","groups":[`+
			`{"name":"apps","versions":[{"groupVersion":"apps/v1","version":"v1"}],`+
			`"preferredVersion":{"groupVersion":"apps/v1","version":"v1"}},`+
			`{"name":"apiextensions.k8s.io","versions":[{"groupVersion":"apiextensions.k8s.io/v1","version":"v1"}],`+
			`"preferredVersion":{"groupVersion":"apiextensions.k8s.io/v1","version":"v1"}}]}`)
	})
	mux.HandleFunc("GET /api/v1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, resourcesV1)
	})
	mux.HandleFunc("GET /apis/apps/v1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"apps/v1","resources":[`+
			`{"name":"daemonsets","singularName":"","namespaced":true,"kind":"DaemonSet","verbs":["get","list","watch"]},`+
			`{"name":"deployments","singularName":"","namespaced":true,"kind":"Deployment","verbs":["get","list","watch"]}]}`)
	})
	// The CRD informer's discovery + census surface (cluster-scoped).
	mux.HandleFunc("GET /apis/apiextensions.k8s.io/v1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"apiextensions.k8s.io/v1","resources":[`+
			`{"name":"customresourcedefinitions","singularName":"","namespaced":false,"kind":"CustomResourceDefinition","verbs":["get","list","watch"]}]}`)
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
		case strings.HasSuffix(r.URL.Path, "/customresourcedefinitions"):
			apiVersion, kind = "apiextensions.k8s.io/v1", "CustomResourceDefinitionList"
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
		_, _ = fmt.Fprintf(w, `{"apiVersion":%q,"kind":%q,"metadata":{"resourceVersion":"1"},"items":[]}`,
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
		// real listener on :9115/:8081/:9116.
		"-metrics-bind-address=:0", "-health-probe-bind-address=:0",
		"-pprof-bind-address=127.0.0.1:0")
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
		[]string{"-metrics-bind-address=bad-address", "-health-probe-bind-address=:0", "-pprof-bind-address=127.0.0.1:0"},
		"KUBECONFIG="+kubeconfig)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (stdout=%q stderr=%q)", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "manager exited") {
		t.Fatalf("stderr missing %q, got %q", "manager exited", stderr)
	}
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

	t.Run("tombstone re-wraps node with preserved key and strips fields", func(t *testing.T) {
		n := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:          "n-del",
				ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubelet"}},
			},
			Status: corev1.NodeStatus{
				Images: []corev1.ContainerImage{{Names: []string{"img:latest"}}},
			},
		}
		out, err := defaultCacheTransform(toolscache.DeletedFinalStateUnknown{
			Key: "n-del",
			Obj: n,
		})
		if err != nil {
			t.Fatalf("transform: %v", err)
		}
		tomb, ok := out.(toolscache.DeletedFinalStateUnknown)
		if !ok {
			t.Fatalf("transformed tombstone is %T, want DeletedFinalStateUnknown", out)
		}
		if tomb.Key != "n-del" {
			t.Fatalf("tomb.Key = %q, want n-del", tomb.Key)
		}
		got, ok := tomb.Obj.(*corev1.Node)
		if !ok {
			t.Fatalf("tomb.Obj is %T, want *corev1.Node", tomb.Obj)
		}
		if got.Status.Images != nil {
			t.Fatalf("Status.Images not stripped: %+v", got.Status.Images)
		}
		if got.GetManagedFields() != nil {
			t.Fatalf("managedFields not stripped: %+v", got.GetManagedFields())
		}
	})

	t.Run("tombstone with nil Obj stays wrapped safely", func(t *testing.T) {
		out, err := defaultCacheTransform(toolscache.DeletedFinalStateUnknown{Key: "gone"})
		if err != nil {
			t.Fatalf("transform: %v", err)
		}
		tomb, ok := out.(toolscache.DeletedFinalStateUnknown)
		if !ok || tomb.Key != "gone" || tomb.Obj != nil {
			t.Fatalf("got %#v, want DeletedFinalStateUnknown{Key:\"gone\", Obj:nil}", out)
		}
	})
}

func TestMakeCRDCacheTransform(t *testing.T) {
	makeCRD := func(rv, schemaDesc string) *apiextensionsv1.CustomResourceDefinition {
		return &apiextensionsv1.CustomResourceDefinition{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "widgets.example.com",
				ResourceVersion: rv,
				ManagedFields:   []metav1.ManagedFieldsEntry{{Manager: "helm"}},
				Annotations: map[string]string{
					corev1.LastAppliedConfigAnnotation: `{"huge":"manifest"}`,
					"keep":                             "yes",
				},
			},
			Spec: apiextensionsv1.CustomResourceDefinitionSpec{
				Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{
					Name: "v1",
					Schema: &apiextensionsv1.CustomResourceValidation{
						OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
							Type:        "object",
							Description: schemaDesc,
						},
					},
				}},
			},
		}
	}

	t.Run("live CRD records unstripped size and strips bulk fields", func(t *testing.T) {
		crdSize := kube.NewCRDSizeTable(16)
		tr := makeCRDCacheTransform(crdSize)
		raw := makeCRD("10", strings.Repeat("x", 512))
		wantSize, err := kube.JSONSize(raw)
		if err != nil {
			t.Fatalf("JSONSize: %v", err)
		}

		out, err := tr(raw)
		if err != nil {
			t.Fatalf("transform: %v", err)
		}
		got, ok := out.(*apiextensionsv1.CustomResourceDefinition)
		if !ok {
			t.Fatalf("out is %T, want *CustomResourceDefinition", out)
		}
		if got.Spec.Versions[0].Schema != nil {
			t.Fatal("Schema not stripped")
		}
		if got.ManagedFields != nil {
			t.Fatal("ManagedFields not stripped")
		}
		if _, exists := got.Annotations[corev1.LastAppliedConfigAnnotation]; exists {
			t.Fatal("LastAppliedConfigAnnotation not stripped")
		}
		if got.Annotations["keep"] != "yes" {
			t.Fatalf("non-applied annotation lost: %+v", got.Annotations)
		}
		recorded, ok := crdSize.Lookup("widgets.example.com", "10")
		if !ok || recorded != wantSize {
			t.Fatalf("crdSize.Lookup = (%d, %v), want (%d, true)", recorded, ok, wantSize)
		}
	})

	t.Run("tombstone CRD re-wraps with key and does not overwrite CRDSizeTable", func(t *testing.T) {
		crdSize := kube.NewCRDSizeTable(16)
		tr := makeCRDCacheTransform(crdSize)
		raw := makeCRD("10", strings.Repeat("y", 512))
		wantSize, err := kube.JSONSize(raw)
		if err != nil {
			t.Fatalf("JSONSize: %v", err)
		}
		crdSize.Record("widgets.example.com", "10", wantSize)

		// DeltaFIFO tombstone carries an already-stripped cached CRD (or partial object).
		stripped := makeCRD("10", "")
		stripped.Spec.Versions[0].Schema = nil
		out, err := tr(toolscache.DeletedFinalStateUnknown{
			Key: "widgets.example.com",
			Obj: stripped,
		})
		if err != nil {
			t.Fatalf("transform: %v", err)
		}
		tomb, ok := out.(toolscache.DeletedFinalStateUnknown)
		if !ok || tomb.Key != "widgets.example.com" {
			t.Fatalf("got %#v, want DeletedFinalStateUnknown with key widgets.example.com", out)
		}
		got, ok := tomb.Obj.(*apiextensionsv1.CustomResourceDefinition)
		if !ok || got.ManagedFields != nil {
			t.Fatalf("tombstone CRD not stripped: %#v", tomb.Obj)
		}
		recorded, ok := crdSize.Lookup("widgets.example.com", "10")
		if !ok || recorded != wantSize {
			t.Fatalf("tombstone overwrote CRDSizeTable: got (%d, %v), want (%d, true)", recorded, ok, wantSize)
		}
	})

	t.Run("non-CRD tombstone stays wrapped", func(t *testing.T) {
		tr := makeCRDCacheTransform(kube.NewCRDSizeTable(16))
		s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "s1"}}
		out, err := tr(toolscache.DeletedFinalStateUnknown{Key: "ns/s1", Obj: s})
		if err != nil {
			t.Fatalf("transform: %v", err)
		}
		tomb, ok := out.(toolscache.DeletedFinalStateUnknown)
		if !ok || tomb.Key != "ns/s1" || tomb.Obj != s {
			t.Fatalf("got %#v, want preserved tombstone", out)
		}
	})
}

// TestPprofMuxAndMetricsServerSeparation pins the loopback-only pprof
// posture: pprofMux serves the /debug/pprof/* endpoints and never
// /metrics, while buildMgrOptions leaves Metrics.ExtraHandlers nil so
// :9115/debug/pprof/ returns 404.
func TestPprofMuxAndMetricsServerSeparation(t *testing.T) {
	mux := pprofMux()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/debug/pprof/heap?debug=1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("heap profile: got %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "heap profile:") {
		t.Fatalf("heap profile body missing header, got:\n%.200s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/debug/pprof/cmdline", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("cmdline: got %d, want 200", rec.Code)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("/metrics on pprofMux: got %d, want 404", rec.Code)
	}

	opts := buildMgrOptions(runtime.NewScheme(), ":9115", ":8081", false, 0, 0, 0, "node-ops", nil, nil, false, false)
	if opts.Metrics.ExtraHandlers != nil {
		t.Fatalf("Metrics.ExtraHandlers = %v, want nil (pprof must not mount on :9115)", opts.Metrics.ExtraHandlers)
	}
}

func TestValidateLoopbackBindAddr(t *testing.T) {
	for _, valid := range []string{
		"127.0.0.1:9116",
		"127.0.0.1:0",
		"127.0.0.42:9116",
		"[::1]:9116",
		"localhost:9116",
		"LOCALHOST:0",
	} {
		if err := httpx.ValidateLoopbackAddr(valid); err != nil {
			t.Errorf("httpx.ValidateLoopbackAddr(%q) unexpected error: %v", valid, err)
		}
	}
	for _, invalid := range []string{
		"0.0.0.0:9116",
		"[::]:9116",
		":9116",
		"10.0.0.1:9116",
		"192.168.1.5:9116",
		"example.com:9116",
		"127.0.0.1:",
		"bad-address",
	} {
		if err := httpx.ValidateLoopbackAddr(invalid); err == nil {
			t.Errorf("httpx.ValidateLoopbackAddr(%q) = nil, want rejection", invalid)
		}
	}
}

func TestRunRejectsNonLoopbackPprof(t *testing.T) {
	if pprofServerOpts.WriteTimeout != 0 {
		t.Fatalf("pprofServerOpts.WriteTimeout = %v, want 0", pprofServerOpts.WriteTimeout)
	}
	t.Run("via flag", func(t *testing.T) {
		t.Setenv("NODE_AUTOMATION_PPROF_BIND_ADDRESS", "")
		if err := run(t.Context(), []string{"-pprof-bind-address=0.0.0.0:9116"}); err == nil {
			t.Fatal("expected run() to reject non-loopback -pprof-bind-address")
		}
	})
	t.Run("via env", func(t *testing.T) {
		t.Setenv("NODE_AUTOMATION_PPROF_BIND_ADDRESS", "0.0.0.0:9116")
		if err := run(t.Context(), nil); err == nil {
			t.Fatal("expected run() to reject non-loopback NODE_AUTOMATION_PPROF_BIND_ADDRESS")
		}
	})
}

// TestGoAndProcessRuntimeMetricsRegistered pins the memory-triage
// contract: the shared controller-runtime registry must expose the Go
// runtime and process collectors so the single :9115 ServiceMonitor
// scrape can attribute a working-set spike to live heap
// (go_memstats_alloc_bytes, heap_inuse) vs retained-but-freed spans
// (heap_sys - heap_released, RSS) — the evidence the GOMEMLIMIT
// sizing depends on. Lives in this package because the collectors are
// registered by controller-runtime's internal metrics init(), which
// only runs when the manager (this package's dependency tree) is
// linked in.
func TestGoAndProcessRuntimeMetricsRegistered(t *testing.T) {
	families, err := ctrlmetrics.Registry.Gather()
	if err != nil {
		t.Fatalf("registry gather: %v", err)
	}
	names := make(map[string]bool, len(families))
	for _, mf := range families {
		names[mf.GetName()] = true
	}
	for _, want := range []string{
		"go_memstats_alloc_bytes", "go_memstats_heap_inuse_bytes",
		"go_goroutines", "process_resident_memory_bytes", "process_open_fds",
	} {
		if !names[want] {
			t.Fatalf("registry missing runtime metric %q", want)
		}
	}
}

func TestLeasePreemptRunnable(t *testing.T) {
	var r leasePreemptRunnable
	if r.NeedLeaderElection() {
		t.Fatal("leasePreemptRunnable.NeedLeaderElection() = true, want false")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := r.Start(ctx); err != nil {
		t.Fatalf("Start with cancelled ctx: %v", err)
	}
}

func TestCanWatchKubeSystemPods(t *testing.T) {
	type verbCase struct {
		name        string
		allowed     map[string]bool
		errVerb     string
		nilRespVerb string
		want        bool
	}
	cases := []verbCase{
		{
			name:    "allowed for list and watch",
			allowed: map[string]bool{"list": true, "watch": true},
			want:    true,
		},
		{
			name:    "denied on list",
			allowed: map[string]bool{"list": false, "watch": true},
			want:    false,
		},
		{
			name:    "denied on watch",
			allowed: map[string]bool{"list": true, "watch": false},
			want:    false,
		},
		{
			name:    "error on SSAR",
			allowed: map[string]bool{"list": true, "watch": true},
			errVerb: "watch",
			want:    false,
		},
		{
			name:        "nil response without error",
			allowed:     map[string]bool{"list": true, "watch": true},
			nilRespVerb: "list",
			want:        false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset()
			var seen []authv1.ResourceAttributes
			cs.PrependReactor("create", "selfsubjectaccessreviews", func(a ktesting.Action) (bool, runtime.Object, error) {
				obj := a.(ktesting.CreateAction).GetObject().(*authv1.SelfSubjectAccessReview)
				ra := *obj.Spec.ResourceAttributes
				seen = append(seen, ra)
				if tc.errVerb == ra.Verb {
					return true, nil, errors.New("apiserver unavailable")
				}
				if tc.nilRespVerb == ra.Verb {
					return true, nil, nil
				}
				out := obj.DeepCopy()
				out.Status.Allowed = tc.allowed[ra.Verb]
				return true, out, nil
			})
			got := canWatchKubeSystemPods(t.Context(), cs, logr.Discard())
			if got != tc.want {
				t.Fatalf("canWatchKubeSystemPods() = %v, want %v", got, tc.want)
			}
			if len(seen) == 0 {
				t.Fatal("expected at least one SSAR call")
			}
			for _, ra := range seen {
				if ra.Group != "" || ra.Resource != "pods" || ra.Namespace != "kube-system" {
					t.Fatalf("unexpected SSAR ResourceAttributes: %+v", ra)
				}
			}
		})
	}
}

func TestBuildCacheOptionsPodInformer(t *testing.T) {
	findPodCfg := func(opts map[client.Object]cache.ByObject) (cache.ByObject, bool) {
		for obj, cfg := range opts {
			if _, ok := obj.(*corev1.Pod); ok {
				return cfg, true
			}
		}
		return cache.ByObject{}, false
	}

	t.Run("watchPods=true includes scoped kube-system Pod informer", func(t *testing.T) {
		opts := buildCacheOptions(nil, false, true)
		podCfg, ok := findPodCfg(opts.ByObject)
		if !ok {
			t.Fatal("ByObject missing *corev1.Pod when watchPods=true")
		}
		if _, hasNS := podCfg.Namespaces["kube-system"]; !hasNS || len(podCfg.Namespaces) != 1 {
			t.Fatalf("Pod Namespaces = %+v, want only kube-system", podCfg.Namespaces)
		}
		if podCfg.Label == nil || podCfg.Label.String() != podCacheLabelSelector.String() {
			t.Fatalf("Pod Label selector = %v, want %v", podCfg.Label, podCacheLabelSelector)
		}
	})

	t.Run("watchPods=false omits Pod informer", func(t *testing.T) {
		opts := buildCacheOptions(nil, false, false)
		if _, ok := findPodCfg(opts.ByObject); ok {
			t.Fatal("ByObject unexpectedly includes *corev1.Pod when watchPods=false")
		}
	})
}
