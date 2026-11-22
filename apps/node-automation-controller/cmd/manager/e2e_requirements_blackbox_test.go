// e2e_requirements_blackbox_test.go — requirement-driven opaque-box E2E test
// harness and thread-safe fake Kubernetes APIServer for node-automation-controller.
package main_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	authv1 "k8s.io/api/authorization/v1"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
)

// TestE2ERequirements compiles ./cmd/manager once and runs all four E2E tiers.
func TestE2ERequirements(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "manager")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	buildCmd.Env = os.Environ()
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("compile manager binary: %v\n%s", err, out)
	}

	sem := make(chan struct{}, 12)

	t.Run("Tier1", func(t *testing.T) {
		t.Parallel()
		runTier1Tests(t, binPath, sem)
	})
	t.Run("Tier2", func(t *testing.T) {
		t.Parallel()
		runTier2Tests(t, binPath, sem)
	})
	t.Run("Tier3", func(t *testing.T) {
		t.Parallel()
		runTier3Tests(t, binPath, sem)
	})
	t.Run("Tier4", func(t *testing.T) {
		t.Parallel()
		runTier4Tests(t, binPath, sem)
	})
}

func acquireManagerSlot(t *testing.T, sem chan struct{}) {
	t.Helper()
	sem <- struct{}{}
	t.Cleanup(func() { <-sem })
}

var (
	reservedReqPortsMu sync.Mutex
	reservedReqPorts   = map[string]struct{}{}
)

func reserveLoopbackPort(t *testing.T) string {
	t.Helper()
	var held []net.Listener
	defer func() {
		for _, ln := range held {
			_ = ln.Close()
		}
	}()
	for range 32 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("allocate loopback port: %v", err)
		}
		_, port, err := net.SplitHostPort(ln.Addr().String())
		if err != nil {
			_ = ln.Close()
			t.Fatalf("split port from %q: %v", ln.Addr().String(), err)
		}
		reservedReqPortsMu.Lock()
		_, exists := reservedReqPorts[port]
		if !exists {
			reservedReqPorts[port] = struct{}{}
			reservedReqPortsMu.Unlock()
			_ = ln.Close()
			t.Cleanup(func() {
				reservedReqPortsMu.Lock()
				delete(reservedReqPorts, port)
				reservedReqPortsMu.Unlock()
			})
			return port
		}
		reservedReqPortsMu.Unlock()
		held = append(held, ln)
	}
	t.Fatalf("exhausted attempts to reserve a unique loopback port")
	return ""
}

func waitReqManagerReady(rawURL string, timeout time.Duration, proc *managerProcess) (ready, bindCollision bool, lastCode int, lastErr error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-proc.done:
			combined := proc.stderr.String() + "\n" + proc.stdout.String()
			if strings.Contains(combined, "bind: address already in use") {
				return false, true, lastCode, proc.waitErr
			}
			return false, false, lastCode, proc.waitErr
		default:
		}
		code, _, err := httpGetBody(rawURL)
		if err == nil && code == http.StatusOK {
			return true, false, code, nil
		}
		lastErr = err
		lastCode = code
		time.Sleep(50 * time.Millisecond)
	}
	return false, false, lastCode, lastErr
}

func startReqManager(t *testing.T, binPath string, srv *reqE2EAPIServer, extraEnv []string, modules string, extraArgs ...string) (proc *managerProcess, metricsURL, probeURL string) {
	t.Helper()
	kubeconfig := writeE2EKubeconfig(t, srv.URL())

	const maxAttempts = 3
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		metricsPort := reserveLoopbackPort(t)
		probePort := reserveLoopbackPort(t)
		metricsAddr := "127.0.0.1:" + metricsPort
		probeAddr := "127.0.0.1:" + probePort

		env := scrubbedKubeEnv(
			"KUBECONFIG="+kubeconfig,
			"NODE_AUTOMATION_PPROF_BIND_ADDRESS=",
		)
		env = append(env, extraEnv...)

		args := []string{
			"-metrics-bind-address=" + metricsAddr,
			"-health-probe-bind-address=" + probeAddr,
			"-pprof-bind-address=",
		}
		if modules != "" {
			args = append(args, "-modules="+modules)
		}
		args = append(args, extraArgs...)

		proc = startManagerProcess(t, binPath, env, args...)
		ready, bindCollision, lastCode, lastErr := waitReqManagerReady("http://"+probeAddr+"/readyz", 25*time.Second, proc)
		if ready {
			t.Cleanup(func() {
				select {
				case <-proc.done:
				default:
					_ = proc.cmd.Process.Signal(os.Interrupt)
					select {
					case <-proc.done:
					case <-time.After(10 * time.Second):
						_ = proc.cmd.Process.Kill()
						<-proc.done
					}
				}
			})
			return proc, "http://" + metricsAddr + "/metrics", "http://" + probeAddr
		}

		select {
		case <-proc.done:
		default:
			_ = proc.cmd.Process.Kill()
			<-proc.done
		}

		if !bindCollision || attempt == maxAttempts {
			t.Fatalf("manager failed to become ready (attempt %d/%d, lastCode=%d, lastErr=%v, waitErr=%v)\nstdout:\n%s\nstderr:\n%s",
				attempt, maxAttempts, lastCode, lastErr, proc.waitErr, proc.stdout.String(), proc.stderr.String())
		}
	}
	return nil, "", ""
}

// ---- Prometheus metrics parser & waiters -----------------------------------

type metricSample struct {
	Name   string
	Labels map[string]string
	Value  float64
}

func scrapeMetrics(t *testing.T, metricsURL string) []metricSample {
	t.Helper()
	code, body, err := httpGetBody(metricsURL)
	if err != nil {
		t.Fatalf("GET %s: %v", metricsURL, err)
	}
	if code != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200", metricsURL, code)
	}
	return parseMetricsText(body)
}

func parseMetricsText(body string) []metricSample {
	var out []metricSample
	for line := range strings.SplitSeq(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var name string
		labels := map[string]string{}
		var rest string
		if braceIdx := strings.IndexByte(line, '{'); braceIdx >= 0 {
			name = line[:braceIdx]
			endBrace := strings.LastIndexByte(line, '}')
			if endBrace < braceIdx {
				continue
			}
			labelsStr := line[braceIdx+1 : endBrace]
			labels = parseMetricLabels(labelsStr)
			rest = strings.TrimSpace(line[endBrace+1:])
		} else {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			name = fields[0]
			rest = fields[1]
		}
		valFields := strings.Fields(rest)
		if len(valFields) == 0 {
			continue
		}
		val, err := strconv.ParseFloat(valFields[0], 64)
		if err != nil {
			continue
		}
		out = append(out, metricSample{Name: name, Labels: labels, Value: val})
	}
	return out
}

func parseMetricLabels(s string) map[string]string {
	out := map[string]string{}
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ',' || s[i] == ' ') {
			i++
		}
		eq := strings.IndexByte(s[i:], '=')
		if eq < 0 {
			break
		}
		key := strings.TrimSpace(s[i : i+eq])
		i += eq + 1
		if i >= len(s) || s[i] != '"' {
			break
		}
		i++
		var val strings.Builder
		for i < len(s) && s[i] != '"' {
			if s[i] == '\\' && i+1 < len(s) {
				i++
				switch s[i] {
				case 'n':
					val.WriteByte('\n')
				default:
					val.WriteByte(s[i])
				}
				i++
				continue
			}
			val.WriteByte(s[i])
			i++
		}
		if i < len(s) && s[i] == '"' {
			i++
		}
		out[key] = val.String()
	}
	return out
}

func findMetric(samples []metricSample, name string, wantLabels map[string]string) (float64, bool) {
	for _, s := range samples {
		if s.Name != name {
			continue
		}
		match := true
		for k, v := range wantLabels {
			if s.Labels[k] != v {
				match = false
				break
			}
		}
		if match {
			return s.Value, true
		}
	}
	return 0, false
}

func sumMetric(samples []metricSample, name string, wantLabels map[string]string) (float64, bool) {
	total := 0.0
	found := false
	for _, s := range samples {
		if s.Name != name {
			continue
		}
		match := true
		for k, v := range wantLabels {
			if s.Labels[k] != v {
				match = false
				break
			}
		}
		if match {
			total += s.Value
			found = true
		}
	}
	return total, found
}

func waitForMetric(t *testing.T, metricsURL string, proc *managerProcess, timeout time.Duration, desc string, pred func([]metricSample) bool) []metricSample {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last []metricSample
	for time.Now().Before(deadline) {
		select {
		case <-proc.done:
			t.Fatalf("manager exited prematurely (%v) while waiting for metric %s\nstdout:\n%s\nstderr:\n%s",
				proc.waitErr, desc, proc.stdout.String(), proc.stderr.String())
		default:
		}
		last = scrapeMetrics(t, metricsURL)
		if pred(last) {
			return last
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for metric %s\nstdout:\n%s\nstderr:\n%s",
		timeout, desc, proc.stdout.String(), proc.stderr.String())
	return last
}

func waitForLog(t *testing.T, proc *managerProcess, timeout time.Duration, desc, substr string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(proc.stderr.String(), substr) {
			return
		}
		select {
		case <-proc.done:
			if strings.Contains(proc.stderr.String(), substr) {
				return
			}
			t.Fatalf("manager exited prematurely (%v) while waiting for log %s (%q)\nstdout:\n%s\nstderr:\n%s",
				proc.waitErr, desc, substr, proc.stdout.String(), proc.stderr.String())
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for log %s (%q)\nstdout:\n%s\nstderr:\n%s",
		timeout, desc, substr, proc.stdout.String(), proc.stderr.String())
}

// ---- Mock PromQL & TLS/TCP Listeners ---------------------------------------

func startMockPromServer(t *testing.T, queryFn func(query string) []map[string]any) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		if q == "" && r.Method == http.MethodPost {
			_ = r.ParseForm()
			q = r.Form.Get("query")
		}
		results := queryFn(q)
		if results == nil {
			results = []map[string]any{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data": map[string]any{
				"resultType": "vector",
				"result":     results,
			},
		})
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/api/v1/query"
}

type blackholeListener struct {
	addr     string
	port     int32
	mu       sync.Mutex
	accepted []time.Time
	conns    []net.Conn
}

func startBlackholeTCPListener(t *testing.T) *blackholeListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen blackhole tcp: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	portNum, _ := strconv.Atoi(portStr)
	bh := &blackholeListener{
		addr: ln.Addr().String(),
		port: int32(portNum),
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}
			bh.mu.Lock()
			bh.accepted = append(bh.accepted, time.Now())
			bh.conns = append(bh.conns, conn)
			bh.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		close(done)
		_ = ln.Close()
		bh.mu.Lock()
		for _, c := range bh.conns {
			_ = c.Close()
		}
		bh.mu.Unlock()
	})
	return bh
}

func (b *blackholeListener) firstAcceptTime() (time.Time, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.accepted) == 0 {
		return time.Time{}, false
	}
	return b.accepted[0], true
}

func (b *blackholeListener) acceptCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.accepted)
}

type healthyTLSListener struct {
	addr     string
	port     int32
	mu       sync.Mutex
	accepted int
}

func (h *healthyTLSListener) acceptCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.accepted
}

func generateSelfSignedCert(t *testing.T, cn string, notAfter time.Time, serial int64) (tls.Certificate, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("127.0.0.2")},
		DNSNames:              []string{cn},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load x509 keypair: %v", err)
	}
	return tlsCert, certPEM
}

func startHealthyTLSListener(t *testing.T) *healthyTLSListener {
	t.Helper()
	hl, err := tryStartHealthyTLSListener(t, "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("listen healthy tls: %v", err)
	}
	return hl
}

func tryStartHealthyTLSListener(t *testing.T, ip string, port int32) (*healthyTLSListener, error) {
	t.Helper()
	cert, _ := generateSelfSignedCert(t, "webhook.e2e.svc", time.Now().Add(365*24*time.Hour), 101)
	ln, err := tls.Listen("tcp", fmt.Sprintf("%s:%d", ip, port), &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		return nil, err
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	portNum, _ := strconv.Atoi(portStr)
	hl := &healthyTLSListener{addr: ln.Addr().String(), port: int32(portNum)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			hl.mu.Lock()
			hl.accepted++
			hl.mu.Unlock()
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return hl, nil
}

func startBlackholeAndHealthyPair(t *testing.T) (*blackholeListener, *healthyTLSListener) {
	t.Helper()
	for range 10 {
		bh := startBlackholeTCPListener(t)
		hl, err := tryStartHealthyTLSListener(t, "127.0.0.2", bh.port)
		if err == nil {
			return bh, hl
		}
	}
	t.Fatalf("failed to bind paired blackhole (127.0.0.1) and healthy TLS (127.0.0.2) listeners on a shared port")
	return nil, nil
}

// ---- reqE2EAPIServer -------------------------------------------------------

type reqRecord struct {
	Method      string
	Path        string
	RawQuery    string
	Accept      string
	ContentType string
	Body        string
	At          time.Time
}

type customDiscoveryEntry struct {
	Group     string
	Version   string
	Resources []metav1.APIResource
}

type reqErrorRule struct {
	Method     string
	PathPrefix string
	Status     int
	Remaining  int // < 0 means unlimited
}

type reqDelayRule struct {
	Method         string
	PathPrefix     string
	AcceptContains string
	Delay          time.Duration
}

type podLogEntry struct {
	Status int
	Body   []byte
}

type proxyHealthEntry struct {
	Status int
	Body   string
}

type reqE2EAPIServer struct {
	srv    *httptest.Server
	scheme *runtime.Scheme
	codecs serializer.CodecFactory

	mu           sync.RWMutex
	nextRV       atomic.Int64
	watchCh      chan struct{}
	ssarAllowed  bool
	versionMajor string
	versionMinor string
	versionRaw   string

	discoveryGroups map[string]customDiscoveryEntry // key: group/version
	enabledCRDs     map[string]bool                 // key: group/version/resource
	errorRules      []*reqErrorRule
	delayRules      []reqDelayRule

	proxyHealth map[string]proxyHealthEntry // key: nodeName
	podLogs     map[string]podLogEntry      // key: ns/pod/container or ns/pod
	evictStatus map[string]int              // key: ns/pod

	reqs []reqRecord

	// Typed stores keyed by "ns/name" or "name" for cluster-scoped.
	nodes       map[string]*corev1.Node
	namespaces  map[string]*corev1.Namespace
	pods        map[string]*corev1.Pod
	services    map[string]*corev1.Service
	endpoints   map[string]*corev1.Endpoints
	configMaps  map[string]*corev1.ConfigMap
	secrets     map[string]*corev1.Secret
	sas         map[string]*corev1.ServiceAccount
	pvs         map[string]*corev1.PersistentVolume
	pvcs        map[string]*corev1.PersistentVolumeClaim
	resQuotas   map[string]*corev1.ResourceQuota
	events      []*corev1.Event
	deployments map[string]*appsv1.Deployment
	replicaSets map[string]*appsv1.ReplicaSet
	statefulSet map[string]*appsv1.StatefulSet
	daemonSets  map[string]*appsv1.DaemonSet
	ctrlRevs    map[string]*appsv1.ControllerRevision
	epSlices    map[string]*discoveryv1.EndpointSlice
	vas         map[string]*storagev1.VolumeAttachment
	scClasses   map[string]*storagev1.StorageClass
	pdbs        map[string]*policyv1.PodDisruptionBudget
	jobs        map[string]*batchv1.Job
	cronJobs    map[string]*batchv1.CronJob
	ingresses   map[string]*networkingv1.Ingress
	ingClasses  map[string]*networkingv1.IngressClass
	netPolicies map[string]*networkingv1.NetworkPolicy
	crbs        map[string]*rbacv1.ClusterRoleBinding
	rbs         map[string]*rbacv1.RoleBinding
	mwcs        map[string]*admissionv1.MutatingWebhookConfiguration
	vwcs        map[string]*admissionv1.ValidatingWebhookConfiguration
	vaps        map[string]*admissionv1.ValidatingAdmissionPolicy
	vapbs       map[string]*admissionv1.ValidatingAdmissionPolicyBinding
	maps        map[string]*admissionv1.MutatingAdmissionPolicy
	mapbs       map[string]*admissionv1.MutatingAdmissionPolicyBinding
	crds        map[string]*apiextensionsv1.CustomResourceDefinition
	leases      map[string]*coordinationv1.Lease

	// Generic unstructured store keyed by "group/version/resource" -> "ns/name" (or "name") -> obj.
	customObjects map[string]map[string]*unstructured.Unstructured
}

func newReqE2EAPIServer(t *testing.T) *reqE2EAPIServer {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(apiextensionsv1.AddToScheme(s))
	utilruntime.Must(admissionv1.AddToScheme(s))
	utilruntime.Must(discoveryv1.AddToScheme(s))
	utilruntime.Must(storagev1.AddToScheme(s))
	utilruntime.Must(policyv1.AddToScheme(s))
	utilruntime.Must(coordinationv1.AddToScheme(s))
	utilruntime.Must(appsv1.AddToScheme(s))
	utilruntime.Must(batchv1.AddToScheme(s))
	utilruntime.Must(networkingv1.AddToScheme(s))
	utilruntime.Must(rbacv1.AddToScheme(s))
	utilruntime.Must(corev1.AddToScheme(s))

	srv := &reqE2EAPIServer{
		scheme:          s,
		codecs:          serializer.NewCodecFactory(s),
		watchCh:         make(chan struct{}),
		ssarAllowed:     true,
		versionMajor:    "1",
		versionMinor:    "34",
		discoveryGroups: map[string]customDiscoveryEntry{},
		enabledCRDs:     map[string]bool{},
		proxyHealth:     map[string]proxyHealthEntry{},
		podLogs:         map[string]podLogEntry{},
		evictStatus:     map[string]int{},
		nodes:           map[string]*corev1.Node{},
		namespaces:      map[string]*corev1.Namespace{},
		pods:            map[string]*corev1.Pod{},
		services:        map[string]*corev1.Service{},
		endpoints:       map[string]*corev1.Endpoints{},
		configMaps:      map[string]*corev1.ConfigMap{},
		secrets:         map[string]*corev1.Secret{},
		sas:             map[string]*corev1.ServiceAccount{},
		pvs:             map[string]*corev1.PersistentVolume{},
		pvcs:            map[string]*corev1.PersistentVolumeClaim{},
		resQuotas:       map[string]*corev1.ResourceQuota{},
		deployments:     map[string]*appsv1.Deployment{},
		replicaSets:     map[string]*appsv1.ReplicaSet{},
		statefulSet:     map[string]*appsv1.StatefulSet{},
		daemonSets:      map[string]*appsv1.DaemonSet{},
		ctrlRevs:        map[string]*appsv1.ControllerRevision{},
		epSlices:        map[string]*discoveryv1.EndpointSlice{},
		vas:             map[string]*storagev1.VolumeAttachment{},
		scClasses:       map[string]*storagev1.StorageClass{},
		pdbs:            map[string]*policyv1.PodDisruptionBudget{},
		jobs:            map[string]*batchv1.Job{},
		cronJobs:        map[string]*batchv1.CronJob{},
		ingresses:       map[string]*networkingv1.Ingress{},
		ingClasses:      map[string]*networkingv1.IngressClass{},
		netPolicies:     map[string]*networkingv1.NetworkPolicy{},
		crbs:            map[string]*rbacv1.ClusterRoleBinding{},
		rbs:             map[string]*rbacv1.RoleBinding{},
		mwcs:            map[string]*admissionv1.MutatingWebhookConfiguration{},
		vwcs:            map[string]*admissionv1.ValidatingWebhookConfiguration{},
		vaps:            map[string]*admissionv1.ValidatingAdmissionPolicy{},
		vapbs:           map[string]*admissionv1.ValidatingAdmissionPolicyBinding{},
		maps:            map[string]*admissionv1.MutatingAdmissionPolicy{},
		mapbs:           map[string]*admissionv1.MutatingAdmissionPolicyBinding{},
		crds:            map[string]*apiextensionsv1.CustomResourceDefinition{},
		leases:          map[string]*coordinationv1.Lease{},
		customObjects:   map[string]map[string]*unstructured.Unstructured{},
	}
	srv.nextRV.Store(10)
	for _, ns := range []string{"default", "kube-system", "kube-node-lease", "node-ops", "medik8s", "flux-system", "apps"} {
		srv.namespaces[ns] = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: ns, ResourceVersion: "1"},
		}
	}

	srv.srv = httptest.NewServer(http.HandlerFunc(srv.serveHTTP))
	t.Cleanup(func() {
		close(srv.watchCh)
		srv.srv.Close()
	})
	return srv
}

func (s *reqE2EAPIServer) URL() string { return s.srv.URL }

func (s *reqE2EAPIServer) bumpRV() string {
	return strconv.FormatInt(s.nextRV.Add(1), 10)
}

func (s *reqE2EAPIServer) setVersion(major, minor string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.versionMajor = major
	s.versionMinor = minor
	s.versionRaw = ""
}

func (s *reqE2EAPIServer) setVersionRaw(raw string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.versionRaw = raw
}

func (s *reqE2EAPIServer) setSSARAllowed(allowed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ssarAllowed = allowed
}

func (s *reqE2EAPIServer) registerDiscoveryGroup(group, version string, resources ...metav1.APIResource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	gv := group + "/" + version
	s.discoveryGroups[gv] = customDiscoveryEntry{
		Group:     group,
		Version:   version,
		Resources: resources,
	}
}

func (s *reqE2EAPIServer) enableCRD(gvr schema.GroupVersionResource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := gvr.Group + "/" + gvr.Version + "/" + gvr.Resource
	s.enabledCRDs[key] = true
	if s.customObjects[key] == nil {
		s.customObjects[key] = map[string]*unstructured.Unstructured{}
	}
}

func (s *reqE2EAPIServer) addCustomObject(gvr schema.GroupVersionResource, obj *unstructured.Unstructured) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := gvr.Group + "/" + gvr.Version + "/" + gvr.Resource
	s.enabledCRDs[key] = true
	if s.customObjects[key] == nil {
		s.customObjects[key] = map[string]*unstructured.Unstructured{}
	}
	cp := obj.DeepCopy()
	if cp.GetResourceVersion() == "" {
		cp.SetResourceVersion(s.bumpRV())
	}
	objKey := cp.GetName()
	if ns := cp.GetNamespace(); ns != "" {
		objKey = ns + "/" + cp.GetName()
	}
	s.customObjects[key][objKey] = cp
}

func (s *reqE2EAPIServer) addErrorRule(method, pathPrefix string, status, remaining int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errorRules = append(s.errorRules, &reqErrorRule{
		Method:     method,
		PathPrefix: pathPrefix,
		Status:     status,
		Remaining:  remaining,
	})
}

func (s *reqE2EAPIServer) addDelayRule(method, pathPrefix, acceptContains string, delay time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delayRules = append(s.delayRules, reqDelayRule{
		Method:         method,
		PathPrefix:     pathPrefix,
		AcceptContains: acceptContains,
		Delay:          delay,
	})
}

func (s *reqE2EAPIServer) setNodeProxyHealthz(node string, status int, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.proxyHealth[node] = proxyHealthEntry{Status: status, Body: body}
}

func (s *reqE2EAPIServer) setPodLog(ns, name, container string, status int, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := ns + "/" + name
	if container != "" {
		key += "/" + container
	}
	s.podLogs[key] = podLogEntry{Status: status, Body: body}
}

func (s *reqE2EAPIServer) setPodEvictionStatus(ns, name string, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictStatus[ns+"/"+name] = status
}

func (s *reqE2EAPIServer) addNode(n *corev1.Node) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := n.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.nodes[cp.Name] = cp
}

func (s *reqE2EAPIServer) addNamespace(ns *corev1.Namespace) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := ns.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.namespaces[cp.Name] = cp
}

func (s *reqE2EAPIServer) addPod(p *corev1.Pod) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := p.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.pods[cp.Namespace+"/"+cp.Name] = cp
}

func (s *reqE2EAPIServer) addService(svc *corev1.Service) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := svc.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.services[cp.Namespace+"/"+cp.Name] = cp
}

func (s *reqE2EAPIServer) addEndpoints(ep *corev1.Endpoints) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := ep.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.endpoints[cp.Namespace+"/"+cp.Name] = cp
}

func (s *reqE2EAPIServer) addConfigMap(cm *corev1.ConfigMap) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := cm.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.configMaps[cp.Namespace+"/"+cp.Name] = cp
}

func (s *reqE2EAPIServer) addSecret(sec *corev1.Secret) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := sec.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.secrets[cp.Namespace+"/"+cp.Name] = cp
}

func (s *reqE2EAPIServer) addServiceAccount(sa *corev1.ServiceAccount) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := sa.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.sas[cp.Namespace+"/"+cp.Name] = cp
}

func (s *reqE2EAPIServer) addPV(pv *corev1.PersistentVolume) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := pv.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.pvs[cp.Name] = cp
}

func (s *reqE2EAPIServer) addPVC(pvc *corev1.PersistentVolumeClaim) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := pvc.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.pvcs[cp.Namespace+"/"+cp.Name] = cp
}

func (s *reqE2EAPIServer) addDeployment(d *appsv1.Deployment) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := d.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.deployments[cp.Namespace+"/"+cp.Name] = cp
}

func (s *reqE2EAPIServer) addReplicaSet(rs *appsv1.ReplicaSet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := rs.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.replicaSets[cp.Namespace+"/"+cp.Name] = cp
}

func (s *reqE2EAPIServer) addStatefulSet(sts *appsv1.StatefulSet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := sts.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.statefulSet[cp.Namespace+"/"+cp.Name] = cp
}

func (s *reqE2EAPIServer) addDaemonSet(ds *appsv1.DaemonSet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := ds.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.daemonSets[cp.Namespace+"/"+cp.Name] = cp
}

func (s *reqE2EAPIServer) addControllerRevision(cr *appsv1.ControllerRevision) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := cr.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.ctrlRevs[cp.Namespace+"/"+cp.Name] = cp
}

func (s *reqE2EAPIServer) addEndpointSlice(es *discoveryv1.EndpointSlice) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := es.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.epSlices[cp.Namespace+"/"+cp.Name] = cp
}

func (s *reqE2EAPIServer) addVolumeAttachment(va *storagev1.VolumeAttachment) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := va.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.vas[cp.Name] = cp
}

func (s *reqE2EAPIServer) addPDB(pdb *policyv1.PodDisruptionBudget) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := pdb.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.pdbs[cp.Namespace+"/"+cp.Name] = cp
}

func (s *reqE2EAPIServer) addJob(j *batchv1.Job) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := j.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.jobs[cp.Namespace+"/"+cp.Name] = cp
}

func (s *reqE2EAPIServer) addIngress(ing *networkingv1.Ingress) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := ing.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.ingresses[cp.Namespace+"/"+cp.Name] = cp
}

func (s *reqE2EAPIServer) addIngressClass(ic *networkingv1.IngressClass) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := ic.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.ingClasses[cp.Name] = cp
}

func (s *reqE2EAPIServer) addMWC(mwc *admissionv1.MutatingWebhookConfiguration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := mwc.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.mwcs[cp.Name] = cp
}

func (s *reqE2EAPIServer) addVWC(vwc *admissionv1.ValidatingWebhookConfiguration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := vwc.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.vwcs[cp.Name] = cp
}

func (s *reqE2EAPIServer) addVAP(vap *admissionv1.ValidatingAdmissionPolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := vap.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.vaps[cp.Name] = cp
}

func (s *reqE2EAPIServer) addVAPB(vapb *admissionv1.ValidatingAdmissionPolicyBinding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := vapb.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.vapbs[cp.Name] = cp
}

func (s *reqE2EAPIServer) addMAP(mp *admissionv1.MutatingAdmissionPolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := mp.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.maps[cp.Name] = cp
}

func (s *reqE2EAPIServer) addMAPB(mpb *admissionv1.MutatingAdmissionPolicyBinding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := mpb.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.mapbs[cp.Name] = cp
}

func (s *reqE2EAPIServer) addCRD(crd *apiextensionsv1.CustomResourceDefinition) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := crd.DeepCopy()
	if cp.ResourceVersion == "" {
		cp.ResourceVersion = s.bumpRV()
	}
	s.crds[cp.Name] = cp
}

func (s *reqE2EAPIServer) requestsMatching(pred func(reqRecord) bool) []reqRecord {
	s.mu.RLock()
	snapshot := append([]reqRecord(nil), s.reqs...)
	s.mu.RUnlock()
	var out []reqRecord
	for _, r := range snapshot {
		if pred(r) {
			out = append(out, r)
		}
	}
	return out
}

func (s *reqE2EAPIServer) requestCount(pred func(reqRecord) bool) int {
	return len(s.requestsMatching(pred))
}

func (s *reqE2EAPIServer) waitForRequest(t *testing.T, proc *managerProcess, timeout time.Duration, desc string, pred func(reqRecord) bool) reqRecord {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-proc.done:
			t.Fatalf("manager exited prematurely (%v) while waiting for request %s\nstdout:\n%s\nstderr:\n%s",
				proc.waitErr, desc, proc.stdout.String(), proc.stderr.String())
		default:
		}
		if matches := s.requestsMatching(pred); len(matches) > 0 {
			return matches[0]
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for request %s\nstdout:\n%s\nstderr:\n%s",
		timeout, desc, proc.stdout.String(), proc.stderr.String())
	return reqRecord{}
}

func (s *reqE2EAPIServer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, 4<<20))
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
	rec := reqRecord{
		Method:      r.Method,
		Path:        r.URL.Path,
		RawQuery:    r.URL.RawQuery,
		Accept:      r.Header.Get("Accept"),
		ContentType: r.Header.Get("Content-Type"),
		Body:        string(bodyBytes),
		At:          time.Now(),
	}
	s.mu.Lock()
	s.reqs = append(s.reqs, rec)
	errStatus := s.matchErrorRuleLocked(r.Method, r.URL.Path)
	var delay time.Duration
	for _, dr := range s.delayRules {
		if (dr.Method == "" || dr.Method == r.Method) &&
			strings.HasPrefix(r.URL.Path, dr.PathPrefix) &&
			(dr.AcceptContains == "" || strings.Contains(rec.Accept, dr.AcceptContains)) {
			delay = dr.Delay
			break
		}
	}
	s.mu.Unlock()

	if delay > 0 {
		time.Sleep(delay)
	}

	if errStatus > 0 {
		reason := metav1.StatusReasonInternalError
		switch errStatus {
		case http.StatusForbidden:
			reason = metav1.StatusReasonForbidden
		case http.StatusNotFound:
			reason = metav1.StatusReasonNotFound
		case http.StatusTooManyRequests:
			reason = metav1.StatusReasonTooManyRequests
		case http.StatusConflict:
			reason = metav1.StatusReasonConflict
		case http.StatusBadRequest:
			reason = metav1.StatusReasonBadRequest
		}
		s.writeStatus(w, r, errStatus, reason, fmt.Sprintf("injected %d", errStatus))
		return
	}

	path := r.URL.Path
	switch {
	case path == "/version":
		s.handleVersion(w)
		return
	case path == "/api":
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"kind":"APIVersions","apiVersion":"v1","versions":["v1"]}`)
		return
	case path == "/apis":
		s.handleAPIGroupList(w)
		return
	case path == "/api/v1":
		s.handleCoreV1Discovery(w)
		return
	case strings.HasPrefix(path, "/apis/") && strings.Count(strings.TrimPrefix(path, "/apis/"), "/") == 1:
		s.handleGroupVersionDiscovery(w, r, strings.TrimPrefix(path, "/apis/"))
		return
	case path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" && r.Method == http.MethodPost:
		s.handleSSAR(w, r, bodyBytes)
		return
	}

	// Subresources
	if strings.HasPrefix(path, "/api/v1/nodes/") && strings.HasSuffix(path, "/proxy/healthz") {
		nodeName := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/nodes/"), "/proxy/healthz")
		s.mu.RLock()
		entry, ok := s.proxyHealth[nodeName]
		s.mu.RUnlock()
		if !ok {
			entry = proxyHealthEntry{Status: http.StatusOK, Body: "ok"}
		}
		w.WriteHeader(entry.Status)
		_, _ = io.WriteString(w, entry.Body)
		return
	}
	if strings.HasPrefix(path, "/api/v1/namespaces/") && strings.HasSuffix(path, "/log") {
		s.handlePodLog(w, r, path)
		return
	}
	if r.Method == http.MethodPost && strings.HasPrefix(path, "/api/v1/namespaces/") && strings.HasSuffix(path, "/eviction") {
		s.handlePodEviction(w, r, path)
		return
	}
	if r.Method == http.MethodPost && strings.HasPrefix(path, "/api/v1/namespaces/") && strings.HasSuffix(path, "/events") {
		s.handleEventCreate(w, r, bodyBytes)
		return
	}

	s.handleResource(w, r, path, bodyBytes)
}

func (s *reqE2EAPIServer) matchErrorRuleLocked(method, path string) int {
	for _, rule := range s.errorRules {
		if (rule.Method == "" || rule.Method == method) && strings.HasPrefix(path, rule.PathPrefix) {
			if rule.Remaining == 0 {
				continue
			}
			if rule.Remaining > 0 {
				rule.Remaining--
			}
			return rule.Status
		}
	}
	return 0
}

func (s *reqE2EAPIServer) handleVersion(w http.ResponseWriter) {
	s.mu.RLock()
	raw := s.versionRaw
	maj, minVer := s.versionMajor, s.versionMinor
	s.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	if raw != "" {
		_, _ = io.WriteString(w, raw)
		return
	}
	_, _ = fmt.Fprintf(w, `{"major":%q,"minor":%q,"gitVersion":"v%s.%s.0"}`, maj, minVer, maj, minVer)
}

func (s *reqE2EAPIServer) handleAPIGroupList(w http.ResponseWriter) {
	groups := []metav1.APIGroup{
		makeAPIGroup("apps", "v1"),
		makeAPIGroup("apiextensions.k8s.io", "v1"),
		makeAPIGroup("coordination.k8s.io", "v1"),
		makeAPIGroup("authorization.k8s.io", "v1"),
		makeAPIGroup("admissionregistration.k8s.io", "v1"),
		makeAPIGroup("discovery.k8s.io", "v1"),
		makeAPIGroup("storage.k8s.io", "v1"),
		makeAPIGroup("policy.k8s.io", "v1"),
		makeAPIGroup("policy", "v1"),
		makeAPIGroup("batch", "v1"),
		makeAPIGroup("networking.k8s.io", "v1"),
		makeAPIGroup("rbac.authorization.k8s.io", "v1"),
	}
	s.mu.RLock()
	for _, entry := range s.discoveryGroups {
		groups = append(groups, makeAPIGroup(entry.Group, entry.Version))
	}
	s.mu.RUnlock()
	gl := metav1.APIGroupList{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "APIGroupList"},
		Groups:   groups,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(gl)
}

func makeAPIGroup(name, version string) metav1.APIGroup {
	gv := name + "/" + version
	return metav1.APIGroup{
		Name: name,
		Versions: []metav1.GroupVersionForDiscovery{
			{GroupVersion: gv, Version: version},
		},
		PreferredVersion: metav1.GroupVersionForDiscovery{GroupVersion: gv, Version: version},
	}
}

func (s *reqE2EAPIServer) handleCoreV1Discovery(w http.ResponseWriter) {
	rl := metav1.APIResourceList{
		TypeMeta:     metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"},
		GroupVersion: "v1",
		APIResources: []metav1.APIResource{
			{Name: "configmaps", Namespaced: true, Kind: "ConfigMap", Verbs: []string{"get", "list", "watch"}},
			{Name: "endpoints", Namespaced: true, Kind: "Endpoints", Verbs: []string{"get", "list", "watch", "update", "patch"}},
			{Name: "events", Namespaced: true, Kind: "Event", Verbs: []string{"create", "patch", "update"}},
			{Name: "namespaces", Namespaced: false, Kind: "Namespace", Verbs: []string{"get", "list", "watch"}},
			{Name: "nodes", Namespaced: false, Kind: "Node", Verbs: []string{"get", "list", "watch", "patch"}},
			{Name: "persistentvolumeclaims", Namespaced: true, Kind: "PersistentVolumeClaim", Verbs: []string{"get", "list", "watch", "patch"}},
			{Name: "persistentvolumes", Namespaced: false, Kind: "PersistentVolume", Verbs: []string{"get", "list", "watch"}},
			{Name: "pods", Namespaced: true, Kind: "Pod", Verbs: []string{"get", "list", "watch", "delete"}},
			{Name: "pods/eviction", Namespaced: true, Kind: "Eviction", Verbs: []string{"create"}},
			{Name: "pods/log", Namespaced: true, Kind: "Pod", Verbs: []string{"get"}},
			{Name: "resourcequotas", Namespaced: true, Kind: "ResourceQuota", Verbs: []string{"get", "list"}},
			{Name: "secrets", Namespaced: true, Kind: "Secret", Verbs: []string{"get", "list", "watch", "delete"}},
			{Name: "serviceaccounts", Namespaced: true, Kind: "ServiceAccount", Verbs: []string{"get", "list"}},
			{Name: "services", Namespaced: true, Kind: "Service", Verbs: []string{"get", "list", "watch"}},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rl)
}

func (s *reqE2EAPIServer) handleGroupVersionDiscovery(w http.ResponseWriter, r *http.Request, gv string) {
	builtins := map[string][]metav1.APIResource{
		"apps/v1": {
			{Name: "controllerrevisions", Namespaced: true, Kind: "ControllerRevision", Verbs: []string{"get", "list", "delete"}},
			{Name: "daemonsets", Namespaced: true, Kind: "DaemonSet", Verbs: []string{"get", "list", "watch", "patch"}},
			{Name: "deployments", Namespaced: true, Kind: "Deployment", Verbs: []string{"get", "list", "watch", "patch"}},
			{Name: "replicasets", Namespaced: true, Kind: "ReplicaSet", Verbs: []string{"get", "list", "patch", "delete"}},
			{Name: "statefulsets", Namespaced: true, Kind: "StatefulSet", Verbs: []string{"get", "list", "watch", "patch"}},
		},
		"apiextensions.k8s.io/v1": {
			{Name: "customresourcedefinitions", Namespaced: false, Kind: "CustomResourceDefinition", Verbs: []string{"get", "list", "watch"}},
		},
		"coordination.k8s.io/v1": {
			{Name: "leases", Namespaced: true, Kind: "Lease", Verbs: []string{"get", "list", "watch", "create", "update", "patch"}},
		},
		"authorization.k8s.io/v1": {
			{Name: "selfsubjectaccessreviews", Namespaced: false, Kind: "SelfSubjectAccessReview", Verbs: []string{"create"}},
		},
		"admissionregistration.k8s.io/v1": {
			{Name: "mutatingwebhookconfigurations", Namespaced: false, Kind: "MutatingWebhookConfiguration", Verbs: []string{"get", "list", "patch"}},
			{Name: "validatingwebhookconfigurations", Namespaced: false, Kind: "ValidatingWebhookConfiguration", Verbs: []string{"get", "list", "patch"}},
			{Name: "validatingadmissionpolicies", Namespaced: false, Kind: "ValidatingAdmissionPolicy", Verbs: []string{"get", "list", "patch"}},
			{Name: "validatingadmissionpolicybindings", Namespaced: false, Kind: "ValidatingAdmissionPolicyBinding", Verbs: []string{"get", "list"}},
			{Name: "mutatingadmissionpolicies", Namespaced: false, Kind: "MutatingAdmissionPolicy", Verbs: []string{"get", "list", "patch"}},
			{Name: "mutatingadmissionpolicybindings", Namespaced: false, Kind: "MutatingAdmissionPolicyBinding", Verbs: []string{"get", "list"}},
		},
		"discovery.k8s.io/v1": {
			{Name: "endpointslices", Namespaced: true, Kind: "EndpointSlice", Verbs: []string{"get", "list", "patch", "delete"}},
		},
		"storage.k8s.io/v1": {
			{Name: "storageclasses", Namespaced: false, Kind: "StorageClass", Verbs: []string{"get", "list"}},
			{Name: "volumeattachments", Namespaced: false, Kind: "VolumeAttachment", Verbs: []string{"get", "list", "delete"}},
		},
		"policy/v1": {
			{Name: "poddisruptionbudgets", Namespaced: true, Kind: "PodDisruptionBudget", Verbs: []string{"get", "list", "patch"}},
		},
		"batch/v1": {
			{Name: "jobs", Namespaced: true, Kind: "Job", Verbs: []string{"get", "list", "delete"}},
			{Name: "cronjobs", Namespaced: true, Kind: "CronJob", Verbs: []string{"get", "list"}},
		},
		"networking.k8s.io/v1": {
			{Name: "ingresses", Namespaced: true, Kind: "Ingress", Verbs: []string{"get", "list"}},
			{Name: "ingressclasses", Namespaced: false, Kind: "IngressClass", Verbs: []string{"get", "list"}},
			{Name: "networkpolicies", Namespaced: true, Kind: "NetworkPolicy", Verbs: []string{"get", "list"}},
		},
		"rbac.authorization.k8s.io/v1": {
			{Name: "clusterrolebindings", Namespaced: false, Kind: "ClusterRoleBinding", Verbs: []string{"get", "list"}},
			{Name: "rolebindings", Namespaced: true, Kind: "RoleBinding", Verbs: []string{"get", "list"}},
		},
	}

	resources, ok := builtins[gv]
	if !ok {
		s.mu.RLock()
		entry, found := s.discoveryGroups[gv]
		s.mu.RUnlock()
		if !found {
			s.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, "groupVersion not found: "+gv)
			return
		}
		resources = entry.Resources
	}
	rl := metav1.APIResourceList{
		TypeMeta:     metav1.TypeMeta{APIVersion: "v1", Kind: "APIResourceList"},
		GroupVersion: gv,
		APIResources: resources,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rl)
}

func (s *reqE2EAPIServer) handleSSAR(w http.ResponseWriter, r *http.Request, body []byte) {
	var sar authv1.SelfSubjectAccessReview
	if err := s.decodeBytes(r.Header.Get("Content-Type"), body, &sar); err != nil {
		s.writeStatus(w, r, http.StatusBadRequest, metav1.StatusReasonBadRequest, err.Error())
		return
	}
	s.mu.RLock()
	allowed := s.ssarAllowed
	s.mu.RUnlock()
	sar.Status.Allowed = allowed
	s.writeObject(w, r, http.StatusCreated, authv1.SchemeGroupVersion, &sar)
}

func (s *reqE2EAPIServer) handlePodLog(w http.ResponseWriter, r *http.Request, path string) {
	trimmed := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/namespaces/"), "/log")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 3 || parts[1] != "pods" {
		s.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, "invalid log path")
		return
	}
	ns, name := parts[0], parts[2]
	container := r.URL.Query().Get("container")

	s.mu.RLock()
	entry, ok := s.podLogs[ns+"/"+name+"/"+container]
	if !ok {
		entry, ok = s.podLogs[ns+"/"+name]
	}
	s.mu.RUnlock()
	if !ok {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		return
	}
	if entry.Status != 0 && entry.Status != http.StatusOK {
		s.writeStatus(w, r, entry.Status, metav1.StatusReasonInternalError, "pod log error")
		return
	}
	data := entry.Body
	if lbStr := r.URL.Query().Get("limitBytes"); lbStr != "" {
		if lb, err := strconv.Atoi(lbStr); err == nil && lb > 0 && len(data) > lb {
			data = data[:lb]
		}
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *reqE2EAPIServer) handlePodEviction(w http.ResponseWriter, r *http.Request, path string) {
	trimmed := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/namespaces/"), "/eviction")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 3 || parts[1] != "pods" {
		s.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, "invalid eviction path")
		return
	}
	key := parts[0] + "/" + parts[2]
	s.mu.RLock()
	status := s.evictStatus[key]
	s.mu.RUnlock()
	if status == 0 {
		status = http.StatusCreated
	}
	switch status {
	case http.StatusCreated, http.StatusOK:
		st := &metav1.Status{
			TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"},
			Status:   metav1.StatusSuccess,
			Code:     int32(http.StatusCreated),
		}
		s.writeObject(w, r, http.StatusCreated, corev1.SchemeGroupVersion, st)
	case http.StatusNotFound:
		s.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, "pod not found")
	case http.StatusTooManyRequests:
		s.writeStatus(w, r, http.StatusTooManyRequests, metav1.StatusReasonTooManyRequests, "Cannot evict pod as it would violate the pod's disruption budget.")
	default:
		s.writeStatus(w, r, status, metav1.StatusReasonInternalError, "eviction failed")
	}
}

func (s *reqE2EAPIServer) handleEventCreate(w http.ResponseWriter, r *http.Request, body []byte) {
	var ev corev1.Event
	if err := s.decodeBytes(r.Header.Get("Content-Type"), body, &ev); err != nil {
		s.writeStatus(w, r, http.StatusBadRequest, metav1.StatusReasonBadRequest, err.Error())
		return
	}
	ev.ResourceVersion = s.bumpRV()
	s.mu.Lock()
	s.events = append(s.events, ev.DeepCopy())
	s.mu.Unlock()
	s.writeObject(w, r, http.StatusCreated, corev1.SchemeGroupVersion, &ev)
}

type parsedKubePath struct {
	Group     string
	Version   string
	Namespace string
	Resource  string
	Name      string
}

func parseKubeResourcePath(path string) (parsedKubePath, bool) {
	trimmed := strings.TrimPrefix(path, "/")
	parts := strings.Split(trimmed, "/")
	var p parsedKubePath
	var rest []string
	switch {
	case len(parts) >= 3 && parts[0] == "api" && parts[1] == "v1":
		p.Group = ""
		p.Version = "v1"
		rest = parts[2:]
	case len(parts) >= 4 && parts[0] == "apis":
		p.Group = parts[1]
		p.Version = parts[2]
		rest = parts[3:]
	default:
		return parsedKubePath{}, false
	}
	if len(rest) >= 2 && rest[0] == "namespaces" {
		p.Namespace = rest[1]
		rest = rest[2:]
	}
	switch len(rest) {
	case 1:
		p.Resource = rest[0]
		return p, true
	case 2:
		p.Resource = rest[0]
		p.Name = rest[1]
		return p, true
	default:
		return parsedKubePath{}, false
	}
}

func (s *reqE2EAPIServer) handleResource(w http.ResponseWriter, r *http.Request, path string, body []byte) {
	kp, ok := parseKubeResourcePath(path)
	if !ok {
		s.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, "not found: "+path)
		return
	}

	if r.URL.Query().Get("watch") == "true" {
		s.handleWatch(w, r, kp)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if kp.Name == "" {
			s.handleList(w, r, kp)
		} else {
			s.handleGet(w, r, kp)
		}
	case http.MethodPatch:
		s.handlePatch(w, r, kp, body)
	case http.MethodDelete:
		s.handleDelete(w, r, kp, body)
	default:
		s.writeStatus(w, r, http.StatusMethodNotAllowed, metav1.StatusReasonMethodNotAllowed, "method not allowed")
	}
}

func (s *reqE2EAPIServer) handleWatch(w http.ResponseWriter, r *http.Request, kp parsedKubePath) {
	gv, itemKind := s.gvAndKindForResource(kp.Group, kp.Version, kp.Resource)
	if itemKind == "" {
		s.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, "unknown watch resource: "+kp.Resource)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if r.URL.Query().Get("sendInitialEvents") == "true" {
		initialObjs := s.watchInitialObjects(gv, itemKind, kp.Resource)
		for _, obj := range initialObjs {
			raw, err := json.Marshal(obj)
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, `{"type":"ADDED","object":%s}`+"\n", raw)
		}
		rv := strconv.FormatInt(s.nextRV.Load(), 10)
		_, _ = fmt.Fprintf(w,
			`{"type":"BOOKMARK","object":{"apiVersion":%q,"kind":%q,"metadata":{"resourceVersion":%q,"annotations":{"k8s.io/initial-events-end":"true"}}}}`+"\n",
			gv.String(), itemKind, rv)
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	select {
	case <-r.Context().Done():
	case <-s.watchCh:
	}
}

func (s *reqE2EAPIServer) watchInitialObjects(gv schema.GroupVersion, kind, resource string) []runtime.Object {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tm := metav1.TypeMeta{APIVersion: gv.String(), Kind: kind}
	var out []runtime.Object
	switch gv.String() + "/" + resource {
	case "v1/nodes":
		for _, k := range slices.Sorted(maps.Keys(s.nodes)) {
			cp := s.nodes[k].DeepCopy()
			cp.TypeMeta = tm
			out = append(out, cp)
		}
	case "v1/namespaces":
		for _, k := range slices.Sorted(maps.Keys(s.namespaces)) {
			cp := s.namespaces[k].DeepCopy()
			cp.TypeMeta = tm
			out = append(out, cp)
		}
	case "v1/secrets":
		for _, k := range slices.Sorted(maps.Keys(s.secrets)) {
			cp := s.secrets[k].DeepCopy()
			cp.TypeMeta = tm
			out = append(out, cp)
		}
	case "v1/configmaps":
		for _, k := range slices.Sorted(maps.Keys(s.configMaps)) {
			cp := s.configMaps[k].DeepCopy()
			cp.TypeMeta = tm
			out = append(out, cp)
		}
	case "v1/endpoints":
		for _, k := range slices.Sorted(maps.Keys(s.endpoints)) {
			cp := s.endpoints[k].DeepCopy()
			cp.TypeMeta = tm
			out = append(out, cp)
		}
	case "apps/v1/deployments":
		for _, k := range slices.Sorted(maps.Keys(s.deployments)) {
			cp := s.deployments[k].DeepCopy()
			cp.TypeMeta = tm
			out = append(out, cp)
		}
	case "apps/v1/daemonsets":
		for _, k := range slices.Sorted(maps.Keys(s.daemonSets)) {
			cp := s.daemonSets[k].DeepCopy()
			cp.TypeMeta = tm
			out = append(out, cp)
		}
	case "apiextensions.k8s.io/v1/customresourcedefinitions":
		for _, k := range slices.Sorted(maps.Keys(s.crds)) {
			cp := s.crds[k].DeepCopy()
			cp.TypeMeta = tm
			out = append(out, cp)
		}
	case "coordination.k8s.io/v1/leases":
		for _, k := range slices.Sorted(maps.Keys(s.leases)) {
			cp := s.leases[k].DeepCopy()
			cp.TypeMeta = tm
			out = append(out, cp)
		}
	}
	return out
}

func (s *reqE2EAPIServer) gvAndKindForResource(group, version, resource string) (schema.GroupVersion, string) {
	gv := schema.GroupVersion{Group: group, Version: version}
	switch gv.String() + "/" + resource {
	case "v1/nodes":
		return gv, "Node"
	case "v1/namespaces":
		return gv, "Namespace"
	case "v1/pods":
		return gv, "Pod"
	case "v1/services":
		return gv, "Service"
	case "v1/endpoints":
		return gv, "Endpoints"
	case "v1/configmaps":
		return gv, "ConfigMap"
	case "v1/secrets":
		return gv, "Secret"
	case "v1/serviceaccounts":
		return gv, "ServiceAccount"
	case "v1/persistentvolumes":
		return gv, "PersistentVolume"
	case "v1/persistentvolumeclaims":
		return gv, "PersistentVolumeClaim"
	case "v1/resourcequotas":
		return gv, "ResourceQuota"
	case "apps/v1/deployments":
		return gv, "Deployment"
	case "apps/v1/replicasets":
		return gv, "ReplicaSet"
	case "apps/v1/statefulsets":
		return gv, "StatefulSet"
	case "apps/v1/daemonsets":
		return gv, "DaemonSet"
	case "apps/v1/controllerrevisions":
		return gv, "ControllerRevision"
	case "apiextensions.k8s.io/v1/customresourcedefinitions":
		return gv, "CustomResourceDefinition"
	case "coordination.k8s.io/v1/leases":
		return gv, "Lease"
	case "admissionregistration.k8s.io/v1/mutatingwebhookconfigurations":
		return gv, "MutatingWebhookConfiguration"
	case "admissionregistration.k8s.io/v1/validatingwebhookconfigurations":
		return gv, "ValidatingWebhookConfiguration"
	case "admissionregistration.k8s.io/v1/validatingadmissionpolicies":
		return gv, "ValidatingAdmissionPolicy"
	case "admissionregistration.k8s.io/v1/validatingadmissionpolicybindings":
		return gv, "ValidatingAdmissionPolicyBinding"
	case "admissionregistration.k8s.io/v1/mutatingadmissionpolicies":
		return gv, "MutatingAdmissionPolicy"
	case "admissionregistration.k8s.io/v1/mutatingadmissionpolicybindings":
		return gv, "MutatingAdmissionPolicyBinding"
	case "discovery.k8s.io/v1/endpointslices":
		return gv, "EndpointSlice"
	case "storage.k8s.io/v1/storageclasses":
		return gv, "StorageClass"
	case "storage.k8s.io/v1/volumeattachments":
		return gv, "VolumeAttachment"
	case "policy/v1/poddisruptionbudgets":
		return gv, "PodDisruptionBudget"
	case "batch/v1/jobs":
		return gv, "Job"
	case "batch/v1/cronjobs":
		return gv, "CronJob"
	case "networking.k8s.io/v1/ingresses":
		return gv, "Ingress"
	case "networking.k8s.io/v1/ingressclasses":
		return gv, "IngressClass"
	case "networking.k8s.io/v1/networkpolicies":
		return gv, "NetworkPolicy"
	case "rbac.authorization.k8s.io/v1/clusterrolebindings":
		return gv, "ClusterRoleBinding"
	case "rbac.authorization.k8s.io/v1/rolebindings":
		return gv, "RoleBinding"
	default:
		return gv, ""
	}
}

func (s *reqE2EAPIServer) handleList(w http.ResponseWriter, r *http.Request, kp parsedKubePath) {
	rv := strconv.FormatInt(s.nextRV.Load(), 10)
	listMeta := metav1.ListMeta{ResourceVersion: rv}
	gv := schema.GroupVersion{Group: kp.Group, Version: kp.Version}
	fieldSel := r.URL.Query().Get("fieldSelector")
	labelSel := r.URL.Query().Get("labelSelector")

	s.mu.RLock()
	defer s.mu.RUnlock()

	var obj runtime.Object
	var metas []metav1.PartialObjectMetadata

	switch gv.String() + "/" + kp.Resource {
	case "v1/nodes":
		items := make([]corev1.Node, 0, len(s.nodes))
		for _, k := range slices.Sorted(maps.Keys(s.nodes)) {
			v := s.nodes[k]
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &corev1.NodeList{ListMeta: listMeta, Items: items}
	case "v1/namespaces":
		items := make([]corev1.Namespace, 0, len(s.namespaces))
		for _, k := range slices.Sorted(maps.Keys(s.namespaces)) {
			v := s.namespaces[k]
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &corev1.NamespaceList{ListMeta: listMeta, Items: items}
	case "v1/pods":
		items := make([]corev1.Pod, 0, len(s.pods))
		for _, k := range slices.Sorted(maps.Keys(s.pods)) {
			v := s.pods[k]
			if kp.Namespace != "" && v.Namespace != kp.Namespace {
				continue
			}
			if !matchPodFieldSelector(v, fieldSel) {
				continue
			}
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &corev1.PodList{ListMeta: listMeta, Items: items}
	case "v1/services":
		items := make([]corev1.Service, 0, len(s.services))
		for _, k := range slices.Sorted(maps.Keys(s.services)) {
			v := s.services[k]
			if kp.Namespace != "" && v.Namespace != kp.Namespace {
				continue
			}
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &corev1.ServiceList{ListMeta: listMeta, Items: items}
	case "v1/endpoints":
		items := make([]corev1.Endpoints, 0, len(s.endpoints))
		for _, k := range slices.Sorted(maps.Keys(s.endpoints)) {
			v := s.endpoints[k]
			if kp.Namespace != "" && v.Namespace != kp.Namespace {
				continue
			}
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &corev1.EndpointsList{ListMeta: listMeta, Items: items}
	case "v1/configmaps":
		items := make([]corev1.ConfigMap, 0, len(s.configMaps))
		for _, k := range slices.Sorted(maps.Keys(s.configMaps)) {
			v := s.configMaps[k]
			if kp.Namespace != "" && v.Namespace != kp.Namespace {
				continue
			}
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &corev1.ConfigMapList{ListMeta: listMeta, Items: items}
	case "v1/secrets":
		items := make([]corev1.Secret, 0, len(s.secrets))
		for _, k := range slices.Sorted(maps.Keys(s.secrets)) {
			v := s.secrets[k]
			if kp.Namespace != "" && v.Namespace != kp.Namespace {
				continue
			}
			if !matchSecretFieldSelector(v, fieldSel) {
				continue
			}
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &corev1.SecretList{ListMeta: listMeta, Items: items}
	case "v1/serviceaccounts":
		items := make([]corev1.ServiceAccount, 0, len(s.sas))
		for _, k := range slices.Sorted(maps.Keys(s.sas)) {
			v := s.sas[k]
			if kp.Namespace != "" && v.Namespace != kp.Namespace {
				continue
			}
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &corev1.ServiceAccountList{ListMeta: listMeta, Items: items}
	case "v1/persistentvolumes":
		items := make([]corev1.PersistentVolume, 0, len(s.pvs))
		for _, k := range slices.Sorted(maps.Keys(s.pvs)) {
			v := s.pvs[k]
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &corev1.PersistentVolumeList{ListMeta: listMeta, Items: items}
	case "v1/persistentvolumeclaims":
		items := make([]corev1.PersistentVolumeClaim, 0, len(s.pvcs))
		for _, k := range slices.Sorted(maps.Keys(s.pvcs)) {
			v := s.pvcs[k]
			if kp.Namespace != "" && v.Namespace != kp.Namespace {
				continue
			}
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &corev1.PersistentVolumeClaimList{ListMeta: listMeta, Items: items}
	case "v1/resourcequotas":
		items := make([]corev1.ResourceQuota, 0, len(s.resQuotas))
		for _, k := range slices.Sorted(maps.Keys(s.resQuotas)) {
			v := s.resQuotas[k]
			if kp.Namespace != "" && v.Namespace != kp.Namespace {
				continue
			}
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &corev1.ResourceQuotaList{ListMeta: listMeta, Items: items}
	case "apps/v1/deployments":
		items := make([]appsv1.Deployment, 0, len(s.deployments))
		for _, k := range slices.Sorted(maps.Keys(s.deployments)) {
			v := s.deployments[k]
			if kp.Namespace != "" && v.Namespace != kp.Namespace {
				continue
			}
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &appsv1.DeploymentList{ListMeta: listMeta, Items: items}
	case "apps/v1/replicasets":
		items := make([]appsv1.ReplicaSet, 0, len(s.replicaSets))
		for _, k := range slices.Sorted(maps.Keys(s.replicaSets)) {
			v := s.replicaSets[k]
			if kp.Namespace != "" && v.Namespace != kp.Namespace {
				continue
			}
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &appsv1.ReplicaSetList{ListMeta: listMeta, Items: items}
	case "apps/v1/statefulsets":
		items := make([]appsv1.StatefulSet, 0, len(s.statefulSet))
		for _, k := range slices.Sorted(maps.Keys(s.statefulSet)) {
			v := s.statefulSet[k]
			if kp.Namespace != "" && v.Namespace != kp.Namespace {
				continue
			}
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &appsv1.StatefulSetList{ListMeta: listMeta, Items: items}
	case "apps/v1/daemonsets":
		items := make([]appsv1.DaemonSet, 0, len(s.daemonSets))
		for _, k := range slices.Sorted(maps.Keys(s.daemonSets)) {
			v := s.daemonSets[k]
			if kp.Namespace != "" && v.Namespace != kp.Namespace {
				continue
			}
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &appsv1.DaemonSetList{ListMeta: listMeta, Items: items}
	case "apps/v1/controllerrevisions":
		items := make([]appsv1.ControllerRevision, 0, len(s.ctrlRevs))
		for _, k := range slices.Sorted(maps.Keys(s.ctrlRevs)) {
			v := s.ctrlRevs[k]
			if kp.Namespace != "" && v.Namespace != kp.Namespace {
				continue
			}
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &appsv1.ControllerRevisionList{ListMeta: listMeta, Items: items}
	case "discovery.k8s.io/v1/endpointslices":
		items := make([]discoveryv1.EndpointSlice, 0, len(s.epSlices))
		for _, k := range slices.Sorted(maps.Keys(s.epSlices)) {
			v := s.epSlices[k]
			if kp.Namespace != "" && v.Namespace != kp.Namespace {
				continue
			}
			if !matchLabelSelector(v.Labels, labelSel) {
				continue
			}
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &discoveryv1.EndpointSliceList{ListMeta: listMeta, Items: items}
	case "storage.k8s.io/v1/storageclasses":
		items := make([]storagev1.StorageClass, 0, len(s.scClasses))
		for _, k := range slices.Sorted(maps.Keys(s.scClasses)) {
			v := s.scClasses[k]
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &storagev1.StorageClassList{ListMeta: listMeta, Items: items}
	case "storage.k8s.io/v1/volumeattachments":
		items := make([]storagev1.VolumeAttachment, 0, len(s.vas))
		for _, k := range slices.Sorted(maps.Keys(s.vas)) {
			v := s.vas[k]
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &storagev1.VolumeAttachmentList{ListMeta: listMeta, Items: items}
	case "policy/v1/poddisruptionbudgets":
		items := make([]policyv1.PodDisruptionBudget, 0, len(s.pdbs))
		for _, k := range slices.Sorted(maps.Keys(s.pdbs)) {
			v := s.pdbs[k]
			if kp.Namespace != "" && v.Namespace != kp.Namespace {
				continue
			}
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &policyv1.PodDisruptionBudgetList{ListMeta: listMeta, Items: items}
	case "batch/v1/jobs":
		items := make([]batchv1.Job, 0, len(s.jobs))
		for _, k := range slices.Sorted(maps.Keys(s.jobs)) {
			v := s.jobs[k]
			if kp.Namespace != "" && v.Namespace != kp.Namespace {
				continue
			}
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &batchv1.JobList{ListMeta: listMeta, Items: items}
	case "batch/v1/cronjobs":
		items := make([]batchv1.CronJob, 0, len(s.cronJobs))
		for _, k := range slices.Sorted(maps.Keys(s.cronJobs)) {
			v := s.cronJobs[k]
			if kp.Namespace != "" && v.Namespace != kp.Namespace {
				continue
			}
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &batchv1.CronJobList{ListMeta: listMeta, Items: items}
	case "networking.k8s.io/v1/ingresses":
		items := make([]networkingv1.Ingress, 0, len(s.ingresses))
		for _, k := range slices.Sorted(maps.Keys(s.ingresses)) {
			v := s.ingresses[k]
			if kp.Namespace != "" && v.Namespace != kp.Namespace {
				continue
			}
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &networkingv1.IngressList{ListMeta: listMeta, Items: items}
	case "networking.k8s.io/v1/ingressclasses":
		items := make([]networkingv1.IngressClass, 0, len(s.ingClasses))
		for _, k := range slices.Sorted(maps.Keys(s.ingClasses)) {
			v := s.ingClasses[k]
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &networkingv1.IngressClassList{ListMeta: listMeta, Items: items}
	case "networking.k8s.io/v1/networkpolicies":
		items := make([]networkingv1.NetworkPolicy, 0, len(s.netPolicies))
		for _, k := range slices.Sorted(maps.Keys(s.netPolicies)) {
			v := s.netPolicies[k]
			if kp.Namespace != "" && v.Namespace != kp.Namespace {
				continue
			}
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &networkingv1.NetworkPolicyList{ListMeta: listMeta, Items: items}
	case "rbac.authorization.k8s.io/v1/clusterrolebindings":
		items := make([]rbacv1.ClusterRoleBinding, 0, len(s.crbs))
		for _, k := range slices.Sorted(maps.Keys(s.crbs)) {
			v := s.crbs[k]
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &rbacv1.ClusterRoleBindingList{ListMeta: listMeta, Items: items}
	case "rbac.authorization.k8s.io/v1/rolebindings":
		items := make([]rbacv1.RoleBinding, 0, len(s.rbs))
		for _, k := range slices.Sorted(maps.Keys(s.rbs)) {
			v := s.rbs[k]
			if kp.Namespace != "" && v.Namespace != kp.Namespace {
				continue
			}
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &rbacv1.RoleBindingList{ListMeta: listMeta, Items: items}
	case "admissionregistration.k8s.io/v1/mutatingwebhookconfigurations":
		items := make([]admissionv1.MutatingWebhookConfiguration, 0, len(s.mwcs))
		for _, k := range slices.Sorted(maps.Keys(s.mwcs)) {
			v := s.mwcs[k]
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &admissionv1.MutatingWebhookConfigurationList{ListMeta: listMeta, Items: items}
	case "admissionregistration.k8s.io/v1/validatingwebhookconfigurations":
		items := make([]admissionv1.ValidatingWebhookConfiguration, 0, len(s.vwcs))
		for _, k := range slices.Sorted(maps.Keys(s.vwcs)) {
			v := s.vwcs[k]
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &admissionv1.ValidatingWebhookConfigurationList{ListMeta: listMeta, Items: items}
	case "admissionregistration.k8s.io/v1/validatingadmissionpolicies":
		items := make([]admissionv1.ValidatingAdmissionPolicy, 0, len(s.vaps))
		for _, k := range slices.Sorted(maps.Keys(s.vaps)) {
			v := s.vaps[k]
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &admissionv1.ValidatingAdmissionPolicyList{ListMeta: listMeta, Items: items}
	case "admissionregistration.k8s.io/v1/validatingadmissionpolicybindings":
		items := make([]admissionv1.ValidatingAdmissionPolicyBinding, 0, len(s.vapbs))
		for _, k := range slices.Sorted(maps.Keys(s.vapbs)) {
			v := s.vapbs[k]
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &admissionv1.ValidatingAdmissionPolicyBindingList{ListMeta: listMeta, Items: items}
	case "admissionregistration.k8s.io/v1/mutatingadmissionpolicies":
		items := make([]admissionv1.MutatingAdmissionPolicy, 0, len(s.maps))
		for _, k := range slices.Sorted(maps.Keys(s.maps)) {
			v := s.maps[k]
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &admissionv1.MutatingAdmissionPolicyList{ListMeta: listMeta, Items: items}
	case "admissionregistration.k8s.io/v1/mutatingadmissionpolicybindings":
		items := make([]admissionv1.MutatingAdmissionPolicyBinding, 0, len(s.mapbs))
		for _, k := range slices.Sorted(maps.Keys(s.mapbs)) {
			v := s.mapbs[k]
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &admissionv1.MutatingAdmissionPolicyBindingList{ListMeta: listMeta, Items: items}
	case "apiextensions.k8s.io/v1/customresourcedefinitions":
		items := make([]apiextensionsv1.CustomResourceDefinition, 0, len(s.crds))
		for _, k := range slices.Sorted(maps.Keys(s.crds)) {
			v := s.crds[k]
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &apiextensionsv1.CustomResourceDefinitionList{ListMeta: listMeta, Items: items}
	case "coordination.k8s.io/v1/leases":
		items := make([]coordinationv1.Lease, 0, len(s.leases))
		for _, k := range slices.Sorted(maps.Keys(s.leases)) {
			v := s.leases[k]
			if kp.Namespace != "" && v.Namespace != kp.Namespace {
				continue
			}
			items = append(items, *v.DeepCopy())
			metas = append(metas, partialMetaFrom(v))
		}
		obj = &coordinationv1.LeaseList{ListMeta: listMeta, Items: items}
	default:
		gvrKey := kp.Group + "/" + kp.Version + "/" + kp.Resource
		if !s.enabledCRDs[gvrKey] {
			s.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, "crd not found: "+gvrKey)
			return
		}
		var items []map[string]any
		for _, k := range slices.Sorted(maps.Keys(s.customObjects[gvrKey])) {
			u := s.customObjects[gvrKey][k]
			if kp.Namespace != "" && u.GetNamespace() != kp.Namespace {
				continue
			}
			if !matchLabelSelector(u.GetLabels(), labelSel) {
				continue
			}
			items = append(items, u.DeepCopy().Object)
			metas = append(metas, partialMetaFrom(u))
		}
		if strings.Contains(r.Header.Get("Accept"), "PartialObjectMetadataList") {
			s.writePartialMetaList(w, rv, metas)
			return
		}
		if items == nil {
			items = []map[string]any{}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"apiVersion": gv.String(),
			"kind":       "List",
			"metadata":   map[string]any{"resourceVersion": rv},
			"items":      items,
		})
		return
	}

	if strings.Contains(r.Header.Get("Accept"), "PartialObjectMetadataList") {
		s.writePartialMetaList(w, rv, metas)
		return
	}
	s.writeObject(w, r, http.StatusOK, gv, obj)
}

func partialMetaFrom(obj metav1.Object) metav1.PartialObjectMetadata {
	return metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"},
		ObjectMeta: metav1.ObjectMeta{
			Name:              obj.GetName(),
			Namespace:         obj.GetNamespace(),
			UID:               obj.GetUID(),
			ResourceVersion:   obj.GetResourceVersion(),
			CreationTimestamp: obj.GetCreationTimestamp(),
			DeletionTimestamp: obj.GetDeletionTimestamp(),
			Labels:            maps.Clone(obj.GetLabels()),
			Annotations:       maps.Clone(obj.GetAnnotations()),
			OwnerReferences:   slices.Clone(obj.GetOwnerReferences()),
			Finalizers:        slices.Clone(obj.GetFinalizers()),
		},
	}
}

func (s *reqE2EAPIServer) writePartialMetaList(w http.ResponseWriter, rv string, items []metav1.PartialObjectMetadata) {
	if items == nil {
		items = []metav1.PartialObjectMetadata{}
	}
	list := metav1.PartialObjectMetadataList{
		TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadataList"},
		ListMeta: metav1.ListMeta{ResourceVersion: rv},
		Items:    items,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(list)
}

func (s *reqE2EAPIServer) handleGet(w http.ResponseWriter, r *http.Request, kp parsedKubePath) {
	gv := schema.GroupVersion{Group: kp.Group, Version: kp.Version}
	key := kp.Name
	if kp.Namespace != "" {
		key = kp.Namespace + "/" + kp.Name
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var obj runtime.Object
	switch gv.String() + "/" + kp.Resource {
	case "v1/nodes":
		if v, ok := s.nodes[kp.Name]; ok {
			obj = v.DeepCopy()
		}
	case "v1/namespaces":
		if v, ok := s.namespaces[kp.Name]; ok {
			obj = v.DeepCopy()
		}
	case "v1/pods":
		if v, ok := s.pods[key]; ok {
			obj = v.DeepCopy()
		}
	case "v1/services":
		if v, ok := s.services[key]; ok {
			obj = v.DeepCopy()
		}
	case "v1/endpoints":
		if v, ok := s.endpoints[key]; ok {
			obj = v.DeepCopy()
		}
	case "v1/configmaps":
		if v, ok := s.configMaps[key]; ok {
			obj = v.DeepCopy()
		}
	case "v1/secrets":
		if v, ok := s.secrets[key]; ok {
			obj = v.DeepCopy()
		}
	case "v1/serviceaccounts":
		if v, ok := s.sas[key]; ok {
			obj = v.DeepCopy()
		}
	case "v1/persistentvolumes":
		if v, ok := s.pvs[kp.Name]; ok {
			obj = v.DeepCopy()
		}
	case "v1/persistentvolumeclaims":
		if v, ok := s.pvcs[key]; ok {
			obj = v.DeepCopy()
		}
	case "apps/v1/deployments":
		if v, ok := s.deployments[key]; ok {
			obj = v.DeepCopy()
		}
	case "apps/v1/replicasets":
		if v, ok := s.replicaSets[key]; ok {
			obj = v.DeepCopy()
		}
	case "apps/v1/statefulsets":
		if v, ok := s.statefulSet[key]; ok {
			obj = v.DeepCopy()
		}
	case "apps/v1/daemonsets":
		if v, ok := s.daemonSets[key]; ok {
			obj = v.DeepCopy()
		}
	case "discovery.k8s.io/v1/endpointslices":
		if v, ok := s.epSlices[key]; ok {
			obj = v.DeepCopy()
		}
	case "policy/v1/poddisruptionbudgets":
		if v, ok := s.pdbs[key]; ok {
			obj = v.DeepCopy()
		}
	case "admissionregistration.k8s.io/v1/mutatingwebhookconfigurations":
		if v, ok := s.mwcs[kp.Name]; ok {
			obj = v.DeepCopy()
		}
	case "admissionregistration.k8s.io/v1/validatingwebhookconfigurations":
		if v, ok := s.vwcs[kp.Name]; ok {
			obj = v.DeepCopy()
		}
	case "admissionregistration.k8s.io/v1/validatingadmissionpolicies":
		if v, ok := s.vaps[kp.Name]; ok {
			obj = v.DeepCopy()
		}
	case "admissionregistration.k8s.io/v1/mutatingadmissionpolicies":
		if v, ok := s.maps[kp.Name]; ok {
			obj = v.DeepCopy()
		}
	default:
		gvrKey := kp.Group + "/" + kp.Version + "/" + kp.Resource
		if !s.enabledCRDs[gvrKey] {
			s.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, "crd not found: "+gvrKey)
			return
		}
		if u, ok := s.customObjects[gvrKey][key]; ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(u.Object)
			return
		}
	}

	if obj == nil {
		s.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, kp.Resource+" "+key+" not found")
		return
	}
	s.writeObject(w, r, http.StatusOK, gv, obj)
}

func (s *reqE2EAPIServer) handlePatch(w http.ResponseWriter, r *http.Request, kp parsedKubePath, patchBytes []byte) {
	gv := schema.GroupVersion{Group: kp.Group, Version: kp.Version}
	key := kp.Name
	if kp.Namespace != "" {
		key = kp.Namespace + "/" + kp.Name
	}
	ct := r.Header.Get("Content-Type")
	if idx := strings.IndexByte(ct, ';'); idx >= 0 {
		ct = strings.TrimSpace(ct[:idx])
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	apply := func(cur runtime.Object) (runtime.Object, error) {
		origBytes, err := json.Marshal(cur)
		if err != nil {
			return nil, err
		}
		var merged []byte
		if ct == string(types.StrategicMergePatchType) {
			merged, err = strategicpatch.StrategicMergePatch(origBytes, patchBytes, cur)
			if err != nil {
				merged, err = mergeJSONBytes(origBytes, patchBytes)
			}
		} else {
			merged, err = mergeJSONBytes(origBytes, patchBytes)
		}
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(merged, cur); err != nil {
			return nil, err
		}
		if m, ok := cur.(metav1.Object); ok {
			m.SetResourceVersion(s.bumpRV())
		}
		return cur, nil
	}

	var updated runtime.Object
	var err error
	switch gv.String() + "/" + kp.Resource {
	case "v1/nodes":
		if v, ok := s.nodes[kp.Name]; ok {
			updated, err = apply(v)
		}
	case "v1/pods":
		if v, ok := s.pods[key]; ok {
			updated, err = apply(v)
		}
	case "v1/persistentvolumeclaims":
		if v, ok := s.pvcs[key]; ok {
			updated, err = apply(v)
		}
	case "v1/endpoints":
		if v, ok := s.endpoints[key]; ok {
			updated, err = apply(v)
		}
	case "apps/v1/deployments":
		if v, ok := s.deployments[key]; ok {
			updated, err = apply(v)
		}
	case "apps/v1/replicasets":
		if v, ok := s.replicaSets[key]; ok {
			updated, err = apply(v)
		}
	case "apps/v1/statefulsets":
		if v, ok := s.statefulSet[key]; ok {
			updated, err = apply(v)
		}
	case "apps/v1/daemonsets":
		if v, ok := s.daemonSets[key]; ok {
			updated, err = apply(v)
		}
	case "discovery.k8s.io/v1/endpointslices":
		if v, ok := s.epSlices[key]; ok {
			updated, err = apply(v)
		}
	case "policy/v1/poddisruptionbudgets":
		if v, ok := s.pdbs[key]; ok {
			updated, err = apply(v)
		}
	case "admissionregistration.k8s.io/v1/mutatingwebhookconfigurations":
		if v, ok := s.mwcs[kp.Name]; ok {
			updated, err = apply(v)
		}
	case "admissionregistration.k8s.io/v1/validatingwebhookconfigurations":
		if v, ok := s.vwcs[kp.Name]; ok {
			updated, err = apply(v)
		}
	case "admissionregistration.k8s.io/v1/validatingadmissionpolicies":
		if v, ok := s.vaps[kp.Name]; ok {
			updated, err = apply(v)
		}
	case "admissionregistration.k8s.io/v1/mutatingadmissionpolicies":
		if v, ok := s.maps[kp.Name]; ok {
			updated, err = apply(v)
		}
	default:
		gvrKey := kp.Group + "/" + kp.Version + "/" + kp.Resource
		if !s.enabledCRDs[gvrKey] {
			s.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, "crd not found: "+gvrKey)
			return
		}
		if u, ok := s.customObjects[gvrKey][key]; ok {
			origBytes, merr := json.Marshal(u.Object)
			if merr != nil {
				s.writeStatus(w, r, http.StatusInternalServerError, metav1.StatusReasonInternalError, merr.Error())
				return
			}
			merged, merr := mergeJSONBytes(origBytes, patchBytes)
			if merr != nil {
				s.writeStatus(w, r, http.StatusBadRequest, metav1.StatusReasonBadRequest, merr.Error())
				return
			}
			var nextMap map[string]any
			if uerr := json.Unmarshal(merged, &nextMap); uerr != nil {
				s.writeStatus(w, r, http.StatusBadRequest, metav1.StatusReasonBadRequest, uerr.Error())
				return
			}
			u.Object = nextMap
			u.SetResourceVersion(s.bumpRV())
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(u.Object)
			return
		}
	}

	if err != nil {
		s.writeStatus(w, r, http.StatusBadRequest, metav1.StatusReasonBadRequest, err.Error())
		return
	}
	if updated == nil {
		s.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, kp.Resource+" "+key+" not found")
		return
	}
	s.writeObject(w, r, http.StatusOK, gv, updated)
}

func mergeJSONBytes(origBytes, patchBytes []byte) ([]byte, error) {
	var origMap, patchMap map[string]any
	if err := json.Unmarshal(origBytes, &origMap); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(patchBytes, &patchMap); err != nil {
		return nil, err
	}
	mergeMap(origMap, patchMap)
	return json.Marshal(origMap)
}

func mergeMap(dst, patch map[string]any) {
	for k, v := range patch {
		if v == nil {
			delete(dst, k)
			continue
		}
		pSub, pOK := v.(map[string]any)
		dSub, dOK := dst[k].(map[string]any)
		if pOK && dOK {
			mergeMap(dSub, pSub)
			continue
		}
		dst[k] = v
	}
}

func (s *reqE2EAPIServer) handleDelete(w http.ResponseWriter, r *http.Request, kp parsedKubePath, body []byte) {
	gv := schema.GroupVersion{Group: kp.Group, Version: kp.Version}
	key := kp.Name
	if kp.Namespace != "" {
		key = kp.Namespace + "/" + kp.Name
	}

	var wantUID string
	if len(body) > 0 {
		var delOpts metav1.DeleteOptions
		if err := s.decodeBytes(r.Header.Get("Content-Type"), body, &delOpts); err == nil && delOpts.Preconditions != nil && delOpts.Preconditions.UID != nil {
			wantUID = string(*delOpts.Preconditions.UID)
		}
	}

	checkUID := func(obj metav1.Object) bool {
		return wantUID == "" || string(obj.GetUID()) == wantUID
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	found := false
	uidOK := true
	switch gv.String() + "/" + kp.Resource {
	case "v1/pods":
		if v, ok := s.pods[key]; ok {
			found = true
			uidOK = checkUID(v)
			if uidOK {
				delete(s.pods, key)
			}
		}
	case "v1/secrets":
		if v, ok := s.secrets[key]; ok {
			found = true
			uidOK = checkUID(v)
			if uidOK {
				delete(s.secrets, key)
			}
		}
	case "apps/v1/replicasets":
		if v, ok := s.replicaSets[key]; ok {
			found = true
			uidOK = checkUID(v)
			if uidOK {
				delete(s.replicaSets, key)
			}
		}
	case "apps/v1/controllerrevisions":
		if v, ok := s.ctrlRevs[key]; ok {
			found = true
			uidOK = checkUID(v)
			if uidOK {
				delete(s.ctrlRevs, key)
			}
		}
	case "batch/v1/jobs":
		if v, ok := s.jobs[key]; ok {
			found = true
			uidOK = checkUID(v)
			if uidOK {
				delete(s.jobs, key)
			}
		}
	case "discovery.k8s.io/v1/endpointslices":
		if v, ok := s.epSlices[key]; ok {
			found = true
			uidOK = checkUID(v)
			if uidOK {
				delete(s.epSlices, key)
			}
		}
	default:
		gvrKey := kp.Group + "/" + kp.Version + "/" + kp.Resource
		if s.enabledCRDs[gvrKey] {
			if u, ok := s.customObjects[gvrKey][key]; ok {
				found = true
				uidOK = checkUID(u)
				if uidOK {
					delete(s.customObjects[gvrKey], key)
				}
			}
		}
	}

	if !found {
		s.writeStatus(w, r, http.StatusNotFound, metav1.StatusReasonNotFound, kp.Resource+" "+key+" not found")
		return
	}
	if !uidOK {
		s.writeStatus(w, r, http.StatusConflict, metav1.StatusReasonConflict, "UID precondition failed")
		return
	}
	st := &metav1.Status{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"},
		Status:   metav1.StatusSuccess,
		Code:     http.StatusOK,
	}
	s.writeObject(w, r, http.StatusOK, corev1.SchemeGroupVersion, st)
}

func matchPodFieldSelector(p *corev1.Pod, raw string) bool {
	if raw == "" {
		return true
	}
	for part := range strings.SplitSeq(raw, ",") {
		if k, v, ok := strings.Cut(part, "="); ok && k == "spec.nodeName" {
			if p.Spec.NodeName != v {
				return false
			}
		}
	}
	return true
}

func matchSecretFieldSelector(sec *corev1.Secret, raw string) bool {
	if raw == "" {
		return true
	}
	for part := range strings.SplitSeq(raw, ",") {
		if k, v, ok := strings.Cut(part, "="); ok && k == "type" {
			if string(sec.Type) != v {
				return false
			}
		}
	}
	return true
}

func matchLabelSelector(labels map[string]string, raw string) bool {
	if raw == "" {
		return true
	}
	const svcKey = "kubernetes.io/service-name"
	if strings.Contains(raw, svcKey+" in (") {
		idx := strings.Index(raw, svcKey+" in (") + len(svcKey+" in (")
		end := strings.IndexByte(raw[idx:], ')')
		if end >= 0 {
			vals := strings.Split(raw[idx:idx+end], ",")
			cur := labels[svcKey]
			for _, v := range vals {
				if strings.TrimSpace(v) == cur {
					return true
				}
			}
			return false
		}
	}
	if raw == svcKey {
		return labels[svcKey] != ""
	}
	if k, v, ok := strings.Cut(raw, "="); ok {
		return labels[k] == v
	}
	return true
}

func hasQueryParam(rawQuery, key, wantVal string) bool {
	vals, err := url.ParseQuery(rawQuery)
	if err != nil {
		return false
	}
	for _, v := range vals[key] {
		if wantVal == "" || v == wantVal {
			return true
		}
	}
	return false
}

func (s *reqE2EAPIServer) decodeBytes(ct string, body []byte, into runtime.Object) error {
	if idx := strings.IndexByte(ct, ';'); idx >= 0 {
		ct = strings.TrimSpace(ct[:idx])
	}
	if ct != "" {
		if info, ok := runtime.SerializerInfoForMediaType(s.codecs.SupportedMediaTypes(), ct); ok {
			if _, _, err := info.Serializer.Decode(body, nil, into); err == nil {
				return nil
			}
		}
	}
	_, _, err := s.codecs.UniversalDeserializer().Decode(body, nil, into)
	return err
}

func (s *reqE2EAPIServer) writeStatus(w http.ResponseWriter, r *http.Request, code int, reason metav1.StatusReason, msg string) {
	status := &metav1.Status{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"},
		Status:   metav1.StatusFailure,
		Reason:   reason,
		Message:  msg,
		Code:     int32(code),
	}
	s.writeObject(w, r, code, corev1.SchemeGroupVersion, status)
}

func (s *reqE2EAPIServer) writeObject(w http.ResponseWriter, r *http.Request, code int, gv schema.GroupVersion, obj runtime.Object) {
	accept := r.Header.Get("Accept")
	supported := s.codecs.SupportedMediaTypes()

	if strings.Contains(accept, "application/vnd.kubernetes.protobuf") {
		if info, ok := runtime.SerializerInfoForMediaType(supported, "application/vnd.kubernetes.protobuf"); ok {
			enc := s.codecs.EncoderForVersion(info.Serializer, gv)
			var buf bytes.Buffer
			if err := enc.Encode(obj, &buf); err == nil {
				w.Header().Set("Content-Type", "application/vnd.kubernetes.protobuf")
				w.WriteHeader(code)
				_, _ = w.Write(buf.Bytes())
				return
			}
		}
	}

	info, ok := runtime.SerializerInfoForMediaType(supported, runtime.ContentTypeJSON)
	if !ok {
		http.Error(w, "json serializer unavailable", http.StatusInternalServerError)
		return
	}
	enc := s.codecs.EncoderForVersion(info.Serializer, gv)
	var buf bytes.Buffer
	if err := enc.Encode(obj, &buf); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", runtime.ContentTypeJSON)
	w.WriteHeader(code)
	_, _ = w.Write(buf.Bytes())
}
