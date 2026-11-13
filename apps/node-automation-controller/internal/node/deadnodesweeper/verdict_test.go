// verdict_test.go — the probe-error classifier behind confirmedDead
// path (b): kubelet-hop failures (per-request timeout, proxy 5xx with
// unreachable-kubelet markers) are death evidence; controller-side
// transport failures, RBAC/rate-limit errors and markerless proxy 5xx
// are inconclusive — and the canary probe guards the verdict against
// a global konnectivity proxy outage. The real-shape tests pin the
// classifier against the error values rest.DoRaw actually returns,
// not synthetic ones.
package deadnodesweeper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// TestProbeErrDeadEvidence walks every error class through the
// classifier: kubelet-hop failures are death evidence, path-side and
// controller-side failures never are.
func TestProbeErrDeadEvidence(t *testing.T) {
	// The shape net/http hands back for a failed controller→apiserver
	// dial/read: *url.Error around *net.OpError around the syscall
	// error. The kubelet sits BEHIND the apiserver's konnectivity hop
	// and cannot produce any of these.
	transportErr := func(syserr error) error {
		return &url.Error{
			Op:  "Get",
			URL: "https://apiserver/api/v1/nodes/w1/proxy/healthz",
			Err: &net.OpError{Op: "dial", Net: "tcp", Err: syserr},
		}
	}
	proxyErr := func(code int, body string) error {
		return apierrors.NewGenericServerResponse(code, "GET",
			schema.GroupResource{Resource: "nodes"}, "w1", body, 0, true)
	}
	cases := []struct {
		name string
		ctx  context.Context
		err  error
		dead bool
	}{
		{"nil is not evidence", t.Context(), nil, false},

		// Per-request timeout (the probe's own 8s budget): nothing
		// answered the tunnel hop — dead evidence.
		{"bare probe deadline", t.Context(), context.DeadlineExceeded, true},
		{"deadline wrapped in url.Error", t.Context(), transportErr(context.DeadlineExceeded), true},
		// ...but only while the ambient sweep context is alive.
		{"sweep context canceled", canceledCtx(), context.DeadlineExceeded, false},
		{"sweep context canceled, transport-shaped", canceledCtx(), transportErr(syscall.ECONNRESET), false},

		// Controller↔apiserver transport failures — the kubelet
		// cannot cause these; a broken controller path fences nothing.
		{"dial refused to apiserver", t.Context(), transportErr(os.NewSyscallError("connect", syscall.ECONNREFUSED)), false},
		{"connection reset", t.Context(), transportErr(os.NewSyscallError("read", syscall.ECONNRESET)), false},
		{"host unreachable", t.Context(), transportErr(os.NewSyscallError("connect", syscall.EHOSTUNREACH)), false},
		{"io.EOF — connection torn down", t.Context(), fmt.Errorf("read body: %w", io.EOF), false},
		{"unexpected EOF mid-response", t.Context(), fmt.Errorf("chunked read: %w", io.ErrUnexpectedEOF), false},

		// RBAC and rate limit: the apiserver answered — the kubelet
		// question was never delivered.
		{"forbidden proxy subresource", t.Context(), apierrors.NewForbidden(
			schema.GroupResource{Resource: "nodes"}, "w1", errors.New("proxy denied")), false},
		{"unauthorized", t.Context(), apierrors.NewUnauthorized("bad token"), false},
		{"rate limited (429)", t.Context(), apierrors.NewTooManyRequests("slow down", 30), false},

		// Proxy 5xx naming the kubelet hop — the apiserver answered
		// and said the kubelet endpoint did not.
		{"proxy 500 with reach-service marker", t.Context(), proxyErr(500,
			"error trying to reach service: dial tcp 10.0.0.7:10250: connect: connection refused"), true},
		{"proxy 502 with connection refused marker", t.Context(), proxyErr(502,
			"error trying to reach service: dial tcp 10.0.0.7:10250: connect: connection refused"), true},
		{"proxy 503 with no route to host marker", t.Context(), proxyErr(503,
			"error trying to reach service: dial tcp 10.0.0.7:10250: no route to host"), true},
		{"proxy 504 with i/o timeout marker", t.Context(), proxyErr(504,
			"error trying to reach service: dial tcp 10.0.0.7:10250: i/o timeout"), true},
		// ...but a 5xx that does NOT name the kubelet hop is the
		// apiserver's own trouble.
		{"proxy 500 without markers", t.Context(), proxyErr(500,
			"runtime error: index out of range"), false},
		{"proxy 503 busy, no markers", t.Context(), apierrors.NewServiceUnavailable("apiserver proxy busy"), false},
		{"plain error with marker but no status", t.Context(), errors.New("error trying to reach service"), false},

		{"opaque apiserver error", t.Context(), errors.New("malformed response"), false},
		{"context canceled (shutdown)", canceledCtx(), context.Canceled, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := probeErrDeadEvidence(tc.ctx, tc.err); got != tc.dead {
				t.Fatalf("probeErrDeadEvidence(%v) = %v, want %v", tc.err, got, tc.dead)
			}
		})
	}
}

// canceledCtx is a dead sweep context for the shutdown-classification
// cases.
func canceledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// The classifier's assumptions are pinned against the REAL error
// shapes client-go's rest.DoRaw returns through a live HTTP stack.
func TestProbeErrDeadEvidenceRealShapes(t *testing.T) {
	t.Run("proxy 5xx naming the kubelet hop is dead evidence", func(t *testing.T) {
		// The real shape for a dead kubelet: the apiserver's node
		// proxy answers 500 with "error trying to reach service: ...
		// connection refused". This is the case the old classifier
		// got backwards — it read as inconclusive while controller-
		// side dial failures read as death certificates.
		s := &deadNodeSweeper{cs: testutil.ProbeClientset(t,
			testutil.ProbeHealthzHandler(500, "error trying to reach service: dial tcp 10.0.0.7:10250: connect: connection refused"))}
		_, err := s.probe(ctx, "w1")
		if err == nil {
			t.Fatal("expected DoRaw to surface an error for HTTP 500")
		}
		if !probeErrDeadEvidence(ctx, err) {
			t.Fatalf("proxy 500 with unreachable-kubelet markers must be dead evidence, got inconclusive for: %v (%T)", err, err)
		}
	})

	t.Run("proxy 503 carrying the marker only in the cause text is dead evidence", func(t *testing.T) {
		// A raw 503 body is NOT copied into the Status message by
		// client-go ("the server is currently unable to handle the
		// request") — the body lands in the UnexpectedServerResponse
		// cause. The marker search must cover both.
		s := &deadNodeSweeper{cs: testutil.ProbeClientset(t,
			testutil.ProbeHealthzHandler(503, "error trying to reach service: dial tcp 10.0.0.7:10250: connect: connection refused"))}
		_, err := s.probe(ctx, "w1")
		if err == nil {
			t.Fatal("expected DoRaw to surface an error for HTTP 503")
		}
		if !probeErrDeadEvidence(ctx, err) {
			t.Fatalf("proxy 503 with unreachable-kubelet markers must be dead evidence, got inconclusive for: %v (%T)", err, err)
		}
	})

	t.Run("markerless proxy 5xx stays inconclusive", func(t *testing.T) {
		s := &deadNodeSweeper{cs: testutil.ProbeClientset(t,
			testutil.ProbeHealthzHandler(500, "internal server oops"))}
		_, err := s.probe(ctx, "w1")
		if err == nil {
			t.Fatal("expected DoRaw to surface an error for HTTP 500")
		}
		if probeErrDeadEvidence(ctx, err) {
			t.Fatalf("markerless proxy 500 must stay inconclusive, got dead evidence for: %v", err)
		}
	})

	t.Run("per-request timeout is dead evidence while the sweep context lives", func(t *testing.T) {
		// The kubeletHealthzTimeout shape: nothing answered inside the
		// request's own budget, the sweep context still alive.
		probeCtx, probeCtxCancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
		defer probeCtxCancel()
		_, err := kube.KubeletHealthz(probeCtx, testutil.ProbeClientset(t,
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-r.Context().Done():
				case <-time.After(5 * time.Second):
				}
			})), "w1")
		if err == nil {
			t.Fatal("expected DoRaw to surface a timeout error")
		}
		if probeCtx.Err() == nil {
			t.Fatal("test setup: expected the probe context deadline to fire")
		}
		// The sweep-level shape is "DeadlineExceeded with the AMBIENT
		// context alive" — here the deadline belongs to the request,
		// so the classifier must see a live ambient ctx as alive.
		if !probeErrDeadEvidence(t.Context(), err) {
			t.Fatalf("per-request deadline must be dead evidence, got inconclusive for: %v (%T)", err, err)
		}
		// The same deadline with the sweep ctx ALSO done is shutdown
		// noise, not kubelet evidence.
		if probeErrDeadEvidence(probeCtx, err) {
			t.Fatalf("deadline with a done sweep context must be inconclusive, got dead evidence for: %v", err)
		}
	})

	t.Run("closed kubelet endpoint (ECONNREFUSED) is a controller-side transport failure", func(t *testing.T) {
		// A dial failure reaches the classifier only when the
		// CONTROLLER could not reach its apiserver — the kubelet is
		// behind the proxy hop and cannot produce it. Inconclusive.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		host := srv.URL
		srv.Close() // port closed — the dial now genuinely refuses
		cs, err := kubernetes.NewForConfig(&rest.Config{Host: host})
		if err != nil {
			t.Fatalf("NewForConfig: %v", err)
		}
		s := &deadNodeSweeper{cs: cs}
		_, err = s.probe(ctx, "w1")
		if err == nil {
			t.Fatal("expected DoRaw to surface a dial error against a closed endpoint")
		}
		if probeErrDeadEvidence(ctx, err) {
			t.Fatalf("controller-side dial failure must be inconclusive, got dead evidence for: %v", err)
		}
	})

	t.Run("response torn down mid-body (EOF) is inconclusive", func(t *testing.T) {
		s := &deadNodeSweeper{cs: testutil.ProbeClientset(t,
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !probeHealthzPath(r) {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Length", "4096")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok")) // far short of the declared length
			}))}
		_, err := s.probe(ctx, "w1")
		if err == nil {
			t.Fatal("expected DoRaw to surface a truncated-body error")
		}
		if probeErrDeadEvidence(ctx, err) {
			t.Fatalf("EOF mid-response must be inconclusive, got dead evidence for: %v (%T)", err, err)
		}
	})
}

// probeHealthzPath mirrors the path check ProbeHealthzHandler does,
// for the one handler this file needs to customize.
func probeHealthzPath(r *http.Request) bool {
	p := r.URL.Path
	const suffix = "/proxy/healthz"
	return len(p) > len("/api/v1/nodes/") &&
		len(p) > len(suffix) &&
		p[:len("/api/v1/nodes/")] == "/api/v1/nodes/" &&
		p[len(p)-len(suffix):] == suffix
}

// Path (b) verdict-level behavior: a probe error only fences when the
// classifier calls it kubelet-hop evidence AND the canary certifies
// the proxy path; anything else withholds the verdict (and is not
// surfaced as a sweep error).
func TestConfirmedDeadProbeErrorClassification(t *testing.T) {
	suspect := func() (*corev1.Node, *fake.Clientset) {
		n := unknownNode("w1", 45*time.Minute)
		cs := fake.NewSimpleClientset(n, stuckTerminatingPod("db", "pg-0", "w1", 20*time.Minute))
		return n, cs
	}
	// deadEvidence is the classifier's real dead-evidence shape: a
	// per-request timeout with nothing answering.
	deadEvidence := func() error { return context.DeadlineExceeded }
	// proxy500Marker is the apiserver-proxy shape for an unreachable
	// kubelet endpoint.
	proxy500Marker := func() error {
		return apierrors.NewGenericServerResponse(500, "GET",
			schema.GroupResource{Resource: "nodes"}, "w1",
			"error trying to reach service: dial tcp 10.0.0.7:10250: connect: connection refused", 0, true)
	}

	t.Run("dead-evidence error with healthy canary fences", func(t *testing.T) {
		n, cs := suspect()
		s := deadNodeSweeperFor(cs, deadNodeDynFake(),
			func(_ context.Context, node string) (bool, error) {
				if node == "canary" {
					return true, nil // the proxy path still answers for a Ready node
				}
				return false, deadEvidence()
			})
		dead, viaSNR, reason, err := s.confirmedDead(ctx, n, &remediationCache{},
			map[string]bool{"w1": true}, "canary")
		if err != nil {
			t.Fatalf("dead evidence must not surface as an error: %v", err)
		}
		if !dead || viaSNR {
			t.Fatalf("dead=%v viaSNR=%v, want dead=true viaSNR=false", dead, viaSNR)
		}
		if reason == "" {
			t.Fatal("dead verdict must carry a reason")
		}
	})

	t.Run("proxy 500 with kubelet marker and healthy canary fences", func(t *testing.T) {
		// The reclassified shape: the apiserver answered and named
		// the kubelet hop — a real death certificate the old
		// classifier withheld.
		n, cs := suspect()
		s := deadNodeSweeperFor(cs, deadNodeDynFake(),
			func(_ context.Context, node string) (bool, error) {
				if node == "canary" {
					return true, nil
				}
				return false, proxy500Marker()
			})
		dead, _, reason, err := s.confirmedDead(ctx, n, &remediationCache{},
			map[string]bool{"w1": true}, "canary")
		if err != nil {
			t.Fatalf("dead evidence must not surface as an error: %v", err)
		}
		if !dead || reason == "" {
			t.Fatalf("dead=%v reason=%q, want a fenced verdict", dead, reason)
		}
	})

	t.Run("canary failing the same way withholds the verdict", func(t *testing.T) {
		// A global konnectivity proxy outage fails EVERY node the
		// same way — the canary must veto the fence.
		n, cs := suspect()
		s := deadNodeSweeperFor(cs, deadNodeDynFake(),
			func(context.Context, string) (bool, error) {
				return false, deadEvidence()
			})
		dead, _, reason, err := s.confirmedDead(ctx, n, &remediationCache{},
			map[string]bool{"w1": true}, "canary")
		if err != nil {
			t.Fatalf("inconclusive verdict must not fail the sweep: %v", err)
		}
		if dead {
			t.Fatal("canary failing the same way must not fence the node")
		}
		if reason != "" {
			t.Fatalf("dead=false must leave reason empty, got %q", reason)
		}
	})

	t.Run("no Ready canary withholds the verdict", func(t *testing.T) {
		// Every node Unknown — the global-outage wave shape: nothing
		// can certify the path, so nothing fences on transport
		// evidence alone.
		n, cs := suspect()
		s := deadNodeSweeperFor(cs, deadNodeDynFake(),
			func(context.Context, string) (bool, error) {
				return false, deadEvidence()
			})
		dead, _, _, err := s.confirmedDead(ctx, n, &remediationCache{},
			map[string]bool{"w1": true}, "")
		if err != nil {
			t.Fatalf("inconclusive verdict must not fail the sweep: %v", err)
		}
		if dead {
			t.Fatal("missing canary must not fence the node")
		}
	})

	t.Run("inconclusive error stays inconclusive even with a healthy canary", func(t *testing.T) {
		n, cs := suspect()
		s := deadNodeSweeperFor(cs, deadNodeDynFake(),
			func(_ context.Context, node string) (bool, error) {
				if node == "canary" {
					return true, nil
				}
				return false, apierrors.NewServiceUnavailable("proxy path down")
			})
		dead, _, reason, err := s.confirmedDead(ctx, n, &remediationCache{},
			map[string]bool{"w1": true}, "canary")
		if err != nil {
			t.Fatalf("inconclusive verdict must not fail the sweep: %v", err)
		}
		if dead {
			t.Fatal("inconclusive probe error must not fence the node")
		}
		if reason != "" {
			t.Fatalf("dead=false must leave reason empty, got %q", reason)
		}
	})

	t.Run("RBAC error never fences", func(t *testing.T) {
		n, cs := suspect()
		s := deadNodeSweeperFor(cs, deadNodeDynFake(),
			func(context.Context, string) (bool, error) {
				return false, apierrors.NewForbidden(
					schema.GroupResource{Resource: "nodes"}, "w1", errors.New("proxy denied"))
			})
		dead, _, _, err := s.confirmedDead(ctx, n, &remediationCache{},
			map[string]bool{"w1": true}, "canary")
		if err != nil {
			t.Fatalf("inconclusive verdict must not fail the sweep: %v", err)
		}
		if dead {
			t.Fatal("RBAC error must not fence the node")
		}
	})
}

// ---------------------------------------------------------------------------
// healthyCanaryName — the sweep's Ready-node pick.
// ---------------------------------------------------------------------------

// The canary is the FIRST Ready=True node in census order; a census
// with no Ready node yields "" — the global-outage shape the canary
// check must veto on.
func TestHealthyCanaryName(t *testing.T) {
	notReady := func(name string) corev1.Node {
		return *testutil.Node(name, corev1.ConditionFalse, nil)
	}
	ready := func(name string) corev1.Node {
		return *testutil.Node(name, corev1.ConditionTrue, nil)
	}

	t.Run("first Ready node in census order", func(t *testing.T) {
		nodes := []corev1.Node{notReady("n0"), ready("n1"), ready("n2")}
		if got := healthyCanaryName(nodes); got != "n1" {
			t.Fatalf("healthyCanaryName = %q, want n1 (first Ready in order)", got)
		}
	})

	t.Run("Ready only later in the census still picked", func(t *testing.T) {
		nodes := []corev1.Node{notReady("n0"), notReady("n1"), ready("n2")}
		if got := healthyCanaryName(nodes); got != "n2" {
			t.Fatalf("healthyCanaryName = %q, want n2", got)
		}
	})

	t.Run("no Ready node yields the empty canary", func(t *testing.T) {
		nodes := []corev1.Node{notReady("n0"), notReady("n1"),
			*testutil.Node("n2", corev1.ConditionUnknown, nil)}
		if got := healthyCanaryName(nodes); got != "" {
			t.Fatalf("healthyCanaryName = %q, want empty (nothing certifies the path)", got)
		}
	})
}

// ---------------------------------------------------------------------------
// remediationItems — the nil-dynamic-client wiring guard.
// ---------------------------------------------------------------------------

// A nil dynamic client is a wiring bug, not "no fencing evidence":
// remediationItems must fail closed with a distinct error (and must
// not cache the failure as fetched), unlike the missing-CRD skip.
func TestRemediationItemsNilDynFailsClosed(t *testing.T) {
	cs := fake.NewSimpleClientset(
		testutil.Node("w1", corev1.ConditionUnknown, nil))
	s := &deadNodeSweeper{cs: cs, probeFn: healthyProbe} // dyn deliberately nil

	rem := &remediationCache{}
	items, err := s.remediationItems(ctx, rem)
	if err == nil {
		t.Fatal("nil dynamic client must fail closed with an error")
	}
	if items != nil {
		t.Fatalf("nil dynamic client returned items %v, want none", items)
	}
	if !strings.Contains(err.Error(), "no dynamic client") {
		t.Fatalf("error %q is not the distinct nil-dyn wiring error", err)
	}
	if rem.fetched {
		t.Fatal("wiring error must not latch the cache as fetched")
	}
}
