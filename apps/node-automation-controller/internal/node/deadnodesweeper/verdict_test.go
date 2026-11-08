// verdict_test.go — the probe-error classifier behind confirmedDead
// path (b): transport-dead failures are death evidence, apiserver-side
// failures (proxy 5xx, 401/403, unparseable) are inconclusive. The
// real-shape tests pin the classifier against the error values
// rest.DoRaw actually returns, not synthetic ones.
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
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/testutil"
)

// TestProbeErrDeadEvidence walks every error class through the
// classifier: transport-dead shapes fence, apiserver-answered shapes
// never do.
func TestProbeErrDeadEvidence(t *testing.T) {
	// The shape net/http hands back for a failed dial/read: *url.Error
	// around *net.OpError around the syscall error.
	transportErr := func(syserr error) error {
		return &url.Error{
			Op:  "Get",
			URL: "https://apiserver/api/v1/nodes/w1/proxy/healthz",
			Err: &net.OpError{Op: "dial", Net: "tcp", Err: syserr},
		}
	}
	cases := []struct {
		name string
		err  error
		dead bool
	}{
		{"nil is not evidence", nil, false},
		{"bare probe deadline", context.DeadlineExceeded, true},
		{"deadline wrapped in url.Error", transportErr(context.DeadlineExceeded), true},
		{"connection refused", transportErr(os.NewSyscallError("connect", syscall.ECONNREFUSED)), true},
		{"connection reset", transportErr(os.NewSyscallError("read", syscall.ECONNRESET)), true},
		{"host unreachable", transportErr(os.NewSyscallError("connect", syscall.EHOSTUNREACH)), true},
		{"io.EOF — connection torn down", fmt.Errorf("read body: %w", io.EOF), true},
		{"unexpected EOF mid-response", fmt.Errorf("chunked read: %w", io.ErrUnexpectedEOF), true},

		// The apiserver answered with an error — never a death
		// certificate (the kubelet may be alive behind a broken
		// proxy path).
		{"HTTP 500 from the apiserver proxy", apierrors.NewGenericServerResponse(500, "GET",
			schema.GroupResource{Resource: "nodes"}, "w1",
			"error trying to reach service: dial tcp 10.0.0.7:10250: connect: connection refused", 0, true), false},
		{"HTTP 503 service unavailable", apierrors.NewServiceUnavailable("apiserver proxy busy"), false},
		{"forbidden proxy subresource", apierrors.NewForbidden(
			schema.GroupResource{Resource: "nodes"}, "w1", errors.New("proxy denied")), false},
		{"unauthorized", apierrors.NewUnauthorized("bad token"), false},
		{"opaque apiserver error", errors.New("error trying to reach service"), false},
		{"context canceled (shutdown)", context.Canceled, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := probeErrDeadEvidence(tc.err); got != tc.dead {
				t.Fatalf("probeErrDeadEvidence(%v) = %v, want %v", tc.err, got, tc.dead)
			}
		})
	}
}

// The classifier's assumptions are pinned against the REAL error
// shapes client-go's rest.DoRaw returns through a live HTTP stack.
func TestProbeErrDeadEvidenceRealShapes(t *testing.T) {
	t.Run("apiserver 5xx is inconclusive", func(t *testing.T) {
		s := &deadNodeSweeper{cs: testutil.ProbeClientset(t,
			testutil.ProbeHealthzHandler(500, "error trying to reach service: dial tcp 10.0.0.7:10250: connect: connection refused"))}
		_, err := s.probe(ctx, "w1")
		if err == nil {
			t.Fatal("expected DoRaw to surface an error for HTTP 500")
		}
		if probeErrDeadEvidence(err) {
			t.Fatalf("apiserver 500 must stay inconclusive, got dead evidence for: %v", err)
		}
	})

	t.Run("closed kubelet endpoint (ECONNREFUSED) is dead evidence", func(t *testing.T) {
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
		if !probeErrDeadEvidence(err) {
			t.Fatalf("connection refused must be dead evidence, got inconclusive for: %v", err)
		}
	})

	t.Run("response torn down mid-body (EOF) is dead evidence", func(t *testing.T) {
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
		if !probeErrDeadEvidence(err) {
			t.Fatalf("EOF mid-response must be dead evidence, got inconclusive for: %v (%T)", err, err)
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

// Path (b) verdict-level behavior: a transport-dead probe error
// fences the node, an inconclusive one withholds the verdict (and is
// not surfaced as a sweep error).
func TestConfirmedDeadProbeErrorClassification(t *testing.T) {
	suspect := func() (*corev1.Node, *fake.Clientset) {
		n := unknownNode("w1", 45*time.Minute)
		cs := fake.NewSimpleClientset(n, stuckTerminatingPod("db", "pg-0", "w1", 20*time.Minute))
		return n, cs
	}

	t.Run("transport-dead error fences", func(t *testing.T) {
		n, cs := suspect()
		s := deadNodeSweeperFor(cs, deadNodeDynFake(),
			func(context.Context, string) (bool, error) {
				return false, &url.Error{Op: "Get", URL: "https://x",
					Err: &net.OpError{Op: "dial", Net: "tcp",
						Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}}
			})
		dead, viaSNR, reason, err := s.confirmedDead(ctx, n, &remediationCache{},
			map[string]bool{"w1": true})
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

	t.Run("inconclusive error withholds the verdict", func(t *testing.T) {
		n, cs := suspect()
		s := deadNodeSweeperFor(cs, deadNodeDynFake(),
			func(context.Context, string) (bool, error) {
				return false, apierrors.NewServiceUnavailable("proxy path down")
			})
		dead, _, reason, err := s.confirmedDead(ctx, n, &remediationCache{},
			map[string]bool{"w1": true})
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
}
