// probe.go — seams for the HTTP/REST-backed probes the fake clientset
// cannot serve: raw :6443 list calls against a stub RoundTripper (no
// bytes leave the process), node/proxy/healthz through a REAL
// clientset pointed at httptest, and get/pods/log reactors.
package testutil

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ktesting "k8s.io/client-go/testing"
)

// StubTransport answers HTTP requests in-process: probes build real
// *http.Request objects (URL assertions included) but nothing dials.
type StubTransport struct {
	Fn func(*http.Request) (*http.Response, error)
}

func (s *StubTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return s.Fn(r)
}

// ProbeResponse is the minimal *http.Response the probe code reads.
func ProbeResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{},
	}
}

// ProbeRVJSON is the list-envelope shape the list-resourceVersion
// probe decodes.
func ProbeRVJSON(rv int64) string {
	return fmt.Sprintf(
		`{"apiVersion":"v1","kind":"List","metadata":{"resourceVersion":"%d"},"items":[]}`, rv)
}

// ProbeRVSplit returns a StubTransport where resourceVersion=0 is
// served from the apiserver's watch cache and any other list is a
// quorum read — the gap between the two RVs is the wedge signal.
func ProbeRVSplit(cacheRV, liveRV int64) *StubTransport {
	return &StubTransport{Fn: func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("resourceVersion") == "0" {
			return ProbeResponse(200, ProbeRVJSON(cacheRV)), nil
		}
		return ProbeResponse(200, ProbeRVJSON(liveRV)), nil
	}}
}

// TrackingBody records how much of the response body was consumed
// before Close — the keep-alive contract probes must keep.
type TrackingBody struct {
	R      io.Reader
	N      int
	Closed bool
}

func (t *TrackingBody) Read(p []byte) (int, error) {
	n, err := t.R.Read(p)
	t.N += n
	return n, err
}

func (t *TrackingBody) Close() error {
	t.Closed = true
	return nil
}

// ErrReadCloser fails every Read — a body that dies mid-stream.
type ErrReadCloser struct{}

func (ErrReadCloser) Read([]byte) (int, error) { return 0, errors.New("connection reset") }
func (ErrReadCloser) Close() error             { return nil }

// ProbeClientset points a real clientset at an httptest apiserver —
// needed for REST paths (e.g. nodes/proxy/healthz) the fake
// clientset's nil RESTClient cannot serve.
func ProbeClientset(t *testing.T, h http.HandlerFunc) *kubernetes.Clientset {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	cs, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatalf("NewForConfig: %v", err)
	}
	return cs
}

// ProbeHealthzHandler serves the kubelet healthz path the node probes
// hit through the apiserver proxy.
func ProbeHealthzHandler(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/nodes/w1/proxy/healthz" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, body)
	}
}

// ProbeLogReactor answers get/pods subresource=log; anything else
// falls through to the tracker.
func ProbeLogReactor(body string, err error) ktesting.ReactionFunc {
	return func(a ktesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() != "log" {
			return false, nil, nil
		}
		if err != nil {
			return true, nil, err
		}
		return true, &runtime.Unknown{Raw: []byte(body)}, nil
	}
}
