// seams_probe — the Probe evidence-read group of the Seams test-seam surface, split out of
// seams.go (which keeps the Seams aggregate + applyDefaults
// orchestration).
package wdeps

import (
	"context"
	"errors"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/probee"
)

// Probe holds the evidence-read seams — every call that fetches a
// verdict or body over the network: the HTTP GET variants, the
// unix-socket dial, the :53 DNS datapath probes, the kubelet
// :10250 /metrics scrape and the pod-log tail.
type Probe struct {
	// ProbeHTTP does one GET and returns nil only on a 2xx response
	// (BUG-H7 — a 500/503 means the probed service is wedged, not
	// "the listener is alive"). Seam.
	ProbeHTTP func(ctx context.Context, url string, timeout time.Duration) error
	// ProbeBodyOK does one GET and reports whether the trimmed body is
	// exactly "ok" — the :10248 healthz contract (curl -s body compare
	// parity: a wedged kubelet can still answer HTTP with a non-ok
	// body, so any-HTTP-code-alive is not enough here). Seam.
	ProbeBodyOK func(ctx context.Context, url string, timeout time.Duration) bool
	// ProbeHTTPStatus does one GET and returns the status code — the
	// ProbeHTTP variant for endpoints where the CODE is the verdict
	// (syncloop 500 vs healthz 200, envoy /ready 503) or where ANY
	// answer proves liveness (kubelet :10250 /healthz, api /livez —
	// a 401/403 is an auth denial, not a dead listener). bearer != ""
	// attaches an Authorization header (kubelet :10250 requires
	// auth). Seam.
	ProbeHTTPStatus func(ctx context.Context, url, bearer string, timeout time.Duration) (int, error)
	// ProbeUnixSock connects to a unix socket under a deadline — the
	// containerd-socket hang probe (A4). Seam.
	ProbeUnixSock func(ctx context.Context, socket string, timeout time.Duration) error
	// HTTPGetBody GETs a plain-HTTP endpoint and returns the body —
	// the envoy admin stats page (envoy-xds-lrp xDS NACK guard). Seam.
	HTTPGetBody func(ctx context.Context, url string, timeout time.Duration) ([]byte, error)
	// DNSProbe sends one UDP DNS query for a fixed cluster name to
	// addr and reports whether a well-formed answer returns before
	// the deadline — the node-local-dns :53 datapath probe
	// (envoy-xds-lrp). Seam.
	DNSProbe func(addr, name string, timeout time.Duration) bool
	// PodLogFn returns a tail of one pod's current log — the
	// clock-jump healer's konnectivity evidence read. Default the
	// kube-client GetLogs call; tests stub with canned output.
	PodLogFn func(ctx context.Context, ns, name string, tailLines int64) (string, error)
	// DNSProbeTCP sends one TCP DNS query — the :53 datapath
	// probe's TCP half (a wedged TCP listener still serves UDP,
	// and truncated/large answers ride TCP). Seam.
	DNSProbeTCP func(addr, name string, timeout time.Duration) bool
	// KubeletMetricsFn GETs the kubelet :10250 /metrics body with
	// the SA bearer — the syncloop check's PLEG relist/last-seen
	// series source. Insecure TLS + Authorization header: kubelet
	// cert SANs never cover the loopback and anonymous /metrics is
	// denied. Seam.
	KubeletMetricsFn func(ctx context.Context, url, bearer string, timeout time.Duration) (string, error)
}

func (s *Probe) applyDefaults(c *Config) {
	if s.HTTPGetBody == nil {
		// Plain HTTP (no TLS) — the envoy admin stats page lives on
		// loopback :9901. A non-200 is an error: the reject-delta
		// verdict is unreadable, not "zero".
		s.HTTPGetBody = func(ctx context.Context, url string,
			timeout time.Duration) ([]byte, error) {
			return probee.HTTPBody(ctx, url, timeout)
		}
	}
	if s.DNSProbe == nil {
		s.DNSProbe = probee.DNSQuery
	}
	if s.ProbeHTTP == nil {
		// BUG-H7: an HTTP response no longer counts as alive on its
		// own — a wedged cilium-agent :9879/healthz answering 500/503
		// must read as DOWN. Only a 2xx is a pass; insecure TLS stays
		// (kubelet cert SANs don't cover 127.0.0.1, curl -ks parity).
		// The closures adapt the seam types to the probees' variadic
		// optional *http.Client (default package client, nil injected).
		s.ProbeHTTP = func(ctx context.Context, url string,
			timeout time.Duration) error {
			return probee.HTTPGet(ctx, url, timeout)
		}
	}
	if s.ProbeBodyOK == nil {
		// kubelet :10248 contract (curl -s parity): the healthz port is
		// unauthenticated plaintext and the body must be exactly "ok" —
		// a wedged kubelet can still answer HTTP with a non-ok body.
		s.ProbeBodyOK = func(ctx context.Context, url string,
			timeout time.Duration) bool {
			return probee.BodyOK(ctx, url, timeout)
		}
	}
	if s.ProbeHTTPStatus == nil {
		// Same insecure-TLS transport as ProbeHTTP — the status code
		// is the verdict (syncloop 500, envoy /ready 503).
		s.ProbeHTTPStatus = func(ctx context.Context, url, bearer string,
			timeout time.Duration) (int, error) {
			return probee.HTTPStatus(ctx, url, bearer, timeout)
		}
	}
	if s.ProbeUnixSock == nil {
		// A successful dial IS the verdict — a close error (e.g. the
		// peer reset first) must not downgrade it.
		s.ProbeUnixSock = probee.UnixDial
	}
	if s.DNSProbeTCP == nil {
		s.DNSProbeTCP = probee.DNSQueryTCP
	}
	if s.KubeletMetricsFn == nil {
		s.KubeletMetricsFn = kubeletMetricsGet
	}
	if s.PodLogFn == nil {
		s.PodLogFn = func(ctx context.Context, ns, name string, tail int64) (string, error) {
			if c.Client == nil {
				return "", errors.New("no kube client wired")
			}
			res := c.Client.CoreV1().Pods(ns).GetLogs(name,
				&corev1.PodLogOptions{TailLines: &tail}).Do(ctx)
			b, err := res.Raw()
			return string(b), err
		}
	}
}

// applyDefaults fills the Host group's production implementations —
// same nil → default logic and order the flat pass had.
