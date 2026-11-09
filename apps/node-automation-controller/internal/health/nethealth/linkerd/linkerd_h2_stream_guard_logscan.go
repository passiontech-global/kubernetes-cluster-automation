// linkerd_h2_stream_guard_logscan.go — the proxy-log scan of the
// linkerd-h2-stream-guard check: the storm/identity marker tables,
// the single bounded log-tail fetch that matches both families, and
// the Prometheus suspect prefilter that narrows which pods get
// tailed.
package linkerd

import (
	"context"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/health/probefw"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// linkerdH2StormMarkers are the proxy-log signatures of an HTTP/2
// connection whose stream table went pathological — a stalled h2
// stream keeps the pod Ready (readiness probes ride HTTP/1.1) while
// multiplexed traffic wedges behind it.
var linkerdH2StormMarkers = []string{
	"enhance_your_calm",
	"too_many_pings",
	"in-flight requests exceeded concurrency limit",
}

// linkerdIdentityStallMarkers are the proxy-log signatures of an
// mTLS identity whose leaf certificate lapsed or whose issuance
// loop wedged — the proxy keeps running (and the pod stays Ready)
// but every new connection fails certificate validation, so the
// only cure is recreating the pod for a fresh leaf cert. Spellings
// cover both linkerd's Rust Debug rendering ("CertificateExpired",
// "InvalidCertificate(Expired)") and the certifier client errors
// (matched case-insensitively per line, like the storm markers).
var linkerdIdentityStallMarkers = []string{
	"certificateexpired",
	"certificate_expired",
	"invalidcertificate(expired)",
	// linkerd-h2-stream-guard — the not-yet-valid leaf (issued-at skew) and the
	// unknown-issuer (trust-root rotation skew) spellings stall the
	// identity exactly like an expiry: every new connection fails
	// validation while the pod stays Ready.
	"invalidcertificate(notvalidyet)",
	"unknownissuer",
	"failed to certify identity",
}

// linkerdH2LogSignals fetches the linkerd-proxy container's log tail
// once and reports which signature families it carries — the storm
// and identity-stall scans share the single bounded fetch
// (probefw.LogTimeout / probefw.LogMaxBytes, same posture as the
// scylla gossip probe) so a flagged pod costs one apiserver read.
// The match closure only COLLECTS; it returns true early solely
// when both families are already proven, so PodLogTail can stop
// scanning. A fetch failure is inconclusive, not healthy.
func (p *linkerdH2StreamGuardCheck) linkerdH2LogSignals(ctx context.Context,
	pod *corev1.Pod) (storm, identity bool, err error) {

	_, err = probefw.PodLogTail(ctx, p.CS, pod, kube.LinkerdProxyContainer,
		probefw.DefaultTailLines, probefw.LogMaxBytes, probefw.LogTimeout,
		func(line string) bool {
			l := strings.ToLower(line)
			for _, marker := range linkerdH2StormMarkers {
				if strings.Contains(l, marker) {
					storm = true
					break
				}
			}
			for _, marker := range linkerdIdentityStallMarkers {
				if strings.Contains(l, marker) {
					identity = true
					break
				}
			}
			return storm && identity
		})
	return storm, identity, err
}

// logSignals is one pod's proxy-log verdict collected by the phase-2
// worker pool — same triple linkerdH2LogSignals returns, packaged
// for the indexed results slice.
type logSignals struct {
	storm, identity bool
	err             error
}

// linkerdSuspectPods pre-filters the log scan through Prometheus:
// pods whose linkerd-proxy restarted recently or is closing
// connections on errors are the only ones worth a log tail — the
// healthy majority never costs a kubelet round-trip. nil means
// "no conclusive verdict" (no endpoint, every query failed, or the
// metrics pipeline simply has nothing) and the caller falls back
// to the legacy full scan — a prefilter must never hide a wedge
// behind a monitoring gap.
func (p *linkerdH2StreamGuardCheck) linkerdSuspectPods(
	ctx context.Context, log logr.Logger) map[string]bool {

	if _, err := p.PromEndpoint(); err != nil {
		return nil
	}
	queries := []string{
		`sum by (namespace, pod) (increase(kube_pod_container_status_restarts_total{container="linkerd-proxy"}[30m])) > 0`,
		`sum by (namespace, pod) (increase(tcp_close_total{error!=""}[30m])) > 0`,
	}
	suspect := map[string]bool{}
	conclusive := false
	for _, q := range queries {
		series, err := p.PromQuery(ctx, q)
		if err != nil {
			continue
		}
		// A query that ANSWERED is conclusive even with an empty
		// vector — "no restarting proxies, no error closes" is a real
		// result that narrows the log scan to nobody; only a query
		// FAILURE leaves the prefilter inconclusive (nil → legacy
		// full scan). Without this, a healthy mesh pays the full
		// kubelet round-trip per pod forever.
		conclusive = true
		for _, s := range series {
			if s.Value <= 0 {
				continue
			}
			ns, pod := s.Label("namespace"), s.Label("pod", "pod_name")
			if ns == "" || pod == "" {
				continue
			}
			suspect[ns+"/"+pod] = true
		}
	}
	if !conclusive {
		return nil
	}
	log.Info("linkerd-h2-stream-guard: prometheus prefilter narrowed the log scan",
		"suspects", len(suspect))
	return suspect
}
