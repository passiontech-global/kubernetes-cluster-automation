// sidecar_shutdown.go — the graceful exit path: POST the sidecar's
// admin quit endpoint directly over pod-IP first, then — when the
// direct dial fails or times out (e.g. a Cilium default-deny ingress
// policy blocking pod-IP traffic from node-ops) or the pod has no
// IP at all — through the apiserver pods/<name>:<port>/proxy
// subresource, which reaches the sidecar through kubelet and is
// immune to pod netpol (sidecar-shutdown-fallback). A sidecar that honors the call
// exits cleanly and kubelet transitions the pod itself.
package zombiesidecarreaper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	hosthttpx "github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/httpx"
)

const (
	// zombieSidecarShutdownTimeout bounds the admin call — a
	// wedged proxy must not stall the sweep. sidecar-shutdown-fallback: 2s per the
	// plan; shared by the direct HTTP POST and the apiserver pod
	// proxy fallback.
	zombieSidecarShutdownTimeout = 2 * time.Second
)

// zombieSidecarShutdownTargets maps each supported sidecar to its
// admin quit endpoint — linkerd's admin serves POST /shutdown on
// :4191, istio's pilot-agent serves POST /quitquitquit on :15000.
var zombieSidecarShutdownTargets = map[string]struct {
	port int
	path string
}{
	kube.LinkerdProxyContainer: {port: 4191, path: "/shutdown"},
	"istio-proxy":              {port: 15000, path: "/quitquitquit"},
}

// zombieSidecarHTTPClient is the module's single http.Client — the
// 2s timeout lives here so a wedged sidecar cannot hold the sweep.
var zombieSidecarHTTPClient = &http.Client{Timeout: zombieSidecarShutdownTimeout, Transport: hosthttpx.PooledTransport(16, nil)}

// shutdownPod runs the graceful sidecar shutdown: the direct
// pod-IP admin call first, then — when the dial fails or times out
// (e.g. Cilium default-deny ingress from node-ops, sidecar-shutdown-fallback) or the
// pod carries no IP — the apiserver pods/<name>:<port>/proxy
// subresource, which reaches the sidecar through kubelet regardless
// of pod-ingress NetworkPolicy.
func (r *zombieSidecarReaper) shutdownPod(ctx context.Context, p *corev1.Pod, sidecar string) error {
	var directErr error
	if p.Status.PodIP != "" {
		if err := r.shutdownFn(ctx, p.Status.PodIP, sidecar); err == nil {
			return nil
		} else {
			directErr = err
		}
	}
	if r.proxyFn == nil {
		r.proxyFn = r.proxyShutdown
	}
	if err := r.proxyFn(ctx, p, sidecar); err != nil {
		if directErr != nil {
			return fmt.Errorf("direct shutdown: %v; proxy shutdown: %w",
				directErr, err)
		}
		return fmt.Errorf("proxy shutdown: %w", err)
	}
	return nil
}

// proxyShutdown POSTs the sidecar admin endpoint through the
// apiserver pods proxy subresource —
// POST /api/v1/namespaces/<ns>/pods/<name>:<port>/proxy/<path> —
// the same request shape kubectl's pod proxy uses. The apiserver
// dials the pod via kubelet, so pod-ingress NetworkPolicy cannot
// blackhole it the way it blackholes the direct pod-IP call.
func (r *zombieSidecarReaper) proxyShutdown(ctx context.Context, p *corev1.Pod, sidecar string) error {
	target, ok := zombieSidecarShutdownTargets[sidecar]
	if !ok {
		target = zombieSidecarShutdownTargets[kube.LinkerdProxyContainer]
	}
	rc := r.cs.CoreV1().RESTClient()
	// The fake clientset returns a typed-nil *rest.RESTClient —
	// guard before dereferencing so unit tests degrade to "proxy
	// unreachable" instead of panicking.
	if rc == nil {
		return errors.New("pods/proxy REST client unavailable")
	}
	if restClient, ok := rc.(*rest.RESTClient); ok && restClient == nil {
		return errors.New("pods/proxy REST client unavailable")
	}
	return rc.Post().
		Namespace(p.Namespace).
		Resource("pods").
		Name(p.Name + ":" + strconv.Itoa(target.port)).
		SubResource("proxy").
		Suffix(strings.TrimPrefix(target.path, "/")).
		Timeout(zombieSidecarShutdownTimeout).
		Do(ctx).Error()
}

// zombieSidecarShutdown POSTs the sidecar's admin quit endpoint — the
// graceful exit path the proxy honors even when its pod's app
// containers are gone (linkerd :4191/shutdown, istio
// :15000/quitquitquit). An unknown sidecar name falls back to the
// linkerd endpoint: zombieSidecarNames only admits the two known
// names, so the fallback is unreachable in practice.
func zombieSidecarShutdown(ctx context.Context, podIP, sidecar string) error {
	target, ok := zombieSidecarShutdownTargets[sidecar]
	if !ok {
		target = zombieSidecarShutdownTargets[kube.LinkerdProxyContainer]
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		// JoinHostPort brackets IPv6 podIPs — plain %s:%d breaks on them.
		"http://"+net.JoinHostPort(podIP,
			strconv.Itoa(target.port))+target.path, nil)
	if err != nil {
		return err
	}
	resp, err := zombieSidecarHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		// Drain before Close so the keep-alive connection can be
		// reused; bounded so a chatty endpoint cannot stall the
		// sweep.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("sidecar %s returned %s", target.path, resp.Status)
	}
	return nil
}
