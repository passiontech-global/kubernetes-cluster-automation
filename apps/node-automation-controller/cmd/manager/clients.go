// clients.go — the kube client construction main() wires into
// shared.Deps: the fleet-wide rate-limit budget on the shared
// rest.Config, then the direct (uncached, per-request-timeout) and
// probe (own rate limiter) typed+dynamic client pairs the modules
// read and patch through.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"
	"k8s.io/client-go/util/flowcontrol"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// tuneClientConfig installs the fleet-wide client-go budget on cfg.
// client-go defaults (QPS 5 / Burst 10) are sized for one controller —
// ~35 modules share this rest.Config, so every sweep and reconcile
// queue fought for the same 10-token bucket and throttled
// client-side. 50/100 matches the aggregate rate the fleet actually
// issues; both are env-overridable for clusters whose apiserver wants
// a lower ceiling.
//
// ONE token bucket for every client built off this config:
// rest.Config carries the RateLimiter interface by reference through
// NewForConfig/CopyConfig, so installing it here makes the manager's
// client, the typed clientset and the dynamic client draw from the
// same 50/100 bucket. Left nil, each of the three constructors builds
// its own limiter and the fleet's real ceiling silently triples to
// 150 QPS / 300 burst.
//
// ONE transport by construction: tuneClientConfig runs before
// ctrl.NewManager and buildKubeClients, so installing the shared
// base *http.Transport on cfg.Transport here covers every kube
// client this binary builds — the manager's cached clients and
// RESTMapper, the direct typed+dynamic pair and the probe pair. The
// previous posture relied on client-go's tlsTransportCache keying
// identical TLS options to one shared transport; the typed configs
// differ from the dynamic ones in ContentType and the cache's
// weak-pointer/GC behavior (client-go v0.37 made cache entries
// weakly held) made the single-transport guarantee implicit rather
// than structural. Baking the resolved TLS options into one
// *http.Transport and pointing every config at it makes the sharing
// hold by construction: one CA pool, one TLS session cache, one
// HTTP/2 conn pool to the apiserver, regardless of how many configs
// are derived. The TLS fields are cleared off cfg after the bake —
// transport.New rejects a custom Transport combined with TLS client
// options, and the options live in the base's tls.Config anyway.
// Auth is NOT baked in: every constructor still wraps the base with
// its own bearer-token/impersonation round-tripper via
// HTTPWrappersForConfig, so SA-token rotation posture is unchanged.
// File-reload rotation (ReloadCAFiles/ReloadTLSFiles) applies to
// kubeconfig-cert deployments; this controller runs in-cluster with
// an immutable projected CA and no TLS client certs, where those
// reloaders never fire. Mirrors transport/cache.go newTransport
// field-for-field so connection behavior (handshake timeout,
// per-host idle pool, HTTP/2 tuning, proxy + CIDR handling) is
// unchanged.
func tuneClientConfig(cfg *rest.Config) error {
	cfg.QPS = float32(envx.GetenvIntMin("NODE_AUTOMATION_KUBE_CLIENT_QPS", 50, 1))
	cfg.Burst = envx.GetenvIntMin("NODE_AUTOMATION_KUBE_CLIENT_BURST", 100, 1)
	cfg.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(cfg.QPS, cfg.Burst)

	tr, err := sharedBaseTransport(cfg)
	if err != nil {
		return err
	}
	cfg.Transport = tr
	cfg.TLSClientConfig = rest.TLSClientConfig{}
	return nil
}

// sharedBaseTransport builds the base *http.Transport shared by every
// kube client, resolving cfg the same way each client constructor
// would: TLS options through rest.TransportConfig + transport.
// TLSConfigFor (CA pool, client-cert callback, server name), proxy
// from cfg.Proxy when set with http.ProxyFromEnvironment as the
// fallback (utilnet's CIDR-aware variant via SetTransportDefaults),
// and the standard 30s/30s dialer. See tuneClientConfig for why the
// sharing is explicit.
func sharedBaseTransport(cfg *rest.Config) (http.RoundTripper, error) {
	tc, err := cfg.TransportConfig()
	if err != nil {
		return nil, fmt.Errorf("resolve kube transport config: %w", err)
	}
	tlsCfg, err := transport.TLSConfigFor(tc)
	if err != nil {
		return nil, fmt.Errorf("build kube tls config: %w", err)
	}
	var dial func(ctx context.Context, network, address string) (net.Conn, error)
	if tc.DialHolder != nil {
		dial = tc.DialHolder.Dial
	} else {
		dial = (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext
	}
	proxy := http.ProxyFromEnvironment
	if tc.Proxy != nil {
		proxy = tc.Proxy
	}
	return utilnet.SetTransportDefaults(&http.Transport{
		Proxy:               proxy,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     tlsCfg,
		MaxIdleConnsPerHost: 25, // transport/cache.go idleConnsPerHost
		DialContext:         dial,
		DisableCompression:  tc.DisableCompression,
	}), nil
}

// kubeClients bundles the four API clients module Setup receives:
// the shared-bucket direct pair every module reads through, and the
// probe-bucket pair the Module.ProbeClients registry rows swap in.
type kubeClients struct {
	cs       kubernetes.Interface
	dyn      dynamic.Interface
	probeCS  kubernetes.Interface
	probeDyn dynamic.Interface
}

// buildKubeClients constructs the direct and probe client pairs off
// cfg. The direct clients get a per-request Timeout: the serial sweep
// loops issue plain REST calls with no sub-context deadline, so a
// dead TCP/conntrack path would hang a whole module forever without
// one. It is set on a COPY, not the shared cfg — rest.Config.Timeout
// becomes http.Client.Timeout, which would also bound the informer
// WATCH streams the manager opens off cfg and churn every watch into
// a 30s reconnect loop.
//
// The probe pair is the SECOND client set for the latency-sensitive
// probes (apiserver-endpoint-guard, kubelet-liveness-reaper,
// dead-node-sweeper — the Module.ProbeClients registry rows). The
// shared bucket above is sized for the whole fleet, and the janitors
// own its biggest bursts: an evicted-pod/failed-jobs sweep deleting
// hundreds of objects per cycle drains it and leaves a probe waiting
// on client-go's queue-delay exactly while a wedge is in progress —
// the moment its verdict latency matters most. probeCfg is a COPY of
// the direct config with a FRESH RateLimiter (rest.Config carries
// the limiter interface by reference through CopyConfig, so the
// field must be replaced, not left shared) and its own
// env-overridable ceiling. The per-request Timeout inherited from
// directCfg keeps the same hung-call posture; the informer WATCH
// streams stay on the manager's config, untouched.
func buildKubeClients(cfg *rest.Config) (*kubeClients, error) {
	directCfg := rest.CopyConfig(cfg)
	directCfg.Timeout = envx.GetenvDuration(
		"NODE_AUTOMATION_KUBE_CLIENT_TIMEOUT", 30*time.Second)
	// The typed clientsets negotiate protobuf: every sweep's Lists
	// (the fleet's dominant traffic — full Pod/Node/Deployment censuses
	// every few minutes across ~35 modules) decode 5-10x faster and
	// transfer several times less than JSON. Protobuf is only offered,
	// never forced: the apiserver answers 406 for resources with no
	// registered scheme, and kubernetes.Interface covers built-in
	// groups only (verified — no aggregated/metrics clientsets are
	// built off this config), where the scheme always exists. Patches
	// are unaffected: typed Patch calls set their own merge-patch
	// content type regardless of the config. The DYNAMIC clients must
	// NOT inherit this: they read CRDs (helmreleases, cert-manager,
	// externalsecrets, medik8s, cilium), which have no protobuf
	// schemas — negotiation there would 406 every read — so dyn
	// stays on the JSON default. Tests run against the fake
	// clientset, which never negotiates; production wiring is the
	// only observer of this flag.
	directTypedCfg := rest.CopyConfig(directCfg)
	directTypedCfg.ContentType = "application/vnd.kubernetes.protobuf"
	cs, err := kubernetes.NewForConfig(directTypedCfg)
	if err != nil {
		return nil, fmt.Errorf("unable to create clientset: %w", err)
	}
	// Dynamic client for CRD types (helmreleases, cert-manager,
	// externalsecrets, medik8s, cilium) — no typed clients in-tree.
	dyn, err := dynamic.NewForConfig(directCfg)
	if err != nil {
		return nil, fmt.Errorf("unable to create dynamic client: %w", err)
	}

	probeCfg := rest.CopyConfig(directCfg)
	probeCfg.QPS = float32(envx.GetenvIntMin("NODE_AUTOMATION_PROBE_CLIENT_QPS", 20, 1))
	probeCfg.Burst = envx.GetenvIntMin("NODE_AUTOMATION_PROBE_CLIENT_BURST", 40, 1)
	probeCfg.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(
		probeCfg.QPS, probeCfg.Burst)
	probeTypedCfg := rest.CopyConfig(probeCfg)
	probeTypedCfg.ContentType = "application/vnd.kubernetes.protobuf"
	probeCS, err := kubernetes.NewForConfig(probeTypedCfg)
	if err != nil {
		return nil, fmt.Errorf("unable to create probe clientset: %w", err)
	}
	probeDyn, err := dynamic.NewForConfig(probeCfg)
	if err != nil {
		return nil, fmt.Errorf("unable to create probe dynamic client: %w", err)
	}
	return &kubeClients{cs: cs, dyn: dyn, probeCS: probeCS, probeDyn: probeDyn}, nil
}
