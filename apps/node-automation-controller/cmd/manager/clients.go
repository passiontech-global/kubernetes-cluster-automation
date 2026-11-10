// clients.go — the kube client construction main() wires into
// shared.Deps: the fleet-wide rate-limit budget on the shared
// rest.Config, then the direct (uncached, per-request-timeout) and
// probe (own rate limiter) typed+dynamic client pairs the modules
// read and patch through.
package main

import (
	"fmt"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
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
func tuneClientConfig(cfg *rest.Config) {
	cfg.QPS = float32(envx.GetenvIntMin("NODE_AUTOMATION_KUBE_CLIENT_QPS", 50, 1))
	cfg.Burst = envx.GetenvIntMin("NODE_AUTOMATION_KUBE_CLIENT_BURST", 100, 1)
	cfg.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(cfg.QPS, cfg.Burst)
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
