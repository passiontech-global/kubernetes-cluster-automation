// Package nethealth holds the network control-plane checks riding the
// cluster-health sweep: coredns-upstream, cilium-bpf-map-pressure,
// cilium-node-ipam-exhaustion, cilium-missing-endpoint,
// cloudflared-tunnel-health, liqo-tunnel-health,
// konnectivity-tunnel-health, gateway-route-health,
// linkerd-outlier-guard, endpointslice-zone-starvation and
// linkerd-sidecar-oom-guard; the three linkerd sweep checks
// (endpoint-sync, protocol-detection-stall, h2-stream-guard) live in
// the leaf linkerd subpackage. Each reports on the
// shared kuberhealthy_check series under its own check name.
package nethealth
