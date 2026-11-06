// Package nethealth holds the network control-plane checks riding the
// cluster-health sweep: coredns-upstream, linkerd-endpoint-sync,
// linkerd-protocol-detection-stall, cilium-bpf-map-pressure,
// cilium-node-ipam-exhaustion, cilium-missing-endpoint,
// linkerd-h2-stream-guard, cloudflared-tunnel-health,
// liqo-tunnel-health, konnectivity-tunnel-health and
// gateway-route-health. Each reports on the
// shared kuberhealthy_check series under its own check name.
package nethealth
