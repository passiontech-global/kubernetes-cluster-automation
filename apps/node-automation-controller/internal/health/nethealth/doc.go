// Package nethealth holds the network control-plane checks riding the
// cluster-health sweep: coredns-upstream, linkerd-endpoint-sync,
// linkerd-protocol-detection-stall, cilium-bpf-map-pressure and
// cilium-node-ipam-exhaustion. Each reports on the shared
// kuberhealthy_check series under its own check name.
package nethealth
