// Package system groups the modules keeping k0s/stack-owned system
// components at their pinned desired state and watching them for
// known failure modes: konnectivity-agent resources
// (konnectivity_patcher), CoreDNS topology/replica pinning
// (coredns_patcher) and stale-watch detection (coredns_watchdog),
// metrics-server pinning (metrics_server_patcher), the Cloudflare
// tunnel proxy watchdog (cftunnel_proxy_watchdog) and the fluent-bit
// config-drift roller (fluentbit_roller).
package system
