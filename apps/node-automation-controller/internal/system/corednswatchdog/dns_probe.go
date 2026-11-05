// dns_probe.go — layer 2 of coredns-stale-watchdog, the active
// freshness query: resolve the probe FQDN directly through each
// coredns pod (UDP :53, nslookup-equivalent) and judge the answer
// against the live endpoint set.
package corednswatchdog

import (
	"context"
	"net"
	"time"
)

// dnsAnswerFresh reports whether a coredns pod's answer proves its
// watch is alive: at least one A record, and — when the caller knows
// the expected answer set — every returned IP inside it. A stale
// replica either resolves NODATA (no records) or answers with IPs the
// EndpointSlice no longer carries.
func dnsAnswerFresh(ips []string, want map[string]bool) bool {
	if len(ips) == 0 {
		return false
	}
	if want == nil {
		return true
	}
	for _, ip := range ips {
		if !want[ip] {
			return false
		}
	}
	return true
}

// dnsProbe resolves fqdn directly through one coredns pod (UDP :53),
// equivalent to `nslookup <fqdn> <podIP>` — returning the A-record
// addresses it answered so the caller can diff them against the live
// endpoint set.
func (w *coreDNSWatchdog) dnsProbe(ctx context.Context, podIP, fqdn string) ([]string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", net.JoinHostPort(podIP, "53"))
		},
	}
	// Bound the whole lookup (dial timeout alone does not cover the
	// resolver's read/retries) — nslookup's default is ~5s.
	pctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	return r.LookupHost(pctx, fqdn)
}
