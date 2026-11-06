// dns_probe.go — layer 2 of coredns-stale-watchdog, the active
// freshness query: resolve the probe FQDN directly through each
// coredns pod over BOTH UDP :53 and TCP :53 (nslookup-equivalent)
// and judge the answers against the live endpoint set. A transport
// that fails, answers empty, or serves an off-set IP is the same
// stale-watch signature — CoreDNS can wedge one listener while the
// other still answers, so both must independently pass.
package corednswatchdog

import (
	"context"
	"fmt"
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

// dnsExchange resolves fqdn through one coredns pod over a single
// transport ("udp"/"tcp") — `nslookup <fqdn> <podIP>` forced onto one
// protocol so each listener is judged on its own. Bounded the same as
// the original UDP-only probe: 3s dial plus a 4s whole-lookup budget
// (nslookup's default is ~5s).
func dnsExchange(ctx context.Context, network, podIP, fqdn string) ([]string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, network, net.JoinHostPort(podIP, "53"))
		},
	}
	// Bound the whole lookup (dial timeout alone does not cover the
	// resolver's read/retries).
	pctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	return r.LookupHost(pctx, fqdn)
}

// dnsProbe resolves fqdn directly through one coredns pod over BOTH
// UDP :53 and TCP :53 — equivalent to `nslookup <fqdn> <podIP>` run
// once per transport. The union of both answers is returned so the
// caller's dnsAnswerFresh diff catches an off-set IP no matter which
// listener served it; a transport that errors or answers NODATA is
// itself the failure, so it returns an error rather than a partial
// answer that would read as fresh.
func (w *coreDNSWatchdog) dnsProbe(ctx context.Context, podIP, fqdn string) ([]string, error) {
	lookup := w.dnsExchangeFn
	if lookup == nil {
		lookup = dnsExchange
	}
	merged := map[string]bool{}
	var out []string
	for _, network := range []string{"udp", "tcp"} {
		ips, err := lookup(ctx, network, podIP, fqdn)
		if err != nil {
			return nil, fmt.Errorf("%s :53 lookup failed: %w", network, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("%s :53 returned no A records for %s", network, fqdn)
		}
		for _, ip := range ips {
			if !merged[ip] {
				merged[ip] = true
				out = append(out, ip)
			}
		}
	}
	return out, nil
}
