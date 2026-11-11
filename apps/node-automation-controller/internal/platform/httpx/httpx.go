// httpx.go — the shared outbound HTTP transport for module probes.
// http.DefaultTransport's MaxIdleConnsPerHost is 2: every checker
// that polls the same host (Prometheus query API, Concourse ATC, a
// webhook backend) churned connections at sweep cadence. One cloned
// transport shared by all module clients keeps 16 idle conns per
// host — http.Transport pools per (scheme, host) anyway, so sharing
// the instance also shares the TLS session cache across modules.
package httpx

import (
	"net/http"
	"sync"
)

// maxIdleConnsPerHost bounds idle keep-alives per upstream host —
// high enough that a sweep's parallel probes reuse connections, low
// enough not to pin sockets on hosts the fleet only touches once.
const maxIdleConnsPerHost = 16

var shared = sync.OnceValue(func() http.RoundTripper {
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		// Defensive: DefaultTransport is *http.Transport by stdlib
		// contract; if that ever changes, fall back to the default
		// rather than panic at init.
		return http.DefaultTransport
	}
	c := t.Clone()
	c.MaxIdleConnsPerHost = maxIdleConnsPerHost
	return c
})

// Transport returns the shared RoundTripper — safe for concurrent
// use by every module http.Client.
func Transport() http.RoundTripper { return shared() }
