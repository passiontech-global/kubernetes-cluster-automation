// Package probee is the shared probe seam: the small one-shot
// liveness helpers every subsystem's test-seam funcs default to.
//
// Each helper exists because the same probe was previously
// re-implemented per subsystem and the copies drifted — workerhygiene
// alone carried seven variants (probeHTTP, probeBodyOK,
// probeHTTPStatus, probeUnixSock, httpGetBody, unixGet, dnsProbe),
// controllerhygiene carried probeAnyCode / probeHTTP2xx /
// httpGetInsecure sharing one package client, and nethealth carried
// probeHTTPGet on http.DefaultClient. The drift was real: the
// "any HTTP answer = alive" contract silently became "2xx only" in
// some spots (BUG-H7), one body fetch skipped TLS verify while
// another skipped the status check, and the DNS wire format was
// hand-rolled per call site.
//
// Semantics are copied verbatim from the originals so the per-
// subsystem seam defaults swap in with zero behavioral delta:
//
//	HTTP2xx / HTTPAnyCode  — insecure-TLS GET, drain 64KiB, bool
//	                         verdict (KCM/scheduler healthz, the
//	                         any-code-alive apiserver probe).
//	HTTPGet                — insecure-TLS GET, nil on 2xx only
//	                         (BUG-H7: a 500 is a wedge, not alive).
//	HTTPStatus             — insecure-TLS GET returning the status
//	                         code, optional bearer token.
//	HTTPBody               — plain-TLS GET, status==200 required,
//	                         4MiB body cap (envoy admin stats).
//	HTTPBodyInsecure       — insecure-TLS GET, NO status check —
//	                         the KCM /metrics scrape keeps the body
//	                         even on a 500 (unreachable is the only
//	                         error).
//	BodyOK                 — plain GET, trimmed body must be exactly
//	                         "ok" (kubelet :10248 contract) — the
//	                         status code is deliberately not checked.
//	UnixGet                — GET over a unix socket, per-call
//	                         transport with keep-alives off.
//	UnixDial               — connect+close proves the socket accepts
//	                         (containerd-socket hang probe).
//	DNSQuery               — one hand-rolled UDP A-record query; any
//	                         well-formed reply (even NXDOMAIN) proves
//	                         the listener answers.
//
// The two package-level http.Clients mirror controllerhygiene's
// probeClient and workerhygiene's seam closures — DefaultTransport
// clones with a 90s IdleConnTimeout so an idle conn survives the
// 60s check cycle instead of being re-dialed (and re-TLS'd) every
// probe. UnixGet is the deliberate exception: its transport is
// per-call with DisableKeepAlives, because a kept-alive unix conn
// pins the transport read/write goroutines.
package probee

import (
	"crypto/tls"
	"net/http"
	"time"
)

// insecureClient backs the kubelet/apiserver/KCM probes — every
// original carried `curl -ks` parity because kubelet and the KCM /
// scheduler endpoints serve certs whose SANs never cover the
// loopback/IP addresses the agent dials.
var insecureClient = func() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // mirrors curl -ks
	tr.IdleConnTimeout = 90 * time.Second
	return &http.Client{Transport: tr}
}()

// plainClient backs the unauthenticated-plaintext probes (kubelet
// :10248 healthz, envoy admin :9901) — a verifying TLS transport,
// matching the originals which set no TLSClientConfig at all.
var plainClient = func() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.IdleConnTimeout = 90 * time.Second
	return &http.Client{Transport: tr}
}()
