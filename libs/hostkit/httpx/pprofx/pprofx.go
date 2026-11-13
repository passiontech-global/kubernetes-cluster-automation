// Package pprofx wires the standard net/http/pprof handlers onto a
// caller-owned ServeMux. It is a separate package on purpose:
// importing net/http/pprof runs its init(), which registers
// /debug/pprof/* on http.DefaultServeMux — keeping that import
// behind an explicit pprofx dependency means binaries that only want
// httpx.New / httpx.PooledTransport never grow a DefaultServeMux
// pprof surface they did not ask for.
package pprofx

import (
	"net/http"
	"net/http/pprof"
)

// Handlers returns the standard net/http/pprof handlers keyed by the
// path each must be mounted at, so callers can attach them to their
// own mux (or httpx-injected handler) without importing
// net/http/pprof themselves. The returned map is a fresh copy per
// call; mutating it does not affect Register or other callers.
func Handlers() map[string]http.Handler {
	return map[string]http.Handler{
		"/debug/pprof/":        http.HandlerFunc(pprof.Index),
		"/debug/pprof/cmdline": http.HandlerFunc(pprof.Cmdline),
		"/debug/pprof/profile": http.HandlerFunc(pprof.Profile),
		"/debug/pprof/symbol":  http.HandlerFunc(pprof.Symbol),
		"/debug/pprof/trace":   http.HandlerFunc(pprof.Trace),
	}
}

// Register mounts the standard net/http/pprof handlers on mux under
// /debug/pprof/ — the index plus the cmdline, profile, symbol and
// trace endpoints. Call once at startup on the mux the debug
// listener serves.
func Register(mux *http.ServeMux) {
	for path, h := range Handlers() {
		mux.Handle(path, h)
	}
}
