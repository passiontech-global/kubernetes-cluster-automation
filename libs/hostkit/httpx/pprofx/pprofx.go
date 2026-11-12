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

// Register mounts the standard net/http/pprof handlers on mux under
// /debug/pprof/ — the index plus the cmdline, profile, symbol and
// trace endpoints. Call once at startup on the mux the debug
// listener serves.
func Register(mux *http.ServeMux) {
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
}
