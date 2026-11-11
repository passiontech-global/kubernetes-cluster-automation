// Package httpx is the minimal bind-then-serve lifecycle for the
// probe/metrics endpoints the apps expose (healthz, /metrics). It is
// stdlib-only by contract (depguard: hostkit-is-leaf): the handler —
// including any promhttp mux — is injected by the caller, this package
// only owns listener/server wiring.
//
// The reason it exists: the naive http.ListenAndServe-in-a-goroutine
// pattern binds lazily, so a port collision or typo'd address surfaces
// asynchronously and whatever probes the endpoint races the bind.
// Here the listener is bound synchronously in New — the address (and
// any bind error) is known before a goroutine exists — and serving
// starts explicitly.
package httpx

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

const (
	// DefaultReadHeaderTimeout guards the probe endpoints against
	// slowloris-style connection exhaustion; a metrics scrape and a
	// health probe both send headers immediately, so 10s is generous.
	DefaultReadHeaderTimeout = 10 * time.Second
	// DefaultShutdownBudget is the drain window Shutdown applies when
	// the caller's ctx carries no deadline.
	DefaultShutdownBudget = 5 * time.Second
)

// Opts tunes New; zero fields fall back to the package defaults.
type Opts struct {
	// ReadHeaderTimeout caps the time from connection accept to full
	// request headers (zero → DefaultReadHeaderTimeout).
	ReadHeaderTimeout time.Duration
	// ShutdownBudget is the drain window Shutdown applies when the
	// caller's ctx carries no deadline (zero → DefaultShutdownBudget).
	ShutdownBudget time.Duration
}

// Server is a bound, not-yet-serving HTTP server.
type Server struct {
	ln     net.Listener
	srv    *http.Server
	budget time.Duration
	done   chan error
}

// New binds addr synchronously — the bind-then-serve ordering that
// lets callers learn the port (Addr works for ":0") and fail fast on a
// collision before anything listens. handler is injected by the caller
// (promhttp mux, plain http.ServeMux, …).
func New(addr string, handler http.Handler, opts Opts) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if opts.ReadHeaderTimeout <= 0 {
		opts.ReadHeaderTimeout = DefaultReadHeaderTimeout
	}
	if opts.ShutdownBudget <= 0 {
		opts.ShutdownBudget = DefaultShutdownBudget
	}
	return &Server{
		ln: ln,
		srv: &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: opts.ReadHeaderTimeout,
		},
		budget: opts.ShutdownBudget,
		done:   make(chan error, 1),
	}, nil
}

// Addr returns the bound listener's address — usable before Serve, so
// the endpoint URL can be published first.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Serve starts accepting connections in the background. The returned
// channel yields nil after a graceful Shutdown (http.ErrServerClosed
// is folded away — shutting down is not a serve failure) or the
// accept-loop error otherwise. Serve must be called once.
func (s *Server) Serve() <-chan error {
	go func() {
		err := s.srv.Serve(s.ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		s.done <- err
	}()
	return s.done
}

// Shutdown gracefully drains in-flight requests and closes the
// listener. A ctx without a deadline gets the server's shutdown
// budget; the returned error is that context's error when the budget
// expires with handlers still running (the caller decides whether to
// escalate to Close).
func (s *Server) Shutdown(ctx context.Context) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.budget)
		defer cancel()
	}
	return s.srv.Shutdown(ctx)
}

// Timeout wraps a single route's handler with http.TimeoutHandler —
// the per-route budget for slow collectors so one hung probe route
// cannot hold the server's worker slots forever. On expiry the client
// gets 503 with msg as the body ("" → a generic message).
func Timeout(h http.Handler, dt time.Duration, msg string) http.Handler {
	if msg == "" {
		msg = "request timed out"
	}
	return http.TimeoutHandler(h, dt, msg)
}
