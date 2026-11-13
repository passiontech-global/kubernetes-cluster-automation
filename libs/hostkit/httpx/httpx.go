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
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	// DefaultReadHeaderTimeout guards the probe endpoints against
	// slowloris-style connection exhaustion; a metrics scrape and a
	// health probe both send headers immediately, so 10s is generous.
	DefaultReadHeaderTimeout = 10 * time.Second
	// DefaultIdleTimeout is the keep-alive window between requests on
	// a connection. It MUST be set explicitly: net/http derives an
	// unset IdleTimeout from ReadTimeout, and an unset ReadTimeout
	// from ReadHeaderTimeout — leaving it zero would sever every
	// keep-alive connection (Prometheus scrapes, webhook deliveries)
	// every 10 seconds.
	DefaultIdleTimeout = 60 * time.Second
	// DefaultShutdownBudget is the drain window Shutdown applies when
	// the caller's ctx carries no deadline.
	DefaultShutdownBudget = 5 * time.Second
	// DefaultMaxHeaderBytes caps request header size when Opts leaves
	// MaxHeaderBytes zero — 64 KiB. Probe/metrics/webhook peers send
	// a handful of modest headers; the tight cap keeps a hostile or
	// buggy peer from parking large header buffers per connection.
	DefaultMaxHeaderBytes = 64 << 10
)

// Opts tunes New; zero fields fall back to the package defaults.
type Opts struct {
	// ReadHeaderTimeout caps the time from connection accept to full
	// request headers (zero → DefaultReadHeaderTimeout).
	ReadHeaderTimeout time.Duration
	// ReadTimeout caps the whole request read — headers AND body
	// (zero → net/http default: unbounded, preserving the metrics/
	// stream behavior older callers relied on).
	ReadTimeout time.Duration
	// WriteTimeout caps the whole response write (zero → unbounded).
	WriteTimeout time.Duration
	// IdleTimeout caps keep-alive connections between requests
	// (zero → DefaultIdleTimeout). See DefaultIdleTimeout for why an
	// explicit value is required.
	IdleTimeout time.Duration
	// ShutdownBudget is the drain window Shutdown applies when the
	// caller's ctx carries no deadline (zero → DefaultShutdownBudget).
	ShutdownBudget time.Duration
	// MaxHeaderBytes caps request header size (zero →
	// DefaultMaxHeaderBytes).
	MaxHeaderBytes int
}

// Server is a bound, not-yet-serving HTTP server.
type Server struct {
	// mu guards ln and closed: Close/Shutdown nil the listener out
	// and latch closed so a second teardown is a no-op, Serve-after-
	// teardown reports a clean close instead of accepting on a dead
	// listener, and a Serve accept-loop error caused BY the teardown
	// (net.ErrClosed on the listener we closed) folds to nil.
	mu        sync.Mutex
	ln        net.Listener
	closed    bool
	srv       *http.Server
	budget    time.Duration
	done      chan error
	serveOnce sync.Once
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
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = DefaultIdleTimeout
	}
	if opts.ShutdownBudget <= 0 {
		opts.ShutdownBudget = DefaultShutdownBudget
	}
	if opts.MaxHeaderBytes <= 0 {
		opts.MaxHeaderBytes = DefaultMaxHeaderBytes
	}
	return &Server{
		ln: ln,
		srv: &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: opts.ReadHeaderTimeout,
			ReadTimeout:       opts.ReadTimeout,
			WriteTimeout:      opts.WriteTimeout,
			IdleTimeout:       opts.IdleTimeout,
			MaxHeaderBytes:    opts.MaxHeaderBytes,
		},
		budget: opts.ShutdownBudget,
		done:   make(chan error, 1),
	}, nil
}

// ListenLoopback binds a TCP listener on 127.0.0.1:port — the
// loopback-only posture debug/diagnostic endpoints (pprof) carry,
// so they can never be reached off-node even if the configured bind
// address is widened by mistake. Port 0 resolves to an ephemeral
// port; the real address is available via ln.Addr().
func ListenLoopback(port int) (net.Listener, error) {
	return net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
}

// Addr returns the bound listener's address — usable before Serve, so
// the endpoint URL can be published first.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Serve starts accepting connections in the background. The returned
// channel yields nil after a graceful Shutdown (http.ErrServerClosed
// is folded away — shutting down is not a serve failure) or the
// accept-loop error otherwise; it is CLOSED after the result so
// repeated receives keep answering nil. Serve is idempotent — a
// second call returns the same channel without spawning a second
// accept loop (serveOnce) — and a call after Close/Shutdown resolves
// nil on the closed listener.
func (s *Server) Serve() <-chan error {
	s.serveOnce.Do(func() {
		s.mu.Lock()
		ln := s.ln
		s.mu.Unlock()
		go func() {
			var err error
			switch {
			case ln == nil || s.isClosed():
				// Torn down before the accept loop started — a clean
				// close, not a serve failure.
				err = http.ErrServerClosed
			default:
				err = s.srv.Serve(ln)
			}
			if errors.Is(err, http.ErrServerClosed) ||
				(errors.Is(err, net.ErrClosed) && s.isClosed()) {
				// ErrServerClosed is the graceful path; net.ErrClosed
				// is the listener WE closed mid-accept (Shutdown/Close
				// race) — equally not a serve failure, but ONLY when the
				// closed flag proves the teardown caused it.
				err = nil
			}
			s.done <- err
			close(s.done)
		}()
	})
	return s.done
}

// isClosed reports whether Shutdown/Close has latched the server
// torn down — read under mu like every other lifecycle field.
func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Shutdown gracefully drains in-flight requests and closes the
// listener. A ctx without a deadline gets the server's shutdown
// budget; the returned error is that context's error when the budget
// expires with handlers still running (the caller decides whether to
// escalate to Close).
//
// The listener is closed HERE, not only via srv.Shutdown: a Server
// that was bound but never Served was never handed to the
// http.Server, so Shutdown cannot see it — without the explicit
// close the socket would leak.
func (s *Server) Shutdown(ctx context.Context) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.budget)
		defer cancel()
	}
	err := s.srv.Shutdown(ctx)
	s.mu.Lock()
	s.closed = true
	if s.ln != nil {
		_ = s.ln.Close()
		s.ln = nil
	}
	s.mu.Unlock()
	return err
}

// Close tears the server down immediately: in-flight requests are
// cut rather than drained, and the bound socket is released even on
// a Server that was never Served. It is the counterpart of Shutdown
// for callers that must not block — and safe to call repeatedly or
// before Serve.
func (s *Server) Close() error {
	s.mu.Lock()
	ln := s.ln
	s.ln = nil
	s.closed = true
	s.mu.Unlock()
	var first error
	// srv.Close FIRST: it closes the listener internally and waits
	// for in-flight handlers; closing ln first made srv.Close's own
	// accept loop surface spurious net.ErrClosed errors.
	if err := s.srv.Close(); err != nil {
		first = err
	}
	if ln != nil {
		// srv.Close already closed a listener it was Serving — the
		// second close reports net.ErrClosed, the expected
		// already-closed state, not a failure. Only a never-Served
		// listener (unknown to srv) can return a real error here.
		if err := ln.Close(); first == nil && !errors.Is(err, net.ErrClosed) {
			first = err
		}
	}
	return first
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

// PooledTransport returns an *http.Transport cloned from
// http.DefaultTransport (keeping its dialer, HTTP/2 and 90s
// IdleConnTimeout defaults) with the per-host idle pool raised to
// maxIdlePerHost — http.DefaultTransport's MaxIdleConnsPerHost of 2
// makes every parallel probe sweep churn connections, and callers
// sharing one transport also share its TLS session cache.
// tlsCfg, when non-nil, replaces the clone's TLSClientConfig.
// maxIdlePerHost <= 0 keeps the stdlib default.
func PooledTransport(maxIdlePerHost int, tlsCfg *tls.Config) *http.Transport {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		// Defensive: DefaultTransport is *http.Transport by stdlib
		// contract; if that ever changes, start from a zero transport
		// rather than panic.
		base = &http.Transport{}
	}
	c := base.Clone()
	if maxIdlePerHost > 0 {
		c.MaxIdleConnsPerHost = maxIdlePerHost
	}
	if tlsCfg != nil {
		c.TLSClientConfig = tlsCfg
	}
	return c
}
