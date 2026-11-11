// Package eventpurge ports scripts/purge-events.py — bulk-deletes stale
// Events through the API server (never etcd directly).
//
// Context: Events carry a 1h TTL but the GC loop dies with the
// control plane, so after a control-plane outage tens of thousands of
// Event objects pile up — etcd balloons and every LIST events burns
// RAM/CPU. The purge deletes only events with
// metadata.creationTimestamp strictly older than the cutoff — pick
// the cluster-recovery moment so new (debuggable) events survive.
//
// The flow is the script's:
//  1. paginate GET /api/v1/events?limit=500&resourceVersion=0&continue=...
//  2. collect /api/v1/namespaces/<ns>/events/<name> for every stale item
//  3. DELETE them in parallel through a worker pool sharing one client
//
// and prints the script's output strings:
//
//	to delete: <N>
//	deleted=<ok> errors=<err>
package eventpurge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"
)

// Defaults mirror purge-events.py.
const (
	defaultAPI     = "https://127.0.0.1:6443"
	defaultWorkers = 8
	defaultTimeout = 30 * time.Second
	// defaultMaxDeletes caps one purge run's DELETEs — tens of
	// thousands of stale Events delete across cycles, never in one
	// unbounded burst against the apiserver.
	defaultMaxDeletes = 5000

	defaultCAFile   = "/var/lib/k0s/pki/ca.crt"
	fallbackCAFile  = "/var/lib/k0s/pki/etcd/ca.crt"
	defaultCertFile = "/var/lib/k0s/pki/admin.crt"
	defaultKeyFile  = "/var/lib/k0s/pki/admin.key"

	// maxResponseBytes caps one apiserver response body — a LIST
	// page of 500 events is ~1-2MB; a hostile or pathological reply
	// must not slurp unbounded heap.
	maxResponseBytes = 8 << 20
)

// DefaultCA resolves the CA the script picked: /var/lib/k0s/pki/ca.crt
// when present, else the etcd CA — single-stack vs kine-etcd PKI
// layouts differ on which exists.
func DefaultCA() string {
	if _, err := os.Stat(defaultCAFile); err == nil {
		return defaultCAFile
	}
	return fallbackCAFile
}

// Config carries the purge inputs — every field test-injectable.
type Config struct {
	API      string // apiserver base URL (no trailing slash)
	CAFile   string // "" → DefaultCA()
	CertFile string // "" → admin.crt
	KeyFile  string // "" → admin.key

	Workers    int           // parallel DELETEs; <=0 → 8
	Timeout    time.Duration // per-request budget; <=0 → 30s
	MaxDeletes int           // per-run DELETE cap; <=0 → 5000 — overflow is skipped, not deleted

	// Client, when non-nil, is used verbatim — CA/cert/key files are
	// ignored. This is the httptest.NewTLSServer seam and the way a
	// caller injects a fully-built transport.
	Client *http.Client
}

func (c *Config) applyDefaults() {
	if c.API == "" {
		c.API = defaultAPI
	}
	if c.CAFile == "" {
		c.CAFile = DefaultCA()
	}
	if c.CertFile == "" {
		c.CertFile = defaultCertFile
	}
	if c.KeyFile == "" {
		c.KeyFile = defaultKeyFile
	}
	if c.Workers <= 0 {
		c.Workers = defaultWorkers
	}
	if c.Timeout <= 0 {
		c.Timeout = defaultTimeout
	}
	if c.MaxDeletes <= 0 {
		c.MaxDeletes = defaultMaxDeletes
	}
}

// httpClient assembles the client the script built with
// ssl.create_default_context(cafile=CA) + load_cert_chain(admin) —
// CA-verified TLS plus admin client-cert auth. The shared Transport
// keeps HTTP/2 multiplexing across the whole worker pool.
func (c Config) httpClient() (*http.Client, error) {
	if c.Client != nil {
		// Caller-injected client: used verbatim (same *http.Client
		// the caller built — CA/cert/key files are ignored). The
		// run's idle-connection teardown lives in Run's
		// CloseIdleConnections defer, so no cloning is needed here.
		return c.Client, nil
	}
	pem, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read CA %s: %w", c.CAFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA %s carries no PEM certificates", c.CAFile)
	}
	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load client cert %s/%s: %w",
			c.CertFile, c.KeyFile, err)
	}
	// Clone http.DefaultTransport rather than build a Transport from
	// scratch: the clone carries ForceAttemptHTTP2, so the custom
	// TLS config below does not silently downgrade the worker pool's
	// shared connections to HTTP/1.1 (a fresh &http.Transport with
	// TLSClientConfig set would — that contradicted the HTTP/2
	// multiplexing this comment block always promised).
	tr := http.DefaultTransport.(*http.Transport).Clone()
	// The worker pool runs cfg.Workers parallel DELETEs —
	// the default MaxIdleConnsPerHost=2 would churn
	// connections every cycle.
	tr.MaxIdleConnsPerHost = c.Workers
	tr.TLSClientConfig = &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	return &http.Client{
		Timeout:   c.Timeout,
		Transport: tr,
	}, nil
}

// eventList is the slice of a core/v1 EventList the purge reads.
type eventList struct {
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
	Items []struct {
		Metadata struct {
			Namespace         string    `json:"namespace"`
			Name              string    `json:"name"`
			CreationTimestamp time.Time `json:"creationTimestamp"`
		} `json:"metadata"`
	} `json:"items"`
}

// Run lists every event older than cutoff, deletes them through the
// worker pool and prints the script's two summary lines to out.
// Per-event DELETE failures are counted in errors, not returned — only
// fatal problems (TLS setup, a failed LIST page) produce an error,
// matching the script which exits 0 regardless of err count. A ctx
// cancellation is fatal too: a SIGTERM/timeout between deletes leaves
// a PARTIAL purge, and returning nil made that read as exit-0
// success — so it is surfaced (cmd.go maps a Run error to exit 1)
// and the tally is marked aborted on the output.
func Run(ctx context.Context, cfg Config, cutoff time.Time, out io.Writer) error {
	cfg.applyDefaults()
	client, err := cfg.httpClient()
	if err != nil {
		return err
	}
	// One-shot run: hand every pooled conn back to the kernel at
	// exit instead of holding them for the default 90s idle window.
	// Locally-built clients only — an INJECTED client is the
	// caller's; closing its idle connections from here would tear
	// down pools the caller may still be using.
	if cfg.Client == nil {
		if t, ok := client.Transport.(*http.Transport); ok {
			defer t.CloseIdleConnections()
		}
	}
	paths, err := listStale(ctx, client, cfg.API, cutoff)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "to delete: %d\n", len(paths))
	// The LIST runs fully, but only the first MaxDeletes stale paths
	// feed the worker pool — the rest are skipped (next run deletes
	// them). The cap line only prints when it actually bit, keeping
	// the script's exact 2-line output otherwise.
	toDelete := paths
	capped := len(paths) > cfg.MaxDeletes
	if capped {
		toDelete = paths[:cfg.MaxDeletes]
	}
	ok, errs, firstErr := deleteAll(ctx, client, cfg.API, toDelete, cfg.Workers)
	_, _ = fmt.Fprintf(out, "deleted=%d errors=%d\n", ok, errs)
	if capped {
		_, _ = fmt.Fprintf(out, "skipped_by_cap=%d\n", len(paths)-len(toDelete))
	}
	if firstErr != "" {
		// The tally alone cannot say WHY deletes failed — RBAC,
		// a wedged apiserver and a 404 storm all read "errors=N".
		_, _ = fmt.Fprintf(out, "first error: %s\n", firstErr)
	}
	// SIGTERM or a caller's bounded deadline killing the run mid-purge
	// leaves a partial delete: report `deleted=N aborted` and fail the
	// run instead of the old unconditional nil that scored the partial
	// purge as a clean exit-0.
	if ctxErr := ctx.Err(); ctxErr != nil {
		_, _ = fmt.Fprintf(out, "deleted=%d aborted: %v\n", ok, ctxErr)
		return fmt.Errorf("purge aborted after deleted=%d of %d: %w",
			ok, len(toDelete), ctxErr)
	}
	return nil
}

// doReq issues one request and returns (status, header, body) —
// status 0 when the request never reached a response (dial/ctx
// error). The header rides along so the DELETE retry policy can
// honor a server-sent Retry-After.
func doReq(ctx context.Context, client *http.Client, method, u string) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	// Read cap+1 so an oversize body is distinguishable from one
	// landing exactly on the cap — a LimitReader-truncated page would
	// otherwise surface downstream as a misleading JSON syntax error.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return resp.StatusCode, resp.Header, nil, err
	}
	if len(body) > maxResponseBytes {
		return resp.StatusCode, resp.Header, nil, fmt.Errorf(
			"response exceeded %dMiB cap", maxResponseBytes>>20)
	}
	return resp.StatusCode, resp.Header, body, nil
}

// listStale walks the paginated event LIST once (limit=500,
// resourceVersion=0 — the script's exact query; rv=0 is a possibly-
// stale cache read, acceptable for a one-shot purge since a freshly
// missed event simply survives to the next run) and returns the
// delete path of every item older than cutoff.
func listStale(ctx context.Context, client *http.Client,
	base string, cutoff time.Time) ([]string, error) {
	var paths []string
	cont := ""
	for {
		code, _, body, err := doReq(ctx, client, http.MethodGet,
			base+"/api/v1/events?limit=500&resourceVersion=0"+cont)
		if err != nil {
			return nil, fmt.Errorf("list events: %w", err)
		}
		if code != http.StatusOK {
			return nil, fmt.Errorf("list events: HTTP %d: %s", code,
				truncate(string(body), 200))
		}
		var d eventList
		if err := json.Unmarshal(body, &d); err != nil {
			return nil, fmt.Errorf("list events: %w", err)
		}
		for _, it := range d.Items {
			m := it.Metadata
			// Strict <, the script's `creationTimestamp < CUTOFF`.
			if m.CreationTimestamp.Before(cutoff) {
				paths = append(paths, "/api/v1/namespaces/"+
					url.PathEscape(m.Namespace)+"/events/"+
					url.PathEscape(m.Name))
			}
		}
		if d.Metadata.Continue == "" {
			return paths, nil
		}
		cont = "&continue=" + url.QueryEscape(d.Metadata.Continue)
	}
}

// Retry policy for one DELETE — a purge bursts 8 workers at full
// speed, and the window that matters (right after a control-plane
// outage, when the event backlog is biggest) is exactly when the
// apiserver is most loaded. The one-attempt version counted every
// 429/5xx as a permanent loss while the remaining workers kept
// slamming full speed.
const (
	// deleteMaxAttempts is first try + 3 retries: still-throttled
	// after 4 tries is load the purge itself is contributing to —
	// back off and let the next cycle finish the backlog.
	deleteMaxAttempts = 4
	deleteBackoffBase = 500 * time.Millisecond
	deleteBackoffCap  = 30 * time.Second
)

// deleteOne issues one event DELETE. 2xx counts as ok — and so do
// 404/410, since an event GC'd or deleted between LIST and DELETE is
// already in the desired end state, not a failure. 429 and 5xx are
// retried up to deleteMaxAttempts, honoring the server's Retry-After
// when present (the seconds form the apiserver sends; also on a 503,
// same header semantics) and exponential backoff otherwise, both
// capped at 30s so a wedged server cannot park a worker forever. A
// give-up after exhausting attempts, a ctx dying (in the request or
// mid-backoff) and any other 4xx count as one error: 4xx is a real
// refusal (RBAC, validation) no retry fixes, and the per-event
// failure stays a tally, never a returned error (the script's
// `except: err += 1`). detail names the first failure for the
// summary line.
func deleteOne(ctx context.Context, client *http.Client, base, p string) (ok bool, detail string) {
	for attempt := 0; ; attempt++ {
		code, hdr, _, err := doReq(ctx, client, http.MethodDelete, base+p)
		if err != nil {
			// Transport-level (dial, TLS, client timeout, dead ctx):
			// retrying into a dying run would only burn the budget.
			return false, fmt.Sprintf("%s: %v", p, err)
		}
		switch {
		case code/100 == 2, code == http.StatusNotFound, code == http.StatusGone:
			return true, ""
		case code == http.StatusTooManyRequests || code/100 == 5:
			if attempt+1 >= deleteMaxAttempts {
				return false, fmt.Sprintf("%s: HTTP %d after %d attempts",
					p, code, attempt+1)
			}
			if !sleepCtx(ctx, retryDelay(hdr, attempt)) {
				return false, fmt.Sprintf("%s: aborted retrying HTTP %d: %v",
					p, code, ctx.Err())
			}
		default:
			return false, fmt.Sprintf("%s: HTTP %d", p, code)
		}
	}
}

// retryDelay picks the wait before the next DELETE attempt: the
// server's Retry-After in seconds when it sent one, else exponential
// 0.5s→1s→2s — capped at 30s either way so a hostile or wedged
// server cannot stretch one worker's pause past the run's usefulness.
func retryDelay(hdr http.Header, attempt int) time.Duration {
	if hdr != nil {
		if ra := hdr.Get("Retry-After"); ra != "" {
			if secs, err := strconv.Atoi(ra); err == nil && secs >= 0 {
				d := time.Duration(secs) * time.Second
				if d > deleteBackoffCap {
					d = deleteBackoffCap
				}
				return d
			}
		}
	}
	d := deleteBackoffBase << attempt
	// d <= 0 guards a shift overflow on absurd attempt counts.
	if d > deleteBackoffCap || d <= 0 {
		d = deleteBackoffCap
	}
	return d
}

// sleepCtx waits d or until ctx dies — true means the full delay
// elapsed and the retry may proceed.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// deleteAll is the script's ThreadPoolExecutor(WORKERS) map — one
// shared client, N workers pulling delete paths off a channel.
// Per-path outcomes follow deleteOne: 2xx/404/410 ok, throttled and
// server-error deletes retried with backoff, everything else (and a
// retry budget exhausted) tallied as errors. The first failure's
// detail is returned for the summary — the bare tally cannot
// distinguish RBAC denials from a wedged apiserver.
func deleteAll(ctx context.Context, client *http.Client, base string,
	paths []string, workers int) (ok, errs int, firstErr string) {
	jobs := make(chan string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				good, detail := deleteOne(ctx, client, base, p)
				mu.Lock()
				if good {
					ok++
				} else {
					errs++
					if firstErr == "" {
						firstErr = detail
					}
				}
				mu.Unlock()
			}
		}()
	}
	for _, p := range paths {
		select {
		case jobs <- p:
		case <-ctx.Done():
			// Stop feeding; jobs is UNBUFFERED so "in-flight" is just
			// the paths a worker already received — those still settle
			// into the counters while wg.Wait drains the pool.
			close(jobs)
			wg.Wait()
			return ok, errs, firstErr
		}
	}
	close(jobs)
	wg.Wait()
	return ok, errs, firstErr
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
