// Package evpurge ports scripts/purge-events.py — bulk-deletes stale
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
package evpurge

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
	"sync"
	"time"
)

// Defaults mirror purge-events.py.
const (
	defaultAPI     = "https://127.0.0.1:6443"
	defaultWorkers = 8
	defaultTimeout = 30 * time.Second

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
	API      string        // apiserver base URL (no trailing slash)
	CAFile   string        // "" → DefaultCA()
	CertFile string        // "" → admin.crt
	KeyFile  string        // "" → admin.key
	Workers  int           // parallel DELETEs; <=0 → 8
	Timeout  time.Duration // per-request budget; <=0 → 30s

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
}

// httpClient assembles the client the script built with
// ssl.create_default_context(cafile=CA) + load_cert_chain(admin) —
// CA-verified TLS plus admin client-cert auth. The shared Transport
// keeps HTTP/2 multiplexing across the whole worker pool.
func (c Config) httpClient() (*http.Client, error) {
	if c.Client != nil {
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
	return &http.Client{
		Timeout: c.Timeout,
		Transport: &http.Transport{
			// The worker pool runs cfg.Workers parallel DELETEs —
			// the default MaxIdleConnsPerHost=2 would churn
			// connections every cycle.
			MaxIdleConnsPerHost: c.Workers,
			TLSClientConfig: &tls.Config{
				RootCAs:      pool,
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			},
		},
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
// matching the script which exits 0 regardless of err count.
func Run(ctx context.Context, cfg Config, cutoff time.Time, out io.Writer) error {
	cfg.applyDefaults()
	client, err := cfg.httpClient()
	if err != nil {
		return err
	}
	paths, err := listStale(ctx, client, cfg.API, cutoff)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "to delete: %d\n", len(paths))
	ok, errs, firstErr := deleteAll(ctx, client, cfg.API, paths, cfg.Workers)
	fmt.Fprintf(out, "deleted=%d errors=%d\n", ok, errs)
	if firstErr != "" {
		// The tally alone cannot say WHY deletes failed — RBAC,
		// a wedged apiserver and a 404 storm all read "errors=N".
		fmt.Fprintf(out, "first error: %s\n", firstErr)
	}
	return nil
}

// doReq issues one request and returns (status, body) — status 0 when
// the request never reached a response (dial/ctx error).
func doReq(ctx context.Context, client *http.Client, method, u string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return 0, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	// Read cap+1 so an oversize body is distinguishable from one
	// landing exactly on the cap — a LimitReader-truncated page would
	// otherwise surface downstream as a misleading JSON syntax error.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if len(body) > maxResponseBytes {
		return resp.StatusCode, nil, fmt.Errorf(
			"response exceeded %dMiB cap", maxResponseBytes>>20)
	}
	return resp.StatusCode, body, nil
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
		code, body, err := doReq(ctx, client, http.MethodGet,
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

// deleteAll is the script's ThreadPoolExecutor(WORKERS) map — one
// shared client, N workers pulling delete paths off a channel.
// A DELETE counts as ok on any 2xx — and on 404/410, since an event
// GC'd or deleted between LIST and DELETE is already in the desired
// end state, not a failure. Any other transport error or non-2xx
// status counts as errors (the script's `except: err += 1`). The
// first failure's detail is returned for the summary — the bare
// tally cannot distinguish RBAC denials from a wedged apiserver.
func deleteAll(ctx context.Context, client *http.Client, base string,
	paths []string, workers int) (ok, errs int, firstErr string) {
	jobs := make(chan string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				code, _, err := doReq(ctx, client, http.MethodDelete, base+p)
				mu.Lock()
				if err == nil && (code/100 == 2 ||
					code == http.StatusNotFound || code == http.StatusGone) {
					// 2xx deleted it; 404/410 means the event was
					// GC'd or deleted between LIST and DELETE — the
					// desired end state either way, not an error.
					ok++
				} else {
					errs++
					if firstErr == "" {
						if err != nil {
							firstErr = fmt.Sprintf("%s: %v", p, err)
						} else {
							firstErr = fmt.Sprintf("%s: HTTP %d", p, code)
						}
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
