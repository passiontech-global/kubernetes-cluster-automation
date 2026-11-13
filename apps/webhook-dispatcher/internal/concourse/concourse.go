// Package concourse implements the small slice of the Concourse ATC
// API the dispatcher needs: listing pipelines and their resources to
// build a repo -> resource index, and POSTing resource check webhooks.
//
// The package is split by concern: this file owns the Client value,
// its HTTP/check-webhook surface and the shared error/URL helpers;
// index.go owns the singleflight cache machinery (Resources /
// EnsureIndex / Refresh / RefreshIndex); match.go owns repo
// normalization, the index fetch itself and the O(1) Match lookup.
package concourse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Resource is one Concourse resource pinned to a GitHub repo. Repo is
// the normalized "org/repo" form produced by NormalizeRepo.
type Resource struct {
	Pipeline string
	Name     string
	Type     string
	Repo     string
	// InstanceVarsQuery is the pipeline's instance_vars rendered as
	// the ATC dot-notation query fragment ("vars.k=<json>&…", "" for
	// non-instanced pipelines). Instanced pipelines only resolve
	// their resources/checks under ?vars.<key>=, so the fragment
	// rides every Resource and is appended to both the /resources
	// listing and the check-webhook POST.
	InstanceVarsQuery string
}

// Client talks to a single Concourse ATC team.
type Client struct {
	BaseURL      string // e.g. http://concourse-web:8080
	Team         string
	User         string // basic auth, parsed from LOCAL_USERS
	Password     string
	WebhookToken string // CI_WEBHOOK_TOKEN, sent as webhook_token=…

	// HTTP is the client used for ATC calls; nil -> http.DefaultClient.
	HTTP *http.Client

	// IndexTTL bounds how long the resource index is served from
	// cache before a refresh; zero -> 1 minute.
	IndexTTL time.Duration

	// MinRefreshInterval bounds forced Refresh calls — zero-match
	// deliveries for repos with no pipeline would otherwise refetch
	// the whole index on every push. Zero -> 30 seconds.
	MinRefreshInterval time.Duration

	// NegCacheTTL is the cold-start negative-cache window: when a
	// fetch fails with NO index to serve, Resources callers used to
	// each stamp a fresh attempt and start their own fetch — N
	// concurrent first deliveries serialized N doomed index
	// rebuilds at a flapping ATC. The shared error is returned
	// instead for this window. Zero -> 3 seconds.
	NegCacheTTL time.Duration

	// mu guards the index cache fields below. It is a RWMutex so the
	// per-delivery Match read path takes only RLock — webhook volume
	// is read-dominated and the publish path replaces the snapshot
	// wholesale, never mutating it in place.
	mu sync.RWMutex

	// index is the last successfully fetched index; lookup is its
	// (type, repo) -> resources map, built once per fetch publish so
	// the per-delivery match is a map hit (Client.Match) instead of a
	// linear scan of every resource in the team. Both are replaced
	// wholesale on publish — never mutated in place — so serving a
	// snapshot is race-free and Match returns value copies.
	index     []Resource
	lookup    map[indexKey][]Resource
	fetchedAt time.Time
	// lastAttemptAt stamps the start of the most recent fetch attempt
	// made by Resources — success or failure — so a failed fetch backs
	// off instead of letting every caller block on a fresh fetch
	// against a dead ATC, and callers arriving mid-fetch are served
	// the current index rather than queueing a second fetch. It
	// belongs to Resources alone: Refresh throttles on its own
	// lastForceRefreshAt clock, so one entry point's attempt stamp
	// never masks the other's.
	lastAttemptAt time.Time
	// lastForceRefreshAt stamps the most recent forced Refresh
	// attempt, throttling Refresh to MinRefreshInterval. It is kept
	// separate from lastAttemptAt: a zero-match delivery's forced
	// refresh must not be suppressed by an unrelated Resources cache
	// miss that just stamped its own attempt, and a Refresh attempt
	// must never double as Resources' backoff stamp.
	lastForceRefreshAt time.Time
	// flight is the in-flight index fetch, if any. Starting a fetch
	// installs a fresh flight under the lock and closes its done
	// channel — only when that fetch itself settles — so concurrent
	// starters never clear each other's in-flight marker. Cold-start
	// callers (no index to serve) capture the channel and wait on it,
	// sharing the in-flight fetch's result instead of stampeding the
	// ATC with duplicate full-index fetches.
	flight *fetchFlight
	// lastErr/lastErrAt are the cold-start negative cache — see
	// NegCacheTTL. Written under c.mu on any fetch failure EXCEPT a
	// caller-cancelled context (not an ATC failure), cleared on
	// success; consulted only while c.index == nil.
	lastErr   error
	lastErrAt time.Time

	// auth is the lazily-built dual-mode credential state (bearer
	// token with basic fallback — see auth.go). It is built ONCE via
	// authOnce — sync.Once, not c.mu — and published through authPtr
	// so invalidateToken's compare-and-clear never has to take the
	// index mutex (or observe a half-built state).
	authOnce sync.Once
	authPtr  atomic.Pointer[atcAuth]

	// now is the internal clock — nil means time.Now. Seam for the
	// index tests: they advance it instead of sleeping across real
	// TTL/backoff windows. Production code leaves it nil.
	now func() time.Time
}

// statusError carries the HTTP status of a failed ATC call so callers
// can distinguish 404 (the object is gone — e.g. a pipeline deleted
// between the listing and its resource fetch) from transient failures
// that must keep last-known data.
type statusError struct {
	status int
	path   string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("GET %s: unexpected status %d", e.path, e.status)
}

// stripURLError unwraps *url.Error — it embeds the full request URL,
// and a BaseURL carrying userinfo (or any future credential-bearing
// query) would leak it into error logs. Non-url errors pass through
// unchanged. CheckWebhook and getJSON both route transport failures
// through here.
func stripURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// SafeBaseURL renders BaseURL with any userinfo stripped — a Concourse
// URL may carry basic-auth credentials in the authority, and the
// value is logged on startup and every index refresh/failure. Logs
// must never see them.
func (c *Client) SafeBaseURL() string {
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.User == nil {
		return c.BaseURL
	}
	u.User = nil
	return u.String()
}

func (c *Client) safeBaseURL() string { return c.SafeBaseURL() }

// SameOriginRedirectPolicy builds an http.Client CheckRedirect that
// allows redirects only back to the origin of base. CheckWebhook
// carries the CI webhook token in the query string, so a redirect to
// another host (a 30x a compromised/misconfigured ATC or an inline
// proxy emits) would replay the credential to that host — never
// follow one. Same-origin redirects stay allowed: a web node may
// legitimately route /api/v1/... through a path rewrite on its own
// host.
func SameOriginRedirectPolicy(base string) func(*http.Request, []*http.Request) error {
	bu, err := url.Parse(base)
	scheme, host := "", ""
	if err == nil {
		scheme, host = bu.Scheme, bu.Host
	}
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		if req.URL.Scheme != scheme || req.URL.Host != host {
			return fmt.Errorf(
				"refusing cross-origin redirect from %s to %s — webhook_token would leak",
				via[len(via)-1].URL.Host, req.URL.Host)
		}
		return nil
	}
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) ttl() time.Duration {
	if c.IndexTTL > 0 {
		return c.IndexTTL
	}
	return time.Minute
}

func (c *Client) minRefreshInterval() time.Duration {
	if c.MinRefreshInterval > 0 {
		return c.MinRefreshInterval
	}
	return 30 * time.Second
}

func (c *Client) negCacheTTL() time.Duration {
	if c.NegCacheTTL > 0 {
		return c.NegCacheTTL
	}
	return 3 * time.Second
}

// CheckWebhook POSTs the resource's check webhook. The webhook_token
// query param is the credential, so no basic auth is sent. It returns
// the ATC status code so the caller can classify warn vs error;
// transport errors return 0.
func (c *Client) CheckWebhook(ctx context.Context, r Resource) (int, error) {
	u := strings.TrimSuffix(c.BaseURL, "/") + c.apiPath(
		"pipelines/"+url.PathEscape(r.Pipeline)+
			"/resources/"+url.PathEscape(r.Name)+"/check/webhook") +
		"?webhook_token=" + url.QueryEscape(c.WebhookToken)
	if r.InstanceVarsQuery != "" {
		// Instanced pipelines check under their instance vars —
		// without ?vars.<key>= the ATC can't resolve which instance
		// to check (and may 404 the resource outright).
		u += "&" + r.InstanceVarsQuery
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		// url.Parse failures surface as *url.Error embedding the raw
		// URL — webhook_token included. Unwrap like the Do path.
		return 0, stripURLError(err)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		// Do wraps transport failures in *url.Error, which embeds the
		// full request URL — webhook_token included — and would leak
		// the token into error logs. Return only the wrapped error.
		return 0, stripURLError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	// Drain (bounded) so the keep-alive connection can be reused.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, nil
}

func (c *Client) apiPath(p string) string {
	return "/api/v1/teams/" + url.PathEscape(c.Team) + "/" + p
}

// maxJSONBody bounds how much of a 2xx ATC response getJSON will
// decode — matched to the handler's 8 MiB inbound webhook body cap
// (handler.maxBodyBytes). Real index/listing payloads are far
// smaller, so a longer body means a wedged or hostile peer and the
// decode must fail instead of buffering the stream whole.
const maxJSONBody = 8 << 20 // 8 MiB

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	// Up to two attempts: a 401 on a bearer-token request invalidates
	// the cached token and re-mints exactly once (auth.go) — a
	// revoked/expired-early token self-heals instead of failing the
	// whole index fetch. Basic-mode requests never retry: their 401
	// is a credential problem, not a stale token.
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			strings.TrimSuffix(c.BaseURL, "/")+path, nil)
		if err != nil {
			return stripURLError(err)
		}
		usedToken, err := c.authorize(ctx, req)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := c.httpClient().Do(req)
		if err != nil {
			return stripURLError(err)
		}
		if resp.StatusCode == http.StatusUnauthorized && usedToken != "" && attempt == 0 {
			// Drain (bounded) BEFORE closing so the keep-alive
			// connection survives into the retry instead of being
			// dropped by the transport over unconsumed bytes.
			_, _ = io.CopyN(io.Discard, resp.Body, 64<<10)
			_ = resp.Body.Close()
			// Invalidate only the token THIS request carried — a
			// fresher token another worker already minted survives.
			c.invalidateToken(usedToken)
			continue
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode/100 != 2 {
			// Drain (bounded) so the keep-alive connection can be reused.
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			return &statusError{status: resp.StatusCode, path: path}
		}
		// Bound the decode: without LimitReader a 2xx body longer than
		// maxJSONBody (an ATC streaming forever) would be buffered whole.
		err = json.NewDecoder(io.LimitReader(resp.Body, maxJSONBody)).Decode(out)
		// Drain whatever the decoder left before the body closes: a decode
		// that finished before EOF (trailing newline, whitespace, extra
		// documents) or one that failed at the maxJSONBody cap would
		// otherwise strand the keep-alive connection, forcing every later
		// call to re-dial. Bounded like the error path — an endless
		// hostile stream is abandoned, not drained forever.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return err
	}
}
