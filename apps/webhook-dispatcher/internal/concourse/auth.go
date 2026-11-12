// auth.go — dual-mode ATC authentication.
//
// Concourse web nodes accept two credential shapes on the team API:
// HTTP Basic (the LOCAL_USERS pair) and an OIDC-style bearer token
// minted by the web node's own token endpoint. Basic works
// everywhere but is checked per request; the bearer token is what
// the fly CLI uses and what newer/SSO-fronted deployments may
// require. This file implements the bearer path with automatic
// fallback:
//
//   - POST {base}/sky/issuer/token (newer web nodes), falling back
//     to {base}/sky/token when the issuer route 404s/405s — a 404/405
//     from BOTH endpoints latches the client into basic-auth mode
//     permanently (an old web node has no token endpoint at all).
//   - grant_type=password with the LOCAL_USERS credentials and the
//     fly client's scope set; client auth is the literal
//     "fly:Zmx5" basic pair the fly CLI sends to the token endpoint.
//   - The token is refreshed 60s before expiry under a singleflight:
//     concurrent callers share one mint, never a thundering herd.
//   - A 401 on a request that USED a bearer token invalidates the
//     cache and re-mints exactly once — a revoked/expired-early
//     token self-heals instead of failing the whole index fetch.
package concourse

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// tokenRefreshMargin is how early before expiry a cached token is
// considered stale — clock skew between dispatcher and ATC plus the
// request flight time must not expire mid-call. It is capped at
// half the token's TTL at store time so a short-lived token never
// gets a refresh window wider than its own lifetime.
const tokenRefreshMargin = 60 * time.Second

// tokenMintTimeout bounds one token mint detached from the caller's
// context — the flight's waiters share the result, so a single
// caller's cancellation must not abort a mint others are waiting on.
const tokenMintTimeout = 15 * time.Second

// tokenDefaultTTL applies when the token response omits expires_in.
const tokenDefaultTTL = time.Hour

// authMode selects how authorize() credentials a request.
type authMode int

const (
	// authModeAuto tries bearer first; a token-endpoint 404/405
	// latches authModeBasic.
	authModeAuto authMode = iota
	authModeBearer
	authModeBasic
)

// atcAuth is the Client's lazily-built auth state. It is created on
// first use under c.mu so zero-value Clients (tests constructing
// Client literals) work unchanged.
type atcAuth struct {
	client  *http.Client // token-endpoint transport (same as API calls)
	baseURL string       // trimmed BaseURL — token paths are root-relative
	user    string
	pass    string

	mu    sync.Mutex
	mode  authMode
	token string
	// refreshAt is expiresAt minus the effective refresh margin —
	// the fast path treats the token as stale once now passes it.
	refreshAt time.Time
	// flight is the in-flight token mint — done closes when it
	// settles; waiters read the result fields after <-done.
	flight *tokenFlight
}

type tokenFlight struct {
	done    chan struct{}
	token   string
	expires time.Time
	basic   bool
	err     error
}

// ensureAuth returns the client's auth state, building it on first
// call. Caller must hold c.mu.
func (c *Client) ensureAuth() *atcAuth {
	if c.auth == nil {
		c.auth = &atcAuth{
			client:  c.httpClient(),
			baseURL: strings.TrimSuffix(c.BaseURL, "/"),
			user:    c.User,
			pass:    c.Password,
		}
	}
	return c.auth
}

// authorize stamps credentials on req: bearer when a token is
// available, basic otherwise. It returns the bearer token it used
// ("" for basic auth or no token) so a 401 can invalidateToken the
// EXACT credential that failed — never a newer token another worker
// already re-minted.
func (c *Client) authorize(ctx context.Context, req *http.Request) (string, error) {
	c.mu.Lock()
	a := c.ensureAuth()
	c.mu.Unlock()
	return a.authorize(ctx, req)
}

// invalidateToken drops the cached token after a 401 — but ONLY when
// the cache still holds badToken, the exact credential the failed
// request carried. Without the match check, N workers whose requests
// all 401'd on the same dead token would each wipe the cache in
// turn, stampeding re-mints every time a fresher token lands.
func (c *Client) invalidateToken(badToken string) {
	if badToken == "" {
		return
	}
	c.mu.Lock()
	if c.auth != nil {
		c.auth.mu.Lock()
		if c.auth.token == badToken {
			c.auth.token = ""
			c.auth.refreshAt = time.Time{}
		}
		c.auth.mu.Unlock()
	}
	c.mu.Unlock()
}

func (a *atcAuth) authorize(ctx context.Context, req *http.Request) (string, error) {
	a.mu.Lock()
	if a.mode == authModeBasic {
		a.mu.Unlock()
		req.SetBasicAuth(a.user, a.pass)
		return "", nil
	}
	// Fast path: cached token still fresh (refreshAt already folds
	// in the min(margin, ttl/2) cap computed at store time).
	if a.token != "" && time.Now().Before(a.refreshAt) {
		tok := a.token
		a.mu.Unlock()
		req.Header.Set("Authorization", "Bearer "+tok)
		return tok, nil
	}
	// Singleflight: one mint at a time; everyone waits on done —
	// INCLUDING the caller that opened the flight, so leader and
	// waiter share one code path below.
	if a.flight == nil {
		f := &tokenFlight{done: make(chan struct{})}
		a.flight = f
		// The mint runs DETACHED from this caller's ctx: the flight
		// is shared, so one worker's cancellation must not fail a
		// mint the other seven are waiting on. WithoutCancel keeps
		// values; the 15s timeout bounds a wedged ATC.
		mintCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx), tokenMintTimeout)
		go func() {
			defer cancel()
			token, expires, basic, err := a.mint(mintCtx)
			a.mu.Lock()
			defer a.mu.Unlock()
			if a.flight == f {
				a.flight = nil
			}
			f.token, f.expires, f.basic, f.err = token, expires, basic, err
			if err == nil {
				if basic {
					a.mode = authModeBasic
				} else {
					a.mode = authModeBearer
					a.token = token
					// Refresh margin: early enough to absorb clock
					// skew + flight time, but never wider than half
					// the TTL — a 90s token with a 60s margin would
					// be stale before it was ever used.
					margin := tokenRefreshMargin
					if half := time.Until(expires) / 2; half < margin {
						margin = half
					}
					a.refreshAt = expires.Add(-margin)
				}
			}
			close(f.done)
		}()
	}
	f := a.flight
	a.mu.Unlock()

	select {
	case <-f.done:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	if f.err != nil {
		return "", f.err
	}
	if f.basic {
		req.SetBasicAuth(a.user, a.pass)
		return "", nil
	}
	req.Header.Set("Authorization", "Bearer "+f.token)
	return f.token, nil
}

// mint performs the token request, returning (token, expiry, basic,
// err). basic=true means both token endpoints 404/405'd — latch
// basic-auth mode.
func (a *atcAuth) mint(ctx context.Context) (string, time.Time, bool, error) {
	form := url.Values{
		"grant_type": {"password"},
		"username":   {a.user},
		"password":   {a.pass},
		"scope":      {"openid profile email federated:id groups"},
	}
	for _, path := range []string{"/sky/issuer/token", "/sky/token"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			a.baseURL+path, strings.NewReader(form.Encode()))
		if err != nil {
			return "", time.Time{}, false, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		// The fly CLI's client pair on the token endpoint.
		req.SetBasicAuth("fly", "Zmx5")
		resp, err := a.client.Do(req)
		if err != nil {
			return "", time.Time{}, false, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxJSONBody))
		_ = resp.Body.Close()
		if err != nil {
			return "", time.Time{}, false, err
		}
		if resp.StatusCode == http.StatusNotFound ||
			resp.StatusCode == http.StatusMethodNotAllowed {
			// This endpoint doesn't exist here — try the legacy path.
			continue
		}
		if resp.StatusCode/100 != 2 {
			return "", time.Time{}, false,
				fmt.Errorf("token endpoint %s: status %d", path, resp.StatusCode)
		}
		var tr struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int64  `json:"expires_in"`
		}
		if err := json.Unmarshal(body, &tr); err != nil {
			return "", time.Time{}, false,
				fmt.Errorf("token endpoint %s: decode: %w", path, err)
		}
		if tr.AccessToken == "" {
			return "", time.Time{}, false,
				fmt.Errorf("token endpoint %s: empty access_token", path)
		}
		ttl := time.Duration(tr.ExpiresIn) * time.Second
		if ttl <= 0 {
			ttl = tokenDefaultTTL
		}
		return tr.AccessToken, time.Now().Add(ttl), false, nil
	}
	// Both token endpoints are absent — this web node predates OIDC
	// tokens; latch basic auth permanently.
	return "", time.Time{}, true, nil
}
