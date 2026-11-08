// Minimal Concourse ATC HTTP client (Concourse 8.3.2) — net/http
// only, replaces the fly binary the bash janitor downloaded from
// /api/v1/cli on every run. Only the calls the janitor needs are
// implemented: OAuth2 password-grant login, workers list, land, prune.
package concoursejanitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// atcClient is the production atcIface.
type atcClient struct {
	base  string
	hc    *http.Client
	token string // "Bearer <token>", set by login
	// user/pass memoize the last SUCCESSFUL login's credentials so
	// doJSON can re-authenticate once when a 401 says the Dex token
	// expired mid-run (a 190m run outlives the ~1h token TTL). Calls
	// are strictly sequential within one run — no locking.
	user, pass string
}

func newATCClient(base string, hc *http.Client) *atcClient {
	return &atcClient{base: strings.TrimRight(base, "/"), hc: hc}
}

// login performs the OAuth2 password grant against skymarshal's
// dex-backed token issuer — the same flow `fly login -u -p` uses on
// Concourse ≥3.15 (fly/commands/login.go passwordGrant): the public
// client credentials fly:Zmx5 travel as HTTP Basic auth while the form
// carries grant_type=password and the user's own basic-auth
// credentials. Response is the standard RFC 6749 shape
// {"access_token","token_type"}.
//
// NOTE: the old `/api/v1/teams/:team/auth/token` GET+Basic endpoint is
// a Concourse ≤3.14 relic and does not exist on 8.x — do not "fix" the
// URL back to it. Any failure here is a real error; the caller
// degrades to flyOK=false (land/drain/prune skipped, pod delete still
// runs — same fail-open semantics as the bash janitor).
func (c *atcClient) login(ctx context.Context, user, pass string) error {
	form := url.Values{
		"grant_type": {"password"},
		"scope":      {"openid profile email federated:id groups"},
		"username":   {user},
		"password":   {pass},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/sky/issuer/token", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	// fly's hardcoded public client_id/client_secret — identical for
	// every fly binary in the world (fly/commands/login.go).
	req.SetBasicAuth("fly", "Zmx5")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		// Drain before Close so the keep-alive connection can be
		// reused; bounded so a misbehaving endpoint cannot stall the
		// return (same 64KiB cap as doJSON).
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("atc token: status %s", resp.Status)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return fmt.Errorf("atc token decode: %w", err)
	}
	if tok.AccessToken == "" {
		return errors.New("atc token response has no access_token")
	}
	c.token = "Bearer " + tok.AccessToken
	c.user, c.pass = user, pass
	return nil
}

// workerState returns the ATC-recorded state of worker `name`
// ("running", "landing", "landed", "stalled", "retiring", "retired"),
// or "" when the worker is not registered at all.
func (c *atcClient) workerState(ctx context.Context, name string) (string, error) {
	var workers []struct {
		Name  string `json:"name"`
		State string `json:"state"`
	}
	if err := c.doJSON(ctx, http.MethodGet, c.base+"/api/v1/workers", &workers); err != nil {
		return "", err
	}
	for _, w := range workers {
		if w.Name == name {
			return w.State, nil
		}
	}
	return "", nil
}

// landWorker PUTs /api/v1/workers/<name>/land — ATC stops scheduling
// new builds onto the worker. Worker routes are NOT team-scoped on
// Concourse 8.x (atc/routes.go).
func (c *atcClient) landWorker(ctx context.Context, name string) error {
	return c.doJSON(ctx, http.MethodPut,
		fmt.Sprintf("%s/api/v1/workers/%s/land", c.base, url.PathEscape(name)), nil)
}

// pruneWorker PUTs /api/v1/workers/<name>/prune — drops the worker
// record and cascade-deletes its volumes/containers from PostgreSQL.
func (c *atcClient) pruneWorker(ctx context.Context, name string) error {
	return c.doJSON(ctx, http.MethodPut,
		fmt.Sprintf("%s/api/v1/workers/%s/prune", c.base, url.PathEscape(name)), nil)
}

// doJSON runs an authenticated request; a non-2xx status is an error
// carrying the status line. A 401 means the token issued at login
// expired mid-run — the whole-run bound (cjRunTimeout) outlives the
// Dex token TTL, and every later call would 401: drain would then
// read the land confirmation as a land FAILURE and delete the worker
// pod undrained. doJSON therefore re-logins with the stored
// credentials and retries the request EXACTLY once — no loop; a
// second 401 (or a failed re-login) surfaces as the error it is.
func (c *atcClient) doJSON(ctx context.Context, method, endpoint string, out any) error {
	status, err := c.atcDo(ctx, method, endpoint, out)
	if err == nil || status != http.StatusUnauthorized {
		return err
	}
	if err := c.relogin(ctx); err != nil {
		return fmt.Errorf("atc re-login after 401 on %s %s: %w", method, endpoint, err)
	}
	_, err = c.atcDo(ctx, method, endpoint, out)
	return err
}

// relogin re-authenticates with the credentials of the last
// successful login — a no-op-friendly passthrough to login when they
// were never stored (the request then fails like the expired token
// did).
func (c *atcClient) relogin(ctx context.Context) error {
	return c.login(ctx, c.user, c.pass)
}

// atcDo issues ONE authenticated request; status is the HTTP status
// code (0 on transport error) and err the transport/status/decode
// error — a non-2xx status is an error carrying the status line.
func (c *atcClient) atcDo(ctx context.Context, method, endpoint string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return 0, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() {
		// Drain so the connection can be reused (keep-alive);
		// bounded like login's drain so a misbehaving endpoint
		// cannot stall the return.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode/100 != 2 {
		return resp.StatusCode, fmt.Errorf("atc %s %s: status %s", method, endpoint, resp.Status)
	}
	if out == nil {
		return resp.StatusCode, nil
	}
	return resp.StatusCode, json.NewDecoder(resp.Body).Decode(out)
}
