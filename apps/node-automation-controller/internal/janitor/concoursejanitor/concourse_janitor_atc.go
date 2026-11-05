// Minimal Concourse ATC HTTP client (Concourse 8.3.2) — net/http
// only, replaces the fly binary the bash janitor downloaded from
// /api/v1/cli on every run. Only the calls the janitor needs are
// implemented: OAuth2 password-grant login, workers list, land, prune.
package concoursejanitor

import (
	"context"
	"encoding/json"
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
		return fmt.Errorf("atc token response has no access_token")
	}
	c.token = "Bearer " + tok.AccessToken
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
// carrying the status line.
func (c *atcClient) doJSON(ctx context.Context, method, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		// Drain so the connection can be reused (keep-alive);
		// bounded like login's drain so a misbehaving endpoint
		// cannot stall the return.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("atc %s %s: status %s", method, endpoint, resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
