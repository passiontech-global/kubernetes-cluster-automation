// Package concourse implements the small slice of the Concourse ATC
// API the dispatcher needs: listing pipelines and their resources to
// build a repo -> resource index, and POSTing resource check webhooks.
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
	"time"
)

// Resource is one Concourse resource pinned to a GitHub repo. Repo is
// the normalized "org/repo" form produced by NormalizeRepo.
type Resource struct {
	Pipeline string
	Name     string
	Type     string
	Repo     string
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

	mu        sync.Mutex
	index     []Resource
	fetchedAt time.Time
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

// Resources returns the repo -> resource index, served from a ~60s
// cache and refreshed on a miss (absent or expired). A failed refresh
// falls back to the stale index when one exists.
func (c *Client) Resources(ctx context.Context) ([]Resource, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.index != nil && time.Since(c.fetchedAt) < c.ttl() {
		return c.index, nil
	}
	index, err := c.fetchIndex(ctx)
	if err != nil {
		if c.index != nil {
			logger().Warn("resource index refresh failed — serving stale",
				"concourse_url", c.BaseURL, "team", c.Team,
				"error", err)
			return c.index, nil
		}
		return nil, err
	}
	c.index, c.fetchedAt = index, time.Now()
	return index, nil
}

// Refresh forces an index refetch, bypassing the TTL — used when a
// delivery matched nothing, covering a pipeline set since the last
// fetch. Calls are throttled to MinRefreshInterval: repos without a
// pipeline zero-match every delivery, so an unthrottled refresh would
// turn org-webhook volume into constant index rebuilds. A failed
// refresh keeps the previous index.
func (c *Client) Refresh(ctx context.Context) ([]Resource, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if time.Since(c.fetchedAt) < c.minRefreshInterval() {
		return c.index, nil
	}
	index, err := c.fetchIndex(ctx)
	if err != nil {
		return nil, err
	}
	c.index, c.fetchedAt = index, time.Now()
	return index, nil
}

// fetchIndexWorkers bounds how many pipeline resource listings run
// concurrently — a large team shouldn't fan one GET per pipeline at
// the ATC all at once, but a serial listing is what made index
// rebuilds slow enough to matter.
const fetchIndexWorkers = 8

// fetchIndex lists the team's pipelines, then each pipeline's
// resources, keeping only resources whose source points at a repo.
// The per-pipeline listings run in parallel (bounded by
// fetchIndexWorkers); results stay in pipeline order so the index is
// deterministic.
func (c *Client) fetchIndex(ctx context.Context) ([]Resource, error) {
	start := time.Now()
	var pipelines []struct {
		Name string `json:"name"`
	}
	if err := c.getJSON(ctx, c.apiPath("pipelines"), &pipelines); err != nil {
		return nil, err
	}

	results := make([][]Resource, len(pipelines))
	sem := make(chan struct{}, fetchIndexWorkers)
	var wg sync.WaitGroup
	for i, p := range pipelines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var resources []struct {
				Name   string         `json:"name"`
				Type   string         `json:"type"`
				Source map[string]any `json:"source"`
			}
			path := "pipelines/" + url.PathEscape(p.Name) + "/resources"
			if err := c.getJSON(ctx, c.apiPath(path), &resources); err != nil {
				// One unreadable pipeline must not lose the whole index.
				logger().Warn("pipeline resource listing failed — skipped",
					"concourse_url", c.BaseURL, "team", c.Team,
					"pipeline", p.Name, "error", err)
				return
			}
			for _, r := range resources {
				repo := NormalizeRepo(sourceRepo(r.Source))
				if repo == "" {
					continue
				}
				results[i] = append(results[i], Resource{
					Pipeline: p.Name,
					Name:     r.Name,
					Type:     r.Type,
					Repo:     repo,
				})
			}
		}()
	}
	wg.Wait()

	var index []Resource
	for _, rs := range results {
		index = append(index, rs...)
	}
	if index == nil {
		// Keep it non-nil: a healthy empty index must still count as
		// "fetched" for the TTL check and the stale fallback.
		index = []Resource{}
	}
	logger().Info("resource index refreshed",
		"concourse_url", c.BaseURL, "team", c.Team,
		"pipelines", len(pipelines), "resources", len(index),
		"duration", time.Since(start).Round(time.Millisecond))
	return index, nil
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		// Do wraps transport failures in *url.Error, which embeds the
		// full request URL — webhook_token included — and would leak
		// the token into error logs. Return only the wrapped error.
		var ue *url.Error
		if errors.As(err, &ue) {
			return 0, ue.Err
		}
		return 0, err
	}
	defer resp.Body.Close()
	// Drain (bounded) so the keep-alive connection can be reused.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, nil
}

// apiPath prefixes p with the team-scoped API root.
func (c *Client) apiPath(p string) string {
	return "/api/v1/teams/" + url.PathEscape(c.Team) + "/" + p
}

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimSuffix(c.BaseURL, "/")+path, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.User, c.Password)
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		// Drain (bounded) so the keep-alive connection can be reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return fmt.Errorf("GET %s: unexpected status %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// sourceRepo pulls the repo identity out of a resource's source:
// git-type resources carry "uri", github-pr resources "repository".
func sourceRepo(source map[string]any) string {
	for _, k := range []string{"uri", "repository"} {
		if v, ok := source[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// NormalizeRepo reduces a GitHub repo identifier — scp-like SSH
// (git@github.com:org/repo.git), HTTPS URL
// (https://github.com/org/repo[.git]) or bare "org/repo" — to the
// lowercase "org/repo" form used for equality matching.
func NormalizeRepo(s string) string {
	s = strings.TrimSpace(s)
	// Strip the "github.com" host prefix from URL/scp-like forms. The
	// boundary check keeps lookalike hosts (e.g. "notgithub.com")
	// from being treated as github.com.
	if i := strings.Index(s, "github.com"); i >= 0 &&
		(i == 0 || strings.ContainsRune("/@.", rune(s[i-1]))) {
		rest := s[i+len("github.com"):]
		if rest != "" && rest[0] == ':' {
			// After the colon: either an optional :port (URL form —
			// digits immediately followed by /) or the scp-style
			// separator itself.
			rest = rest[1:]
			j := 0
			for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
				j++
			}
			if j > 0 && j < len(rest) && rest[j] == '/' {
				rest = rest[j:]
			}
		}
		s = strings.TrimLeft(rest, "/")
	}
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimSuffix(s, ".git")
	return strings.ToLower(s)
}
