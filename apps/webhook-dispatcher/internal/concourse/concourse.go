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
	// lastAttemptAt stamps the start of the most recent fetch attempt
	// — success or failure — so a failed refresh backs off instead of
	// letting every caller block on a fresh fetch against a dead ATC,
	// and callers arriving mid-fetch are served the current index
	// rather than queueing a second fetch.
	lastAttemptAt time.Time
	// fetching marks an in-flight index fetch (never held across the
	// network wait without the mutex released — it is set under the
	// lock before the fetch starts and cleared after it settles), so
	// a caller with no index to serve fails fast instead of starting
	// its own duplicate fetch.
	fetching bool
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
// falls back to the stale index when one exists, and further calls
// inside the TTL window keep serving it — lastAttemptAt backs the
// fetch off so an ATC outage doesn't serialize every webhook request
// behind the HTTP timeout.
//
// The mutex is never held across the network fetch: the decision and
// the lastAttemptAt stamp happen under the lock, the fetch runs
// unlocked, and only a successful publish re-takes it. Callers that
// arrive while a fetch is in flight are served the current index
// immediately (stale is fine — the in-flight fetch will replace it),
// so a slow or wedged ATC cannot serialize webhook deliveries behind
// c.mu.
func (c *Client) Resources(ctx context.Context) ([]Resource, error) {
	c.mu.Lock()
	if c.index != nil && time.Since(c.fetchedAt) < c.ttl() {
		index := c.index
		c.mu.Unlock()
		return index, nil
	}
	// The last attempt failed inside the same TTL window — serve the
	// stale index without re-fetching. Without this backoff every
	// request re-takes the mutex and blocks on a doomed fetch.
	if c.index != nil && time.Since(c.lastAttemptAt) < c.ttl() {
		index := c.index
		c.mu.Unlock()
		return index, nil
	}
	// A fetch already in flight and no index to serve: fail fast —
	// queueing this caller behind the in-flight fetch is exactly the
	// serialization this method exists to avoid.
	if c.index == nil && c.fetching {
		c.mu.Unlock()
		return nil, errors.New("resource index refresh already in progress")
	}
	// Stamp the attempt before starting the fetch: concurrent callers
	// hitting the checks above while this fetch is in flight must see
	// a fresh lastAttemptAt and be served the existing index instead
	// of starting their own fetch behind this one.
	c.lastAttemptAt = time.Now()
	c.fetching = true
	prev := append([]Resource(nil), c.index...)
	c.mu.Unlock()

	index, err := c.fetchIndex(ctx, prev)
	c.mu.Lock()
	c.fetching = false
	if err != nil {
		if c.index != nil {
			logger().Warn("resource index refresh failed — serving stale",
				"concourse_url", c.BaseURL, "team", c.Team,
				"error", err)
			c.mu.Unlock()
			return c.index, nil
		}
		c.mu.Unlock()
		return nil, err
	}
	c.index, c.fetchedAt = index, time.Now()
	c.mu.Unlock()
	return index, nil
}

// Refresh forces an index refetch, bypassing the TTL — used when a
// delivery matched nothing, covering a pipeline set since the last
// fetch. Calls are throttled to MinRefreshInterval: repos without a
// pipeline zero-match every delivery, so an unthrottled refresh would
// turn org-webhook volume into constant index rebuilds. A failed
// refresh keeps the previous index.
//
// The throttle watches lastAttemptAt, not just fetchedAt: fetchedAt
// only moves on success, so during an ATC outage an unmatched
// delivery would otherwise grab the mutex and block on a doomed
// network fetch every time — stalling every other webhook behind
// the HTTP timeout. The fetch itself runs outside the mutex, same
// snapshot pattern as Resources.
func (c *Client) Refresh(ctx context.Context) ([]Resource, error) {
	c.mu.Lock()
	// lastAttemptAt >= fetchedAt always (a success stamps both, a
	// failure stamps only the attempt), so the attempt stamp alone
	// covers both "recently fetched" and "recently failed".
	if time.Since(c.lastAttemptAt) < c.minRefreshInterval() {
		index := c.index
		c.mu.Unlock()
		return index, nil
	}
	// Stamp the attempt before the fetch so concurrent Refresh callers
	// take the throttle branch instead of queueing a second doomed
	// fetch behind this one; a failure keeps that stamp so a later
	// Resources call serves the stale index inside its backoff window
	// instead of immediately re-fetching a just-failed ATC.
	c.lastAttemptAt = time.Now()
	c.fetching = true
	prev := append([]Resource(nil), c.index...)
	c.mu.Unlock()

	index, err := c.fetchIndex(ctx, prev)
	c.mu.Lock()
	c.fetching = false
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.index, c.fetchedAt = index, time.Now()
	c.mu.Unlock()
	return index, nil
}

// fetchIndexWorkers bounds how many pipeline resource listings run
// concurrently — a large team shouldn't fan one GET per pipeline at
// the ATC all at once, but a serial listing is what made index
// rebuilds slow enough to matter.
const fetchIndexWorkers = 8

// fetchIndex lists the team's pipelines, then each pipeline's
// resources, keeping only resources whose source points at a repo.
// prev is the caller's snapshot of the current index, taken under
// c.mu before the fetch started. The per-pipeline listings run in
// parallel (bounded by fetchIndexWorkers); results stay in pipeline
// order so the index is deterministic.
func (c *Client) fetchIndex(ctx context.Context,
	prev []Resource) ([]Resource, error) {
	start := time.Now()
	var pipelines []struct {
		Name string `json:"name"`
	}
	if err := c.getJSON(ctx, c.apiPath("pipelines"), &pipelines); err != nil {
		return nil, err
	}

	// Snapshot the previous index per pipeline: a transient
	// per-pipeline listing failure below must carry its last-known
	// resources into the new index rather than silently unregistering
	// them — err stays nil, so a partial result would otherwise
	// overwrite c.index with a silently smaller view. (Copied from
	// c.index under c.mu by the caller before this fetch started, so
	// no lock is needed here.)
	prevByPipeline := make(map[string][]Resource)
	for _, r := range prev {
		prevByPipeline[r.Pipeline] = append(prevByPipeline[r.Pipeline], r)
	}

	results := make([][]Resource, len(pipelines))
	// lost[i] records a pipeline whose listing failed with nothing in
	// the previous index to carry over — the refreshed index would be
	// silently missing its resources, so the fetch must fail instead
	// of caching an incomplete view (see below).
	lost := make([]string, len(pipelines))
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
				// One unreadable pipeline must not lose the whole
				// index — and must not lose its own resources either:
				// retain the previous index's entries for it (the
				// pipeline still exists — only its listing failed).
				// Pipelines truly gone drop out via the pipeline list
				// itself, not through this path.
				results[i] = append(results[i], prevByPipeline[p.Name]...)
				if len(prevByPipeline[p.Name]) == 0 {
					// Nothing to carry over — the new index would
					// silently lack this pipeline's resources.
					lost[i] = p.Name
				}
				logger().Warn("pipeline resource listing failed — keeping last-known resources",
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

	// A pipeline whose listing failed with no last-known resources to
	// carry means the index is incomplete: caching it would stamp
	// fetchedAt and answer 202/nothing-matched for the TTL window,
	// dropping build triggers. Fail the fetch instead — the callers
	// then serve the stale index (or 502 on a cold start) and retry.
	var missing []string
	for _, name := range lost {
		if name != "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf(
			"resource listings failed with no prior data: %s",
			strings.Join(missing, ","))
	}

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
	defer func() { _ = resp.Body.Close() }()
	// Drain (bounded) so the keep-alive connection can be reused.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, nil
}

// apiPath prefixes p with the team-scoped API root.
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
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		// Drain (bounded) so the keep-alive connection can be reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return fmt.Errorf("GET %s: unexpected status %d", path, resp.StatusCode)
	}
	// Bound the decode: without LimitReader a 2xx body longer than
	// maxJSONBody (an ATC streaming forever) would be buffered whole.
	return json.NewDecoder(io.LimitReader(resp.Body, maxJSONBody)).Decode(out)
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
// (git@github.com:org/repo.git), ssh:// or HTTPS URL
// (ssh://git@github.com[:port]/org/repo[.git],
// https://github.com[:port]/org/repo[.git]) or bare "org/repo" — to
// the lowercase "org/repo" form used for equality matching.
func NormalizeRepo(s string) string {
	// Lowercase and strip the trailing ".git" up front: the host
	// match and the suffix strip are both case-sensitive, and an
	// upper-cased "GitHub.COM"/"Repo.GIT" must still normalize.
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimSuffix(s, ".git")
	// Strip the "github.com" host prefix from URL/scp-like forms. The
	// boundary check keeps lookalike hosts (e.g. "notgithub.com")
	// from being treated as github.com.
	if i := strings.Index(s, "github.com"); i >= 0 &&
		(i == 0 || strings.ContainsRune("/@.", rune(s[i-1]))) {
		rest := s[i+len("github.com"):]
		if rest != "" && rest[0] == ':' {
			rest = rest[1:]
			// What the colon means depends on the syntax around the
			// host:
			//   scheme://[user@]host:port/path — a :<digits>/ segment
			//     is a TCP port to drop;
			//   host:port/path with no user part — likewise a port;
			//   user@host:path (scp-like, "git@github.com:…") — the
			//     colon IS the path separator, so an all-numeric
			//     first segment is an org, not a port.
			// Scp-like = a user@ part ahead of the host with no "//"
			// authority marker before it.
			prefix := s[:i]
			scpLike := strings.ContainsRune(prefix, '@') &&
				!strings.Contains(prefix, "//")
			if !scpLike {
				j := 0
				for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
					j++
				}
				if j > 0 && j < len(rest) && rest[j] == '/' {
					rest = rest[j:]
				}
			}
		}
		s = strings.TrimLeft(rest, "/")
	}
	return s
}
