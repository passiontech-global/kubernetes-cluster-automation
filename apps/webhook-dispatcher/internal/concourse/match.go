// match.go — the repo-identity half of the index: NormalizeRepo
// (every GitHub repo spelling -> lowercase "org/repo"), the source
// decode fetchIndex runs per resource, the ATC instance_vars query
// encoding, the fetchIndex pipeline walk itself, and the O(1)
// (type, repo) -> resources lookup Match serves per delivery.
package concourse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// indexKey keys the lookup map: one entry per (resource type, repo)
// pair. A delivery's match is then a handful of map hits instead of a
// linear scan of every resource in the team on every webhook.
type indexKey struct {
	typ  string
	repo string
}

// newLookup builds the (type, repo) -> resources map for a freshly
// fetched index. Called once per publish, not once per delivery.
func newLookup(index []Resource) map[indexKey][]Resource {
	lookup := make(map[indexKey][]Resource, len(index))
	for _, r := range index {
		k := indexKey{r.Type, r.Repo}
		lookup[k] = append(lookup[k], r)
	}
	return lookup
}

// Match returns the current index's resources of wantType whose repo
// is one of repos — the O(1) lookup the handler's per-delivery match
// runs on, over the map newLookup built at the last fetch publish.
// Returned Resource values are copies: callers cannot reach the
// client's snapshot. Repos are visited in sorted order so the result
// order is deterministic (equal inputs, equal output — helps logs and
// tests; the fan-out itself is order-insensitive).
func (c *Client) Match(wantType string, repos map[string]struct{}) []Resource {
	c.mu.RLock()
	defer c.mu.RUnlock()
	// Fast path: the overwhelmingly common delivery carries exactly
	// one normalized repo — answer it without building the sorted
	// key slice. The value is still cloned out of the lookup map:
	// callers must never reach the client's snapshot.
	if len(repos) == 1 {
		for repo := range repos {
			return slices.Clone(c.lookup[indexKey{wantType, repo}])
		}
	}
	var matched []Resource
	for _, repo := range slices.Sorted(maps.Keys(repos)) {
		matched = append(matched, c.lookup[indexKey{wantType, repo}]...)
	}
	return matched
}

// source is the slice of a resource's source config the index needs:
// git-type resources carry the repo in "uri", github-pr resources in
// "repository". A struct rather than map[string]any: the decode keeps
// encoding/json's tolerance for every other key a resource type
// carries (interval, check_every, ...) and skips the per-resource map
// allocation — a whole-team index decode used to build a map per
// resource only to fish out one string.
type source struct {
	URI        string `json:"uri"`
	Repository string `json:"repository"`
}

// sourceRepo pulls the repo identity out of a resource's source;
// "uri" wins when both keys are present (a github-pr resource with a
// git uri checks out via the uri), the same precedence the map-based
// decode had.
func sourceRepo(s source) string {
	if s.URI != "" {
		return s.URI
	}
	return s.Repository
}

// NormalizeRepo reduces a GitHub repo identifier — scp-like SSH
// (git@github.com:org/repo.git), ssh:// or HTTPS URL
// (ssh://git@github.com[:port]/org/repo[.git],
// https://github.com[:port]/org/repo[.git]) or bare "org/repo" — to
// the lowercase "org/repo" form used for equality matching.
//
// The "github.com" prefix is stripped only where github.com can
// actually be the host: at the start of the string, or immediately
// after "://" (scheme separator) or "@" (scp user marker), AND only
// when "/" or ":" follows (path or scp separator). Anywhere else —
// "git.github.com", "notgithub.com", "github.com.evil.com", a mention
// inside a path — the match is part of a longer hostname or of the
// path, and the input must NOT collapse to "org/repo" or it would
// match resources it has no business matching.
func NormalizeRepo(s string) string {
	// Lowercase and strip the trailing ".git" up front: the host
	// match and the suffix strip are both case-sensitive, and an
	// upper-cased "GitHub.COM"/"Repo.GIT" must still normalize.
	// TrimRight (not a single TrimSuffix) so "org/repo//" does not
	// keep a stray trailing slash past the host strip below.
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimRight(s, "/")
	s = strings.TrimSuffix(s, ".git")
	// Scan every occurrence of "github.com": the FIRST literal match
	// is not necessarily the host — "github.com.evil.com/git@github.com:org/repo"
	// has a lookalike in front of a real host. The first occurrence
	// that passes the boundary check wins; if none does, every match
	// was part of a longer hostname or of a path, and the input must
	// NOT collapse to "org/repo".
	for i := strings.Index(s, "github.com"); i >= 0; {
		// Host boundary: start of string, or right after the scheme
		// separator or a user marker — and the host must be followed
		// by the path separator ("/") or the scp separator (":").
		atHost := i == 0 ||
			strings.HasSuffix(s[:i], "://") || strings.HasSuffix(s[:i], "@")
		rest := s[i+len("github.com"):]
		if atHost && hostInAuthority(s[:i]) && rest != "" &&
			(rest[0] == '/' || rest[0] == ':') {
			return normalizeRepoRest(s[:i], rest)
		}
		next := i + len("github.com")
		j := strings.Index(s[next:], "github.com")
		if j < 0 {
			break
		}
		i = next + j
	}
	return s
}

// hostInAuthority reports whether a "github.com" match at the end of
// prefix sits in the URL authority component — no '/' between the
// last "://" (or the string start) and the match. The "@" boundary
// check alone is not enough: "https://evil.com/git@github.com:org/repo"
// has a literal "git@" right before the match, but that "@" lives in
// the URL PATH, not the userinfo — without this guard the lookalike
// host collapses the whole URL to "org/repo" and matches resources
// it has no business matching.
func hostInAuthority(prefix string) bool {
	auth := prefix
	if k := strings.LastIndex(auth, "://"); k >= 0 {
		auth = auth[k+3:]
	}
	return !strings.ContainsRune(auth, '/')
}

// normalizeRepoRest strips the host's separator (scp colon, or an
// embedded :port on URL forms) and returns the trailing path.
// prefix is everything before the host match; rest starts at the
// "/" or ":" that confirmed the host boundary.
func normalizeRepoRest(prefix, rest string) string {
	if rest[0] == ':' {
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
	return strings.TrimLeft(rest, "/")
}

// fetchIndexWorkers bounds how many pipeline resource listings run
// concurrently — a large team shouldn't fan one GET per pipeline at
// the ATC all at once, but a serial listing is what made index
// rebuilds slow enough to matter.
const fetchIndexWorkers = 8

// fetchIndex lists the team's pipelines, then each pipeline's
// resources, keeping only resources whose source points at a repo.
// prev is the caller's snapshot of the current index, taken under
// c.mu before the fetch started; it is only read here. The
// per-pipeline listings run on at most min(fetchIndexWorkers,
// len(pipelines)) workers; results stay in pipeline order so the
// index is deterministic.
func (c *Client) fetchIndex(ctx context.Context,
	prev []Resource) ([]Resource, error) {
	start := time.Now()
	var pipelines []struct {
		Name         string         `json:"name"`
		Archived     bool           `json:"archived"`
		InstanceVars map[string]any `json:"instance_vars"`
	}
	if err := c.getJSON(ctx, c.apiPath("pipelines"), &pipelines); err != nil {
		return nil, err
	}
	// Archived pipelines are gone for check purposes — listing their
	// resources would index dead entries (and their /resources calls
	// can 404 or hang on the archived flag). Drop them up front.
	live := pipelines[:0]
	for _, p := range pipelines {
		if !p.Archived {
			live = append(live, p)
		}
	}
	pipelines = live

	// Snapshot the previous index per (pipeline, varsQuery): a
	// transient per-pipeline listing failure below must carry its
	// last-known resources into the new index rather than silently
	// unregistering them — err stays nil, so a partial result would
	// otherwise overwrite c.index with a silently smaller view. The
	// varsQuery half of the key matters: a set_pipeline step can
	// re-instance a pipeline under DIFFERENT vars while keeping the
	// name — carrying the old instance's resources over would index
	// entries the new instance does not have. (Copied from c.index
	// under c.mu by the caller before this fetch started, so no
	// lock is needed here.)
	prevByPipeline := make(map[string][]Resource)
	for _, r := range prev {
		key := r.Pipeline + "\x00" + r.InstanceVarsQuery
		prevByPipeline[key] = append(prevByPipeline[key], r)
	}

	results := make([][]Resource, len(pipelines))
	// varsQuery[i] is the pipeline's instance_vars rendered as the
	// ATC dot-notation query fragment — instanced pipelines only
	// resolve /resources and check webhooks under ?vars.<key>=, so
	// the same fragment rides every Resource and both call sites.
	// Empty for non-instanced pipelines.
	varsQuery := make([]string, len(pipelines))
	for i, p := range pipelines {
		varsQuery[i] = instanceVarsQuery(p.InstanceVars)
	}
	// lost[i] records a pipeline whose listing failed with nothing in
	// the previous index to carry over — the refreshed index would be
	// silently missing its resources, so the fetch must fail instead
	// of caching an incomplete view (see below). failed[i] records
	// ANY listing failure (404-deleted pipelines excluded — they are
	// gone, not unreadable): when every listing fails the "refresh"
	// learned nothing, and returning the carried-over prev data as a
	// success would stamp fetchedAt and freeze the stale index for
	// the whole TTL.
	lost := make([]string, len(pipelines))
	failed := make([]bool, len(pipelines))
	// Bounded worker pool: spawn at most min(fetchIndexWorkers,
	// len(pipelines)) goroutines — one per pipeline is wasted on
	// small teams, and every goroutine beyond the semaphore bound
	// was just parked on the channel anyway. Each worker pulls a
	// pipeline index off jobs and writes its result slot; results
	// stay indexed by pipeline, so order and dedup are unchanged.
	workers := min(fetchIndexWorkers, len(pipelines))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for i := range jobs {
				p := pipelines[i]
				var resources []struct {
					Name   string `json:"name"`
					Type   string `json:"type"`
					Source source `json:"source"`
				}
				path := "pipelines/" + url.PathEscape(p.Name) + "/resources"
				if varsQuery[i] != "" {
					path += "?" + varsQuery[i]
				}
				if err := c.getJSON(ctx, c.apiPath(path), &resources); err != nil {
					var se *statusError
					if errors.As(err, &se) && se.status == http.StatusNotFound {
						// The pipeline was deleted between the pipeline
						// listing and this fetch — it has no resources.
						// Carrying prevByPipeline entries over would keep
						// ghost resources of a dead pipeline in the index.
						return
					}
					// One unreadable pipeline must not lose the whole
					// index — and must not lose its own resources either:
					// retain the previous index's entries for it (the
					// pipeline still exists — only its listing failed).
					// Pipelines truly gone drop out via the pipeline list
					// itself, not through this path. The carry-over key
					// includes the vars fragment — resources of a
					// re-instanced pipeline under different vars must
					// not leak into the new instance's index.
					carryKey := p.Name + "\x00" + varsQuery[i]
					results[i] = append(results[i], prevByPipeline[carryKey]...)
					failed[i] = true
					if len(prevByPipeline[carryKey]) == 0 {
						// Nothing to carry over — the new index would
						// silently lack this pipeline's resources.
						lost[i] = p.Name
					}
					logger().Warn("pipeline resource listing failed — keeping last-known resources",
						"concourse_url", c.safeBaseURL(), "team", c.Team,
						"pipeline", p.Name, "error", err)
					return
				}
				for _, r := range resources {
					repo := NormalizeRepo(sourceRepo(r.Source))
					if repo == "" {
						continue
					}
					results[i] = append(results[i], Resource{
						Pipeline:          p.Name,
						Name:              r.Name,
						Type:              r.Type,
						Repo:              repo,
						InstanceVarsQuery: varsQuery[i],
					})
				}
			}
		})
	}
	for i := range pipelines {
		jobs <- i
	}
	close(jobs)
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

	// Every pipeline listing failed: the fetch produced nothing but
	// carried-over prev entries. Returning them as a success would
	// stamp fetchedAt (and satisfy Refresh's freshness throttle) on
	// data that never refreshed — the stale index would be served as
	// "fresh" for the whole TTL. Fail so the callers take the error
	// path: serve stale through lastAttemptAt backoff and retry.
	if len(pipelines) > 0 {
		allFailed := true
		for _, f := range failed {
			if !f {
				allFailed = false
				break
			}
		}
		if allFailed {
			return nil, fmt.Errorf(
				"all %d pipeline resource listings failed", len(pipelines))
		}
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
		"concourse_url", c.safeBaseURL(), "team", c.Team,
		"pipelines", len(pipelines), "resources", len(index),
		"duration", time.Since(start).Round(time.Millisecond))
	return index, nil
}

// instanceVarsQuery renders a pipeline's instance_vars as the ATC
// dot-notation query fragment, mirroring Concourse's own encoder
// (atc/pipeline.go QueryParams over vars.StaticVariables.Flatten):
// nested maps are FLATTENED into dot-joined leaf paths — the ATC
// parses vars.a.b back into {"a":{"b":...}}, so a nested instance_vars
// must never be sent as one JSON blob — and every path segment that
// contains a dot (or any of ",.:/ ") is %q-quoted so a literal
// "release.line" key stays one segment instead of reading as nesting.
// One vars.<key>=<json-val> param per leaf, keys sorted by rendered
// ref so two fetches of the same vars produce byte-identical
// fragments (cache-friendly, diff-friendly logs). "" for
// non-instanced pipelines; empty maps flatten to zero pairs (the var
// vanishes, matching Flatten); a leaf whose value fails to marshal
// is skipped rather than failing the whole listing.
func instanceVarsQuery(vars map[string]any) string {
	if len(vars) == 0 {
		return ""
	}
	pairs := flattenInstanceVars(vars)
	slices.SortFunc(pairs, func(a, b instanceVarPair) int {
		return strings.Compare(a.ref, b.ref)
	})
	var b strings.Builder
	for _, p := range pairs {
		v, err := json.Marshal(p.value)
		if err != nil {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape("vars." + p.ref))
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(string(v)))
	}
	return b.String()
}

// instanceVarPair is one flattened leaf: the dot-notation ref the
// ATC parses (segments already quoting-applied) plus its JSON value.
type instanceVarPair struct {
	ref   string
	value any
}

// flattenInstanceVars walks the instance_vars tree the way
// vars.StaticVariables.Flatten does: only map[string]any nodes
// recurse — every other value (including lists and nil) is a leaf.
// An empty map contributes zero pairs.
func flattenInstanceVars(vars map[string]any) []instanceVarPair {
	var pairs []instanceVarPair
	for k, v := range vars {
		pairs = append(pairs, flattenInstanceVar(k, nil, v)...)
	}
	return pairs
}

func flattenInstanceVar(path string, fields []string, value any) []instanceVarPair {
	if m, ok := value.(map[string]any); ok {
		var out []instanceVarPair
		for k, v := range m {
			out = append(out, flattenInstanceVar(path, append(fields, k), v)...)
		}
		return out
	}
	var b strings.Builder
	b.WriteString(instanceVarSegment(path))
	for _, f := range fields {
		b.WriteByte('.')
		b.WriteString(instanceVarSegment(f))
	}
	return []instanceVarPair{{ref: b.String(), value: value}}
}

// instanceVarSegment quotes a path segment exactly like Concourse's
// refSegmentString: segments containing a separator char (",.:/ ")
// are wrapped in Go quoting so the ATC's dot-notation parser keeps
// them as ONE field.
func instanceVarSegment(seg string) string {
	if strings.ContainsAny(seg, ",.:/ ") {
		return fmt.Sprintf("%q", seg)
	}
	return seg
}
