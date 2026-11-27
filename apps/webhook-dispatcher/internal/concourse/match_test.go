// match_test.go — repo identity and matching: NormalizeRepo's
// host-boundary cases, the source decode precedence, the O(1) Match
// lookup checked against a linear scan, the instance_vars query
// encoding, and the per-delivery fan-out lookup benchmark.
package concourse

import (
	json "encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"testing"
)

func TestNormalizeRepo(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"git@github.com:org/repo.git", "org/repo"},
		{"git@github.com:org/repo", "org/repo"},
		{"https://github.com/org/repo.git", "org/repo"},
		{"https://github.com/org/repo", "org/repo"},
		{"https://github.com/org/repo/", "org/repo"},
		{"https://github.com/org/repo.git/", "org/repo"},
		{"http://github.com/org/repo", "org/repo"},
		{"ssh://git@github.com/org/repo.git", "org/repo"},
		{"ssh://git@github.com:22/org/repo.git", "org/repo"},
		{"github.com:443/org/repo", "org/repo"},
		// Digits after the scp colon that aren't followed by a slash
		// are part of the repo name, not a port.
		{"git@github.com:22org/repo", "22org/repo"},
		// An all-numeric org after the scp colon is an ORG, not a
		// port — "git@host:path" carries no port syntax.
		{"git@github.com:12345/repo.git", "12345/repo"},
		{"git@github.com:12345/Repo", "12345/repo"},
		// Real ports on URL forms are still dropped.
		{"ssh://git@github.com:2222/org/repo.git", "org/repo"},
		{"https://github.com:8443/org/repo", "org/repo"},
		// Case is normalized everywhere — host match and the .git
		// strip must see the lowercased input.
		{"HTTPS://GitHub.COM/Org/Repo.GIT", "org/repo"},
		{"SSH://Git@GitHub.Com:2222/Org/Repo.Git", "org/repo"},
		{"git://github.com/org/repo", "org/repo"},
		{"github.com/org/repo", "org/repo"},
		{"org/repo", "org/repo"},
		{"org/repo.git", "org/repo"},
		{"org/repo/.git", "org/repo"},
		{"Org/Repo", "org/repo"},
		{"  git@github.com:Org/Repo.git  ", "org/repo"},
		{"", ""},
		{"  ", ""},
		// A lookalike host must not collapse to "org/repo" — the
		// boundary check keeps it from matching a real resource.
		{"https://notgithub.com/org/repo", "https://notgithub.com/org/repo"},
		// Mid-string matches are part of a longer hostname or of a
		// path — never stripped, whatever surrounds them.
		{"https://git.github.com/org/repo", "https://git.github.com/org/repo"},
		{"https://mygithub.com:8443/org/repo", "https://mygithub.com:8443/org/repo"},
		{"https://example.com/github.com/org/repo", "https://example.com/github.com/org/repo"},
		{"org/github.com", "org/github.com"},
		{"github.comorg/repo", "github.comorg/repo"},
		// The host must be followed by "/" or ":" — a different next
		// byte means the match is not the host (spoofed or bare host).
		{"https://github.com.evil.com/org/repo", "https://github.com.evil.com/org/repo"},
		{"git@github.com.evil.com:org/repo", "git@github.com.evil.com:org/repo"},
		{"github.com", "github.com"},
		// Multiple trailing slashes are trimmed with the rest —
		// TrimRight, not a single-suffix strip.
		{"org/repo///", "org/repo"},
		{"https://github.com/org/repo//", "org/repo"},
		{"git@github.com:org/repo//", "org/repo"},
		// The first "github.com" literal may be a lookalike host while
		// a LATER occurrence is the real host — the scan must keep
		// going instead of giving up at #1. Here the second match
		// sits in the URL userinfo ("…@github.com/…"), so it IS the
		// host.
		{"https://github.com.evil.com@github.com/org/repo", "org/repo"},
		// But a github.com in a PATH (after a slash) is never a host,
		// whatever it is followed by — even when a lookalike host
		// precedes it and a "git@" marker sits right before the match
		// (that "@" is path text, not userinfo).
		{"github.com.evil.com/git@github.com:org/repo", "github.com.evil.com/git@github.com:org/repo"},
		{"https://git.example.com/github.com/org/repo", "https://git.example.com/github.com/org/repo"},
		{"mirror/github.com/org/repo", "mirror/github.com/org/repo"},
		{"github.com/org/repo", "org/repo"},
		{"ssh://github.com:owner/repo", "owner/repo"},
		{"GIT@GitHub.COM:Owner/Repo.Git", "owner/repo"},
		// Query, fragment, and path-embedded "://" authority smuggling
		// must never collapse to "org/repo".
		{"https://evil.com?x=@github.com/org/repo", "https://evil.com?x=@github.com/org/repo"},
		{"https://evil.com#x=@github.com/org/repo", "https://evil.com#x=@github.com/org/repo"},
		{"evil.com?x=@github.com:org/repo", "evil.com?x=@github.com:org/repo"},
		{"https://evil.com/http://github.com/org/repo", "https://evil.com/http://github.com/org/repo"},
		{"https://evil.com?next=https://github.com/org/repo", "https://evil.com?next=https://github.com/org/repo"},
		{"https://evil.com#https://github.com/org/repo", "https://evil.com#https://github.com/org/repo"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := NormalizeRepo(tc.in); got != tc.want {
				t.Fatalf("NormalizeRepo(%q)=%q want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSourceRepo(t *testing.T) {
	// "uri" wins when both keys are present — the same precedence the
	// map-based decode had.
	if got := sourceRepo(source{URI: "u", Repository: "r"}); got != "u" {
		t.Fatalf("uri precedence=%q want u", got)
	}
	if got := sourceRepo(source{Repository: "r"}); got != "r" {
		t.Fatalf("repository=%q want r", got)
	}
	if got := sourceRepo(source{}); got != "" {
		t.Fatalf("empty source=%q want empty", got)
	}
	// Struct decode tolerance: every other field a resource type
	// carries (interval, check_every, nested version, ...) must be
	// ignored without failing the decode.
	var s source
	body := `{"uri":"git@github.com:org/repo.git","repository":"org/repo",` +
		`"interval":"1h","check_every":"0","insecure":true,"depth":1,` +
		`"version":{"ref":"main"},"tags":["v1"]}`
	if err := json.Unmarshal([]byte(body), &s); err != nil {
		t.Fatalf("decode with unknown fields: %v", err)
	}
	if s.URI != "git@github.com:org/repo.git" || s.Repository != "org/repo" {
		t.Fatalf("decoded=%+v want the uri/repository strings", s)
	}

	// Non-string uri/repository values (object, array, number, bool, null)
	// and null source must decode cleanly without failing with SemanticError.
	for _, tc := range []struct {
		name string
		json string
		want source
	}{
		{"object_uri_string_repo", `{"uri":{"url":"x"},"repository":"org/repo"}`, source{Repository: "org/repo"}},
		{"array_uri_bool_repo", `{"uri":["a"],"repository":true}`, source{}},
		{"number_uri_null_repo", `{"uri":123,"repository":null}`, source{}},
		{"bool_uri_object_repo", `{"uri":false,"repository":{"owner":"org"}}`, source{}},
		{"null_uri_string_repo", `{"uri":null,"repository":"org/pr"}`, source{Repository: "org/pr"}},
		{"null_source", `null`, source{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got source
			if err := json.Unmarshal([]byte(tc.json), &got); err != nil {
				t.Fatalf("Unmarshal(%s): %v", tc.json, err)
			}
			if got != tc.want {
				t.Fatalf("got=%+v want %+v", got, tc.want)
			}
		})
	}

	// Non-object JSON value returns *json.SemanticError.
	var badType source
	var semErr *json.SemanticError
	if err := json.Unmarshal([]byte(`[]`), &badType); !errors.As(err, &semErr) {
		t.Fatalf("Unmarshal([]) err=%v want *json.SemanticError", err)
	}
	// Truncated/invalid JSON surfaces syntactic/IO error rather than SemanticError.
	if err := json.Unmarshal([]byte(`{"uri":`), &badType); err == nil {
		t.Fatal("Unmarshal truncated JSON want error")
	} else if errors.As(err, &semErr) {
		t.Fatalf("Unmarshal truncated JSON returned SemanticError %v, want syntactic/EOF error", err)
	}
}

func TestFetchIndexUsesConfigEndpointWhenResourcesOmitsSource(t *testing.T) {
	// Regression: real Concourse ATC /pipelines/<p>/resources omits "source"
	// completely; fetchIndex must read /pipelines/<p>/config instead.
	stub := newATCStub(t, map[string]string{
		"/api/v1/teams/main/pipelines": `[{"name":"p1"}]`,
		"/api/v1/teams/main/pipelines/p1/resources": `[
			{"name":"real-git","pipeline_name":"p1","team_name":"main","type":"git","last_checked":1795768279}
		]`,
		"/api/v1/teams/main/pipelines/p1/config": `{"config":{
			"jobs":[{"name":"build"}],
			"resources":[
				{"name":"real-git","type":"git","webhook_token":"((ci.github_webhook_token))","source":{"uri":"git@github.com:org/repo.git","private_key":"((ci.github_private_key))"}},
				{"name":"real-pr","type":"github-pr","webhook_token":"((ci.github_webhook_token))","source":{"repository":"org/repo"}}
			]
		}}`,
	})
	c := &Client{BaseURL: stub.srv.URL, Team: "main", User: "u", Password: "p"}

	index, err := c.Resources(t.Context())
	if err != nil {
		t.Fatalf("Resources failed: %v", err)
	}
	if len(index) != 2 {
		t.Fatalf("index=%+v want 2 resources from /config", index)
	}
	if stub.hitCount("/api/v1/teams/main/pipelines/p1/config") != 1 {
		t.Fatalf("expected 1 hit to /config, got %d", stub.hitCount("/api/v1/teams/main/pipelines/p1/config"))
	}
	if stub.hitCount("/api/v1/teams/main/pipelines/p1/resources") != 0 {
		t.Fatalf("expected 0 hits to /resources, got %d", stub.hitCount("/api/v1/teams/main/pipelines/p1/resources"))
	}
}

func TestFetchIndexToleratesNonStringSourceFields(t *testing.T) {
	stub := newATCStub(t, map[string]string{
		"/api/v1/teams/main/pipelines": `[{"name":"p1"}]`,
		"/api/v1/teams/main/pipelines/p1/config": `{"config":{"resources":[
			{"name":"custom-obj-uri","type":"custom","source":{"uri":{"nested":1},"repository":"org/repo"}},
			{"name":"custom-num-repo","type":"custom","source":{"repository":42}},
			{"name":"null-source","type":"time","source":null},
			{"name":"real-git","type":"git","source":{"uri":"https://github.com/org/repo"}}
		]}}`,
	})
	c := &Client{BaseURL: stub.srv.URL, Team: "main", User: "u", Password: "p"}

	index, err := c.Resources(t.Context())
	if err != nil {
		t.Fatalf("Resources failed on non-string source fields: %v", err)
	}
	if len(index) != 2 {
		t.Fatalf("index=%+v want 2 resources", index)
	}
}

func TestSourceDecodeToleratesUnknownFields(t *testing.T) {
	// fetchIndex decodes Source into the two-key source struct, not
	// map[string]any: every other field a resource type carries must
	// be ignored (no decode failure), and "uri" must win over
	// "repository" when both are present — the map decode's precedence.
	stub := newATCStub(t, map[string]string{
		"/api/v1/teams/main/pipelines": `[{"name":"p1"}]`,
		"/api/v1/teams/main/pipelines/p1/config": `{"config":{"jobs":[{"name":"build"}],"resources":[
			{"name":"both","type":"git","source":{
				"uri":"git@github.com:org/repo.git",
				"repository":"org/other",
				"check_every":"15m","insecure":true,
				"version":{"ref":"main"}}},
			{"name":"repo-only","type":"github-pr","source":{
				"repository":"org/repo","team":"org",
				"api_key":"secret-value"}},
			{"name":"norepo","type":"time","source":{
				"interval":"1h","days":["sunday"]}}
		]}}`,
	})
	c := &Client{BaseURL: stub.srv.URL, Team: "main", User: "u", Password: "p"}

	index, err := c.Resources(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := map[Resource]bool{
		// "both": the git uri wins over the repository key → org/repo.
		{Pipeline: "p1", Name: "both", Type: "git", Repo: "org/repo"}:            true,
		{Pipeline: "p1", Name: "repo-only", Type: "github-pr", Repo: "org/repo"}: true,
	}
	if len(index) != len(want) {
		t.Fatalf("index=%+v want %d resources", index, len(want))
	}
	for _, r := range index {
		if !want[r] {
			t.Fatalf("unexpected resource in index: %+v", r)
		}
	}
}

// linearScan is the reference implementation the O(1) lookup is
// checked against — the per-delivery scan Match replaced.
func linearScan(resources []Resource, wantType string,
	repos []string) []Resource {
	var out []Resource
	for _, r := range resources {
		if r.Type != wantType {
			continue
		}
		if !slices.Contains(repos, r.Repo) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// sameResources compares resource slices as multisets — Match visits
// repos in sorted order, the scan in index order, so order differs by
// design while content must not.
func sameResources(got, want []Resource) bool {
	if len(got) != len(want) {
		return false
	}
	counts := map[Resource]int{}
	for _, r := range want {
		counts[r]++
	}
	for _, r := range got {
		counts[r]--
		if counts[r] < 0 {
			return false
		}
	}
	return true
}

func TestMatchMatchesLinearScan(t *testing.T) {
	// Client.Match must return exactly what a linear scan of the
	// fetched index returns — the (type, repo) lookup map built once
	// per fetch publish is an optimization over the old per-delivery
	// scan, not a behavior change.
	stub := newATCStub(t, stubRoutes())
	c := &Client{BaseURL: stub.srv.URL, Team: "main", User: "u", Password: "p"}

	index, err := c.Resources(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	repos := []string{"org/repo", "org/other", "org/none"}
	for _, wantType := range []string{"git", "github-pr", "time", "docker"} {
		got := c.Match(wantType, repos)
		if want := linearScan(index, wantType, repos); !sameResources(got, want) {
			t.Fatalf("Match(%s)=%+v want %+v", wantType, got, want)
		}
		// Deterministic: same inputs, same output order.
		if again := c.Match(wantType, repos); !slices.Equal(again, got) {
			t.Fatalf("Match(%s) order unstable: %+v vs %+v", wantType, again, got)
		}
	}
	// Unsorted + duplicate repos (stack path <=8 and heap fallback >8)
	// must deduplicate without mutating the caller's slice.
	unsorted := []string{"org/other", "org/repo", "org/other"}
	origUnsorted := slices.Clone(unsorted)
	got := c.Match("git", unsorted)
	if !slices.Equal(unsorted, origUnsorted) {
		t.Fatalf("caller slice mutated: got %v want %v", unsorted, origUnsorted)
	}
	if want := linearScan(index, "git", []string{"org/other", "org/repo"}); !sameResources(got, want) {
		t.Fatalf("Match unsorted+dup=%+v want %+v", got, want)
	}
	many := []string{"org/z", "org/other", "org/a", "org/b", "org/c", "org/d", "org/e", "org/f", "org/repo", "org/other"}
	origMany := slices.Clone(many)
	gotMany := c.Match("git", many)
	if !slices.Equal(many, origMany) {
		t.Fatalf("caller >8 slice mutated: got %v want %v", many, origMany)
	}
	if want := linearScan(index, "git", []string{"org/other", "org/repo"}); !sameResources(gotMany, want) {
		t.Fatalf("Match >8 unsorted+dup=%+v want %+v", gotMany, want)
	}

	// Edge cases: no repos and unknown repos match nothing.
	if got := c.Match("git", nil); len(got) != 0 {
		t.Fatalf("Match(git, nil)=%+v want empty", got)
	}
	if got := c.Match("git", []string{"org/absent"}); len(got) != 0 {
		t.Fatalf("Match(git, absent)=%+v want empty", got)
	}
}

func TestReturnedIndexAndMatchesAreCopies(t *testing.T) {
	// Resources/Refresh return clone copies and Match value copies —
	// a caller mutating what it got back must not be able to corrupt
	// the client's shared snapshot (other deliveries match against
	// it under load).
	stub := newATCStub(t, stubRoutes())
	c := &Client{BaseURL: stub.srv.URL, Team: "main", User: "u", Password: "p"}

	index, err := c.Resources(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	index[0].Repo = "mutated/caller"

	fresh, err := c.Resources(t.Context()) // cache hit → clone
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range fresh {
		if r.Repo == "mutated/caller" {
			t.Fatalf("caller mutation reached the cached index: %+v", r)
		}
	}

	matched := c.Match("git", []string{"org/repo"})
	if len(matched) == 0 {
		t.Fatal("Match returned nothing — index build broken")
	}
	matched[0].Repo = "mutated/caller"
	if again := c.Match("git", []string{"org/repo"}); slices.ContainsFunc(again,
		func(r Resource) bool { return r.Repo == "mutated/caller" }) {
		t.Fatal("caller mutation reached the lookup map")
	}
}

// TestInstanceVarsQuery pins the ATC dot-notation contract
// (atc/pipeline.go QueryParams over vars.Flatten): nested maps
// flatten to dot paths, separator chars in a segment force %q
// quoting, leaves are JSON values, pairs sort by rendered ref.
func TestInstanceVarsQuery(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]any
		want string
	}{
		{"nil", nil, ""},
		{"empty", map[string]any{}, ""},
		{"flat string", map[string]any{"branch": "master"},
			`vars.branch=%22master%22`},
		{"flat number", map[string]any{"replicas": float64(3)},
			`vars.replicas=3`},
		{"nested map flattens", map[string]any{
			"release": map[string]any{"line": "1.2", "channel": "stable"},
		}, `vars.release.channel=%22stable%22&vars.release.line=%221.2%22`},
		{"dotted key stays one segment", map[string]any{
			"release.line": "1.2",
		}, `vars.%22release.line%22=%221.2%22`},
		{"mixed nested + dotted", map[string]any{
			"a": map[string]any{"b.c": 1.0},
		}, `vars.a.%22b.c%22=1`},
		// A literal double quote in a segment forces %q quoting;
		// the quote must be escaped as %5C%22 inside the quoted
		// segment, not treated as the quoting delimiter.
		{"double quote in key", map[string]any{
			`a"b`: "x",
		}, `vars.%22a%5C%22b%22=%22x%22`},
		// A backslash is itself escaped by %q (%5C%5C) — losing
		// that escape would collapse two distinct instance vars
		// onto one ATC query ref.
		{"backslash in key", map[string]any{
			`a\b`: "x",
		}, `vars.%22a%5C%5Cb%22=%22x%22`},
		// Both metacharacters together, plus a value carrying the
		// same pair (JSON-quoted then URL-escaped): the key and
		// value encodings must stay independent.
		{"quote and backslash in key and value", map[string]any{
			`q"\b`: `v"l\z`,
		}, `vars.%22q%5C%22%5C%5Cb%22=%22v%5C%22l%5C%5Cz%22`},
		{"list is a leaf not a map", map[string]any{
			"zones": []any{"a", "b"},
		}, `vars.zones=%5B%22a%22%2C%22b%22%5D`},
		{"empty map vanishes", map[string]any{
			"gone": map[string]any{}, "here": "x",
		}, `vars.here=%22x%22`},
		{"sort by rendered ref", map[string]any{
			"z": "1", "a": "2", "m.n": "3",
			// Rendered refs sort byte-wise like Concourse's
			// Ref.String(): the quoted `"m.n"` (0x22) precedes `a`.
		}, `vars.%22m.n%22=%223%22&vars.a=%222%22&vars.z=%221%22`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := instanceVarsQuery(tc.in); got != tc.want {
				t.Fatalf("instanceVarsQuery(%v)=%q want %q", tc.in, got, tc.want)
			}
		})
	}
}

// benchmarkIndex builds a realistic mid-size team: 40 pipelines × 12
// resources ≈ 480 entries — git resources dominate (the push fan-out
// target), github-pr and unmatchable types fill out the lookup-map
// shape real webhook volume hits. Deterministic: no randomness, so
// run-to-run comparisons stay honest.
func benchmarkIndex() []Resource {
	types := []string{"git", "github-pr", "git", "docker", "time", "git", "git", "github-pr"}
	var index []Resource
	for p := range 40 {
		for r := range 12 {
			index = append(index, Resource{
				Pipeline: fmt.Sprintf("pipeline-%02d", p),
				Name:     fmt.Sprintf("res-%02d", r),
				Type:     types[(p+r)%len(types)],
				Repo:     fmt.Sprintf("org%02d/repo-%02d", p%8, r),
			})
		}
	}
	return index
}

// benchmarkClient publishes index directly — the benchmark measures
// the serving-side lookup, not the fetch.
func benchmarkClient(index []Resource) *Client {
	return &Client{index: index, lookup: newLookup(index)}
}

// BenchmarkMatch drives the per-delivery fan-out lookup over the
// realistic index above: the overwhelmingly common delivery matches a
// single repo (the one-entry fast path), while a multi-repo fan-out
// set exercises the sorted-visit path.
func BenchmarkMatch(b *testing.B) {
	c := benchmarkClient(benchmarkIndex())
	single := []string{"org03/repo-07"}
	fanout := make([]string, 0, 16)
	for i := range 16 {
		r := fmt.Sprintf("org%02d/repo-%02d", i%8, i%12)
		if !slices.Contains(fanout, r) {
			fanout = append(fanout, r)
		}
	}
	b.Run("one_repo", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			c.Match("git", single)
		}
	})
	b.Run("fan_out_set", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			c.Match("git", fanout)
		}
	})
}
