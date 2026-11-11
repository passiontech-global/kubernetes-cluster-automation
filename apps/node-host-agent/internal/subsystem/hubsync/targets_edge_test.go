// targets_edge_test.go — the omBool/strOf coercion corners and the
// aggregateTargets merge cases the fixture vars dir can't express:
// the default-user fallback, dedup field overrides, non-mapping list
// entries and dropped-name bookkeeping.
package hubsync

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/jinja"
)

// TestOmBoolCoercions: ansible-truthy string spellings coerce, bare
// bools pass through, ints read non-zero-true, and unrecognized
// values fall back to def — the omBool shims' table, now pinned
// against *jinja.OMap.BoolDef, the getter the target aggregation
// delegates to.
func TestOmBoolCoercions(t *testing.T) {
	newOM := func(kv ...any) *jinja.OMap {
		m := jinja.NewOMap()
		for i := 0; i < len(kv); i += 2 {
			m.Set(kv[i].(string), kv[i+1])
		}
		return m
	}
	truthy := []any{true, "true", "True", " yes ", "1", "on", int64(5), 1.5}
	for _, v := range truthy {
		if !newOM("k", v).BoolDef("k", false) {
			t.Fatalf("BoolDef(%v) want true", v)
		}
	}
	falsy := []any{false, "false", "No", "0", "off", int64(0), 0.0}
	for _, v := range falsy {
		if newOM("k", v).BoolDef("k", true) {
			t.Fatalf("BoolDef(%v) want false", v)
		}
	}
	// Unrecognized scalar → def; missing key → def.
	if !newOM("k", "garbage").BoolDef("k", true) {
		t.Fatal("unrecognized value must fall back to def")
	}
	if !newOM().BoolDef("k", true) {
		t.Fatal("missing key must fall back to def")
	}
}

// TestStrOfTypes: strings pass through, int64/float64 format, and
// nil/containers are dropped — the omStr/strOf table, now pinned
// against *jinja.OMap.Str. bools differ from the old shim on
// purpose: the lib getter renders true → "true" (the YAML/registry
// spelling) where hubsync's copy dropped them.
func TestStrOfTypes(t *testing.T) {
	om := jinja.NewOMap()
	for i, tc := range []struct {
		v    any
		want string
	}{{"s", "s"}, {int64(42), "42"}, {float64(2.5), "2.5"},
		{true, "true"}, {false, ""}, {nil, ""},
		// An unknown non-container struct renders via fmt — the
		// getter's documented fallback (the old shim returned "").
		{struct{}{}, "{}"}} {
		k := "k" + strconv.Itoa(i)
		om.Set(k, tc.v)
		if got := om.Str(k); got != tc.want {
			t.Fatalf("Str(%v)=%q want %q", tc.v, got, tc.want)
		}
	}
}

// writeEdgeVars lays out the edge-case inventory: no
// interdc_ssh_default_user anywhere (root fallback), a deduped host
// across extra_hosts + api_lb_guard_vms whose later registration
// overrides user, an api-lb pair where the second registration
// override user + proxyjump, non-mapping list entries, and a registry
// entry with no ip (dropped — interdc entries drop under their
// registry key, which is always their Name).
func writeEdgeVars(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"defaults.yaml": "interdc_nebula_enabled: true\n",
		"cluster.yaml": `node_exporter_extra_hosts:
  - { name: dup-a, ip: "10.9.0.1" }
  - { name: dup-a2, ip: "10.9.0.1" }
  - broken-scalar
api_lb_guard_vms:
  - { name: alb, ip: "10.9.0.2" }
  - { name: alb2, ip: "10.9.0.2", ssh_user: ops, ssh_proxyjump: "root@10.9.0.9" }
  - { name: dup-a, ip: "10.9.0.1", ssh_user: converge }
  - also-broken
`,
		"interdc_nodes.yaml": `n1:
  agent: false
  ip: 10.9.0.3
n2:
  agent: false
n3:
  agent: false
  ip: 10.9.0.4
n4:
  agent: false
  ip: 10.9.0.4
  ssh_user: jump-user
  ssh_proxyjump: "root@10.9.0.15"
`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestAggregateTargetsEdges walks the merge corner cases against the
// synthetic vars dir.
func TestAggregateTargetsEdges(t *testing.T) {
	targets, dropped, notes, err := loadTargets(writeEdgeVars(t))
	if err != nil {
		t.Fatalf("loadTargets: %v", err)
	}
	if len(dropped) != 1 || dropped[0] != "n2" {
		t.Fatalf("dropped=%v want [n2]", dropped)
	}
	_ = notes // non-fatal derivation notes, asserted by callers

	byName := map[string]Target{}
	for _, tg := range targets {
		byName[tg.Name] = tg
	}
	if len(targets) != 4 {
		t.Fatalf("targets=%d want 4: %+v", len(targets), targets)
	}

	// No interdc_ssh_default_user → the root fallback.
	n1 := byName["n1"]
	if !n1.InterDC || n1.SSHUser != "root" {
		t.Fatalf("n1: %+v", n1)
	}
	// Later registrations override the resolved user: extra_hosts
	// gave dup-a root, the api_lb entry's converge wins; flags OR.
	dup := byName["dup-a"]
	if dup.SSHUser != "converge" || !dup.APILB || dup.InterDC {
		t.Fatalf("dup-a: %+v", dup)
	}
	// The api-lb pair dedups by ip; the second registration's
	// ssh_user overrides, flags stay APILB (api-lb entries carry no
	// proxyjump — only interdc registrations do).
	alb := byName["alb2"]
	if alb.SSHUser != "ops" || alb.ProxyJump != "" || !alb.APILB {
		t.Fatalf("alb2: %+v", alb)
	}
	// Two interdc registrations on one ip dedup; the later one's
	// ssh_user + ssh_proxyjump override.
	n4 := byName["n4"]
	if !n4.InterDC || n4.SSHUser != "jump-user" ||
		n4.ProxyJump != "root@10.9.0.15" {
		t.Fatalf("n4: %+v", n4)
	}
}
