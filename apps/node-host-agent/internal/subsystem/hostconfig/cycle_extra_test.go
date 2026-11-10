// cycle_extra_test.go — the orchestration layer's uncovered arms:
// topology-level errors surfacing through CycleWithErrors, lazy vars
// resolution failures counted, the tplCtx relay-map build, and the
// nil-OMap node-IP helper.
package hostconfig

import (
	"context"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/jinja"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/timex"
)

// cycleFixture — cleanCycleFixture's runner replies against a vars
// dir I can patch BEFORE load (cleanCycleFixture owns its own dir).
func cycleFixture(t *testing.T, varsDir string) *Reconciler {
	t.Helper()
	sr := newScripted(map[string]string{
		"/usr/local/bin/coredns -version":               "CoreDNS-1.14.7",
		"dig @127.0.0.1":                                "10.0.1.10",
		"dpkg-query -W -f=${db:Status-Status} fail2ban": "installed",
		"sshd -T": "passwordauthentication no",
	}, nil)
	r, err := New(Config{NodeName: "node-b", HostRoot: t.TempDir(),
		VarsDir: varsDir, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		DownloadDir: t.TempDir(), Runner: sr,
		Clock: timex.NewCell(func() time.Time { return time.Unix(1_700_000_000, 0) })}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestCycleWithErrorsCountsTopologyErrors — a structurally broken
// interdc_dns_zone.yaml lands in t.Errors at load and counts a cycle
// error (the converge still runs the groups).
func TestCycleWithErrorsCountsTopologyErrors(t *testing.T) {
	vars := writeVarsDir(t, "")
	patchVarsFile(t, vars, "interdc_dns_zone.yaml", "just-a-scalar\n")
	r := cycleFixture(t, vars)
	if got := r.CycleWithErrors(context.Background()); got == 0 {
		t.Fatal("topology errors did not count a cycle error")
	}
}

// TestCycleWithErrorsCountsLazyVarsFailures — a self-referencing var
// the watchdog conf reads resolves lazily during the groups and must
// surface as cycle errors, not silently render raw text.
func TestCycleWithErrorsCountsLazyVarsFailures(t *testing.T) {
	vars := writeVarsDir(t, `interdc_slowpath_rtt_ms: "{{ interdc_slowpath_rtt_ms }}"
`)
	r := cycleFixture(t, vars)
	if got := r.CycleWithErrors(context.Background()); got == 0 {
		t.Fatal("vars reference cycle did not count a cycle error")
	}
}

// TestTplCtxRelayMapBuilt — self relay entries reach the template
// context as ip-mapped lists (nebula-up.sh's relay loop source).
func TestTplCtxRelayMapBuilt(t *testing.T) {
	vars := writeVarsDir(t, "")
	patchVarsFile(t, vars, "interdc_nodes.yaml", `node-a:
  name: a
  ip: 10.0.1.10
  site: s1
  hub: true
  relay:
    - ip: 198.18.0.1
node-b:
  name: b
  ip: 10.0.2.20
  site: s2
node-c:
  name: c
  ip: 10.0.1.30
  site: s1
`)
	sr := newScripted(nil, nil)
	r, err := New(Config{NodeName: "node-a", HostRoot: t.TempDir(),
		VarsDir: vars, NebulaCertsDir: t.TempDir(), WatchdogScriptsDir: t.TempDir(),
		Runner: sr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := loadCyc(t, r, vars, "node-a")
	ctx := c.tplCtx()
	relayV, ok := ctx["interdc_relay_map"].(*jinja.OMap)
	if !ok || relayV == nil {
		t.Fatalf("interdc_relay_map missing or wrong type: %T", ctx["interdc_relay_map"])
	}
	selfV, _ := relayV.Get("a")
	lst, ok := selfV.(*jinja.List)
	if !ok || len(lst.V) != 1 {
		t.Fatalf("relay list for self missing: %#v", selfV)
	}
}

// TestNodeIPStrNilMap — the nil-tolerant lookup returns "" instead of
// panicking on a missing node map.
func TestNodeIPStrNilMap(t *testing.T) {
	if got := nodeIPStr(nil, "ip"); got != "" {
		t.Fatalf("nodeIPStr(nil) = %q, want \"\"", got)
	}
}

// TestTopologyPlainListAndScalars — the deep plain-renderer walks
// lists and passes scalars through (the needsRestart tun compare's
// unsafe_routes path).
func TestTopologyPlainListAndScalars(t *testing.T) {
	lst := &jinja.List{V: []any{"a", "b"}}
	out := topologyPlain(lst)
	got, ok := out.([]any)
	if !ok || len(got) != 2 || got[0] != "a" {
		t.Fatalf("topologyPlain(list) = %#v", out)
	}
	if v := topologyPlain(42); v != 42 {
		t.Fatalf("topologyPlain(scalar) = %v", v)
	}
}
