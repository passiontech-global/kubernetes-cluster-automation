// backends_test.go — backend helpers (up/maint/vip), mergeStatic
// dedup/ordering, actionTarget svname resolution, withDefaultPort.
package apiprober

import (
	"context"
	"strings"
	"testing"
)

func TestBackendHelpers(t *testing.T) {
	cases := []struct {
		b            backend
		up, mnt, vip bool
	}{
		{backend{Name: "hub1", Status: "UP"}, true, false, false},
		{backend{Name: "hub1", Status: "UP 2/3"}, true, false, false},
		{backend{Name: "hub1", Status: "DOWN"}, false, false, false},
		{backend{Name: "hub1", Status: "MAINT"}, false, true, false},
		{backend{Name: "hub1", Status: "MAINT(via)"}, false, true, false},
		{backend{Name: "api_datahub_lb", Status: "UP"}, true, false, true},
		{backend{Name: "api_datahub_lb", Status: "MAINT"}, false, true, true},
	}
	for _, tc := range cases {
		if got := tc.b.up(); got != tc.up {
			t.Errorf("%+v.up()=%v want %v", tc.b, got, tc.up)
		}
		if got := tc.b.maint(); got != tc.mnt {
			t.Errorf("%+v.maint()=%v want %v", tc.b, got, tc.mnt)
		}
		if got := tc.b.vip(); got != tc.vip {
			t.Errorf("%+v.vip()=%v want %v", tc.b, got, tc.vip)
		}
	}
}

func TestStaticBackendDedupedAgainstDiscovery(t *testing.T) {
	stub := newAPIStub(t)
	ha := newFakeHAProxy(t, [2]string{"hub1", stub.addr()})
	p := fixtureExt(t, ha, ModeDryRun, nil, func(c *Config) {
		c.StaticBackends = []StaticBackend{
			{Name: "hub1", Addr: "10.9.9.9:6443"}, // same name — discovery wins
			{Name: "hub2", Addr: "10.0.0.2:6443"}, // new name — appended
		}
	})
	backends, err := p.discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	merged := mergeStatic(backends, p.cfg.StaticBackends)
	if len(merged) != 2 {
		t.Fatalf("merged=%v want 2 backends", merged)
	}
	if merged[0].Addr != stub.addr() {
		t.Fatalf("discovered addr overwritten by static: %q", merged[0].Addr)
	}
	if merged[1].Name != "hub2" || merged[1].Addr != "10.0.0.2:6443" || !merged[1].up() {
		t.Fatalf("static append wrong: %+v", merged[1])
	}
}

func TestMergeStaticDedupsStaticNames(t *testing.T) {
	// The same server name in two conf layers must not be appended
	// twice — it would be double-probed every cycle.
	merged := mergeStatic(nil, []StaticBackend{
		{Name: "hub1", Addr: "10.0.0.1:6443"},
		{Name: "hub1", Addr: "10.0.0.1:6443"}, // duplicate name
		{Name: "hub2", Addr: "10.0.0.2:6443"},
	})
	if len(merged) != 2 {
		t.Fatalf("merged=%v want 2 (same-named statics deduped)", merged)
	}
}

func TestMergeStaticDedupsByAddr(t *testing.T) {
	// The production incident shape: discovery returns the HAProxy
	// svname for an addr that API_BACKENDS also carries as a bare
	// self-named "ip:port" entry — the same physical apiserver must
	// be tracked ONCE under its svname, or the addr-keyed twin
	// drains under a name HAProxy does not know.
	merged := mergeStatic(
		[]backend{
			{Name: "api_contabo_ctrl", Addr: "147.93.159.255:6443",
				Status: "UP", discovered: true},
			{Name: "api_datahub_ctrl", Addr: "103.186.101.25:6443",
				Status: "UP", discovered: true},
		},
		[]StaticBackend{
			// worker API_BACKENDS = bare apiserver_probe_backends
			// addrs — both are already discovered under svnames.
			{Name: "147.93.159.255:6443", Addr: "147.93.159.255:6443"},
			{Name: "103.186.101.25:6443", Addr: "103.186.101.25:6443"},
			{Name: "api_contabo_ctrl", Addr: "147.93.159.255:6443"}, // name dedup too
			{Name: "ghost", Addr: "10.9.9.9:6443"},                  // genuinely absent
		})
	if len(merged) != 3 {
		t.Fatalf("merged=%v want 3 (2 discovered + ghost)", merged)
	}
	if merged[2].Name != "ghost" || merged[2].discovered {
		t.Fatalf("merged[2]=%+v want undiscovered ghost", merged[2])
	}
}

func TestMergeStaticPrefersConfiguredNameOverBareAddr(t *testing.T) {
	// Static-vs-static same-addr: the configured name claims the
	// identity even when the bare self-named entry is listed first
	// — the addr is never the preferred key.
	merged := mergeStatic(nil, []StaticBackend{
		{Name: "10.0.0.1:6443", Addr: "10.0.0.1:6443"}, // bare, listed first
		{Name: "ctrl1", Addr: "10.0.0.1:6443"},
	})
	if len(merged) != 1 || merged[0].Name != "ctrl1" {
		t.Fatalf("merged=%v want [ctrl1] — named entry must win the addr", merged)
	}
}

func TestActionTarget(t *testing.T) {
	byAddr := map[string]string{"10.0.0.1:6443": "api_ctrl1"}
	cases := []struct {
		b        backend
		wantName string
		wantPrim bool
	}{
		{backend{Name: "api_ctrl1", Addr: "10.0.0.1:6443", discovered: true},
			"api_ctrl1", true},
		// Non-discovered row shadowing a discovered addr → the real
		// svname, never the addr key.
		{backend{Name: "10.0.0.1:6443", Addr: "10.0.0.1:6443"},
			"api_ctrl1", true},
		// Static-only name — absent from the primary backend.
		{backend{Name: "ghost", Addr: "10.9.9.9:6443"}, "ghost", false},
	}
	for _, tc := range cases {
		name, prim := actionTarget(tc.b, byAddr)
		if name != tc.wantName || prim != tc.wantPrim {
			t.Fatalf("actionTarget(%+v) = %q,%v want %q,%v",
				tc.b, name, prim, tc.wantName, tc.wantPrim)
		}
	}
}

func TestMergeStaticDefaultPort(t *testing.T) {
	// Bare-IP API_BACKENDS entry → bash default port 443; without it
	// every TCP preflight failed "missing port in address" → the
	// backend counted unreachable forever.
	merged := mergeStatic(nil, []StaticBackend{
		{Name: "hub1", Addr: "10.0.0.1"},
		{Name: "hub2", Addr: "10.0.0.2:6443"},
	})
	if merged[0].Addr != "10.0.0.1:443" {
		t.Fatalf("bare IP addr=%q want :443 default", merged[0].Addr)
	}
	if merged[1].Addr != "10.0.0.2:6443" {
		t.Fatalf("explicit port clobbered: %q", merged[1].Addr)
	}
}

func TestWithDefaultPort(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.1":      "10.0.0.1:443",
		"10.0.0.1:6443": "10.0.0.1:6443",
		"host.example":  "host.example:443",
		"[::1]":         "[::1]:443",
		"":              "",
	} {
		if got := withDefaultPort(in); got != want {
			t.Fatalf("withDefaultPort(%q)=%q want %q", in, got, want)
		}
	}
}

// mergeStatic drops empty entries silently and char-spray garbage
// (a jinja scalar string arriving rune-by-rune) with a warn — only
// plausible name/addr pairs survive, and a valid entry still lands
// marked UP.
func TestMergeStaticSkipsEmptyAndMalformed(t *testing.T) {
	buf := captureSlog(t)
	got := mergeStatic(nil, []StaticBackend{
		{},                                     // both fields empty — dropped silently
		{Name: "hub 1", Addr: "10.0.0.1:6443"}, // space → char-spray guard
		{Name: "{ctl}", Addr: "10.0.0.2"},      // brace spray → guard
		{Name: "x", Addr: "10.0.0.3"},          // single-char name → guard
		{Name: "ctl1", Addr: "10.0.0.4:6443"},  // valid
	})
	if len(got) != 1 || got[0].Name != "ctl1" ||
		got[0].Addr != "10.0.0.4:6443" || got[0].Status != "UP" {
		t.Fatalf("mergeStatic=%+v want only ctl1", got)
	}
	if !strings.Contains(buf.String(), "skipping malformed API_BACKENDS entry") {
		t.Fatalf("malformed entry not warned:\n%s", buf.String())
	}
}
