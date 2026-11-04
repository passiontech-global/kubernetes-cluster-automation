package watchdogconf

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseListsAndScalars(t *testing.T) {
	c, err := Parse([]byte(`
# a comment line
OVERLAY_PROBE_TARGETS="10.8.0.1 10.8.0.2"
OVERLAY_PROBE_MARKERS='10.8.1.1 10.8.1.2'
OVERLAY_SLOWPATH_MARKERS=10.8.1.2
OVERLAY_SITE_MARKERS=10.9.0.1 # inline comment
OVERLAY_SLOWPATH_RTT_MS=120
OVERLAY_EGRESS_TCP="8.8.8.8:53 1.1.1.1:443"
OVERLAY_EGRESS_RELAYS=8.8.8.8 1.1.1.1
OVERLAY_ACTIVE=nebula
DNS_FALLBACK_MAP="api.example.internal:6443=10.0.0.1,10.0.0.2 db.example.internal=10.0.0.9"
API_BACKENDS="hub1=10.0.0.1:6443 hub2=10.0.0.2:6443"
NEBULA_NET=interdc
NEBULA_PORT=45670
NEBULA_DEV=neb1
NEBULA_STATS_URL=http://127.0.0.1:9800/metrics
export WD_SIG_OVERLAY_EGRESS=off
WD_SIG_DNS_FALLBACK=on
`))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.OverlayProbeTargets, []string{"10.8.0.1", "10.8.0.2"}) {
		t.Fatalf("targets=%v", c.OverlayProbeTargets)
	}
	if !reflect.DeepEqual(c.OverlayProbeMarkers, []string{"10.8.1.1", "10.8.1.2"}) {
		t.Fatalf("markers=%v", c.OverlayProbeMarkers)
	}
	if c.OverlaySlowpathRTTms != 120 {
		t.Fatalf("slowpath rtt=%v", c.OverlaySlowpathRTTms)
	}
	if c.OverlayEgressTCP["8.8.8.8"] != "53" {
		t.Fatalf("egress tcp=%v", c.OverlayEgressTCP)
	}
	if c.OverlayActive != "nebula" {
		t.Fatalf("overlay active=%q", c.OverlayActive)
	}
	if len(c.DNSFallback) != 2 {
		t.Fatalf("dns entries=%v", c.DNSFallback)
	}
	d := c.DNSFallback[0]
	if d.Name != "api.example.internal" || d.Port != "6443" ||
		!reflect.DeepEqual(d.Candidates, []string{"10.0.0.1", "10.0.0.2"}) {
		t.Fatalf("dns entry=%+v", d)
	}
	if c.DNSFallback[1].Port != "443" {
		t.Fatalf("default port=%q want 443", c.DNSFallback[1].Port)
	}
	if len(c.APIBackends) != 2 || c.APIBackends[0].Name != "hub1" ||
		c.APIBackends[0].Addr != "10.0.0.1:6443" {
		t.Fatalf("api backends=%+v", c.APIBackends)
	}
	if got := c.APIBackendIPs(); !reflect.DeepEqual(got, []string{"10.0.0.1", "10.0.0.2"}) {
		t.Fatalf("backend ips=%v", got)
	}
	if c.NebulaPort != 45670 || c.NebulaDev != "neb1" {
		t.Fatalf("nebula=%+v", c)
	}
	if c.SignalEnabled("overlay-egress") {
		t.Fatal("WD_SIG_OVERLAY_EGRESS=off did not disable")
	}
	if !c.SignalEnabled("dns-fallback") {
		t.Fatal("WD_SIG_DNS_FALLBACK=on reported disabled")
	}
	if !c.SignalEnabled("never-configured") {
		t.Fatal("unset signal reported disabled")
	}
}

func TestParseTincFallbackKeys(t *testing.T) {
	c, err := Parse([]byte("TINC_PROBE_TARGETS=10.8.0.9\nTINC_EGRESS_RELAYS=8.8.8.8\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.OverlayProbeTargets, []string{"10.8.0.9"}) {
		t.Fatalf("fallback targets=%v", c.OverlayProbeTargets)
	}
	// Explicit OVERLAY_* wins over TINC_*.
	c, err = Parse([]byte("TINC_PROBE_TARGETS=10.8.0.9\nOVERLAY_PROBE_TARGETS=10.8.0.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.OverlayProbeTargets, []string{"10.8.0.1"}) {
		t.Fatalf("overlay did not win=%v", c.OverlayProbeTargets)
	}
}

func TestLoadMissingFileTolerated(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "no-such.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if c == nil || len(c.OverlayProbeTargets) != 0 {
		t.Fatalf("missing file cfg=%+v", c)
	}
	// Defaults still applied on the empty config.
	if c.NebulaNet != "interdc" || c.NebulaPort != 45670 {
		t.Fatalf("defaults=%+v", c)
	}
}

func TestLoadFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "node-watchdog.conf")
	if err := os.WriteFile(p, []byte("NEBULA_PORT=9999\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.NebulaPort != 9999 {
		t.Fatalf("port=%d", c.NebulaPort)
	}
}

func TestMalformedEntriesSkipped(t *testing.T) {
	c, err := Parse([]byte(`
no-equals-sign
=novalue
DNS_FALLBACK_MAP="broken =x y"
API_BACKENDS="=10.0.0.1:6443 ok=10.0.0.2:6443"
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.DNSFallback) != 0 {
		t.Fatalf("dns=%+v", c.DNSFallback)
	}
	if len(c.APIBackends) != 1 || c.APIBackends[0].Name != "ok" {
		t.Fatalf("backends=%+v", c.APIBackends)
	}
}

func TestParseQuotedValueWithInlineComment(t *testing.T) {
	c, err := Parse([]byte(`
FOO="a b" # note
BAR='x y' # note
BAZ=plain # note
HASH=a#b
QHASH="a#b" # trailing
`))
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{
		"FOO": "a b", "BAR": "x y", "BAZ": "plain", "HASH": "a#b", "QHASH": "a#b",
	}
	// Re-parse through vars path: spot-check via new key fields and
	// a parse of the raw map.
	for k, want := range vars {
		if got := parseKV("X_" + k + "=" + map[string]string{
			"FOO":   `"a b" # note`,
			"BAR":   `'x y' # note`,
			"BAZ":   `plain # note`,
			"HASH":  `a#b`,
			"QHASH": `"a#b" # trailing`,
		}[k])["X_"+k]; got != want {
			t.Fatalf("%s=%q want %q", k, got, want)
		}
	}
	_ = c
}

func TestParseControllerBlock(t *testing.T) {
	c, err := Parse([]byte(`
API_SELF="10.0.0.1:6443"
API_PEER="10.0.0.2:6443"
KINE_DB_PROBE="10.0.0.9:6432"
SIG13_AUTOFIX="enforce"
SIG13_MIN_RESTART_S="7200"
APISERVER_SOLO_CYCLES="8"
APISERVER_STALE_MIN_ERRS="15"
APISERVER_GAP_MIN="10000"
APISERVER_GAP_CYCLES="2"
APISERVER_FROZEN_CYCLES="2"
KINE_TTL_AUTOFIX="dry-run"
KINE_TTL_MIN_RESTART_S="1800"
KINE_TTL_REWEDGE_CYCLES="2"
KINE_TTL_CTL_RESTART_S="7200"
KINE_POOL_AUTOFIX="enforce"
KINE_POOL_MAX_CONNS="72"
KINE_POOL_CYCLES="3"
KINE_POOL_MIN_RESTART_S="1200"
K0S_OOMLOOP_AUTOFIX="enforce"
K0S_OOMLOOP_MIN_KILLS="3"
K0S_OOMLOOP_WINDOW_S="3600"
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.APISelf != "10.0.0.1:6443" || c.APIPeer != "10.0.0.2:6443" ||
		c.KineDBProbe != "10.0.0.9:6432" {
		t.Fatalf("endpoints=%+v", c)
	}
	if c.Sig13Autofix != "enforce" || c.Sig13MinRestartS != 7200 ||
		c.Sig13SoloCycles != 8 || c.Sig13StaleMinErrs != 15 ||
		c.Sig13GapMin != 10000 || c.Sig13GapCycles != 2 || c.Sig13FrozenCycles != 2 {
		t.Fatalf("sig13=%+v", c)
	}
	if c.KineTTLAutofix != "dry-run" || c.KineTTLMinRestartS != 1800 ||
		c.KineTTLRewedgeCycle != 2 || c.KineTTLCtlRestartS != 7200 {
		t.Fatalf("ttl=%+v", c)
	}
	if c.KinePoolAutofix != "enforce" || c.KinePoolMaxConns != 72 ||
		c.KinePoolCycles != 3 || c.KinePoolMinRestartS != 1200 {
		t.Fatalf("pool=%+v", c)
	}
	if c.OOMLoopAutofix != "enforce" || c.OOMLoopMinKills != 3 ||
		c.OOMLoopWindowS != 3600 {
		t.Fatalf("oom=%+v", c)
	}
}

func TestReloaderSeesRewrites(t *testing.T) {
	p := filepath.Join(t.TempDir(), "node-watchdog.conf")
	if err := os.WriteFile(p, []byte("NEBULA_PORT=1\nAPI_BACKENDS=\"hub1=10.0.0.1:6443\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := NewReloader(p, nil)
	if got := r.Get().APIBackendIPs(); len(got) != 1 {
		t.Fatalf("initial backends=%v", got)
	}
	// hostconfig-style rewrite lands on the next Get.
	if err := os.WriteFile(p, []byte("API_BACKENDS=\"hub1=10.0.0.1:6443 hub2=10.0.0.2:6443\"\nWD_SIG_CILIUM=off\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := r.Get()
	if len(c.APIBackends) != 2 || c.SignalEnabled("cilium") {
		t.Fatalf("rewrite not picked up: %+v", c)
	}
	// A missing file reverts to the all-defaults config (shell
	// `source` parity: absent file = defaults).
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if got := r.Get().APIBackends; len(got) != 0 {
		t.Fatalf("missing file backends=%v want empty defaults", got)
	}
}

// ${A:-B} falls back on UNSET-OR-EMPTY — an explicitly empty
// primary does NOT win over a non-empty fallback.
func TestPickFallsBackOnEmptyPrimary(t *testing.T) {
	c, err := Parse([]byte("OVERLAY_PROBE_TARGETS=\nTINC_PROBE_TARGETS=10.8.0.9\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.OverlayProbeTargets, []string{"10.8.0.9"}) {
		t.Fatalf("empty-primary targets=%v want TINC fallback", c.OverlayProbeTargets)
	}
	// Quoted empty behaves the same.
	c, err = Parse([]byte("OVERLAY_PROBE_TARGETS=\"\"\nTINC_PROBE_TARGETS=10.8.0.9\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.OverlayProbeTargets, []string{"10.8.0.9"}) {
		t.Fatalf("quoted-empty-primary targets=%v", c.OverlayProbeTargets)
	}
	// And a non-empty primary still wins.
	c, err = Parse([]byte("OVERLAY_PROBE_TARGETS=10.8.0.1\nTINC_PROBE_TARGETS=10.8.0.9\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.OverlayProbeTargets, []string{"10.8.0.1"}) {
		t.Fatalf("primary=%v", c.OverlayProbeTargets)
	}
}

// Bash quote removal happens per word: KEY="a"#tail → `a#tail`
// (mid-word '#' is literal), not the raw `"a"#tail`.
func TestParseQuotedThenHashTail(t *testing.T) {
	vars := parseKV("A=\"a\"#comment\nB=\"a\" # comment\nC=x'y'z\nD=''#x\n")
	for k, want := range map[string]string{
		"A": "a#comment", // '#' glued to the closing quote is literal
		"B": "a",         // '#' after whitespace opens the comment
		"C": "xyz",       // mid-word quote removal
		"D": "#x",        // empty quoted word + glued '#'
	} {
		if vars[k] != want {
			t.Fatalf("%s=%q want %q", k, vars[k], want)
		}
	}
}

// Bare/bracketed IPv6 backends must keep their full host part —
// a bare "::1" used to last-colon-chop to ":".
func TestAPIBackendIPsIPv6(t *testing.T) {
	c := &Config{APIBackends: []APIBackend{
		{Name: "b1", Addr: "::1"},
		{Name: "b2", Addr: "[::1]:6443"},
		{Name: "b3", Addr: "[fe80::1]"},
		{Name: "b4", Addr: "10.0.0.1:6443"},
		{Name: "b5", Addr: "10.0.0.2"},
	}}
	want := []string{"::1", "::1", "fe80::1", "10.0.0.1", "10.0.0.2"}
	if got := c.APIBackendIPs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ips=%v want %v", got, want)
	}
}
