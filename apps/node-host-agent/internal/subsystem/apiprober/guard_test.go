// guard_test.go — /etc/api-backend-guard.conf parsing
// (LoadGuardConf), the GuardReloader keep-last-good contract,
// and the mid-run conf overlay on the prober's effective config.
package apiprober

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// --- /etc/api-backend-guard.conf (LoadGuardConf) ---

func TestLoadGuardConfMissingFile(t *testing.T) {
	g, err := LoadGuardConf(filepath.Join(t.TempDir(), "absent.conf"))
	if err != nil {
		t.Fatalf("missing conf err=%v want nil (zero defaults)", err)
	}
	if g.SocketPath != "" || g.BackendName != "" || g.Mode != "" ||
		g.TokenFile != "" || g.CAFile != "" ||
		len(g.CompanionBackends) != 0 || len(g.StaticBackends) != 0 {
		t.Fatalf("missing conf guard=%+v want zero value", g)
	}
}

func TestLoadGuardConfParse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api-backend-guard.conf")
	content := `# guard conf — comment lines skipped
MODE=enforce

# quoted list with an inline comment
API_BACKENDS="hub1=10.0.0.1:6443 hub2=10.0.0.2:6443 10.0.0.3:6443" # trailing

HAPROXY_BACKEND=kubeAPI_backend
HAPROXY_BACKENDS="kubeAPI_backend konnectivity_back"
HAPROXY_SOCKET=/run/haproxy-admin/admin.sock

TOKEN_FILE=/etc/api-backend-guard/token
CA_FILE='/etc/api-backend-guard/ca.crt'
export EXTRA=ignored
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	g, err := LoadGuardConf(path)
	if err != nil {
		t.Fatal(err)
	}
	if g.Mode != "enforce" {
		t.Fatalf("Mode=%q want enforce", g.Mode)
	}
	if g.SocketPath != "/run/haproxy-admin/admin.sock" {
		t.Fatalf("SocketPath=%q", g.SocketPath)
	}
	if g.BackendName != "kubeAPI_backend" {
		t.Fatalf("BackendName=%q", g.BackendName)
	}
	// The primary backend is NOT a companion — HAPROXY_BACKENDS
	// includes it, and the prober already acts on BackendName.
	if len(g.CompanionBackends) != 1 || g.CompanionBackends[0] != "konnectivity_back" {
		t.Fatalf("CompanionBackends=%v want [konnectivity_back]", g.CompanionBackends)
	}
	want := []StaticBackend{
		{Name: "hub1", Addr: "10.0.0.1:6443"},
		{Name: "hub2", Addr: "10.0.0.2:6443"},
		// Bare "ip:port" entries name themselves (watchdogconf parity).
		{Name: "10.0.0.3:6443", Addr: "10.0.0.3:6443"},
	}
	if len(g.StaticBackends) != len(want) {
		t.Fatalf("StaticBackends=%v want %v", g.StaticBackends, want)
	}
	for i, sb := range want {
		if g.StaticBackends[i] != sb {
			t.Fatalf("StaticBackends[%d]=%+v want %+v", i, g.StaticBackends[i], sb)
		}
	}
	if g.TokenFile != "/etc/api-backend-guard/token" {
		t.Fatalf("TokenFile=%q", g.TokenFile)
	}
	if g.CAFile != "/etc/api-backend-guard/ca.crt" {
		t.Fatalf("CAFile=%q (single quotes must strip)", g.CAFile)
	}
}

func TestLoadGuardConfUnreadableErrors(t *testing.T) {
	// A path that exists but is a directory → real read error
	// (distinct from the absent-file zero-defaults contract).
	_, err := LoadGuardConf(t.TempDir())
	if err == nil {
		t.Fatal("LoadGuardConf on a directory want error")
	}
}

func TestLoadGuardConfOriginalKeySpelling(t *testing.T) {
	// The deployed ansible contract (api-backend-guard.conf.j2) —
	// VMs in the field carry ONLY this spelling.
	path := filepath.Join(t.TempDir(), "api-backend-guard.conf")
	content := `MODE=enforce
HAPROXY_SOCKET=/run/haproxy-admin/admin.sock
API_TOKEN_FILE=/etc/api-backend-guard/token
API_CA_FILE=/etc/api-backend-guard/ca.crt
GAP_MIN=10000
FAIL_CYCLES=2
FROZEN_CYCLES=2
RECOVER_CYCLES=3
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	g, err := LoadGuardConf(path)
	if err != nil {
		t.Fatal(err)
	}
	if g.TokenFile != "/etc/api-backend-guard/token" {
		t.Fatalf("TokenFile=%q want API_TOKEN_FILE value", g.TokenFile)
	}
	if g.CAFile != "/etc/api-backend-guard/ca.crt" {
		t.Fatalf("CAFile=%q want API_CA_FILE value", g.CAFile)
	}
	if g.GapMin != 10000 || g.FailCycles != 2 || g.FrozenCycles != 2 || g.RecoverCycles != 3 {
		t.Fatalf("thresholds=%+v want 10000/2/2/3", g)
	}
}

func TestLoadGuardConfAPIPrefixWins(t *testing.T) {
	// Both spellings present → API_-prefixed (original contract) wins.
	path := filepath.Join(t.TempDir(), "api-backend-guard.conf")
	content := `TOKEN_FILE=/short/token
API_TOKEN_FILE=/orig/token
CA_FILE=/short/ca
API_CA_FILE=/orig/ca
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	g, err := LoadGuardConf(path)
	if err != nil {
		t.Fatal(err)
	}
	if g.TokenFile != "/orig/token" || g.CAFile != "/orig/ca" {
		t.Fatalf("API_-prefixed keys must win: %+v", g)
	}
}

func TestGuardReloaderRefreshesAndKeepsLastGood(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard.conf")
	rl := NewGuardReloader(path, GuardDefaults{})
	// Missing file → zero defaults.
	if g := rl.Get(); g.Mode != "" {
		t.Fatalf("missing conf Mode=%q want zero", g.Mode)
	}
	if err := os.WriteFile(path, []byte("MODE=dry-run\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if g := rl.Get(); g.Mode != "dry-run" {
		t.Fatalf("Mode=%q want dry-run", g.Mode)
	}
	if err := os.WriteFile(path, []byte("MODE=enforce\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if g := rl.Get(); g.Mode != "enforce" {
		t.Fatalf("edited conf not picked up: Mode=%q", g.Mode)
	}
	// Unreadable path (directory replaces the file) → last good kept.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if g := rl.Get(); g.Mode != "enforce" {
		t.Fatalf("unreadable conf must keep last good, Mode=%q", g.Mode)
	}
}

func TestGuardConfAppliesMidRun(t *testing.T) {
	// The incident shape: agent up before hostconfig renders the
	// conf. dry-run at startup; once the conf lands MODE=enforce
	// mid-run, the NEXT cycle drains — no restart.
	bad := newAPIStub(t)
	good := newAPIStub(t)
	ha := newFakeHAProxy(t,
		[2]string{"hub1", bad.addr()},
		[2]string{"hub2", good.addr()},
	)
	confPath := filepath.Join(t.TempDir(), "api-backend-guard.conf")
	p := fixtureExt(t, ha, ModeDryRun, nil, func(c *Config) {
		c.GuardSrc = NewGuardReloader(confPath, GuardDefaults{})
	})
	bad.set(100, 200) // frozen wedge signature
	good.set(500, 500)
	for i := 0; i < 3; i++ {
		p.Cycle(context.Background())
	}
	if hasCmd(ha.commands(), "disable server") {
		t.Fatalf("drain under dry-run: %v", ha.commands())
	}
	// hostconfig's first render lands mid-run.
	if err := os.WriteFile(confPath, []byte("MODE=enforce\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p.Cycle(context.Background())
	if !hasCmd(ha.commands(), "disable server kube_apiserver/hub1") {
		t.Fatalf("enforce MODE from mid-run conf not applied: %v", ha.commands())
	}
}

func TestGuardConfOverlayFields(t *testing.T) {
	confPath := filepath.Join(t.TempDir(), "api-backend-guard.conf")
	content := `MODE=enforce
HAPROXY_SOCKET=/run/other.sock
HAPROXY_BACKEND=other_back
HAPROXY_BACKENDS="other_back extra_back"
API_BACKENDS="ctl1=10.0.0.9 ctl2=10.0.0.10:6443"
API_TOKEN_FILE=/g/token
API_CA_FILE=/g/ca
GAP_MIN=500
FAIL_CYCLES=4
`
	if err := os.WriteFile(confPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	ha := newFakeHAProxy(t, [2]string{"hub1", "10.0.0.1:6443"})
	p := fixtureExt(t, ha, ModeDryRun, nil, func(c *Config) {
		c.GuardSrc = NewGuardReloader(confPath, GuardDefaults{})
		c.StaticBackends = []StaticBackend{{Name: "ctl1", Addr: "10.9.9.9:6443"}}
	})
	p.refreshGuard()
	if p.eff.mode != ModeEnforce || p.eff.socket != "/run/other.sock" ||
		p.eff.backend != "other_back" || p.eff.tokenFile != "/g/token" ||
		p.eff.caFile != "/g/ca" || p.eff.gapMin != 500 || p.eff.failCycles != 4 {
		t.Fatalf("eff=%+v", p.eff)
	}
	if len(p.eff.companions) != 1 || p.eff.companions[0] != "extra_back" {
		t.Fatalf("companions=%v", p.eff.companions)
	}
	// Conf ctl1 (10.0.0.9) wins over the startup ctl1 — first-seen
	// in the conf-first ordering.
	if len(p.eff.statics) != 2 || p.eff.statics[0].Addr != "10.0.0.9" {
		t.Fatalf("statics=%v want conf-first dedup", p.eff.statics)
	}
	if got := p.staticAddr("ctl1"); got != "10.0.0.9:443" {
		t.Fatalf("staticAddr=%q want conf addr + :443", got)
	}
}
