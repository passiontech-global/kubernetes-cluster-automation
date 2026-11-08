package nebulasign

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeCertScript writes an executable stand-in for nebula-cert: the
// sign invocation gets an empty host.crt at -out-crt; fail=true makes
// every invocation exit 1 with a message (the sign-failure path).
func fakeCertScript(t *testing.T, fail bool) string {
	t.Helper()
	dir := t.TempDir()
	body := "#!/bin/sh\n"
	if fail {
		body += "echo 'simulated nebula-cert failure' >&2\nexit 1\n"
	} else {
		body += `out=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-out-crt" ]; then out="$a"; fi
  prev="$a"
done
[ -n "$out" ] && printf 'CERTDATA
' > "$out"
exit 0
`
	}
	p := filepath.Join(dir, "nebula-cert")
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// caFixture lays out a CA dir with ca.crt + ca.key — the files
// nebulaSign stats before doing anything.
func caFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, f := range []string{"ca.crt", "ca.key"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("ca"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// varsFixture writes a minimal registry: defaults.yaml + cluster.yaml
// + interdc_nodes.yaml in a vars dir (topology.Load's input).
func varsFixture(t *testing.T, defaults, nodes string) string {
	t.Helper()
	dir := t.TempDir()
	if defaults == "" {
		defaults = "interdc_nebula_enabled: true\ninterdc_marker_base: \"172.29.0\"\n"
	}
	if nodes == "" {
		nodes = "hub-a:\n  name: hub-a\n  ip: 10.0.0.1\n  marker_octet: 3\n" +
			"  nebula_key: UHViQQ==\n"
	}
	for name, content := range map[string]string{
		"defaults.yaml":      defaults,
		"cluster.yaml":       "interdc_ssh_default_user: admin\n",
		"interdc_nodes.yaml": nodes,
	} {
		if err := os.WriteFile(filepath.Join(dir, name),
			[]byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestSignAll: one job signed + verified with the fake nebula-cert and
// installed at <varsDir>/nebula-<name>.crt; a failing binary aborts
// with the sign wording.
func TestSignAll(t *testing.T) {
	caDir := caFixture(t)
	varsDir := t.TempDir()
	cfg := signConfig{CaDir: caDir, VarsDir: varsDir, Duration: "8760h"}
	jobs := []signJob{{
		Hostname: "hub-a", Name: "hub-a",
		IPCIDR: "172.29.0.3/24", Subnets: "10.0.0.1/32",
		Pub: "UHViQQ==",
	}}
	if err := signAll(context.Background(),
		fakeCertScript(t, false), cfg, jobs); err != nil {
		t.Fatalf("signAll: %v", err)
	}
	crt := filepath.Join(varsDir, "nebula-hub-a.crt")
	b, err := os.ReadFile(crt)
	if err != nil {
		t.Fatalf("signed crt missing: %v", err)
	}
	if string(b) != "CERTDATA\n" {
		t.Fatalf("crt=%q want CERTDATA", b)
	}

	err = signAll(context.Background(),
		fakeCertScript(t, true), cfg, jobs)
	if err == nil || !strings.Contains(err.Error(), "nebula-cert sign") {
		t.Fatalf("failing binary err=%v want sign failure", err)
	}
}

// TestCmdDispatch: the flag-dispatch contract — -h is a clean exit,
// a bad flag is a usage error, a runtime failure (unreachable
// --runc-source style input here: a CA dir missing ca.key) is
// ExitRuntime.
func TestCmdDispatch(t *testing.T) {
	ctx := context.Background()
	if code := Cmd(ctx, []string{"-h"}); code != 0 {
		t.Fatalf("-h exit=%d want 0", code)
	}
	if code := Cmd(ctx, []string{"--bogus"}); code != 2 {
		t.Fatalf("bad flag exit=%d want 2", code)
	}
	if code := Cmd(ctx, nil); code != 2 {
		t.Fatalf("missing --ca-dir exit=%d want 2", code)
	}
	// ca-dir prepared but PATH has no nebula-cert → runtime failure.
	t.Setenv("PATH", t.TempDir())
	if code := Cmd(ctx, []string{"--ca-dir", caFixture(t),
		"--vars-dir", varsFixture(t, "", "")}); code != 1 {
		t.Fatalf("no nebula-cert exit=%d want 1", code)
	}
}

// TestNebulaSignEndToEnd: PATH carries the fake nebula-cert; a
// registry node with nebula_key signs without any SSH fetch and lands
// <varsDir>/nebula-hub-a.crt.
func TestNebulaSignEndToEnd(t *testing.T) {
	binDir := fakeCertScript(t, false)
	t.Setenv("PATH", filepath.Dir(binDir)+string(os.PathListSeparator)+os.Getenv("PATH"))
	varsDir := varsFixture(t, "", "")
	cfg := signConfig{
		VarsDir: varsDir, CaDir: caFixture(t), Duration: "8760h",
		SSHKey: "no-such-key",
	}
	if err := nebulaSign(context.Background(), cfg); err != nil {
		t.Fatalf("nebulaSign: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(varsDir, "nebula-hub-a.crt"))
	if err != nil || string(b) != "CERTDATA\n" {
		t.Fatalf("crt read=%q err=%v", b, err)
	}
}

// TestNebulaSignErrorPaths: no binary in PATH, an unsafe
// interdc_nebula_net, and a node with no resolvable pubkey each fail
// with the specific wording.
func TestNebulaSignErrorPaths(t *testing.T) {
	ctx := context.Background()
	emptyBin := t.TempDir() // no nebula-cert in it
	t.Setenv("PATH", emptyBin)
	err := nebulaSign(ctx, signConfig{CaDir: caFixture(t),
		VarsDir: varsFixture(t, "", "")})
	if err == nil || !strings.Contains(err.Error(),
		"nebula-cert not found in PATH") {
		t.Fatalf("no binary err=%v", err)
	}

	// Restore a working binary for the vars-level failures.
	t.Setenv("PATH", filepath.Dir(fakeCertScript(t, false))+
		string(os.PathListSeparator)+os.Getenv("PATH"))

	err = nebulaSign(ctx, signConfig{CaDir: caFixture(t),
		VarsDir: varsFixture(t,
			"interdc_nebula_enabled: true\ninterdc_nebula_net: \"bad net\"\n", "")})
	if err == nil || !strings.Contains(err.Error(),
		"invalid interdc_nebula_net") {
		t.Fatalf("bad net err=%v", err)
	}

	// Node with an ip but an already-cancelled ctx: the SSH fallback
	// fails instantly (ctx.Err) → the missing-pubkey list error.
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = nebulaSign(cctx, signConfig{CaDir: caFixture(t),
		VarsDir: varsFixture(t, "",
			"lonely:\n  name: lonely\n  ip: 10.0.0.9\n  marker_octet: 9\n")})
	if err == nil || !strings.Contains(err.Error(),
		"missing nebula pubkey for lonely (lonely)") {
		t.Fatalf("missing pub err=%v", err)
	}
	_ = cancel
}

// TestSSHFetchHostPub: the local gate (no ip) and the ctx-cancelled
// dial both error without touching a real host.
func TestSSHFetchHostPub(t *testing.T) {
	if _, err := sshFetchHostPub(context.Background(),
		signJob{Name: "n"}, "interdc", "/tmp/key"); err == nil ||
		!strings.Contains(err.Error(), "no ip in registry") {
		t.Fatalf("no-ip err=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Dial honours the ctx budget — a cancelled ctx errors before any
	// packet goes out.
	if _, err := sshFetchHostPub(ctx,
		signJob{Name: "n", IP: "127.0.0.1"}, "interdc", "/tmp/key"); err == nil {
		t.Fatal("cancelled dial want error")
	}
}
