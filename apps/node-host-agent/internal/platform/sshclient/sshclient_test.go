package sshclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// dlConn is a net.Conn that only records SetDeadline calls — the
// seam for asserting BoundOp behaviour without a real socket, and
// for emulating the x/crypto chanConn Jump.Dial returns whose
// SetDeadline always errors ("deadline not supported").
type dlConn struct {
	dls []time.Time
	err error
}

func (c *dlConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *dlConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *dlConn) Close() error                { return nil }
func (c *dlConn) LocalAddr() net.Addr         { return nil }
func (c *dlConn) RemoteAddr() net.Addr        { return nil }
func (c *dlConn) SetDeadline(t time.Time) error {
	c.dls = append(c.dls, t)
	return c.err
}
func (c *dlConn) SetReadDeadline(time.Time) error  { return nil }
func (c *dlConn) SetWriteDeadline(time.Time) error { return nil }

// --- BoundOp (moved from hubsync's ssh_test.go — the mechanics
// moved here with the dial code) ---

// TestBoundOpSetsAndClearsDeadline: the per-op bound is applied then
// cleared — steady-state session I/O stays governed by ctx +
// Session.Close, not a stale conn deadline.
func TestBoundOpSetsAndClearsDeadline(t *testing.T) {
	nc := &dlConn{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clear := BoundOp(context.Background(), log, nc, time.Minute)
	if len(nc.dls) != 1 || nc.dls[0].IsZero() {
		t.Fatalf("deadline not applied: %v", nc.dls)
	}
	clear()
	if len(nc.dls) != 2 || !nc.dls[1].IsZero() {
		t.Fatalf("deadline not cleared: %v", nc.dls)
	}
}

// TestBoundOpUnsupportedIsLoud: a conn rejecting SetDeadline leaves
// the op unbounded — the warning must say so instead of letting a
// wedged-target hang look identical to a bounded op.
func TestBoundOpUnsupportedIsLoud(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	nc := &dlConn{err: errors.New("deadline not supported")}
	clear := BoundOp(context.Background(), log, nc, time.Minute)
	clear()
	if !strings.Contains(buf.String(), "unbounded") {
		t.Fatalf("rejected SetDeadline not warned:\n%s", buf.String())
	}
}

// TestBoundOpNilLog: the nil-log fallback (nebulasign wiring) must
// still bound + clear and must not panic on a rejected SetDeadline.
func TestBoundOpNilLog(t *testing.T) {
	nc := &dlConn{err: errors.New("deadline not supported")}
	clear := BoundOp(context.Background(), nil, nc, time.Minute)
	clear()
	if len(nc.dls) != 2 {
		t.Fatalf("deadlines not applied+cleared: %v", nc.dls)
	}
}

// TestBoundOpCtxUsesCtxDeadline: the whole-op bound mirrors the
// caller's ctx budget (hubsync's per-target timeout), not the dial
// timeout — a blackholed session body must fail AT the op budget.
func TestBoundOpCtxUsesCtxDeadline(t *testing.T) {
	nc := &dlConn{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	want := time.Now().Add(3 * time.Minute)
	ctx, cancel := context.WithDeadline(context.Background(), want)
	defer cancel()
	clear := BoundOpCtx(ctx, log, nc, time.Second)
	if len(nc.dls) != 1 || !nc.dls[0].Equal(want) {
		t.Fatalf("deadline = %v, want the ctx deadline %v", nc.dls, want)
	}
	clear()
	if len(nc.dls) != 2 || !nc.dls[1].IsZero() {
		t.Fatalf("deadline not cleared: %v", nc.dls)
	}
}

// TestBoundOpCtxFallbackTimeout: a deadline-less ctx falls back to
// now+timeout — the op still can't hang forever on a dead transport.
func TestBoundOpCtxFallbackTimeout(t *testing.T) {
	nc := &dlConn{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	before := time.Now().Add(time.Minute)
	clear := BoundOpCtx(context.Background(), log, nc, time.Minute)
	after := time.Now().Add(time.Minute)
	if len(nc.dls) != 1 || nc.dls[0].Before(before) || nc.dls[0].After(after) {
		t.Fatalf("deadline = %v, want ~now+1m", nc.dls)
	}
	clear()
}

// TestBoundOpCtxUnsupportedIsLoud: same rejected-SetDeadline
// contract as BoundOp — an unbounded body must warn.
func TestBoundOpCtxUnsupportedIsLoud(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	nc := &dlConn{err: errors.New("deadline not supported")}
	clear := BoundOpCtx(context.Background(), log, nc, time.Minute)
	clear()
	if !strings.Contains(buf.String(), "unbounded") {
		t.Fatalf("rejected SetDeadline not warned:\n%s", buf.String())
	}
}

// TestLinkDeadlineConn: behind a bastion Net is the chanConn
// (SetDeadline always errors) while every muxed channel rides the
// jump's real TCP conn — the per-op bound must land on JumpNet.
// (hubsync's TestDeadlineConnPrefersJump, retargeted at Link.)
func TestLinkDeadlineConn(t *testing.T) {
	direct, jump := &dlConn{}, &dlConn{}
	if got := (&Link{Net: direct}).DeadlineConn(); got != direct {
		t.Fatal("direct conn must be its own deadline handle")
	}
	if got := (&Link{Net: direct, JumpNet: jump}).DeadlineConn(); got != jump {
		t.Fatal("bastion conn must bound on the jump's TCP conn")
	}
}

// TestSplitUserHost: the ssh_proxyjump spec both originals accepted —
// "user@host[:port]" keeps its port, an unported spec returns ""
// (the caller applies Config.Port).
func TestSplitUserHost(t *testing.T) {
	for _, tc := range []struct {
		in               string
		user, host, port string
	}{
		{"admin@10.0.0.1:2222", "admin", "10.0.0.1", "2222"},
		{"10.0.0.1", "root", "10.0.0.1", ""},
		{"ops@bastion", "ops", "bastion", ""},
		{"bastion:2222", "root", "bastion", "2222"},
	} {
		user, host, port := SplitUserHost(tc.in)
		if user != tc.user || host != tc.host || port != tc.port {
			t.Fatalf("SplitUserHost(%q)=%q,%q,%q want %q,%q,%q",
				tc.in, user, host, port, tc.user, tc.host, tc.port)
		}
	}
}

// TestExpandHome: "~/" resolves against the home dir (nebulasign's
// default key path); absolute paths pass through (hubsync's).
func TestExpandHome(t *testing.T) {
	if got := ExpandHome("/etc/node-converge-ssh/id_ed25519"); got != "/etc/node-converge-ssh/id_ed25519" {
		t.Fatalf("absolute path rewritten: %q", got)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir to expand against")
	}
	if got, want := ExpandHome("~/.ssh/id_ed25519"),
		filepath.Join(home, ".ssh/id_ed25519"); got != want {
		t.Fatalf("ExpandHome=%q want %q", got, want)
	}
}

// testSigner generates a real ed25519 signer + its PEM encoding —
// LoadSigner must round-trip it.
func testSigner(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pem.EncodeToMemory(block)
}

// TestClientConfigSilentByDefault: nil Log → the bare
// InsecureIgnoreHostKey tolerance (nebulasign parity) — accepts any
// key without logging.
func TestClientConfigSilentByDefault(t *testing.T) {
	signer, _ := testSigner(t)
	cfg := (Config{Timeout: 15 * time.Second}).ClientConfig("root", signer)
	if cfg.User != "root" || cfg.Timeout != 15*time.Second {
		t.Fatalf("cfg = %+v", cfg)
	}
	if len(cfg.Auth) != 1 {
		t.Fatalf("auth methods = %d want 1", len(cfg.Auth))
	}
	if err := cfg.HostKeyCallback("h:22", nil, signer.PublicKey()); err != nil {
		t.Fatalf("host key rejected: %v", err)
	}
}

// TestClientConfigLogsFingerprint: a set Log → hubsync's audit trail —
// the accepted key's fingerprint is logged, still returning nil.
func TestClientConfigLogsFingerprint(t *testing.T) {
	signer, _ := testSigner(t)
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	cfg := (Config{Log: log}).ClientConfig("ops", signer)
	err := cfg.HostKeyCallback("10.0.0.1:22",
		&net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 22},
		signer.PublicKey())
	if err != nil {
		t.Fatalf("host key rejected: %v", err)
	}
	if !strings.Contains(buf.String(), ssh.FingerprintSHA256(signer.PublicKey())) {
		t.Fatalf("fingerprint not audit-logged:\n%s", buf.String())
	}
}

// TestLoadSignerErrors: read vs parse failures carry the stage +
// resolved path — the wording nebulasign produced.
func TestLoadSignerErrors(t *testing.T) {
	if _, err := (Config{KeyPath: "/nonexistent/key"}).LoadSigner(); err == nil ||
		!strings.Contains(err.Error(), "read ssh key /nonexistent/key") {
		t.Fatalf("missing key err = %v", err)
	}
	p := filepath.Join(t.TempDir(), "bad.key")
	if err := os.WriteFile(p, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Config{KeyPath: p}).LoadSigner(); err == nil ||
		!strings.Contains(err.Error(), "parse ssh key "+p) {
		t.Fatalf("bad key err = %v", err)
	}
}

// TestLoadSignerRoundTrip: a real PEM key parses — and "~/"-expansion
// still applies on the way in.
func TestLoadSignerRoundTrip(t *testing.T) {
	_, pemBytes := testSigner(t)
	p := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Config{KeyPath: p}).LoadSigner(); err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
}

// TestDialKeyErrorPrecedesNetwork: Dial must surface the key error
// before any network attempt — same ordering both originals had.
func TestDialKeyErrorPrecedesNetwork(t *testing.T) {
	_, err := (Config{KeyPath: "/nonexistent/key", Port: 22,
		Timeout: time.Second}).Dial(context.Background(), "", "10.0.0.1", "")
	if err == nil || !strings.Contains(err.Error(), "read ssh key") {
		t.Fatalf("dial err = %v, want key error", err)
	}
}
