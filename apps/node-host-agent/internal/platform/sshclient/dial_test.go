// dial_test.go — the ctx-aware TCP dial, deadline-bounded handshake
// and Link teardown, driven against an in-process loopback SSH
// server (the handshake success path needs a real ssh.NewClientConn
// exchange; no external network — 127.0.0.1 only).

package sshclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// startTestSSHServer runs an in-process SSH server on a loopback
// port: no client auth (the targets' InsecureIgnoreHostKey parity),
// a throwaway host key. Channels are refused — DialTCP/Handshake/
// Close only need the banner + auth exchange.
func startTestSSHServer(t *testing.T) string {
	t.Helper()
	addr, _ := startTestSSHServerHostKey(t)
	return addr
}

// startTestSSHServerHostKey is startTestSSHServer, returning the
// server's public host key — the host-key pin tests need it to build
// the fingerprint a real operator would read off the VM.
func startTestSSHServerHostKey(t *testing.T) (string, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	srvCfg := &ssh.ServerConfig{NoClientAuth: true}
	srvCfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return // listener closed by cleanup
			}
			go func() {
				sconn, chans, reqs, err := ssh.NewServerConn(nc, srvCfg)
				if err != nil {
					return // dead conns are the failure-path tests' business
				}
				defer sconn.Close()
				go ssh.DiscardRequests(reqs)
				for range chans {
				}
			}()
		}
	}()
	return ln.Addr().String(), hostSigner.PublicKey()
}

// startTestSSHJumpServer runs an in-process SSH server that forwards
// "direct-tcpip" channels to the address the client asked for — the
// bastion half of Config.Dial's proxyJump hop (ssh -W %h:%p parity).
// Other channel types are rejected so a stray session open fails
// fast instead of hanging the test.
func startTestSSHJumpServer(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	srvCfg := &ssh.ServerConfig{NoClientAuth: true}
	srvCfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return // listener closed by cleanup
			}
			go func() {
				sconn, chans, reqs, err := ssh.NewServerConn(nc, srvCfg)
				if err != nil {
					return
				}
				defer sconn.Close()
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					if ch.ChannelType() != "direct-tcpip" {
						_ = ch.Reject(ssh.Prohibited, "only direct-tcpip")
						continue
					}
					dconn, creqs, err := ch.Accept()
					if err != nil {
						continue
					}
					go ssh.DiscardRequests(creqs)
					host, port, ok := parseDirectTCPIP(ch.ExtraData())
					if !ok {
						_ = dconn.Close()
						continue
					}
					target, err := net.DialTimeout("tcp",
						net.JoinHostPort(host, strconv.Itoa(int(port))),
						5*time.Second)
					if err != nil {
						_ = dconn.Close()
						continue
					}
					go func() {
						_, _ = io.Copy(target, dconn)
						_ = target.Close()
						_ = dconn.Close()
					}()
					go func() {
						_, _ = io.Copy(dconn, target)
						_ = target.Close()
						_ = dconn.Close()
					}()
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// parseDirectTCPIP decodes the direct-tcpip channel-open payload:
// string host-to-connect, uint32 port, string originator addr,
// uint32 originator port (each string uint32-length-prefixed).
func parseDirectTCPIP(payload []byte) (host string, port uint32, ok bool) {
	if len(payload) < 4 {
		return "", 0, false
	}
	hl := binary.BigEndian.Uint32(payload)
	payload = payload[4:]
	if uint64(hl)+4 > uint64(len(payload)) {
		return "", 0, false
	}
	host = string(payload[:hl])
	payload = payload[hl:]
	if len(payload) < 4 {
		return "", 0, false
	}
	return host, binary.BigEndian.Uint32(payload), true
}

// dialTestConfig builds a Config whose key file holds a fresh ed25519
// PEM — LoadSigner must round-trip it per dial.
func dialTestConfig(t *testing.T, log *slog.Logger) Config {
	t.Helper()
	_, pemBytes := testSigner(t)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return Config{KeyPath: keyPath, Port: 22, Timeout: 5 * time.Second, Log: log}
}

// dialTestClient performs a full successful DialTCP against the test
// server — the shared setup of the Link tests.
func dialTestClient(t *testing.T, addr string, cfg Config) (net.Conn, *ssh.Client) {
	t.Helper()
	signer, err := cfg.LoadSigner()
	if err != nil {
		t.Fatal(err)
	}
	nc, client, err := cfg.DialTCP(context.Background(), addr,
		cfg.ClientConfig("root", signer))
	if err != nil {
		t.Fatalf("DialTCP %s: %v", addr, err)
	}
	return nc, client
}

// TestDialTCPConnectsAndLinkCloses: the happy path lands a real
// *ssh.Client over the transport conn; the direct Link bounds on its
// own conn and Close tears the transport down (a post-Close Close
// must error — the conn really went away).
func TestDialTCPConnectsAndLinkCloses(t *testing.T) {
	addr := startTestSSHServer(t)
	cfg := dialTestConfig(t, nil)

	nc, client := dialTestClient(t, addr, cfg)
	link := &Link{Client: client, Net: nc}
	if got := link.DeadlineConn(); got != nc {
		t.Fatal("direct Link must bound on its own conn")
	}
	if err := link.Close(); err != nil {
		t.Fatalf("Close = %v want nil", err)
	}
	if err := client.Close(); err == nil {
		t.Fatal("client conn still open after Link.Close")
	}
}

// TestLinkCloseClosesJumpClient: behind a bastion the tunneled
// client rides the jump's conn — Close must tear down BOTH clients,
// jump last (both originals' order).
func TestLinkCloseClosesJumpClient(t *testing.T) {
	addr := startTestSSHServer(t)
	cfg := dialTestConfig(t, nil)

	nc1, client1 := dialTestClient(t, addr, cfg)
	nc2, client2 := dialTestClient(t, addr, cfg)
	link := &Link{Client: client1, Net: nc1, JumpNet: nc2, Jump: client2}

	if err := link.Close(); err != nil {
		t.Fatalf("Close = %v want nil", err)
	}
	if err := client1.Close(); err == nil {
		t.Fatal("tunneled client conn still open after Link.Close")
	}
	if err := client2.Close(); err == nil {
		t.Fatal("jump client conn still open after Link.Close")
	}
}

// TestHandshakeDeadConnIsLoud: a carrier that rejects SetDeadline
// (here: a closed TCP conn — the same rejection a chanConn always
// gives) leaves the handshake unbounded, and Handshake must say so
// through Config.Log — the nil-Log fallback resolves the package
// logger and must not panic either.
func TestHandshakeDeadConnIsLoud(t *testing.T) {
	addr := startTestSSHServer(t)
	cfg := dialTestConfig(t, nil)
	signer, err := cfg.LoadSigner()
	if err != nil {
		t.Fatal(err)
	}
	sshCfg := cfg.ClientConfig("root", signer)

	// A TCP conn closed before the handshake rejects every
	// SetDeadline ("use of closed network connection").
	deadConn := func() net.Conn {
		t.Helper()
		nc, err := net.DialTimeout("tcp", addr, cfg.Timeout)
		if err != nil {
			t.Fatal(err)
		}
		_ = nc.Close()
		return nc
	}

	var buf bytes.Buffer
	cfg.Log = slog.New(slog.NewTextHandler(&buf, nil))
	if _, err := cfg.Handshake(context.Background(), deadConn(), deadConn(),
		addr, sshCfg); err == nil {
		t.Fatal("handshake on a dead conn want error")
	}
	if !strings.Contains(buf.String(), "unbounded") {
		t.Fatalf("rejected SetDeadline not warned:\n%s", buf.String())
	}

	// nil Log → the package-logger fallback branch — still errors.
	silent := Config{KeyPath: cfg.KeyPath, Timeout: cfg.Timeout}
	nc := deadConn()
	if _, err := silent.Handshake(context.Background(), nc, nc,
		addr, sshCfg); err == nil {
		t.Fatal("handshake on a dead conn want error (nil log)")
	}
}

// TestDialTCPRefusedTargetErrors: a listening-then-closed loopback
// port is a reliably refused target — DialTCP surfaces the net error
// (Dial wraps it in the "dial %s:" wording).
func TestDialTCPRefusedTargetErrors(t *testing.T) {
	cfg := dialTestConfig(t, nil)
	signer, err := cfg.LoadSigner()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	nc, client, err := cfg.DialTCP(context.Background(), addr,
		cfg.ClientConfig("root", signer))
	if err == nil {
		_ = client.Close()
		t.Fatal("dial to a closed port want error")
	}
	if nc != nil || client != nil {
		t.Fatal("failed dial must return nil conn and client")
	}
}

// portOf extracts the port half of a "host:port" test-server addr.
func portOf(t *testing.T, addr string) int {
	t.Helper()
	_, ps, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(ps)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestDialDirectSuccess: Config.Dial's no-jump path lands a Link whose
// Client completed the handshake; an empty user defaults to root and
// DeadlineConn bounds on the transport conn itself.
func TestDialDirectSuccess(t *testing.T) {
	addr := startTestSSHServer(t)
	cfg := dialTestConfig(t, nil)
	cfg.Port = portOf(t, addr)

	link, err := cfg.Dial(context.Background(), "", "127.0.0.1", "")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = link.Close() }()
	if link.Client == nil || link.Net == nil {
		t.Fatalf("direct Link missing client/conn: %+v", link)
	}
	if link.Jump != nil || link.JumpNet != nil {
		t.Fatal("direct Link must not carry bastion fields")
	}
	if link.DeadlineConn() != link.Net {
		t.Fatal("direct Link must bound on its own conn")
	}
}

// TestDialDirectRefused: the no-jump dial error carries the
// "dial <addr>:" wording both originals used.
func TestDialDirectRefused(t *testing.T) {
	cfg := dialTestConfig(t, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	cfg.Port = portOf(t, addr)

	link, err := cfg.Dial(context.Background(), "root", "127.0.0.1", "")
	if err == nil {
		_ = link.Close()
		t.Fatal("dial to a closed port want error")
	}
	if !strings.Contains(err.Error(), "dial 127.0.0.1:") {
		t.Fatalf("err = %v, want the dial-wrapped address", err)
	}
}

// TestDialViaProxyJump: the bastion hop — DialTCP+handshake to the
// jump, a BoundOp'd direct-tcpip channel to the target, then the
// end-to-end SSH handshake over the chanConn. The Link keeps the
// jump client + its real TCP conn so DeadlineConn bounds on JumpNet
// (a chanConn's SetDeadline always errors).
func TestDialViaProxyJump(t *testing.T) {
	target := startTestSSHServer(t)
	jump := startTestSSHJumpServer(t)
	cfg := dialTestConfig(t, nil)
	cfg.Port = portOf(t, target)

	link, err := cfg.Dial(context.Background(), "",
		"127.0.0.1", "ops@127.0.0.1:"+strconv.Itoa(portOf(t, jump)))
	if err != nil {
		t.Fatalf("Dial via jump: %v", err)
	}
	defer func() { _ = link.Close() }()
	if link.Client == nil || link.Jump == nil || link.JumpNet == nil {
		t.Fatalf("jump Link missing fields: %+v", link)
	}
	if link.DeadlineConn() != link.JumpNet {
		t.Fatal("jump Link must bound on the jump's TCP conn")
	}
}

// TestDialProxyJumpDefaultPort: an unported proxyjump spec takes the
// jump port from Config.Port — here the jump IS the only server, so
// the "target" the channel forwards to is the jump itself (still a
// valid SSH endpoint; the point is the default-port resolution).
func TestDialProxyJumpDefaultPort(t *testing.T) {
	jump := startTestSSHJumpServer(t)
	cfg := dialTestConfig(t, nil)
	cfg.Port = portOf(t, jump)

	link, err := cfg.Dial(context.Background(), "root",
		"127.0.0.1", "root@127.0.0.1")
	if err != nil {
		t.Fatalf("Dial via unported jump: %v", err)
	}
	_ = link.Close()
}

// TestDialProxyJumpDialFails: an unreachable bastion fails inside
// DialTCP — the error is wrapped with the "jump <spec>:" wording.
func TestDialProxyJumpDialFails(t *testing.T) {
	cfg := dialTestConfig(t, nil)
	cfg.Port = 22
	cfg.Timeout = 2 * time.Second
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := portOf(t, ln.Addr().String())
	_ = ln.Close()

	link, err := cfg.Dial(context.Background(), "root", "10.0.0.1",
		"root@127.0.0.1:"+strconv.Itoa(dead))
	if err == nil {
		_ = link.Close()
		t.Fatal("dial via dead jump want error")
	}
	if !strings.Contains(err.Error(), "jump root@127.0.0.1:") {
		t.Fatalf("err = %v, want the jump-wrapped dial error", err)
	}
}

// TestDialProxyJumpChannelFails: the jump answers SSH but never
// accepts the direct-tcpip channel — the BoundOp deadline turns the
// wedged channel-open into the "jump <spec> → <addr>:" error.
func TestDialProxyJumpChannelFails(t *testing.T) {
	target := startTestSSHServer(t)
	// A plain SSH server that discards channels without Accept —
	// the channel open never confirms.
	staller := startTestSSHServer(t)
	_ = target
	cfg := dialTestConfig(t, nil)
	cfg.Port = portOf(t, staller)
	cfg.Timeout = 500 * time.Millisecond

	link, err := cfg.Dial(context.Background(), "root", "127.0.0.1",
		"root@127.0.0.1:"+strconv.Itoa(portOf(t, staller)))
	if err == nil {
		_ = link.Close()
		t.Fatal("dial via channel-stalling jump want error")
	}
	if !strings.Contains(err.Error(), "→") {
		t.Fatalf("err = %v, want the channel-open wrapped error", err)
	}
}

// TestDialProxyJumpHandshakeFails: the jump forwards fine but the
// "target" is a plain TCP listener that accepts and closes — the
// end-to-end handshake over the chanConn fails and the error names
// both hops.
func TestDialProxyJumpHandshakeFails(t *testing.T) {
	// Plain TCP sink: accept + close, so the forwarded conn dies
	// before the SSH banner arrives.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			_ = nc.Close()
		}
	}()
	jump := startTestSSHJumpServer(t)
	cfg := dialTestConfig(t, nil)
	cfg.Port = portOf(t, ln.Addr().String())
	cfg.Timeout = 2 * time.Second

	link, err := cfg.Dial(context.Background(), "root", "127.0.0.1",
		"root@127.0.0.1:"+strconv.Itoa(portOf(t, jump)))
	if err == nil {
		_ = link.Close()
		t.Fatal("dial via non-SSH target want error")
	}
	if !strings.Contains(err.Error(), "via root@127.0.0.1:") {
		t.Fatalf("err = %v, want the via-wrapped handshake error", err)
	}
}

// TestBoundOpCtxPrefersEarlierCtxDeadline: BoundOpCtx bounds at
// min(now+timeout, ctx deadline) — a ctx expiring BEFORE the op
// budget wins, so a blackholed session body fails at the ctx bound
// instead of hanging for the full timeout.
func TestBoundOpCtxPrefersEarlierCtxDeadline(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close(); _ = c2.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	clear := BoundOpCtx(ctx, nil, c1, 30*time.Second)
	defer clear()

	start := time.Now()
	if _, err := c1.Read(make([]byte, 1)); err == nil {
		t.Fatal("read on a silent pipe want timeout error")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("read blocked %v — the ctx deadline did not bound the op", d)
	}
}

// TestDialTCPHonorsEarlierCtxDeadline: Handshake's deadline picks the
// earlier of now+Timeout and the ctx deadline — a ctx expiring
// sooner must still let a fast handshake succeed (the bound is a
// ceiling, not a delay).
func TestDialTCPHonorsEarlierCtxDeadline(t *testing.T) {
	addr := startTestSSHServer(t)
	cfg := dialTestConfig(t, nil)
	cfg.Timeout = 30 * time.Second
	signer, err := cfg.LoadSigner()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	nc, client, err := cfg.DialTCP(ctx, addr,
		cfg.ClientConfig("root", signer))
	if err != nil {
		t.Fatalf("DialTCP under earlier ctx deadline: %v", err)
	}
	_ = client.Close()
	_ = nc.Close()
}
