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
	"log/slog"
	"net"
	"os"
	"path/filepath"
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
