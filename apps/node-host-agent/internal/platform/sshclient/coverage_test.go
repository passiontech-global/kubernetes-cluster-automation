package sshclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestSessionHelpersAndKnownHosts(t *testing.T) {
	if got := NormalizeHost(" [2001:db8::1]:2222 "); got != "2001:db8::1" {
		t.Fatalf("NormalizeHost(v6+port) = %q", got)
	}
	if got := NormalizeHost("Example.COM:22"); got != "example.com" {
		t.Fatalf("NormalizeHost(host:port) = %q", got)
	}
	if got := NormalizeHost("HOST.LOCAL"); got != "host.local" {
		t.Fatalf("NormalizeHost(bare) = %q", got)
	}

	if got := KnownHostsPath(""); got != "" {
		t.Fatalf("KnownHostsPath('') = %q, want empty", got)
	}
	if got := KnownHostsPath("id_ed25519"); got != "" {
		t.Fatalf("KnownHostsPath('id_ed25519') = %q, want empty", got)
	}
	if got := KnownHostsPath("/etc/ssh/id_ed25519"); got != "/etc/ssh/known_hosts" {
		t.Fatalf("KnownHostsPath = %q", got)
	}

	addr := hostPortAddr("127.0.0.1:22")
	if addr.Network() != "tcp" || addr.String() != "127.0.0.1:22" {
		t.Fatalf("hostPortAddr = (%q,%q)", addr.Network(), addr.String())
	}

	// cappedOut Write: unlimited vs capped.
	var uncapped cappedOut
	_, _ = uncapped.Write([]byte("hello world"))
	if uncapped.buf.String() != "hello world" {
		t.Fatalf("uncapped = %q", uncapped.buf.String())
	}
	capped := cappedOut{max: 5}
	n, err := capped.Write([]byte("hello world"))
	if err != nil || n != 11 || capped.buf.String() != "hello" {
		t.Fatalf("capped = (%d,%v,%q)", n, err, capped.buf.String())
	}

	// CheckKnownHosts: matched, unlisted, mismatched, parse error.
	_, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer1, err := ssh.NewSignerFromKey(priv1)
	if err != nil {
		t.Fatal(err)
	}
	_, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer2, err := ssh.NewSignerFromKey(priv2)
	if err != nil {
		t.Fatal(err)
	}

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{"[node1.example.com]:2222"}, signer1.PublicKey()) + "\n"
	if err := os.WriteFile(khPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	if matched, unlisted, err := CheckKnownHosts(khPath, "node1.example.com", 2222, signer1.PublicKey()); err != nil || !matched || unlisted {
		t.Fatalf("CheckKnownHosts match = (%v,%v,%v)", matched, unlisted, err)
	}
	if matched, unlisted, err := CheckKnownHosts(khPath, "unknown.example.com", 0, signer1.PublicKey()); err == nil || matched || !unlisted {
		t.Fatalf("CheckKnownHosts unlisted = (%v,%v,%v)", matched, unlisted, err)
	}
	if matched, unlisted, err := CheckKnownHosts(khPath, "node1.example.com", 2222, signer2.PublicKey()); err == nil || matched || unlisted {
		t.Fatalf("CheckKnownHosts mismatch = (%v,%v,%v)", matched, unlisted, err)
	}
	if _, _, err := CheckKnownHosts(filepath.Join(t.TempDir(), "missing"), "node1", 22, signer1.PublicKey()); !errors.Is(err, ErrKnownHostsParse) {
		t.Fatalf("CheckKnownHosts missing file err = %v, want ErrKnownHostsParse", err)
	}
}

func TestLinkNewSessionAndCombinedOutputCapped(t *testing.T) {
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srvCfg := &ssh.ServerConfig{NoClientAuth: true}
	srvCfg.AddHostKey(hostSigner)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, chans, reqs, err := ssh.NewServerConn(conn, srvCfg)
		if err != nil {
			_ = conn.Close()
			return
		}
		go ssh.DiscardRequests(reqs)
		for newCh := range chans {
			ch, chReqs, err := newCh.Accept()
			if err != nil {
				continue
			}
			go func(c ssh.Channel, in <-chan *ssh.Request) {
				defer c.Close()
				for req := range in {
					if req.Type == "exec" {
						_ = req.Reply(true, nil)
						_, _ = c.Write([]byte("0123456789abcdef"))
						_, _ = c.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
						return
					}
					_ = req.Reply(false, nil)
				}
			}(ch, chReqs)
		}
	}()

	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cliCfg := &ssh.ClientConfig{
		User:            "root",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}
	cc, chans, reqs, err := ssh.NewClientConn(rawConn, ln.Addr().String(), cliCfg)
	if err != nil {
		t.Fatal(err)
	}
	link := &Link{
		Client: ssh.NewClient(cc, chans, reqs),
		Net:    rawConn,
	}
	defer link.Close()

	out, err := link.CombinedOutputCapped(context.Background(), slog.Default(), 2*time.Second, "echo hi", 6)
	if err != nil {
		t.Fatalf("CombinedOutputCapped: %v", err)
	}
	if string(out) != "012345" {
		t.Fatalf("CombinedOutputCapped = %q, want 012345", string(out))
	}

	// Cancelled ctx path triggers l.Close and returns context.Canceled.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = link.CombinedOutputCapped(ctx, slog.Default(), 2*time.Second, "echo hi", 6)
	if err == nil {
		t.Fatal("expected error with cancelled ctx")
	}
	_ = fmt.Sprint(strings.TrimSpace(""))
}
