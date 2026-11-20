package sshclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

func TestBastionClosedAndLinkForceClose(t *testing.T) {
	var nilB *Bastion
	if nilB.Closed() {
		t.Fatal("nil Bastion.Closed() must be false")
	}
	if err := nilB.Close(); err != nil {
		t.Fatalf("nil Bastion.Close() = %v", err)
	}

	c1, c2 := net.Pipe()
	defer func() { _ = c2.Close() }()
	b := &Bastion{Spec: "jump", Net: c1}
	if b.Closed() {
		t.Fatal("fresh Bastion must not be Closed()")
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Bastion.Close() = %v", err)
	}
	if !b.Closed() {
		t.Fatal("Bastion.Closed() must be true after Close()")
	}

	// Link.Close() leaves JumpShared bastion open; Link.ForceClose() tears it down.
	j1, j2 := net.Pipe()
	defer func() { _ = j2.Close() }()
	sharedB := &Bastion{Spec: "shared", Net: j1}
	t1, t2 := net.Pipe()
	defer func() { _ = t2.Close() }()
	link := &Link{Net: t1, JumpNet: j1, JumpShared: true, bastion: sharedB}
	if err := link.Close(); err != nil {
		t.Fatalf("Link.Close() = %v", err)
	}
	if sharedB.Closed() {
		t.Fatal("Link.Close() closed JumpShared bastion")
	}
	if err := link.ForceClose(); err != nil {
		t.Fatalf("Link.ForceClose() = %v", err)
	}
	if !sharedB.Closed() {
		t.Fatal("Link.ForceClose() did not mark shared bastion closed")
	}
}

type blackholeConn struct {
	net.Conn
	blackholed atomic.Bool
	closed     chan struct{}
	closeOnce  sync.Once
}

func newBlackholeConn(c net.Conn) *blackholeConn {
	return &blackholeConn{Conn: c, closed: make(chan struct{})}
}

func (b *blackholeConn) Read(p []byte) (int, error) {
	if b.blackholed.Load() {
		<-b.closed
		return 0, net.ErrClosed
	}
	return b.Conn.Read(p)
}

func (b *blackholeConn) Write(p []byte) (int, error) {
	if b.blackholed.Load() {
		<-b.closed
		return 0, net.ErrClosed
	}
	return b.Conn.Write(p)
}

func (b *blackholeConn) Close() error {
	b.closeOnce.Do(func() { close(b.closed) })
	return b.Conn.Close()
}

func TestCombinedOutputCappedEscalatesOnBlackholedSharedBastion(t *testing.T) {
	// Target SSH server: accepts exec and holds the channel open until blackhole closes.
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	srvCfg := &ssh.ServerConfig{NoClientAuth: true}
	srvCfg.AddHostKey(hostSigner)

	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = targetLn.Close() }()

	blackhole := make(chan struct{})
	defer close(blackhole)
	execStarted := make(chan struct{})
	go func() {
		for {
			conn, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, chans, reqs, err := ssh.NewServerConn(c, srvCfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for newCh := range chans {
					ch, chReqs, err := newCh.Accept()
					if err != nil {
						continue
					}
					go func(ch ssh.Channel, in <-chan *ssh.Request) {
						defer ch.Close()
						for req := range in {
							if req.Type == "exec" {
								_ = req.Reply(true, nil)
								close(execStarted)
								<-blackhole
								return
							}
							_ = req.Reply(false, nil)
						}
					}(ch, chReqs)
				}
			}(conn)
		}
	}()

	jumpAddr := startTestSSHJumpServer(t)
	rawJump, err := net.Dial("tcp", jumpAddr)
	if err != nil {
		t.Fatal(err)
	}
	bh := newBlackholeConn(rawJump)
	cfg := dialTestConfig(t, nil)
	cfg.Port = portOf(t, targetLn.Addr().String())
	cfg.Timeout = 2 * time.Second
	signer, err := cfg.LoadSigner()
	if err != nil {
		t.Fatal(err)
	}
	jumpClient, err := cfg.Handshake(context.Background(), bh, bh, jumpAddr,
		cfg.jumpClientConfig("root", signer))
	if err != nil {
		t.Fatal(err)
	}
	b := &Bastion{Spec: jumpAddr, Net: bh, Client: jumpClient}

	link, err := cfg.DialVia(context.Background(), "root", "127.0.0.1", b)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-execStarted
		bh.blackholed.Store(true)
		cancel()
	}()

	start := time.Now()
	_, err = link.CombinedOutputCapped(ctx, slog.Default(), 5*time.Second, "sleep 60", 1024)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("CombinedOutputCapped err = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("CombinedOutputCapped took %v to unblock on cancelled blackholed bastion", elapsed)
	}
	if !b.Closed() {
		t.Fatal("blackholed shared bastion was not ForceClosed after grace")
	}

	// Explicit CloseWait escalation test on net.Pipe when done never fires and l.Close() blocks.
	p1, p2 := net.Pipe()
	defer func() { _ = p2.Close() }()
	b2 := &Bastion{Spec: "stuck", Net: p1}
	l2 := &Link{Net: p1, JumpNet: p1, JumpShared: true, bastion: b2}
	stalledDone := make(chan error, 1)
	go func() {
		_, rerr := p1.Read(make([]byte, 1))
		stalledDone <- rerr
	}()
	start = time.Now()
	if err := l2.CloseWait(stalledDone, 25*time.Millisecond); err == nil {
		t.Fatal("expected read error from ForceClosed pipe")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("CloseWait took %v to escalate", elapsed)
	}
	if !b2.Closed() {
		t.Fatal("CloseWait escalation did not mark bastion Closed()")
	}
}

func TestHandshakeCancelsImmediatelyOnCtxCancel(t *testing.T) {
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close(); _ = c2.Close() }()

	cfg := dialTestConfig(t, nil)
	cfg.Timeout = 10 * time.Second
	signer, err := cfg.LoadSigner()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	if _, err := cfg.Handshake(ctx, c1, c1, "127.0.0.1:22", cfg.ClientConfig("root", signer)); err == nil {
		t.Fatal("Handshake on silent pipe with cancelled ctx must fail")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Handshake took %v — ctx.AfterFunc did not cancel", elapsed)
	}
}

func startTestSSHExecServer(t *testing.T, onSession func(ssh.NewChannel)) string {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
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
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, chans, reqs, err := ssh.NewServerConn(c, srvCfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for newCh := range chans {
					if onSession != nil {
						go onSession(newCh)
						continue
					}
					ch, chReqs, err := newCh.Accept()
					if err != nil {
						continue
					}
					go func(ch ssh.Channel, in <-chan *ssh.Request) {
						defer ch.Close()
						for req := range in {
							if req.Type == "exec" {
								_ = req.Reply(true, nil)
								_, _ = ch.Write([]byte("ok"))
								_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
								return
							}
							_ = req.Reply(false, nil)
						}
					}(ch, chReqs)
				}
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func startTestSSHStallDialJumpServer(t *testing.T, stallPort int, release <-chan struct{}) string {
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
				return
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
					host, port, ok := parseDirectTCPIP(ch.ExtraData())
					if !ok {
						_ = ch.Reject(ssh.ConnectionFailed, "bad payload")
						continue
					}
					if int(port) == stallPort {
						go func(newCh ssh.NewChannel) {
							<-release
							_ = newCh.Reject(ssh.ConnectionFailed, "stalled")
						}(ch)
						continue
					}
					dconn, creqs, err := ch.Accept()
					if err != nil {
						continue
					}
					go ssh.DiscardRequests(creqs)
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

func TestSharedBastionSurvivesTargetCtxCancel(t *testing.T) {
	assertHealthyExec := func(t *testing.T, cfg Config, b *Bastion, execPort int) {
		t.Helper()
		if b.Closed() {
			t.Fatal("shared bastion unexpectedly marked Closed()")
		}
		cfgExec := cfg
		cfgExec.Port = execPort
		link, err := cfgExec.DialVia(context.Background(), "root", "127.0.0.1", b)
		if err != nil {
			t.Fatalf("subsequent DialVia on healthy shared bastion failed: %v", err)
		}
		defer func() { _ = link.Close() }()
		out, err := link.CombinedOutputCapped(context.Background(), slog.Default(), 2*time.Second, "echo ok", 1024)
		if err != nil || string(out) != "ok" {
			t.Fatalf("subsequent CombinedOutputCapped = (%q, %v), want (\"ok\", nil)", string(out), err)
		}
	}

	t.Run("DialVia_timeout_and_cancel", func(t *testing.T) {
		release := make(chan struct{})
		defer close(release)
		const stallPort = 59998
		jumpAddr := startTestSSHStallDialJumpServer(t, stallPort, release)
		execAddr := startTestSSHExecServer(t, nil)
		execPort := portOf(t, execAddr)

		cfg := dialTestConfig(t, nil)
		cfg.Timeout = 2 * time.Second
		b, err := cfg.OpenBastion(context.Background(), "root@"+jumpAddr)
		if err != nil {
			t.Fatalf("OpenBastion: %v", err)
		}
		defer func() { _ = b.Close() }()

		cfgStall := cfg
		cfgStall.Port = stallPort
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancel()
		start := time.Now()
		if _, err := cfgStall.DialVia(ctx, "root", "127.0.0.1", b); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("DialVia stalled err = %v, want context.DeadlineExceeded", err)
		} else if !strings.Contains(err.Error(), "→") {
			t.Fatalf("DialVia stalled err = %v, want arrow format", err)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("DialVia took %v on 40ms timeout", elapsed)
		}

		cctx, ccancel := context.WithCancel(context.Background())
		ccancel()
		if _, err := cfgStall.DialVia(cctx, "root", "127.0.0.1", b); !errors.Is(err, context.Canceled) {
			t.Fatalf("DialVia pre-cancelled err = %v, want context.Canceled", err)
		}

		assertHealthyExec(t, cfg, b, execPort)
	})

	t.Run("Handshake_timeout", func(t *testing.T) {
		jumpAddr := startTestSSHJumpServer(t)
		execAddr := startTestSSHExecServer(t, nil)
		execPort := portOf(t, execAddr)

		// Silent TCP server: accepts connections and holds them without sending SSH banner.
		silentLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = silentLn.Close() }()
		var silentConnsMu sync.Mutex
		var silentConns []net.Conn
		t.Cleanup(func() {
			silentConnsMu.Lock()
			for _, c := range silentConns {
				_ = c.Close()
			}
			silentConnsMu.Unlock()
		})
		go func() {
			for {
				c, err := silentLn.Accept()
				if err != nil {
					return
				}
				silentConnsMu.Lock()
				silentConns = append(silentConns, c)
				silentConnsMu.Unlock()
			}
		}()

		cfg := dialTestConfig(t, nil)
		cfg.Timeout = 2 * time.Second
		b, err := cfg.OpenBastion(context.Background(), "root@"+jumpAddr)
		if err != nil {
			t.Fatalf("OpenBastion: %v", err)
		}
		defer func() { _ = b.Close() }()

		cfgSilent := cfg
		cfgSilent.Port = portOf(t, silentLn.Addr().String())
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancel()
		start := time.Now()
		if _, err := cfgSilent.DialVia(ctx, "root", "127.0.0.1", b); err == nil {
			t.Fatal("DialVia to silent target must fail")
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("DialVia Handshake took %v on 40ms timeout", elapsed)
		}
		assertHealthyExec(t, cfg, b, execPort)

		// Also verify direct Handshake(ctx, chanConn, b.Net, ...) preserves b.Net.
		nc, err := b.Client.Dial("tcp", silentLn.Addr().String())
		if err != nil {
			t.Fatalf("b.Client.Dial: %v", err)
		}
		signer, err := cfg.LoadSigner()
		if err != nil {
			t.Fatal(err)
		}
		ctx2, cancel2 := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancel2()
		if _, err := cfg.Handshake(ctx2, nc, b.Net, silentLn.Addr().String(), cfg.ClientConfig("root", signer)); err == nil {
			t.Fatal("direct Handshake to silent target must fail")
		}
		assertHealthyExec(t, cfg, b, execPort)
	})

	t.Run("NewSession_and_CombinedOutputCapped_timeout", func(t *testing.T) {
		jumpAddr := startTestSSHJumpServer(t)
		execAddr := startTestSSHExecServer(t, nil)
		execPort := portOf(t, execAddr)

		doneCh := make(chan struct{})
		defer close(doneCh)
		stallSessAddr := startTestSSHExecServer(t, func(ssh.NewChannel) {
			<-doneCh // never accept/reject session channel open
		})
		stallExecAddr := startTestSSHExecServer(t, func(newCh ssh.NewChannel) {
			ch, chReqs, err := newCh.Accept()
			if err != nil {
				return
			}
			go func() {
				defer ch.Close()
				for req := range chReqs {
					if req.Type == "exec" {
						_ = req.Reply(true, nil)
						<-doneCh
						return
					}
					_ = req.Reply(false, nil)
				}
			}()
		})

		cfg := dialTestConfig(t, nil)
		cfg.Timeout = 2 * time.Second
		b, err := cfg.OpenBastion(context.Background(), "root@"+jumpAddr)
		if err != nil {
			t.Fatalf("OpenBastion: %v", err)
		}
		defer func() { _ = b.Close() }()

		// 1) NewSession stalls on target -> times out without poisoning shared bastion.
		cfgSess := cfg
		cfgSess.Port = portOf(t, stallSessAddr)
		link1, err := cfgSess.DialVia(context.Background(), "root", "127.0.0.1", b)
		if err != nil {
			t.Fatalf("DialVia stallSess: %v", err)
		}
		ctx1, cancel1 := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancel1()
		if _, _, err := link1.NewSession(ctx1, slog.Default(), 2*time.Second); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("NewSession stalled err = %v, want context.DeadlineExceeded", err)
		}
		assertHealthyExec(t, cfg, b, execPort)

		// 2) CombinedOutputCapped stalls on exec with short timeout -> bounds via runCtx without poisoning bastion.
		cfgExecStall := cfg
		cfgExecStall.Port = portOf(t, stallExecAddr)
		link2, err := cfgExecStall.DialVia(context.Background(), "root", "127.0.0.1", b)
		if err != nil {
			t.Fatalf("DialVia stallExec: %v", err)
		}
		defer func() { _ = link2.Close() }()
		if _, err := link2.CombinedOutputCapped(context.Background(), slog.Default(), 40*time.Millisecond, "sleep 60", 1024); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("CombinedOutputCapped stalled err = %v, want context.DeadlineExceeded", err)
		}
		assertHealthyExec(t, cfg, b, execPort)
	})
}

func TestBlackholedSharedBastionEscalatesAcrossOps(t *testing.T) {
	openBlackholeBastion := func(t *testing.T, targetPort int) (Config, *Bastion, *blackholeConn) {
		t.Helper()
		jumpAddr := startTestSSHJumpServer(t)
		rawJump, err := net.Dial("tcp", jumpAddr)
		if err != nil {
			t.Fatal(err)
		}
		bh := newBlackholeConn(rawJump)
		cfg := dialTestConfig(t, nil)
		cfg.Port = targetPort
		cfg.Timeout = 2 * time.Second
		signer, err := cfg.LoadSigner()
		if err != nil {
			t.Fatal(err)
		}
		jumpClient, err := cfg.Handshake(context.Background(), bh, bh, jumpAddr,
			cfg.jumpClientConfig("root", signer))
		if err != nil {
			t.Fatal(err)
		}
		b := &Bastion{Spec: jumpAddr, Net: bh, Client: jumpClient}
		t.Cleanup(func() { _ = b.Close() })
		return cfg, b, bh
	}

	t.Run("DialVia_blackholed", func(t *testing.T) {
		execAddr := startTestSSHExecServer(t, nil)
		cfg, b, bh := openBlackholeBastion(t, portOf(t, execAddr))
		bh.blackholed.Store(true)

		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancel()
		start := time.Now()
		if _, err := cfg.DialVia(ctx, "root", "127.0.0.1", b); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("DialVia on blackholed bastion err = %v, want context.DeadlineExceeded", err)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("DialVia took %v on blackholed bastion", elapsed)
		}
		if err := b.Close(); err != nil {
			t.Fatalf("b.Close() = %v", err)
		}
		if !b.Closed() {
			t.Fatal("b.Closed() must be true after Close()")
		}
	})

	t.Run("Handshake_blackholed", func(t *testing.T) {
		silentLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = silentLn.Close() }()
		accepted := make(chan struct{}, 1)
		go func() {
			for {
				c, err := silentLn.Accept()
				if err != nil {
					return
				}
				t.Cleanup(func() { _ = c.Close() })
				go func(nc net.Conn) {
					// Wait for client SSH banner byte so DialVia has definitely
					// finished b.Client.Dial and entered Handshake before blackholing.
					var buf [1]byte
					if _, rerr := nc.Read(buf[:]); rerr != nil {
						return
					}
					select {
					case accepted <- struct{}{}:
					default:
					}
				}(c)
			}
		}()

		cfg, b, bh := openBlackholeBastion(t, portOf(t, silentLn.Addr().String()))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			<-accepted
			bh.blackholed.Store(true)
			cancel()
		}()

		start := time.Now()
		if _, err := cfg.DialVia(ctx, "root", "127.0.0.1", b); err == nil {
			t.Fatal("DialVia Handshake on blackholed bastion must fail")
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("Handshake took %v to escalate on blackholed bastion", elapsed)
		}
		if !b.Closed() {
			t.Fatal("blackholed bastion was not Closed() during Handshake escalation")
		}
	})

	t.Run("NewSession_blackholed", func(t *testing.T) {
		execAddr := startTestSSHExecServer(t, nil)
		cfg, b, bh := openBlackholeBastion(t, portOf(t, execAddr))
		link, err := cfg.DialVia(context.Background(), "root", "127.0.0.1", b)
		if err != nil {
			t.Fatalf("DialVia: %v", err)
		}

		bh.blackholed.Store(true)
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancel()
		start := time.Now()
		if _, _, err := link.NewSession(ctx, slog.Default(), 2*time.Second); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("NewSession on blackholed bastion err = %v, want context.DeadlineExceeded", err)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("NewSession took %v to escalate on blackholed bastion", elapsed)
		}
		if !b.Closed() {
			t.Fatal("blackholed bastion was not ForceClosed during NewSession escalation")
		}
	})

	t.Run("CloseWait_done_early_close_blackholed", func(t *testing.T) {
		execAddr := startTestSSHExecServer(t, nil)
		cfg, b, bh := openBlackholeBastion(t, portOf(t, execAddr))
		link, err := cfg.DialVia(context.Background(), "root", "127.0.0.1", b)
		if err != nil {
			t.Fatalf("DialVia: %v", err)
		}

		// Simulate <-done firing before grace while l.Close() stalls on blackholed bastion.
		bh.blackholed.Store(true)
		done := make(chan error, 1)
		done <- context.Canceled
		start := time.Now()
		if err := link.CloseWait(done, 25*time.Millisecond); !errors.Is(err, context.Canceled) {
			t.Fatalf("CloseWait err = %v, want context.Canceled", err)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("CloseWait took %v to escalate when l.Close() stalled", elapsed)
		}
		if !b.Closed() {
			t.Fatal("CloseWait did not ForceClose bastion when l.Close() stalled after <-done")
		}
	})
}
