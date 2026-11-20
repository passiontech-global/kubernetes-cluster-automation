// ssh_transport_test.go — the sshConn paths against scripted
// in-process servers: sudo-failure stderr wording, the link-kill
// cancel semantics for Run/Write, and the session/exec rejection
// errors. The happy-path transport walk lives in ssh_dialer_test.go.
package hubsync

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/sshclient"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// pemKeyFile writes the client key in OpenSSH PEM form (the shape
// sshclient.Config.LoadSigner parses) and returns its path.
func pemKeyFile(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(p, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// dialLive opens a conn to srv — the plumbing every transport test
// shares.
func dialLive(t *testing.T, keyPath string, port int, user string) (Conn, context.CancelFunc) {
	t.Helper()
	d, err := newSSHDialer(keyPath, port, 5*time.Second, time.Minute, "", true, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	conn, err := d.Dial(ctx, Target{Name: "t", IP: "127.0.0.1", SSHUser: user})
	if err != nil {
		cancel()
		t.Fatalf("dial: %v", err)
	}
	return conn, cancel
}

// TestSSHConnSudoFailureWording: a non-zero sudo exit carries the
// remote stderr — "sudo: a password is required" lands in the error
// instead of a bare "exit status 1".
func TestSSHConnSudoFailureWording(t *testing.T) {
	key := pemKeyFile(t)
	srv := newTestSSHServerOpts(t, key,
		func(string, []byte) string { return "" },
		sshServerOpts{failOn: map[string]string{
			"sudo -n id": "sudo: a password is required",
		}})
	conn, cancel := dialLive(t, key, srv.port(), "ubuntu")
	defer cancel()

	_, err := conn.Run(context.Background(), "id")
	if err == nil ||
		!strings.Contains(err.Error(), "status 1") ||
		!strings.Contains(err.Error(), "sudo: a password is required") {
		t.Fatalf("sudo failure err=%v want exit status + remote stderr", err)
	}
}

// TestSSHConnRunCancelKillsLink: a wedged target (exec accepted but
// never answered) is recovered by ctx cancel — Run tears down the
// link and returns ctx.Err instead of hanging on CombinedOutput.
func TestSSHConnRunCancelKillsLink(t *testing.T) {
	key := pemKeyFile(t)
	srv := newTestSSHServerOpts(t, key,
		func(string, []byte) string { return "unreachable" },
		sshServerOpts{hangOn: []string{"sha256sum"}})
	conn, _ := dialLive(t, key, srv.port(), "")

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// Cancel exactly when the server accepts the exec — the call
		// is wedged from that instant, no guessed delay needed.
		select {
		case <-srv.execSeen:
		case <-time.After(2 * time.Second):
		}
		cancel()
	}()
	out, err := conn.Run(ctx, "sha256sum /f")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("run=%q err=%v want context.Canceled", out, err)
	}
}

// gateReader blocks Read until its gate closes, then fails — it
// simulates a slow/broken local source so Write's copy goroutine is
// still parked when the cancel lands. entered, when set, closes the
// moment Read is reached — the deterministic "copy goroutine parked"
// signal.
type gateReader struct {
	gate    chan struct{}
	entered chan struct{}
}

func (g *gateReader) Read([]byte) (int, error) {
	if g.entered != nil {
		close(g.entered) // one-shot: the copy goroutine reached Read
		g.entered = nil
	}
	<-g.gate
	return 0, io.ErrClosedPipe
}

// TestSSHConnWriteCancelKillsLink: the Write cancel path waits for
// the copy goroutine to release the reader before returning ctx.Err —
// the caller may close the handle right after.
func TestSSHConnWriteCancelKillsLink(t *testing.T) {
	key := pemKeyFile(t)
	srv := newTestSSHServerOpts(t, key,
		func(string, []byte) string { return "" },
		sshServerOpts{hangOn: []string{"cat >"}})
	conn, dialCancel := dialLive(t, key, srv.port(), "")
	t.Cleanup(dialCancel)

	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	gate := make(chan struct{})
	go func() {
		<-entered // Write's copy goroutine is parked in gateReader.Read
		cancel()
		waitDone := make(chan struct{})
		go func() {
			_ = conn.(*sshConn).link.Client.Wait()
			close(waitDone)
		}()
		select {
		case <-waitDone:
		case <-time.After(2 * time.Second):
		}
		close(gate)
	}()
	err := conn.Write(ctx, "/dst/file", &gateReader{gate: gate, entered: entered})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("write err=%v want context.Canceled", err)
	}
}

// TestSSHConnSessionRejected: a target refusing session channels
// surfaces the channel-open failure through both Run and Write.
func TestSSHConnSessionRejected(t *testing.T) {
	key := pemKeyFile(t)
	srv := newTestSSHServerOpts(t, key,
		func(string, []byte) string { return "" },
		sshServerOpts{rejectSession: true})
	conn, cancel := dialLive(t, key, srv.port(), "")
	defer cancel()

	if _, err := conn.Run(context.Background(), "id"); err == nil {
		t.Fatal("rejected session Run want error")
	}
	if err := conn.Write(context.Background(), "/f",
		strings.NewReader("x")); err == nil {
		t.Fatal("rejected session Write want error")
	}
}

// TestSSHConnExecRejected: a session that opens but refuses the exec
// request fails sess.Start — the Write staging path errors instead of
// streaming into nothing.
func TestSSHConnExecRejected(t *testing.T) {
	key := pemKeyFile(t)
	srv := newTestSSHServerOpts(t, key,
		func(string, []byte) string { return "" },
		sshServerOpts{rejectExec: true})
	conn, cancel := dialLive(t, key, srv.port(), "")
	defer cancel()

	if err := conn.Write(context.Background(), "/f",
		strings.NewReader("x")); err == nil {
		t.Fatal("rejected exec Write want error")
	}
	if _, err := conn.Run(context.Background(), "id"); err == nil {
		t.Fatal("rejected exec Run want error")
	}
}

// TestSSHConnExecChannelDropped: a session that dies exactly as the
// exec request lands fails sess.Start (the StdinPipe is already
// open — the write staging must not stream into a dead channel).
func TestSSHConnExecChannelDropped(t *testing.T) {
	key := pemKeyFile(t)
	srv := newTestSSHServerOpts(t, key,
		func(string, []byte) string { return "" },
		sshServerOpts{closeOnExec: true})
	conn, cancel := dialLive(t, key, srv.port(), "")
	defer cancel()

	if err := conn.Write(context.Background(), "/f",
		strings.NewReader("x")); err == nil {
		t.Fatal("dropped exec channel Write want error")
	}
}

type testJumpBastion struct {
	ln        net.Listener
	blackhole atomic.Bool
}

func newTestJumpBastion(t *testing.T, targetAddr string) *testJumpBastion {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	scfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	scfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	jb := &testJumpBastion{ln: ln}
	quit := make(chan struct{})
	t.Cleanup(func() {
		close(quit)
		_ = ln.Close()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(raw net.Conn) {
				_, chans, reqs, err := ssh.NewServerConn(raw, scfg)
				if err != nil {
					_ = raw.Close()
					return
				}
				go func() {
					for req := range reqs {
						if req.WantReply && !jb.blackhole.Load() {
							_ = req.Reply(false, nil)
						}
					}
				}()
				for ch := range chans {
					if ch.ChannelType() != "direct-tcpip" {
						if !jb.blackhole.Load() {
							_ = ch.Reject(ssh.UnknownChannelType, "no")
						}
						continue
					}
					if jb.blackhole.Load() {
						// Blackholed bastion: leave channel open without forwarding or replying.
						continue
					}
					up, derr := net.Dial("tcp", targetAddr)
					if derr != nil {
						_ = ch.Reject(ssh.ConnectionFailed, derr.Error())
						continue
					}
					down, _, aerr := ch.Accept()
					if aerr != nil {
						_ = up.Close()
						continue
					}
					go func() {
						defer up.Close()
						defer down.Close()
						bridgeDone := make(chan struct{}, 2)
						go func() { _, _ = io.Copy(up, down); bridgeDone <- struct{}{} }()
						go func() { _, _ = io.Copy(down, up); bridgeDone <- struct{}{} }()
						select {
						case <-quit:
						case <-bridgeDone:
						}
					}()
				}
			}(c)
		}
	}()
	return jb
}

func (jb *testJumpBastion) spec() string {
	return "jump@" + jb.ln.Addr().String()
}

type blackholeNetConn struct {
	net.Conn
	blackholed atomic.Bool
	closed     chan struct{}
	closeOnce  sync.Once
}

func newBlackholeNetConn(c net.Conn) *blackholeNetConn {
	return &blackholeNetConn{Conn: c, closed: make(chan struct{})}
}

func (b *blackholeNetConn) Read(p []byte) (int, error) {
	if b.blackholed.Load() {
		<-b.closed
		return 0, io.EOF
	}
	return b.Conn.Read(p)
}

func (b *blackholeNetConn) Write(p []byte) (int, error) {
	if b.blackholed.Load() {
		<-b.closed
		return 0, net.ErrClosed
	}
	return b.Conn.Write(p)
}

func (b *blackholeNetConn) Close() error {
	b.closeOnce.Do(func() { close(b.closed) })
	return b.Conn.Close()
}

// TestSSHConnStreamCmdSharedBastionCancelPreservesBastion verifies E15:
// cancelling a stalled streamCmd over a healthy shared bastion closes only the
// per-target link without poisoning/closing the cached *sshclient.Bastion.
func TestSSHConnStreamCmdSharedBastionCancelPreservesBastion(t *testing.T) {
	key := pemKeyFile(t)
	srv := newTestSSHServerOpts(t, key,
		func(cmd string, _ []byte) string { return "ok:" + cmd },
		sshServerOpts{hangOn: []string{"cat >"}})

	jb := newTestJumpBastion(t, srv.addr())
	d, err := newSSHDialer(key, srv.port(), 2*time.Second, time.Minute, "", true, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.closeBastions)

	conn, err := d.Dial(context.Background(), Target{Name: "t1", IP: "127.0.0.1", ProxyJump: jb.spec()})
	if err != nil {
		t.Fatalf("dial t1: %v", err)
	}
	d.mu.Lock()
	b := d.jumps[jb.spec()]
	d.mu.Unlock()
	if b == nil {
		t.Fatal("bastion not cached")
	}

	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	gate := make(chan struct{})
	go func() {
		<-entered
		cancel()
		waitDone := make(chan struct{})
		go func() {
			_ = conn.(*sshConn).link.Client.Wait()
			close(waitDone)
		}()
		select {
		case <-waitDone:
		case <-time.After(2 * time.Second):
		}
		close(gate)
	}()
	err = conn.Write(ctx, "/dst/file", &gateReader{gate: gate, entered: entered})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Write err=%v want context.Canceled", err)
	}
	if b.Closed() {
		t.Fatal("shared bastion closed after single target streamCmd cancel")
	}

	// Second target over the SAME cached shared bastion succeeds.
	conn2, err := d.Dial(context.Background(), Target{Name: "t2", IP: "127.0.0.1", ProxyJump: jb.spec()})
	if err != nil {
		t.Fatalf("dial t2: %v", err)
	}
	if out, err := conn2.Run(context.Background(), "id"); err != nil || out != "ok:id" {
		_ = conn2.Close()
		t.Fatalf("t2 Run=(%q, %v) want ok:id", out, err)
	}
	_ = conn2.Close()
	d.mu.Lock()
	bAfter := d.jumps[jb.spec()]
	d.mu.Unlock()
	if bAfter != b {
		t.Fatal("expected t2 to reuse the same healthy cached bastion")
	}

	// Shared-bastion idle timer fires cleanly when remote tail stalls past c.timeout
	// without touching b.Net deadline (preserving healthy shared bastion).
	conn3, err := d.Dial(context.Background(), Target{Name: "t3", IP: "127.0.0.1", ProxyJump: jb.spec()})
	if err != nil {
		t.Fatalf("dial t3: %v", err)
	}
	sc3 := conn3.(*sshConn)
	sc3.timeout = 40 * time.Millisecond
	if err := sc3.Write(context.Background(), "/dst/stall", strings.NewReader("chunk")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected idle timeout DeadlineExceeded, got %v", err)
	}
	if b.Closed() {
		t.Fatal("shared bastion closed on healthy bastion idle timeout")
	}
}

// TestSSHConnStreamCmdBlackholedBastionEscalates verifies E15: a blackholed
// shared bastion during streamCmd escalates via Link.CloseWait -> ForceClose,
// marks b.Closed(), does not hang, and d.bastion evicts the closed bastion.
func TestSSHConnStreamCmdBlackholedBastionEscalates(t *testing.T) {
	key := pemKeyFile(t)
	srv := newTestSSHServerOpts(t, key,
		func(string, []byte) string { return "" },
		sshServerOpts{hangOn: []string{"cat >"}})
	jb := newTestJumpBastion(t, srv.addr())
	d, err := newSSHDialer(key, srv.port(), 2*time.Second, time.Minute, "", true, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.closeBastions)

	// Open a Bastion over blackholeNetConn so we can blackhole b.Net mid-streamCmd.
	rawJump, err := net.Dial("tcp", jb.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	bh := newBlackholeNetConn(rawJump)
	jcfg := d.cfg
	jcfg.HostKeyVerify = func(string, ssh.PublicKey) error { return nil }
	signer, err := jcfg.LoadSigner()
	if err != nil {
		t.Fatal(err)
	}
	jclient, err := jcfg.Handshake(context.Background(), bh, bh, jb.ln.Addr().String(), &ssh.ClientConfig{
		User:            "jump",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test jump server
	})
	if err != nil {
		t.Fatal(err)
	}
	b := &sshclient.Bastion{Spec: jb.spec(), Net: bh, Client: jclient}
	d.mu.Lock()
	d.jumps = map[string]*sshclient.Bastion{jb.spec(): b}
	d.mu.Unlock()

	conn, err := d.Dial(context.Background(), Target{Name: "t1", IP: "127.0.0.1", ProxyJump: jb.spec()})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-srv.execSeen
		bh.blackholed.Store(true)
		cancel()
	}()
	start := time.Now()
	err = conn.Write(ctx, "/dst/bh", strings.NewReader("chunk"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Write err=%v want context.Canceled", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("streamCmd hung on blackholed bastion (%s)", time.Since(start))
	}
	if !b.Closed() {
		t.Fatal("blackholed bastion not closed by CloseWait -> ForceClose escalation")
	}
	// Eviction check: d.bastion must not hand back the closed bastion.
	b2, err := d.bastion(context.Background(), &d.cfg, jb.spec())
	if err != nil {
		t.Fatalf("re-open bastion after eviction: %v", err)
	}
	if b2 == b || b2.Closed() {
		t.Fatal("d.bastion returned the closed bastion instead of evicting it")
	}
}

// TestSSHDialerCloseBastionsAndLeaseLoss verifies E15: closeBastions closes and
// clears d.jumps, guards concurrent OpenBastion via jumpGen, and renewLease
// invokes closeBastions on lease loss (!held).
func TestSSHDialerCloseBastionsAndLeaseLoss(t *testing.T) {
	key := pemKeyFile(t)
	srv := newTestSSHServer(t, key, func(string, []byte) string { return "" })
	jb := newTestJumpBastion(t, srv.addr())
	d, err := newSSHDialer(key, srv.port(), 2*time.Second, time.Minute, "", true, "", nil)
	if err != nil {
		t.Fatal(err)
	}

	b, err := d.bastion(context.Background(), &d.cfg, jb.spec())
	if err != nil {
		t.Fatalf("open bastion: %v", err)
	}
	cs := testutil.FakeKube()
	s, err := New(Config{
		Client:   cs,
		Identity: "pod-a",
		Dialer:   d,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Failing renew (e.g. lease stolen or API error) -> !held -> closes bastions.
	if !s.renewLease(context.Background()) {
		t.Fatal("expected initial acquire")
	}
	if b.Closed() {
		t.Fatal("bastion closed while lease held")
	}
	// Another pod takes the lease -> renewLease returns false -> closeBastions runs.
	l, _ := cs.CoordinationV1().Leases("node-ops").Get(context.Background(), "node-host-agent-hubsync", metav1.GetOptions{})
	other := "pod-b"
	l.Spec.HolderIdentity = &other
	_, err = cs.CoordinationV1().Leases("node-ops").Update(context.Background(), l, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if s.renewLease(context.Background()) {
		t.Fatal("expected lease loss")
	}
	if !b.Closed() {
		t.Fatal("cached bastion not closed on lease loss")
	}
	d.mu.Lock()
	remaining := len(d.jumps)
	d.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("d.jumps not cleared on closeBastions, len=%d", remaining)
	}

	// Race test: concurrent bastion() open vs closeBastions() under -race.
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			_, _ = d.bastion(context.Background(), &d.cfg, jb.spec())
		})
		wg.Go(func() {
			d.closeBastions()
		})
	}
	wg.Wait()
	d.closeBastions()
}

// TestSSHConnPrepareHostAndProbeDirs tests the batched sshConn fast paths.
func TestSSHConnPrepareHostAndProbeDirs(t *testing.T) {
	key := pemKeyFile(t)
	var cmds []string
	var mode string
	srv := newTestSSHServer(t, key, func(cmd string, _ []byte) string {
		cmds = append(cmds, cmd)
		switch mode {
		case "ok":
			// Extract the unique nonce token from the sh -c script.
			start := strings.Index(cmd, "__HS_")
			end := strings.Index(cmd[start:], "LS:0")
			tok := cmd[start : start+end]
			return fmt.Sprintf("%sLS:0\ncluster.yaml\nsubdir/\n%sLS:1\nnebula-ca.crt\n%sFIND:0\n.old.tmp\n%sFIND:1\n",
				tok, tok, tok, tok)
		case "truncated":
			start := strings.Index(cmd, "__HS_")
			end := strings.Index(cmd[start:], "LS:0")
			tok := cmd[start : start+end]
			return fmt.Sprintf("%sLS:0\ncluster.yaml\n", tok)
		default:
			return ""
		}
	})
	d, err := newSSHDialer(key, srv.port(), 2*time.Second, time.Minute, "", true, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d.Dial(context.Background(), Target{Name: "t", IP: "127.0.0.1", SSHUser: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	sc := conn.(*sshConn)

	if err := sc.PrepareHost(context.Background(), []remoteDir{
		{path: "/etc/node-host-agent/vars"},
		{path: "/etc/api-backend-guard", mode: "0700"},
	}); err != nil {
		t.Fatalf("PrepareHost: %v", err)
	}
	if len(cmds) != 1 || !strings.HasPrefix(cmds[0], "sudo -n sh -c ") || !strings.Contains(cmds[0], "chmod 0700") {
		t.Fatalf("unexpected PrepareHost cmd: %v", cmds)
	}

	mode = "ok"
	lsMap, orphanMap, err := sc.ProbeDirs(context.Background(),
		[]string{"/etc/node-host-agent/vars", "/etc/node-host-agent/nebula-certs"},
		[]string{"/usr/local/bin", "/etc/node-host-agent/vars"})
	if err != nil {
		t.Fatalf("ProbeDirs ok: %v", err)
	}
	if !slices.Equal(lsMap["/etc/node-host-agent/vars"], []string{"cluster.yaml", "subdir/"}) {
		t.Fatalf("vars ls = %v", lsMap)
	}
	if !slices.Equal(lsMap["/etc/node-host-agent/nebula-certs"], []string{"nebula-ca.crt"}) {
		t.Fatalf("certs ls = %v", lsMap)
	}
	if !slices.Equal(orphanMap["/usr/local/bin"], []string{".old.tmp"}) {
		t.Fatalf("orphans = %v", orphanMap)
	}

	mode = "truncated"
	if _, _, err := sc.ProbeDirs(context.Background(),
		[]string{"/etc/node-host-agent/vars", "/etc/node-host-agent/nebula-certs"},
		[]string{"/usr/local/bin"}); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("expected truncated error, got %v", err)
	}
}
