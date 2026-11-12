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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
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
	d, err := newSSHDialer(keyPath, port, 5*time.Second, "", true, "", nil)
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
		time.Sleep(80 * time.Millisecond)
		cancel()
	}()
	out, err := conn.Run(ctx, "sha256sum /f")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("run=%q err=%v want context.Canceled", out, err)
	}
}

// gateReader blocks Read until its gate closes, then fails — it
// simulates a slow/broken local source so Write's copy goroutine is
// still parked when the cancel lands.
type gateReader struct {
	gate chan struct{}
}

func (g *gateReader) Read([]byte) (int, error) {
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
	conn, _ := dialLive(t, key, srv.port(), "")

	ctx, cancel := context.WithCancel(context.Background())
	gate := make(chan struct{})
	go func() {
		time.Sleep(80 * time.Millisecond)
		cancel()
		close(gate)
	}()
	err := conn.Write(ctx, "/dst/file", &gateReader{gate: gate})
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
