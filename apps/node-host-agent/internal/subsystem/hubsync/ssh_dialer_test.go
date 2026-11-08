package hubsync

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"golang.org/x/crypto/ssh"
)

// TestEnabled: present file → live, directory → not, empty path → the
// default key path (absent in the test env).
func TestEnabled(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(key, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !Enabled(key) {
		t.Fatal("key file not enabled")
	}
	if Enabled(dir) {
		t.Fatal("directory must not count as a key")
	}
	if Enabled(filepath.Join(key, "sub")) {
		t.Fatal("path under a file must not count")
	}
	if c := (Config{SSHKeyPath: key}); !c.Enabled() {
		t.Fatal("Config.Enabled not reading SSHKeyPath")
	}
}

// TestSyncerName: the agent.Subsystem identifier.
func TestSyncerName(t *testing.T) {
	s := newTestSyncer(fake.NewClientset(),
		time.Unix(0, 0).UTC)
	if got := s.Name(); got != "hubsync" {
		t.Fatalf("name=%q", got)
	}
}

// TestNewSSHDialer: the constructor only records the config — a
// missing key file is NOT an error at construction (Dial loads the
// signer), and a nil log falls back to the package logger.
func TestNewSSHDialer(t *testing.T) {
	d, err := newSSHDialer("/no/such/key", 2222, 7*time.Second, nil)
	if err != nil {
		t.Fatalf("construct err=%v", err)
	}
	if d.cfg.KeyPath != "/no/such/key" || d.cfg.Port != 2222 ||
		d.cfg.Timeout != 7*time.Second {
		t.Fatalf("cfg=%+v", d.cfg)
	}
	if d.cfg.Log == nil || d.log == nil {
		t.Fatal("nil log not defaulted")
	}
}

// --- in-process SSH server ---

// testServer is a minimal SSH server: public-key auth always
// accepted, each exec request served by execFn(cmd, stdin) → output.
type testServer struct {
	ln  net.Listener
	cfg *ssh.ServerConfig

	mu   sync.Mutex
	cmds []string
}

func newTestSSHServer(t *testing.T, clientKeyPath string,
	execFn func(cmd string, stdin []byte) string) *testServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	s := &testServer{cfg: &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}}
	s.cfg.AddHostKey(hostSigner)
	s.ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.ln.Close() })
	go s.acceptLoop(execFn)
	return s
}

func (s *testServer) addr() string { return s.ln.Addr().String() }

func (s *testServer) port() int {
	_, port, _ := net.SplitHostPort(s.addr())
	n, _ := strconv.Atoi(port)
	return n
}

func (s *testServer) acceptLoop(execFn func(string, []byte) string) {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		sconn, chans, reqs, err := ssh.NewServerConn(c, s.cfg)
		if err != nil {
			_ = c.Close()
			continue
		}
		go func() {
			defer sconn.Close()
			for req := range reqs {
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		}()
		for ch := range chans {
			if ch.ChannelType() != "session" {
				_ = ch.Reject(ssh.UnknownChannelType, "no")
				continue
			}
			srv, inReqs, _ := ch.Accept()
			go s.serveSession(srv, inReqs, execFn)
		}
	}
}

// serveSession answers exactly one exec: the command runs after the
// client's stdin hits EOF (the Write path closes it; Run sends
// nothing), the output goes back, exit-status 0 follows.
func (s *testServer) serveSession(srv ssh.Channel,
	inReqs <-chan *ssh.Request, execFn func(string, []byte) string) {
	defer srv.Close()
	for req := range inReqs {
		if req.Type != "exec" {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
		// exec payload is a bare length-prefixed string.
		if len(req.Payload) < 4 {
			return
		}
		n := binary.BigEndian.Uint32(req.Payload[:4])
		if int(n)+4 > len(req.Payload) {
			return
		}
		cmd := string(req.Payload[4 : 4+n])
		if req.WantReply {
			_ = req.Reply(true, nil)
		}
		s.mu.Lock()
		s.cmds = append(s.cmds, cmd)
		s.mu.Unlock()
		// Write commands (`cat >` / `sudo -n tee`) stream stdin —
		// drain to EOF before answering.
		var stdin []byte
		if strings.HasPrefix(cmd, "cat >") ||
			strings.HasPrefix(cmd, "sudo -n tee") {
			stdin, _ = io.ReadAll(srv)
		}
		_, _ = srv.Write([]byte(execFn(cmd, stdin)))
		status := make([]byte, 4)
		binary.BigEndian.PutUint32(status, 0)
		_, _ = srv.SendRequest("exit-status", false, status)
		return
	}
}

func (s *testServer) commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.cmds...)
}

// TestSSHConnLiveServer: sshDialer.Dial + sshConn Run/Write/Close
// (and newSession) against the in-process server — root user, then
// the sudo escalation prefixes for a non-root user.
func TestSSHConnLiveServer(t *testing.T) {
	// Client key the server's always-accept auth lets through; written
	// in OpenSSH PEM form so sshclient.Config.LoadSigner parses it.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	pemBytes := pem.EncodeToMemory(block)
	if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	var written []byte
	srv := newTestSSHServer(t, keyPath,
		func(cmd string, stdin []byte) string {
			switch {
			case strings.HasPrefix(cmd, "cat > "):
				written = stdin
				return ""
			case strings.HasPrefix(cmd, "sudo -n tee"):
				written = stdin
				return ""
			default:
				return "remote-out " + cmd
			}
		})

	d, err := newSSHDialer(keyPath, srv.port(), 5*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Root user: no sudo wrap.
	conn, err := d.Dial(ctx, Target{Name: "t", IP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	out, err := conn.Run(ctx, "sha256sum /f")
	if err != nil || out != "remote-out sha256sum /f" {
		t.Fatalf("run=%q err=%v", out, err)
	}
	if err := conn.Write(ctx, "/dst/file", strings.NewReader("payload")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if string(written) != "payload" {
		t.Fatalf("written=%q", written)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Non-root user: every op carries the `sudo -n ` escalation.
	conn, err = d.Dial(ctx, Target{Name: "t", IP: "127.0.0.1",
		SSHUser: "ubuntu"})
	if err != nil {
		t.Fatalf("sudo dial: %v", err)
	}
	if _, err := conn.Run(ctx, "id"); err != nil {
		t.Fatalf("sudo run: %v", err)
	}
	if err := conn.Write(ctx, "/dst/file", strings.NewReader("p2")); err != nil {
		t.Fatalf("sudo write: %v", err)
	}
	// Exactly the sudo conn's two ops carry the escalation prefix.
	cmds := srv.commands()
	sudo := 0
	for _, c := range cmds {
		if strings.HasPrefix(c, "sudo -n ") {
			sudo++
		}
	}
	if sudo != 2 {
		t.Fatalf("sudo-wrapped ops=%d in %v", sudo, cmds)
	}
	_ = conn.Close()

	// Dial against a closed port → transport error.
	down, err := newSSHDialer(keyPath, 1, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := down.Dial(ctx, Target{IP: "127.0.0.1"}); err == nil {
		t.Fatal("dial to unused port want error")
	}
}
