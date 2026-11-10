// sshfetch_test.go — sshFetchHostPub's transport against in-process
// SSH endpoints. The fetch dials port 22 unconditionally, so the live
// path routes through an in-process bastion: the jump server bridges
// every direct-tcpip channel open (whatever address the client asked
// for) onto the second, in-process target server. Covers the dial +
// session + CombinedOutput success, the remote cat failure, the
// session rejection and the ctx-cancel mid-command path.
package nebulasign

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

	"golang.org/x/crypto/ssh"
)

// sshTestServer is a minimal SSH endpoint: public-key auth always
// accepted. Mode picks the exec behaviour; bridge != "" turns it into
// a bastion that tunnels direct-tcpip opens onto that TCP address.
type sshTestServer struct {
	ln     net.Listener
	cfg    *ssh.ServerConfig
	bridge string // dial target for direct-tcpip ("" → reject)
	mode   string // "cat" | "fail" | "hang" | "reject-session"
	out    string
	quit   chan struct{}

	mu   sync.Mutex
	cmds []string
}

func newSSHTestServer(t *testing.T, mode, out string) *sshTestServer {
	t.Helper()
	s := &sshTestServer{mode: mode, out: out, quit: make(chan struct{})}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	s.cfg = &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	s.cfg.AddHostKey(signer)
	s.ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		close(s.quit)
		_ = s.ln.Close()
	})
	go s.acceptLoop()
	return s
}

func (s *sshTestServer) port() int {
	_, port, _ := net.SplitHostPort(s.ln.Addr().String())
	n, _ := strconv.Atoi(port)
	return n
}

func (s *sshTestServer) commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.cmds...)
}

func (s *sshTestServer) acceptLoop() {
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
			switch ch.ChannelType() {
			case "session":
				if s.mode == "reject-session" {
					_ = ch.Reject(ssh.Prohibited, "sessions disabled")
					continue
				}
				srv, inReqs, _ := ch.Accept()
				go s.serveSession(srv, inReqs)
			case "direct-tcpip":
				// Bastion hop: ignore the requested address and
				// tunnel onto the in-process target server.
				if s.bridge == "" {
					_ = ch.Reject(ssh.Prohibited, "no forwarding")
					continue
				}
				target, _, err := ch.Accept()
				if err != nil {
					continue
				}
				go bridgeChannels(target, s.bridge)
			default:
				_ = ch.Reject(ssh.UnknownChannelType, "no")
			}
		}
	}
}

// bridgeChannels copies both directions until either side closes.
func bridgeChannels(ch ssh.Channel, addr string) {
	up, err := net.Dial("tcp", addr)
	if err != nil {
		_ = ch.Close()
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, ch); done <- struct{}{} }()
	go func() { _, _ = io.Copy(ch, up); done <- struct{}{} }()
	<-done
	_ = up.Close()
	_ = ch.Close()
}

func (s *sshTestServer) serveSession(srv ssh.Channel,
	inReqs <-chan *ssh.Request) {
	defer srv.Close()
	for req := range inReqs {
		if req.Type != "exec" {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			continue
		}
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
		switch {
		case s.mode == "hang":
			<-s.quit // never answer — only a link teardown unblocks
		case s.mode == "fail":
			_, _ = srv.Stderr().Write([]byte(
				"cat: /etc/nebula/interdc/host.pub: No such file or directory"))
			status := make([]byte, 4)
			binary.BigEndian.PutUint32(status, 1)
			_, _ = srv.SendRequest("exit-status", false, status)
		default:
			_, _ = srv.Write([]byte(s.out))
			status := make([]byte, 4)
			_, _ = srv.SendRequest("exit-status", false, status)
		}
		return
	}
}

// fetchKey writes the client key in OpenSSH PEM form.
func fetchKey(t *testing.T) string {
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

const testPubPEM = "-----BEGIN NEBULA X25519 PUBLIC KEY-----\n" +
	"QUJDREVGRw==\n-----END NEBULA X25519 PUBLIC KEY-----\n"

// fetchJob routes the fetch through the in-process bastion — the
// fetch's hardcoded :22 final hop never touches a real network.
func fetchJob(bastionPort int) signJob {
	return signJob{
		Hostname:  "hub-a",
		Name:      "hub-a",
		IP:        "127.0.0.1",
		SSHUser:   "root",
		ProxyJump: "root@127.0.0.1:" + strconv.Itoa(bastionPort),
	}
}

// TestSSHFetchHostPubThroughBastion: the full dial → jump tunnel →
// session → cat round-trip returns the host.pub content.
func TestSSHFetchHostPubThroughBastion(t *testing.T) {
	final := newSSHTestServer(t, "cat", testPubPEM)
	bastion := newSSHTestServer(t, "cat", "")
	bastion.bridge = final.ln.Addr().String()

	out, err := sshFetchHostPub(context.Background(),
		fetchJob(bastion.port()), "interdc", fetchKey(t))
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if out != testPubPEM {
		t.Fatalf("out=%q want the PEM block", out)
	}
	want := "cat /etc/nebula/interdc/host.pub"
	if cmds := final.commands(); len(cmds) != 1 || cmds[0] != want {
		t.Fatalf("target commands=%v want [%s]", cmds, want)
	}
}

// TestSSHFetchHostPubRemoteFailure: a non-zero remote cat carries the
// stderr in the error wording.
func TestSSHFetchHostPubRemoteFailure(t *testing.T) {
	final := newSSHTestServer(t, "fail", "")
	bastion := newSSHTestServer(t, "cat", "")
	bastion.bridge = final.ln.Addr().String()

	_, err := sshFetchHostPub(context.Background(),
		fetchJob(bastion.port()), "interdc", fetchKey(t))
	if err == nil ||
		!strings.Contains(err.Error(), "read host.pub") ||
		!strings.Contains(err.Error(), "No such file or directory") {
		t.Fatalf("err=%v", err)
	}
}

// TestSSHFetchHostPubSessionRejected: a target refusing session
// channels surfaces the channel-open failure.
func TestSSHFetchHostPubSessionRejected(t *testing.T) {
	final := newSSHTestServer(t, "reject-session", "")
	bastion := newSSHTestServer(t, "cat", "")
	bastion.bridge = final.ln.Addr().String()

	_, err := sshFetchHostPub(context.Background(),
		fetchJob(bastion.port()), "interdc", fetchKey(t))
	if err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("err=%v", err)
	}
}

// TestSSHFetchHostPubCancelMidCommand: a wedged target (exec accepted
// but never answered) is recovered by the ctx budget — the fetch
// tears the link down and reports ctx.Err instead of hanging.
func TestSSHFetchHostPubCancelMidCommand(t *testing.T) {
	final := newSSHTestServer(t, "hang", "")
	bastion := newSSHTestServer(t, "cat", "")
	bastion.bridge = final.ln.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	_, err := sshFetchHostPub(ctx, fetchJob(bastion.port()),
		"interdc", fetchKey(t))
	if err == nil {
		t.Fatal("hang want ctx error")
	}
}
