package hubsync

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/sshclient"
)

func TestSSHDialerBastionHelpers(t *testing.T) {
	// Spin up a minimal in-process SSH server that rejects direct-tcpip channels.
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientSigner, err := ssh.NewSignerFromKey(clientPriv)
	if err != nil {
		t.Fatal(err)
	}

	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	pemBytes, err := ssh.MarshalPrivateKey(clientPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	// Write dummy key file? OpenBastion reads KeyPath; we can also test OpenBastion failure
	// and cached Bastion via a real ssh.Client over net.Listen.
	_ = keyPath
	_ = pemBytes

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	srvCfg := &ssh.ServerConfig{NoClientAuth: true}
	srvCfg.AddHostKey(hostSigner)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				sconn, chans, reqs, err := ssh.NewServerConn(conn, srvCfg)
				if err != nil {
					return
				}
				defer func() { _ = sconn.Close() }()
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					_ = ch.Reject(ssh.Prohibited, "no forwarding")
				}
			}(c)
		}
	}()

	cliConn, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
		User:            "jump",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Write a non-existent key path so the fallback OpenBastion fails fast after dropBastion.
	badKey := filepath.Join(t.TempDir(), "missing_key")
	_ = os.Remove(badKey)
	cfg := &sshclient.Config{
		KeyPath: badKey,
		Timeout: 200 * time.Millisecond,
	}

	b := &sshclient.Bastion{
		Spec:   "jump@" + ln.Addr().String(),
		Client: cliConn,
	}
	d := &sshDialer{
		jumps: map[string]*sshclient.Bastion{
			b.Spec: b,
		},
	}

	// Cache hit in bastion().
	gotB, err := d.bastion(context.Background(), cfg, b.Spec)
	if err != nil || gotB != b {
		t.Fatalf("bastion cache hit = (%v, %v), want cached bastion", gotB, err)
	}

	// dialViaBastion: DialVia fails on rejected channel, drops bastion, retries bastion() which fails OpenBastion.
	_, err = d.dialViaBastion(context.Background(), cfg, Target{
		IP:        "10.0.0.2",
		SSHUser:   "root",
		ProxyJump: b.Spec,
	})
	if err == nil {
		t.Fatal("expected dialViaBastion to fail when channel rejected and OpenBastion fails")
	}
	if _, stillCached := d.jumps[b.Spec]; stillCached {
		t.Fatal("expected dropBastion to evict failed bastion from cache")
	}
}
