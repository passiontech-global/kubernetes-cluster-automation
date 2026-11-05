// ssh.go — the minimal SSH host.pub fetch backing nebulaSign.
//
// hubsync's real dialer is package-private; the signer only needs a
// one-command fetch so it carries the smallest dialer: same key
// resolution (flag/env, default ~/.ssh/id_ed25519), same tolerance
// (InsecureIgnoreHostKey — infra VMs rotate host keys on rebuild),
// same ssh_proxyjump bastion semantics as hubsync's sshDialer.
package nebulasign

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// nebulaNetRe gates the network name before it lands in the remote
// `cat /etc/nebula/<net>/host.pub` command — vars are operator input.
var nebulaNetRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func sshFetchHostPub(ctx context.Context, j signJob, nebulaNet, keyPath string) (string, error) {
	if j.IP == "" {
		return "", fmt.Errorf("no ip in registry")
	}
	keyPath = expandHome(keyPath)
	pem, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("read ssh key %s: %w", keyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return "", fmt.Errorf("parse ssh key %s: %w", keyPath, err)
	}
	user := j.SSHUser
	if user == "" {
		user = "root"
	}
	timeout := 15 * time.Second
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // hub_converge parity
		Timeout:         timeout,
	}
	addr := net.JoinHostPort(j.IP, "22")

	var client *ssh.Client
	var jumpClient *ssh.Client
	if j.ProxyJump != "" {
		juser, jhost, jport := splitJump(j.ProxyJump)
		jcfg := &ssh.ClientConfig{
			User:            juser,
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
			Timeout:         timeout,
		}
		jc, err := dialSSH(ctx, net.JoinHostPort(jhost, jport), jcfg, timeout)
		if err != nil {
			return "", fmt.Errorf("jump %s: %w", j.ProxyJump, err)
		}
		jumpClient = jc
		defer jumpClient.Close()
		nc, err := jc.Dial("tcp", addr)
		if err != nil {
			return "", fmt.Errorf("jump %s -> %s: %w", j.ProxyJump, addr, err)
		}
		c, chans, reqs, err := ssh.NewClientConn(nc, addr, cfg)
		if err != nil {
			nc.Close()
			return "", fmt.Errorf("handshake via %s: %w", j.ProxyJump, err)
		}
		client = ssh.NewClient(c, chans, reqs)
	} else {
		client, err = dialSSH(ctx, addr, cfg, timeout)
		if err != nil {
			return "", err
		}
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := sess.CombinedOutput(
			"cat /etc/nebula/" + nebulaNet + "/host.pub")
		done <- result{out, err}
	}()
	select {
	case <-ctx.Done():
		sess.Close()
		return "", ctx.Err()
	case r := <-done:
		if r.err != nil {
			return "", fmt.Errorf("read host.pub: %w (%s)", r.err,
				strings.TrimSpace(string(r.out)))
		}
		return string(r.out), nil
	}
}

func dialSSH(ctx context.Context, addr string, cfg *ssh.ClientConfig,
	timeout time.Duration) (*ssh.Client, error) {
	nd := net.Dialer{Timeout: timeout}
	nc, err := nd.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	dl := time.Now().Add(timeout)
	if cdl, ok := ctx.Deadline(); ok && cdl.Before(dl) {
		dl = cdl
	}
	_ = nc.SetDeadline(dl)
	c, chans, reqs, err := ssh.NewClientConn(nc, addr, cfg)
	if err != nil {
		nc.Close()
		return nil, err
	}
	_ = nc.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

// splitJump parses "user@host[:port]" / "host" from ssh_proxyjump —
// the same shape hubsync's splitUserHost accepts.
func splitJump(j string) (user, host, port string) {
	user, port = "root", "22"
	if u, h, ok := strings.Cut(j, "@"); ok {
		user, j = u, h
	}
	host = j
	if h, p, err := net.SplitHostPort(j); err == nil {
		host, port = h, p
	}
	return user, host, port
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}
