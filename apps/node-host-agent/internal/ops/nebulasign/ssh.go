// ssh.go — the SSH host.pub fetch backing nebulaSign.
//
// The dial mechanics (key resolution + "~/" expansion, the
// InsecureIgnoreHostKey tolerance, the ssh_proxyjump bastion hop)
// moved to platform/sshclient, shared with hubsync's converge
// dialer — this file used to carry a second private copy of them.
// What stays is nebulasign's own contract: the nebulaNet gate and
// the one-shot `cat /etc/nebula/<net>/host.pub`.
//
// Parity notes vs the removed private dialer:
//   - Port 22 and the 15s Timeout reproduce the hard-coded knobs.
//   - Config.Log stays nil → bare ssh.InsecureIgnoreHostKey,
//     exactly the old silent tolerance (infra VMs rotate host keys
//     on rebuild; hub_converge parity).
//   - sshclient bounds the bastion channel-open + tunneled
//     handshake (this copy left them unbounded — a wedged bastion
//     could hang forever) and warns on a rejected SetDeadline via
//     its package logger; dial error strings are sshclient's
//     unified wording. Failure-path tightening only — the success
//     path is identical.
package nebulasign

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/sshclient"
)

// nebulaNetRe gates the network name before it lands in the remote
// `cat /etc/nebula/<net>/host.pub` command — vars are operator input.
var nebulaNetRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// knownHostsVerify resolves the operator known_hosts file next to the
// SSH client key — the documented trust source for converge-family
// SSH traffic (ENV: NODE_HOST_AGENT_CONVERGE_SSH_KEY sits in a dir
// with its known_hosts). An absent file means no trust material and
// no verification: the historical tolerant dial stays, but a file
// that EXISTS is enforced — an unlisted host or a key mismatch
// fails the fetch closed.
func knownHostsVerify(keyPath string) (func(hostname string, key ssh.PublicKey) error, error) {
	p := filepath.Join(filepath.Dir(keyPath), "known_hosts")
	if _, err := os.Stat(p); err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no trust material — tolerant parity
		}
		return nil, fmt.Errorf("stat %s: %w", p, err)
	}
	cb, err := knownhosts.New(p)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	// knownhosts matches entries port-exactly in host:port form —
	// the nebulasign fetch is hard-coded to port 22 (knownhosts
	// keys off the host:port string; the addr is only formatting).
	return func(hostname string, key ssh.PublicKey) error {
		return cb(net.JoinHostPort(hostname, "22"),
			&net.TCPAddr{Port: 22}, key)
	}, nil
}

func sshFetchHostPub(ctx context.Context, j signJob, nebulaNet, keyPath string) (string, error) {
	if j.IP == "" {
		return "", errors.New("no ip in registry")
	}
	verify, err := knownHostsVerify(keyPath)
	if err != nil {
		return "", err
	}
	cfg := sshclient.Config{
		KeyPath: keyPath,
		Port:    22,
		Timeout: 15 * time.Second,
		// Host key trust: a known_hosts file next to the SSH key
		// pins every host it lists (mismatch and unlisted both
		// reject); without it the documented rotating-infra-VM
		// tolerance applies.
		HostKeyVerify: verify,
	}
	link, err := cfg.Dial(ctx, j.SSHUser, j.IP, j.ProxyJump)
	if err != nil {
		return "", err
	}
	defer func() { _ = link.Close() }()

	// Bound the channel-open on the conn (NewSession takes no ctx —
	// a wedged target would block it forever), then re-arm at the
	// ctx budget for the session BODY: CombinedOutput needs a real
	// transport deadline — Session.Close only sends an SSH
	// channel-close, which a blackholed conn never drains.
	clear := sshclient.BoundOp(ctx, cfg.Log, link.DeadlineConn(), cfg.Timeout)
	sess, err := link.Client.NewSession()
	clear()
	if err != nil {
		return "", err
	}
	defer func() { _ = sess.Close() }()
	defer sshclient.BoundOpCtx(ctx, cfg.Log, link.DeadlineConn(), cfg.Timeout)()
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
		// sess.Close can't unblock a dead transport — only killing
		// the conn makes the CombinedOutput goroutine return (the
		// deferred link.Close above is idempotent).
		_ = link.Close()
		return "", ctx.Err()
	case r := <-done:
		if r.err != nil {
			return "", fmt.Errorf("read host.pub: %w (%s)", r.err,
				strings.TrimSpace(string(r.out)))
		}
		return string(r.out), nil
	}
}
