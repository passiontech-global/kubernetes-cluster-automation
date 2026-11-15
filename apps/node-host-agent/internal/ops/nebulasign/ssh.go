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
//   - Host-key trust fails closed: a known_hosts file next to the
//     SSH key is enforced; its absence is an error unless the
//     operator passes --insecure-ignore-host-key (the old silent
//     tolerance survives only behind that explicit flag).
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
// with its known_hosts). Host-key trust fails CLOSED: an absent
// known_hosts is an error unless the operator passed the explicit
// --insecure-ignore-host-key opt-out; a file that EXISTS is always
// enforced — an unlisted host or a key mismatch fails the fetch.
func knownHostsVerify(keyPath string, insecure bool) (func(hostname string, key ssh.PublicKey) error, error) {
	// Derive known_hosts after ExpandHome so "~/.ssh/id_ed25519" stats the
	// expanded directory rather than literal "~/.ssh".
	p := sshclient.KnownHostsPath(keyPath)
	if p == "" {
		if insecure {
			return nil, nil
		}
		return nil, fmt.Errorf("no known_hosts trust material for %s — "+
			"place a known_hosts next to the SSH key or pass "+
			"--insecure-ignore-host-key", keyPath)
	}
	if _, err := os.Stat(p); err != nil {
		if os.IsNotExist(err) {
			if insecure {
				return nil, nil // explicit opt-out — tolerant dial
			}
			return nil, fmt.Errorf("no known_hosts trust material at %s — "+
				"place a known_hosts next to the SSH key or pass "+
				"--insecure-ignore-host-key", p)
		}
		return nil, fmt.Errorf("stat %s: %w", p, err)
	}
	cb, err := knownhosts.New(p)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	// knownhosts matches entries port-exactly in host:port form (port 22).
	return func(hostname string, key ssh.PublicKey) error {
		return cb(net.JoinHostPort(hostname, "22"),
			&net.TCPAddr{Port: 22}, key)
	}, nil
}

func sshFetchHostPub(ctx context.Context, j signJob, nebulaNet, keyPath string, insecure bool) (string, error) {
	if j.IP == "" {
		return "", errors.New("no ip in registry")
	}
	verify, err := knownHostsVerify(keyPath, insecure)
	if err != nil {
		return "", err
	}
	cfg := sshclient.Config{
		KeyPath: keyPath,
		Port:    22,
		Timeout: 15 * time.Second,
		// Host key trust: a known_hosts file next to the SSH key
		// pins every host it lists (mismatch and unlisted both
		// reject); without it the fetch fails closed unless the
		// operator passed --insecure-ignore-host-key.
		HostKeyVerify: verify,
	}
	link, err := cfg.Dial(ctx, j.SSHUser, j.IP, j.ProxyJump)
	if err != nil {
		return "", err
	}
	defer func() { _ = link.Close() }()

	out, err := link.CombinedOutputCapped(ctx, cfg.Log, cfg.Timeout,
		"cat /etc/nebula/"+nebulaNet+"/host.pub", sshclient.DefaultMaxOutputBytes)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "", err
		}
		return "", fmt.Errorf("read host.pub: %w (%s)", err,
			strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
