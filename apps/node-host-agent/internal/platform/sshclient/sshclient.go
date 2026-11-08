// Package sshclient owns the SSH dial mechanics that hubsync's
// converge loop and the nebula-sign host.pub fetch each carried a
// private copy of: private-key loading, public-key client config
// with rotating-host-key tolerance, ctx-aware TCP dial +
// deadline-bounded handshake, and the ssh_proxyjump bastion hop.
//
// Key-path precedence (explicit path → env → built-in default) is
// NOT owned here — it lives in each caller's flag/env plumbing:
// nebulasign's --ssh-key flag defaults to
// $NODE_HOST_AGENT_CONVERGE_SSH_KEY else ~/.ssh/id_ed25519, while
// hubsync's NODE_HOST_AGENT_CONVERGE_SSH_KEY env knob defaults to
// /etc/node-converge-ssh/id_ed25519. Config takes the resolved path;
// "~/" expansion happens in LoadSigner (a no-op on absolute paths).
//
// The two originals differed in three knobs — kept as Config fields
// rather than unified away, so each side's behavior is preserved:
//
//   - Port: hubsync dialed Config.SSHPort, nebulasign fixed 22. Port
//     also feeds the bastion default, into which both originals'
//     jump-port defaults (SSHPort / literal 22) collapse.
//   - Timeout: hubsync's SSHTimeout vs nebulasign's fixed 15s.
//   - Log: hubsync audit-logged every accepted host key (a rotated
//     or spoofed key leaves a fingerprint trail); nebulasign used
//     bare ssh.InsecureIgnoreHostKey. A nil Log restores the silent
//     form.
//
// Two failure-path tightenings over nebulasign's copy are
// deliberate — success paths are byte-identical: the bastion
// channel-open and the tunneled handshake now ride the same
// deadline bound hubsync applied (a wedged bastion could otherwise
// hang forever), and a rejected SetDeadline warns via the package
// logger instead of passing silently.
package sshclient

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Config carries the dial knobs the two former private dialers
// hard-coded differently (see the package doc).
type Config struct {
	// KeyPath is the SSH private-key path — "~/"-expanded, re-read
	// and re-parsed on every Dial so a rotated key (or a
	// late-mounted secret) is picked up without a restart.
	KeyPath string
	// Port is the target SSH port AND the default bastion port for
	// an unported proxyjump — the two originals' defaults collapse
	// here. <=0 falls back to 22.
	Port int
	// Timeout bounds the TCP dial, the handshake deadline and every
	// per-op bound (BoundOp).
	Timeout time.Duration
	// Log selects host-key observability: non-nil → every accepted
	// host key's fingerprint is audit-logged (hubsync parity);
	// nil → bare ssh.InsecureIgnoreHostKey (nebulasign parity).
	Log *slog.Logger
	// HostKeyFingerprint pins the expected host key: a SHA256 base64
	// fingerprint of the key's wire form, as `ssh -o
	// FingerprintHash=sha256` and ssh.FingerprintSHA256 print it —
	// "SHA256:<base64>" (the prefix and any base64 padding are
	// accepted and stripped). When set, the HostKeyCallback rejects
	// any key whose fingerprint does not match the pin in constant
	// time — the bastion hop rides the same Config (see Dial), so one
	// pin covers the jump target too. Default "" keeps the tolerant
	// no-pin behavior: targets are infra VMs whose host keys rotate
	// on rebuild and the keypair (plus, for hubsync, the lease) is
	// the authentication boundary — the pin is the opt-in
	// tightening for callers that can distribute one.
	HostKeyFingerprint string
}

// port resolves the effective SSH port — the <=0 fallback exists so
// a zero Config still matches the originals' baked-in 22.
func (c Config) port() int {
	if c.Port <= 0 {
		return 22
	}
	return c.Port
}

// log resolves the warn channel for the pathological SetDeadline
// rejections — the caller's logger when set, the package logger
// otherwise: a silently unbounded op is a hang nobody can diagnose.
func (c Config) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return logger()
}

// LoadSigner reads + parses Config.KeyPath. It runs per dial — the
// hubsync secret mounts optional:true and keys rotate — and applies
// "~/" expansion so nebulasign's ~/.ssh/id_ed25519 default resolves.
// Error wording is the former nebulasign wording (hubsync's outer
// "ssh key %s:" wrap is dropped — the stage-prefixed message already
// carries the path).
func (c Config) LoadSigner() (ssh.Signer, error) {
	p := ExpandHome(c.KeyPath)
	pem, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read ssh key %s: %w", p, err)
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("parse ssh key %s: %w", p, err)
	}
	return signer, nil
}

// ClientConfig builds the ssh.ClientConfig for user+signer. The
// HostKeyCallback accepts any host key — StrictHostKeyChecking=no
// parity with the ansible converge: targets are infra VMs whose
// host keys rotate on rebuild, so the keypair (and, for hubsync,
// the lease) is the authentication boundary. A HostKeyFingerprint
// pin replaces the tolerance with a constant-time fingerprint match
// (see the Config field). With Log set, the negotiated fingerprint
// is audit-logged so a rotated/spoofed key leaves a trail instead of
// passing silently (hubsync parity); a nil Log is the silent
// InsecureIgnoreHostKey the nebulasign fetch used.
func (c Config) ClientConfig(user string, signer ssh.Signer) *ssh.ClientConfig {
	cb := ssh.InsecureIgnoreHostKey() // documented parity above
	switch {
	case c.HostKeyFingerprint != "":
		cb = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			remoteAddr := "<nil>"
			if remote != nil {
				remoteAddr = remote.String()
			}
			if err := checkHostKeyFingerprint(c.HostKeyFingerprint, key); err != nil {
				c.log().Warn("sshclient: host key fingerprint mismatch — rejecting",
					"addr", hostname, "remote", remoteAddr,
					"expected", c.HostKeyFingerprint,
					"got", ssh.FingerprintSHA256(key))
				return err
			}
			if c.Log != nil {
				c.Log.Info("sshclient: pinned ssh host key verified",
					"addr", hostname, "remote", remoteAddr,
					"fingerprint", ssh.FingerprintSHA256(key))
			}
			return nil
		}
	case c.Log != nil:
		log := c.Log
		cb = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			log.Info("sshclient: ssh host key accepted (no strict check)",
				"addr", hostname, "remote", remote.String(),
				"fingerprint", ssh.FingerprintSHA256(key))
			return nil
		}
	}
	return &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: cb,
		Timeout:         c.Timeout,
	}
}

// checkHostKeyFingerprint pins a host key by its SHA256 fingerprint —
// the wire-format key bytes (ssh.PublicKey.Marshal) hashed and
// base64'd exactly as ssh.FingerprintSHA256 / `ssh -o
// FingerprintHash=sha256` print them. The pin may carry the
// "SHA256:" prefix and trailing '=' padding; both are stripped
// before a constant-time compare, so a mismatch reveals nothing
// about how close the presented key was to the pin.
func checkHostKeyFingerprint(pin string, key ssh.PublicKey) error {
	sum := sha256.Sum256(key.Marshal())
	got := base64.RawStdEncoding.EncodeToString(sum[:])
	want := strings.TrimPrefix(strings.TrimSpace(pin), "SHA256:")
	want = strings.TrimRight(want, "=")
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return fmt.Errorf("sshclient: host key fingerprint mismatch: got SHA256:%s, want pinned %s",
			got, pin)
	}
	return nil
}
