package sshclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// DefaultMaxOutputBytes caps one CombinedOutputCapped run's retained
// stdout+stderr (1 MiB) so a noisy remote command cannot exhaust agent RAM.
const DefaultMaxOutputBytes = 1 << 20

// NewSession opens a session channel on l bounded by BoundOp on the channel
// open, and returns it paired with a body-deadline release callback armed via
// BoundOpCtx (which callers MUST defer).
func (l *Link) NewSession(ctx context.Context, log *slog.Logger, timeout time.Duration) (*ssh.Session, func(), error) {
	clear := BoundOp(ctx, log, l.DeadlineConn(), timeout)
	sess, err := l.Client.NewSession()
	clear()
	if err != nil {
		return nil, nil, err
	}
	return sess, BoundOpCtx(ctx, log, l.DeadlineConn(), timeout), nil
}

type cappedOut struct {
	mu  sync.Mutex
	max int
	buf strings.Builder
}

func (w *cappedOut) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.max <= 0 {
		_, _ = w.buf.Write(p)
		return len(p), nil
	}
	if rem := w.max - w.buf.Len(); rem > 0 {
		if rem > len(p) {
			rem = len(p)
		}
		_, _ = w.buf.Write(p[:rem])
	}
	return len(p), nil
}

// CombinedOutputCapped opens one SSH session on l, runs cmd, and captures
// merged stdout+stderr (capped at maxBytes when maxBytes > 0, draining excess).
// When ctx cancels or times out while the remote side is silent, l.Close is
// called to unblock the transport and wait cleanly for the session goroutine.
func (l *Link) CombinedOutputCapped(ctx context.Context, log *slog.Logger,
	timeout time.Duration, cmd string, maxBytes int) ([]byte, error) {
	sess, unbind, err := l.NewSession(ctx, log, timeout)
	if err != nil {
		return nil, err
	}
	defer unbind()
	defer func() { _ = sess.Close() }()

	out := cappedOut{max: maxBytes}
	sess.Stdout = &out
	sess.Stderr = &out
	done := make(chan error, 1)
	go func() {
		done <- sess.Run(cmd)
	}()
	select {
	case <-ctx.Done():
		// sess.Close only sends an SSH channel-close, which a blackholed
		// transport never drains. Closing l tears down the carrier conn so
		// sess.Run returns promptly and the goroutine does not leak.
		_ = l.Close()
		if rerr := <-done; rerr != nil && log != nil {
			log.Debug("sshclient: ssh session failed after cancel", "error", rerr)
		}
		return nil, ctx.Err()
	case rerr := <-done:
		return []byte(out.buf.String()), rerr
	}
}

// NormalizeHost lowercases hostname, strips any :port suffix, and unwraps
// IPv6 square brackets for consistent pin/TOFU/known_hosts keying.
func NormalizeHost(hostname string) string {
	h := strings.ToLower(strings.TrimSpace(hostname))
	if host, _, err := net.SplitHostPort(h); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(h, "[]")
}

// KnownHostsPath returns the sibling known_hosts path next to keyPath after
// home expansion, or "" if keyPath yields no concrete directory.
func KnownHostsPath(keyPath string) string {
	if keyPath == "" {
		return ""
	}
	dir := filepath.Dir(ExpandHome(keyPath))
	if dir == "" || dir == "." {
		return ""
	}
	return filepath.Join(dir, "known_hosts")
}

type hostPortAddr string

func (a hostPortAddr) Network() string { return "tcp" }
func (a hostPortAddr) String() string  { return string(a) }

// ErrKnownHostsParse indicates that an existing known_hosts file could not be parsed.
var ErrKnownHostsParse = errors.New("known_hosts parse")

// CheckKnownHosts verifies key against the OpenSSH known_hosts file at path
// for hostname:port. It distinguishes a key mismatch/parse error from an
// unlisted host (unlisted=true).
func CheckKnownHosts(path, hostname string, port int, key ssh.PublicKey) (matched, unlisted bool, err error) {
	cb, kerr := knownhosts.New(path)
	if kerr != nil {
		return false, false, fmt.Errorf("%w %s: %w", ErrKnownHostsParse, path, kerr)
	}
	if port <= 0 {
		port = 22
	}
	addrPort := net.JoinHostPort(NormalizeHost(hostname), strconv.Itoa(port))
	err = cb(addrPort, hostPortAddr(addrPort), key)
	if err == nil {
		return true, false, nil
	}
	var ke *knownhosts.KeyError
	if errors.As(err, &ke) && len(ke.Want) == 0 {
		return false, true, err
	}
	return false, false, err
}
