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

// defaultCancelGrace bounds how long CloseWait lets a clean Link.Close
// drain an in-flight session before escalating to Link.ForceClose.
const defaultCancelGrace = 100 * time.Millisecond

// NewSession opens a session channel on l bounded by BoundOp on direct
// connections, or by goroutine+ctx/timeout without touching b.Net when
// l.JumpShared is true. It returns the session paired with a body-deadline
// release callback (which callers MUST defer).
func (l *Link) NewSession(ctx context.Context, log *slog.Logger, timeout time.Duration) (*ssh.Session, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if !l.JumpShared {
		dc := l.DeadlineConn()
		clear := BoundOp(ctx, log, dc, timeout)
		cbDone := make(chan struct{})
		stopCancel := context.AfterFunc(ctx, func() {
			defer close(cbDone)
			_ = dc.SetDeadline(time.Now())
		})
		sess, err := l.Client.NewSession()
		if !stopCancel() {
			<-cbDone
		}
		clear()
		if err != nil {
			return nil, nil, err
		}
		return sess, BoundOpCtx(ctx, log, dc, timeout), nil
	}

	sessCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		sessCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	type sessResult struct {
		sess *ssh.Session
		err  error
	}
	ch := make(chan sessResult, 1)
	go func() {
		s, err := l.Client.NewSession()
		ch <- sessResult{sess: s, err: err}
	}()
	select {
	case res := <-ch:
		if res.err != nil {
			return nil, nil, res.err
		}
		return res.sess, func() {}, nil
	case <-sessCtx.Done():
		done := make(chan error, 1)
		go func() {
			res := <-ch
			if res.sess != nil {
				_ = res.sess.Close()
			}
			done <- res.err
		}()
		_ = l.CloseWait(done, defaultCancelGrace)
		return nil, nil, sessCtx.Err()
	}
}

// CloseWait closes l cleanly (preserving any shared Bastion for grace)
// while waiting for done to report that the in-flight operation has
// unwound. If done or l.Close does not complete within grace (e.g. a
// blackholed shared bastion where SSH_MSG_CHANNEL_CLOSE cannot drain),
// CloseWait escalates to l.ForceClose() and waits for <-done and <-closeDone.
func (l *Link) CloseWait(done <-chan error, grace time.Duration) error {
	if grace <= 0 {
		grace = defaultCancelGrace
	}
	closeDone := make(chan struct{})
	go func() {
		defer close(closeDone)
		_ = l.Close()
	}()
	t := time.NewTimer(grace)
	defer t.Stop()
	var err error
	select {
	case err = <-done:
		select {
		case <-closeDone:
		case <-t.C:
			_ = l.ForceClose()
			<-closeDone
		}
		return err
	case <-t.C:
		_ = l.ForceClose()
		err = <-done
		<-closeDone
		return err
	}
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

	runCtx := ctx
	if l.JumpShared && timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	out := cappedOut{max: maxBytes}
	sess.Stdout = &out
	sess.Stderr = &out
	done := make(chan error, 1)
	go func() {
		done <- sess.Run(cmd)
	}()
	select {
	case <-runCtx.Done():
		// sess.Close only sends an SSH channel-close, which a blackholed
		// transport never drains. CloseWait tries Link.Close first (so a
		// healthy shared bastion survives target-only timeouts) and
		// escalates to ForceClose if done stalls past grace.
		if rerr := l.CloseWait(done, defaultCancelGrace); rerr != nil && log != nil {
			log.Debug("sshclient: ssh session failed after cancel", "error", rerr)
		}
		return nil, runCtx.Err()
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
