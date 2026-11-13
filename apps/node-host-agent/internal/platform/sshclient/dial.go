// dial.go — ctx-aware TCP dial, deadline-bounded handshake and the
// ssh_proxyjump bastion hop. Both former private dialers carried
// this sequence; the shared version keeps hubsync's bounding of the
// channel ops that take no ctx (see the package doc for the
// nebulasign deltas).
package sshclient

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

// Link is an established SSH connection: the ready client plus the
// transport conns and — behind a bastion — the jump client. The
// conns stay reachable because the channel ops callers issue next
// (Client.NewSession, Client.Dial) take no ctx: bound each one with
// BoundOp on DeadlineConn.
type Link struct {
	Client  *ssh.Client
	Net     net.Conn    // transport conn — TCP direct, chanConn via bastion
	JumpNet net.Conn    // the bastion's TCP conn (nil on a direct dial)
	Jump    *ssh.Client // bastion client (nil on a direct dial)
	// JumpShared marks Jump as BORROWED from a caller-owned Bastion
	// (DialVia): Close then leaves the bastion alive for the next
	// target. A one-shot Config.Dial clears it — the Link owns the
	// bastion and Close shuts it like before.
	JumpShared bool
}

// DeadlineConn picks the conn a per-op SetDeadline must land on.
// Direct dial: Net is the TCP conn. Behind a bastion Net is the
// chanConn Jump.Dial returned — SetDeadline always errors on it
// ("deadline not supported") while every muxed channel rides the
// jump's real TCP conn, so the bound belongs on JumpNet.
func (l *Link) DeadlineConn() net.Conn {
	if l.JumpNet != nil {
		return l.JumpNet
	}
	return l.Net
}

// Close shuts the client, then the bastion client — the order both
// originals used (the tunneled client rides the jump's conn, so it
// goes first). A borrowed bastion (JumpShared) stays open: the
// Bastion owner closes it when the last target releases it.
func (l *Link) Close() error {
	err := l.Client.Close()
	if l.Jump != nil && !l.JumpShared {
		_ = l.Jump.Close()
	}
	return err
}

// Bastion is a reusable ProxyJump connection: the bastion's TCP
// conn plus its SSH client, opened once and shared by every target
// hop through the same jump spec (hubsync converges N targets per
// cycle through one bastion — per-target jump dials used to pay a
// full TCP+SSH handshake each). Spec is the ssh_proxyjump spec it
// was opened for, kept for error parity with Config.Dial.
type Bastion struct {
	Spec   string
	Net    net.Conn
	Client *ssh.Client
}

// Close shuts the bastion client (which owns Net) — idempotent via
// the ssh.Client contract callers already rely on.
func (b *Bastion) Close() error {
	if b == nil {
		return nil
	}
	return b.Client.Close()
}

// OpenBastion dials only the proxyJump hop — the reusable half of
// Config.Dial's jump path. The SAME signer and host-key policy
// serve the bastion (HostKeyVerify covers it, jumpClientConfig
// parity).
func (c Config) OpenBastion(ctx context.Context, proxyJump string) (*Bastion, error) {
	juser, jhost, jport := SplitUserHost(proxyJump)
	if jport == "" {
		jport = strconv.Itoa(c.port())
	}
	signer, err := c.LoadSigner()
	if err != nil {
		return nil, err
	}
	jnc, jump, err := c.DialTCP(ctx, net.JoinHostPort(jhost, jport),
		c.jumpClientConfig(juser, signer))
	if err != nil {
		return nil, fmt.Errorf("jump %s: %w", proxyJump, err)
	}
	return &Bastion{Spec: proxyJump, Net: jnc, Client: jump}, nil
}

// DialVia is Config.Dial's target half against an already-open
// Bastion — same channel-open bound, same handshake bound, same
// Link contract; JumpShared marks the bastion borrowed so Link.Close
// leaves it for the next target. Callers that serialize their dials
// (hubsync's per-target loop) get one jump handshake per cycle
// instead of one per target.
func (c Config) DialVia(ctx context.Context, user, host string,
	b *Bastion) (*Link, error) {
	if user == "" {
		user = "root"
	}
	port := c.port()
	signer, err := c.LoadSigner()
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	cfg := c.ClientConfig(user, signer)

	// Channel-open on the jump has no ctx wiring — bound it on
	// the jump's conn the same way the handshake is bounded.
	clear := BoundOp(ctx, c.Log, b.Net, c.Timeout)
	nc, err := b.Client.Dial("tcp", addr)
	clear()
	if err != nil {
		return nil, fmt.Errorf("jump %s → %s: %w", b.Spec, addr, err)
	}
	// nc here is a chanConn — SetDeadline always errors on it,
	// so the handshake is bounded on b.Net (the real TCP conn all
	// muxed traffic rides).
	client, err := c.Handshake(ctx, nc, b.Net, addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("%s via %s: %w", addr, b.Spec, err)
	}
	return &Link{Client: client, Net: nc, JumpNet: b.Net,
		Jump: b.Client, JumpShared: true}, nil
}

// Dial connects to host:Port as user (empty → root), through
// proxyJump when set. proxyJump is the ssh_proxyjump spec
// "user@host[:port]" (bare "host" and "host:port" accepted too) —
// jump user defaults to root, jump port to Port, and the SAME
// signer and host-key policy serve both hops: the hub_converge
// `ProxyCommand ssh -W %h:%p <jump>` parity both originals kept.
// Error wording is hubsync's (the richer of the two originals).
func (c Config) Dial(ctx context.Context, user, host, proxyJump string) (*Link, error) {
	if user == "" {
		user = "root"
	}

	if proxyJump != "" {
		b, err := c.OpenBastion(ctx, proxyJump)
		if err != nil {
			return nil, err
		}
		link, err := c.DialVia(ctx, user, host, b)
		if err != nil {
			// Channel-open/handshake failures own the bastion's
			// lifetime now — close it like the original inline path.
			_ = b.Close()
			return nil, err
		}
		// One-shot dial: the Link owns the bastion — Close shuts it
		// via Jump like the pre-Bastion code did.
		link.JumpShared = false
		return link, nil
	}

	port := c.port()
	signer, err := c.LoadSigner()
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	cfg := c.ClientConfig(user, signer)

	nc, client, err := c.DialTCP(ctx, addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	return &Link{Client: client, Net: nc}, nil
}

// jumpClientConfig is ClientConfig for the bastion hop: the jump
// host's key is pinned by JumpHostKeyFingerprint when set, else by
// the shared HostKeyFingerprint — the two hops are different
// machines, so an operator pinning both needs the split field.
func (c Config) jumpClientConfig(user string, signer ssh.Signer) *ssh.ClientConfig {
	pin := c.JumpHostKeyFingerprint
	if pin == "" {
		pin = c.HostKeyFingerprint
	}
	return c.clientConfigFor(user, signer, pin)
}

// DialTCP opens the TCP conn under ctx + the dial timeout and runs
// the bounded handshake, returning the underlying net.Conn —
// callers keep it to bound later channel ops (jump.Dial, NewSession)
// that take no ctx.
func (c Config) DialTCP(ctx context.Context, addr string,
	cfg *ssh.ClientConfig) (net.Conn, *ssh.Client, error) {
	nd := net.Dialer{Timeout: c.Timeout}
	nc, err := nd.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	client, err := c.Handshake(ctx, nc, nc, addr, cfg)
	if err != nil {
		return nil, nil, err
	}
	return nc, client, nil
}

// Handshake runs NewClientConn under a conn deadline covering the
// SSH banner + auth exchange, then clears it so sessions get their
// own deadlines. carrier is the conn SetDeadline actually works on:
// nc itself for a direct dial, but the JUMP's TCP conn when nc is
// the chanConn jump.Dial returned — a chanConn's SetDeadline always
// errors while every muxed channel rides the jump conn. A rejected
// SetDeadline leaves the handshake effectively unbounded — warn so
// a silent hang is at least loud in the logs.
func (c Config) Handshake(ctx context.Context, nc, carrier net.Conn,
	addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	dl := time.Now().Add(c.Timeout)
	if cdl, ok := ctx.Deadline(); ok && cdl.Before(dl) {
		dl = cdl
	}
	if err := carrier.SetDeadline(dl); err != nil {
		c.log().Warn("sshclient: ssh handshake unbounded — SetDeadline unsupported",
			"addr", addr, "error", err)
	} else {
		// Clear on EVERY exit path, error ones included: nc is the
		// failed hop's chanConn (jump case) and gets closed below,
		// but carrier is the shared bastion conn — a deadline left
		// armed on it would kill every later channel muxed over the
		// bastion once the handshake budget expired.
		defer func() { _ = carrier.SetDeadline(time.Time{}) }()
	}
	conn, chans, reqs, err := ssh.NewClientConn(nc, addr, cfg)
	if err != nil {
		_ = nc.Close()
		return nil, err
	}
	return ssh.NewClient(conn, chans, reqs), nil
}

// BoundOp sets a conn deadline covering one blocking channel op —
// NewSession/Client.Dial take no ctx and the handshake clears the
// conn deadline, so without this a wedged target blocks forever.
// The deadline is min(now+timeout, ctx deadline); the returned func
// clears it. For the SESSION BODY that follows a channel-open use
// BoundOpCtx instead: Session.Close alone cannot unblock a dead
// transport (it only sends an SSH channel-close), so the body needs
// its own deadline. Thin wrapper: the two ops shared a 100%
// identical body (the rejected-SetDeadline warn + nil-log fallback
// included), so BoundOpCtx owns the implementation.
func BoundOp(ctx context.Context, log *slog.Logger, nc net.Conn,
	timeout time.Duration) func() {
	return BoundOpCtx(ctx, log, nc, timeout)
}

// BoundOpCtx sets a conn deadline covering a whole ctx-scoped op —
// the session body a caller runs after a BoundOp-bounded channel
// open. The bound is min(now+timeout, ctx deadline) — exactly like
// BoundOp/Handshake: a deadline-less ctx (or one expiring LATER than
// the op budget) falls back to now+timeout, while an earlier-expiring
// ctx deadline wins. A CombinedOutput/io.Copy/Wait blocked on a
// blackholed transport then fails AT the earlier of the two bounds
// instead of hanging forever (Session.Close only writes a
// channel-close, which a dead transport never drains). The returned
// func clears the deadline; a rejected SetDeadline leaves the op
// unbounded — warn, same contract as BoundOp. A nil log falls back
// to the package logger.
func BoundOpCtx(ctx context.Context, log *slog.Logger, nc net.Conn,
	timeout time.Duration) func() {
	if log == nil {
		log = logger()
	}
	dl := time.Now().Add(timeout)
	if cdl, ok := ctx.Deadline(); ok && cdl.Before(dl) {
		dl = cdl
	}
	if err := nc.SetDeadline(dl); err != nil {
		log.Warn("sshclient: conn deadline rejected — op unbounded", "error", err)
	}
	return func() { _ = nc.SetDeadline(time.Time{}) }
}
