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
// goes first).
func (l *Link) Close() error {
	err := l.Client.Close()
	if l.Jump != nil {
		_ = l.Jump.Close()
	}
	return err
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
	port := c.port()
	signer, err := c.LoadSigner()
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	cfg := c.ClientConfig(user, signer)

	if proxyJump != "" {
		juser, jhost, jport := SplitUserHost(proxyJump)
		if jport == "" {
			jport = strconv.Itoa(port)
		}
		jnc, jump, err := c.DialTCP(ctx, net.JoinHostPort(jhost, jport),
			c.ClientConfig(juser, signer))
		if err != nil {
			return nil, fmt.Errorf("jump %s: %w", proxyJump, err)
		}
		// Channel-open on the jump has no ctx wiring — bound it on
		// the jump's conn the same way the handshake is bounded.
		clear := BoundOp(ctx, c.Log, jnc, c.Timeout)
		nc, err := jump.Dial("tcp", addr)
		clear()
		if err != nil {
			_ = jump.Close()
			return nil, fmt.Errorf("jump %s → %s: %w", proxyJump, addr, err)
		}
		// nc here is a chanConn — SetDeadline always errors on it,
		// so the handshake is bounded on jnc (the real TCP conn all
		// muxed traffic rides).
		client, err := c.Handshake(ctx, nc, jnc, addr, cfg)
		if err != nil {
			_ = jump.Close()
			return nil, fmt.Errorf("%s via %s: %w", addr, proxyJump, err)
		}
		return &Link{Client: client, Net: nc, JumpNet: jnc, Jump: jump}, nil
	}

	nc, client, err := c.DialTCP(ctx, addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	return &Link{Client: client, Net: nc}, nil
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
	}
	conn, chans, reqs, err := ssh.NewClientConn(nc, addr, cfg)
	if err != nil {
		_ = nc.Close()
		return nil, err
	}
	_ = carrier.SetDeadline(time.Time{})
	return ssh.NewClient(conn, chans, reqs), nil
}

// BoundOp sets a conn deadline covering one blocking channel op —
// NewSession/Client.Dial take no ctx and the handshake clears the
// conn deadline, so without this a wedged target blocks forever.
// The deadline is min(now+timeout, ctx deadline); the returned func
// clears it. For the SESSION BODY that follows a channel-open use
// BoundOpCtx instead: Session.Close alone cannot unblock a dead
// transport (it only sends an SSH channel-close), so the body needs
// its own deadline. A rejected SetDeadline leaves the op unbounded —
// warn so a silent hang is at least loud in the logs. A nil log
// falls back to the package logger.
func BoundOp(ctx context.Context, log *slog.Logger, nc net.Conn,
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
