package hubsync

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Conn is the remote-host seam — one SSH session channel to a target.
// Run executes a shell command and returns its trimmed combined
// output; a non-zero remote exit is an error carrying ExitStatus
// (see ExitError). Write streams content into a remote path (NOT
// atomic — callers stage to a tmp path then chmod+mv via Run).
type Conn interface {
	Run(ctx context.Context, cmd string) (string, error)
	Write(ctx context.Context, remotePath string, r io.Reader) error
	Close() error
}

// Dialer opens a Conn to a target — the unit-test seam (fakes record
// commands/writes instead of doing SSH).
type Dialer interface {
	Dial(ctx context.Context, t Target) (Conn, error)
}

// ExitError is the non-zero-remote-exit contract — *ssh.ExitError
// satisfies it, and test fakes implement it to simulate "file absent"
// (sha256sum exit 1) vs transport failures.
type ExitError interface {
	error
	ExitStatus() int
}

// shq single-quotes a shell word (paths are admin-controlled, but
// quotes keep the commands robust against stray spaces).
func shq(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// tmpPath is the staging path for an atomic write:
// /usr/local/bin/node-host-agent → /usr/local/bin/.node-host-agent.tmp
// (hub_converge copy-then-mv parity).
func tmpPath(p string) string {
	return path.Dir(p) + "/." + path.Base(p) + ".tmp"
}

// remoteSHA256 returns the hex sha256 of a remote file. Exit 1
// (file absent — sha256sum's missing-file status) reads as "" —
// drift — while other non-zero exits (126/127 missing tool or
// denied exec, sudo/shell failures) and transport errors propagate:
// treating them as "absent" would re-upload on every cycle.
// A DIRECTORY at remotePath is surfaced first: sha256sum exits 1
// for a dir exactly like a missing file, and the follow-up
// `mv tmp remotePath` would then silently NEST the staging file
// inside the directory instead of replacing a file.
func remoteSHA256(ctx context.Context, c Conn, remotePath string) (string, error) {
	if _, err := c.Run(ctx, "test -d "+shq(remotePath)); err == nil {
		return "", fmt.Errorf("%s is a directory", remotePath)
	}
	out, err := c.Run(ctx, "sha256sum "+shq(remotePath))
	if err != nil {
		var ee ExitError
		if isExitErr(err, &ee) && ee.ExitStatus() == 1 {
			return "", nil
		}
		return "", err
	}
	fields := strings.Fields(out)
	if len(fields) == 0 {
		return "", nil
	}
	return fields[0], nil
}

// isExitErr reports whether err is (or wraps) an ExitError.
func isExitErr(err error, ee *ExitError) bool {
	for err != nil {
		if e, ok := err.(ExitError); ok {
			*ee = e
			return true
		}
		if u, ok := err.(interface{ Unwrap() error }); ok {
			err = u.Unwrap()
			continue
		}
		break
	}
	return false
}

// putAtomic streams r into <path>'s staging file, chmods it and
// atomically renames it over the destination — the order ansible's
// copy module + mv produced, and the ordering the tests assert.
func putAtomic(ctx context.Context, c Conn, remotePath string, r io.Reader, mode string) error {
	tmp := tmpPath(remotePath)
	if err := c.Write(ctx, tmp, r); err != nil {
		return fmt.Errorf("upload %s: %w", tmp, err)
	}
	// The staging file lands under the remote umask (~0644 via
	// `cat >`/`tee`) — for secret material (0600 mode: tokens,
	// .key files) tighten it IMMEDIATELY after the upload so the
	// tmp copy is never world-readable, then the final-mode chmod
	// below still applies before the atomic rename.
	if mode == "0600" || isKeyMaterial(path.Base(remotePath)) {
		if _, err := c.Run(ctx, "chmod 0600 "+shq(tmp)); err != nil {
			return fmt.Errorf("chmod 0600 %s: %w", tmp, err)
		}
	}
	if _, err := c.Run(ctx, "chmod "+mode+" "+shq(tmp)); err != nil {
		return fmt.Errorf("chmod %s: %w", tmp, err)
	}
	if _, err := c.Run(ctx, "mv "+shq(tmp)+" "+shq(remotePath)); err != nil {
		return fmt.Errorf("mv %s: %w", remotePath, err)
	}
	return nil
}

// --- real SSH implementation ---

type sshDialer struct {
	keyPath string
	port    int
	timeout time.Duration
	log     *slog.Logger
}

// newSSHDialer only records the key path — the signer is loaded at
// Dial time so Syncer.New succeeds while the (optional:true) secret
// is not mounted yet, and a rotated key is picked up on the next
// dial without a pod restart.
func newSSHDialer(keyPath string, port int, timeout time.Duration,
	log *slog.Logger) (*sshDialer, error) {
	if log == nil {
		log = logger()
	}
	return &sshDialer{keyPath: keyPath, port: port, timeout: timeout, log: log}, nil
}

func (d *sshDialer) loadSigner() (ssh.Signer, error) {
	pem, err := os.ReadFile(d.keyPath)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", d.keyPath, err)
	}
	return signer, nil
}

// clientConfig builds the per-target config. HostKeyCallback accepts
// any host key — StrictHostKeyChecking=no parity with the ansible
// converge (targets are infra VMs whose host keys rotate on rebuild;
// the lease+keypair is the authentication boundary) — and logs the
// negotiated fingerprint so a rotated/spoofed key leaves an audit
// trail instead of passing silently.
func (d *sshDialer) clientConfig(user string, signer ssh.Signer) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error { //nolint:gosec // documented parity
			d.log.Info("hubsync: ssh host key accepted (no strict check)",
				"addr", hostname, "remote", remote.String(),
				"fingerprint", ssh.FingerprintSHA256(key))
			return nil
		},
		Timeout: d.timeout,
	}
}

func (d *sshDialer) Dial(ctx context.Context, t Target) (Conn, error) {
	user := t.SSHUser
	if user == "" {
		user = "root"
	}
	signer, err := d.loadSigner()
	if err != nil {
		return nil, fmt.Errorf("ssh key %s: %w", d.keyPath, err)
	}
	addr := net.JoinHostPort(t.IP, strconv.Itoa(d.port))
	cfg := d.clientConfig(user, signer)
	sudo := needsSudo(user)

	if t.ProxyJump != "" {
		// ssh_proxyjump parity: hub_converge used ProxyCommand
		// `ssh -W %h:%p <jump>` — same key, no host-key check.
		juser, jhost, jport := splitUserHost(t.ProxyJump)
		if jport == "" {
			jport = strconv.Itoa(d.port)
		}
		jnc, jump, err := d.dialTCP(ctx, net.JoinHostPort(jhost, jport),
			d.clientConfig(juser, signer))
		if err != nil {
			return nil, fmt.Errorf("jump %s: %w", t.ProxyJump, err)
		}
		// Channel-open on the jump has no ctx wiring — bound it on
		// the jump's conn the same way the handshake is bounded.
		clear := boundOp(ctx, d.log, jnc, d.timeout)
		nc, err := jump.Dial("tcp", addr)
		clear()
		if err != nil {
			jump.Close()
			return nil, fmt.Errorf("jump %s → %s: %w", t.ProxyJump, addr, err)
		}
		// nc here is a chanConn — SetDeadline always errors on it,
		// so the handshake is bounded on jnc (the real TCP conn all
		// muxed traffic rides).
		client, err := d.handshake(ctx, nc, jnc, addr, cfg)
		if err != nil {
			jump.Close()
			return nil, fmt.Errorf("%s via %s: %w", addr, t.ProxyJump, err)
		}
		return &sshConn{client: client, netc: nc, jnc: jnc, jump: jump,
			sudo: sudo, timeout: d.timeout, log: d.log}, nil
	}

	nc, client, err := d.dialTCP(ctx, addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	return &sshConn{client: client, netc: nc, sudo: sudo,
		timeout: d.timeout, log: d.log}, nil
}

// dialTCP opens the TCP conn with ctx + handshake deadline and
// returns the underlying net.Conn — callers keep it to bound later
// channel ops (jump.Dial, NewSession) that take no ctx.
func (d *sshDialer) dialTCP(ctx context.Context, addr string,
	cfg *ssh.ClientConfig) (net.Conn, *ssh.Client, error) {
	nd := net.Dialer{Timeout: d.timeout}
	nc, err := nd.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	c, err := d.handshake(ctx, nc, nc, addr, cfg)
	if err != nil {
		return nil, nil, err
	}
	return nc, c, nil
}

// handshake runs NewClientConn under a conn deadline covering the
// SSH banner + auth exchange, then clears it so sessions get their
// own deadlines. carrier is the conn SetDeadline actually works
// on: nc itself for a direct dial, but the JUMP's TCP conn when nc
// is the chanConn jump.Dial returned — a chanConn's SetDeadline
// always errors while every muxed channel rides the jump conn.
func (d *sshDialer) handshake(ctx context.Context, nc, carrier net.Conn,
	addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	dl := time.Now().Add(d.timeout)
	if cdl, ok := ctx.Deadline(); ok && cdl.Before(dl) {
		dl = cdl
	}
	if err := carrier.SetDeadline(dl); err != nil {
		d.log.Warn("hubsync: ssh handshake unbounded — SetDeadline unsupported",
			"addr", addr, "error", err)
	}
	c, chans, reqs, err := ssh.NewClientConn(nc, addr, cfg)
	if err != nil {
		nc.Close()
		return nil, err
	}
	_ = carrier.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

// boundOp sets a conn deadline covering one blocking channel op —
// NewSession/Client.Dial take no ctx and the handshake clears the
// conn deadline, so without this a wedged target blocks forever.
// The deadline is min(now+timeout, ctx deadline); the returned func
// clears it so steady-state session I/O stays governed by ctx +
// Session.Close. A rejected SetDeadline leaves the op unbounded —
// warn so a silent hang is at least loud in the logs.
func boundOp(ctx context.Context, log *slog.Logger, nc net.Conn, timeout time.Duration) func() {
	dl := time.Now().Add(timeout)
	if cdl, ok := ctx.Deadline(); ok && cdl.Before(dl) {
		dl = cdl
	}
	if err := nc.SetDeadline(dl); err != nil {
		log.Warn("hubsync: conn deadline rejected — op unbounded", "error", err)
	}
	return func() { _ = nc.SetDeadline(time.Time{}) }
}

// needsSudo reports whether remote ops on the target must escalate —
// hub_converge ran every task with become:true, so a resolved SSH
// user other than root (registry ssh_user / site-map entries like
// lanit→ubuntu) wraps every command in `sudo -n` and streams writes
// through `sudo -n tee`.
func needsSudo(user string) bool { return user != "" && user != "root" }

// splitUserHost parses "user@host[:port]" / "host" from
// ssh_proxyjump — the same spec cli.go's splitJump accepts: an
// explicit port is honoured (empty return = caller's default port).
func splitUserHost(j string) (user, host, port string) {
	user = "root"
	if u, h, ok := strings.Cut(j, "@"); ok {
		user, j = u, h
	}
	host = j
	if h, p, err := net.SplitHostPort(j); err == nil {
		host, port = h, p
	}
	return user, host, port
}

type sshConn struct {
	client  *ssh.Client
	netc    net.Conn    // deadline handle for channel ops (direct dial)
	jnc     net.Conn    // jump's TCP conn — the deadline handle behind a bastion
	jump    *ssh.Client // non-nil when dialed through a bastion
	sudo    bool        // non-root SSH user → wrap ops in sudo -n
	timeout time.Duration
	log     *slog.Logger
}

// deadlineConn picks the conn a SetDeadline actually works on.
// Direct dial: netc is the TCP conn. Behind a bastion netc is the
// chanConn jump.Dial returned (SetDeadline always errors —
// "deadline not supported") while ALL muxed channel traffic rides
// the jump's real TCP conn, so the bound belongs on jnc.
func (c *sshConn) deadlineConn() net.Conn {
	if c.jnc != nil {
		return c.jnc
	}
	return c.netc
}

func (c *sshConn) Close() error {
	err := c.client.Close()
	if c.jump != nil {
		c.jump.Close()
	}
	return err
}

// newSession opens a session channel under a per-op conn deadline —
// NewSession can block indefinitely on a wedged target since the
// handshake cleared the conn deadline and the call takes no ctx.
func (c *sshConn) newSession(ctx context.Context) (*ssh.Session, error) {
	defer boundOp(ctx, c.log, c.deadlineConn(), c.timeout)()
	return c.client.NewSession()
}

func (c *sshConn) Run(ctx context.Context, cmd string) (string, error) {
	if c.sudo {
		cmd = "sudo -n " + cmd
	}
	sess, err := c.newSession(ctx)
	if err != nil {
		return "", err
	}
	defer sess.Close()
	done := make(chan struct{})
	var out []byte
	var runErr error
	go func() {
		defer close(done)
		out, runErr = sess.CombinedOutput(cmd)
	}()
	select {
	case <-ctx.Done():
		_ = sess.Close()
		<-done
		return "", ctx.Err()
	case <-done:
	}
	if c.sudo && runErr != nil {
		// A `sudo -n` failure is otherwise a bare "exit status 1" —
		// attach the remote stderr ("sudo: a password is required")
		// so the converge log says WHY escalation failed.
		if o := strings.TrimSpace(string(out)); o != "" {
			runErr = fmt.Errorf("%w — remote: %s", runErr, o)
		}
	}
	return strings.TrimRight(string(out), "\n"), runErr
}

// Write streams r into remotePath via `cat >` — avoids pulling an
// sftp dependency; the converge only needs whole-file puts. Non-root
// targets escalate through `sudo -n tee` instead (a `>` redirect
// can't elevate — the shell opens the file as the SSH user).
func (c *sshConn) Write(ctx context.Context, remotePath string, r io.Reader) error {
	sess, err := c.newSession(ctx)
	if err != nil {
		return err
	}
	defer sess.Close()
	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	cmd := "cat > " + shq(remotePath)
	if c.sudo {
		cmd = "sudo -n tee " + shq(remotePath) + " >/dev/null"
	}
	if err := sess.Start(cmd); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() {
		_, cerr := io.Copy(stdin, r)
		stdin.Close()
		if cerr != nil {
			done <- cerr
			return
		}
		done <- sess.Wait()
	}()
	select {
	case <-ctx.Done():
		_ = sess.Close()
		// Wait for the copy goroutine to release r before returning
		// — the caller closes the file/handle right after Write.
		<-done //nolint:errcheck // value is sess.Wait() result — intentionally dropped on the cancel path
		return ctx.Err()
	case err := <-done:
		return err
	}
}
