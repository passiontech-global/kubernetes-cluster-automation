package hubsync

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path"
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

// remoteSHA256 returns the hex sha256 of a remote file. A non-zero
// exit (missing file, missing sha256sum) reads as "" — drift —
// while transport errors propagate.
func remoteSHA256(ctx context.Context, c Conn, remotePath string) (string, error) {
	out, err := c.Run(ctx, "sha256sum "+shq(remotePath))
	if err != nil {
		var ee ExitError
		if isExitErr(err, &ee) {
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
}

// newSSHDialer only records the key path — the signer is loaded at
// Dial time so Syncer.New succeeds while the (optional:true) secret
// is not mounted yet, and a rotated key is picked up on the next
// dial without a pod restart.
func newSSHDialer(keyPath string, port int, timeout time.Duration) (*sshDialer, error) {
	return &sshDialer{keyPath: keyPath, port: port, timeout: timeout}, nil
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
// the lease+keypair is the authentication boundary).
func (d *sshDialer) clientConfig(user string, signer ssh.Signer) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // documented parity
		Timeout:         d.timeout,
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
	addr := net.JoinHostPort(t.IP, fmt.Sprint(d.port))
	cfg := d.clientConfig(user, signer)
	sudo := needsSudo(user)

	if t.ProxyJump != "" {
		// ssh_proxyjump parity: hub_converge used ProxyCommand
		// `ssh -W %h:%p <jump>` — same key, no host-key check.
		juser, jhost, jport := splitUserHost(t.ProxyJump)
		if jport == "" {
			jport = fmt.Sprint(d.port)
		}
		jump, err := d.dialTCP(ctx, net.JoinHostPort(jhost, jport),
			d.clientConfig(juser, signer))
		if err != nil {
			return nil, fmt.Errorf("jump %s: %w", t.ProxyJump, err)
		}
		nc, err := jump.Dial("tcp", addr)
		if err != nil {
			jump.Close()
			return nil, fmt.Errorf("jump %s → %s: %w", t.ProxyJump, addr, err)
		}
		client, err := d.handshake(ctx, nc, addr, cfg)
		if err != nil {
			jump.Close()
			return nil, fmt.Errorf("%s via %s: %w", addr, t.ProxyJump, err)
		}
		return &sshConn{client: client, jump: jump, sudo: sudo}, nil
	}

	client, err := d.dialTCP(ctx, addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	return &sshConn{client: client, sudo: sudo}, nil
}

// dialTCP opens the TCP conn with ctx + handshake deadline.
func (d *sshDialer) dialTCP(ctx context.Context, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	nd := net.Dialer{Timeout: d.timeout}
	nc, err := nd.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return d.handshake(ctx, nc, addr, cfg)
}

func (d *sshDialer) handshake(ctx context.Context, nc net.Conn, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	// Bound the handshake: the conn deadline covers the SSH banner +
	// auth exchange, then is cleared so sessions get their own
	// deadlines.
	dl := time.Now().Add(d.timeout)
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
	client *ssh.Client
	jump   *ssh.Client // non-nil when dialed through a bastion
	sudo   bool        // non-root SSH user → wrap ops in sudo -n
}

func (c *sshConn) Close() error {
	err := c.client.Close()
	if c.jump != nil {
		c.jump.Close()
	}
	return err
}

func (c *sshConn) Run(ctx context.Context, cmd string) (string, error) {
	if c.sudo {
		cmd = "sudo -n " + cmd
	}
	sess, err := c.client.NewSession()
	if err != nil {
		return "", err
	}
	done := make(chan struct{})
	var out []byte
	var runErr error
	go func() {
		defer close(done)
		out, runErr = sess.CombinedOutput(cmd)
	}()
	select {
	case <-ctx.Done():
		sess.Close()
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
	sess, err := c.client.NewSession()
	if err != nil {
		return err
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		sess.Close()
		return err
	}
	cmd := "cat > " + shq(remotePath)
	if c.sudo {
		cmd = "sudo -n tee " + shq(remotePath) + " >/dev/null"
	}
	if err := sess.Start(cmd); err != nil {
		sess.Close()
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
		sess.Close()
		return ctx.Err()
	case err := <-done:
		return err
	}
}
