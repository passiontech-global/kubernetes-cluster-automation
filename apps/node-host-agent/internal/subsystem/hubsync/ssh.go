package hubsync

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/sshclient"
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
		if errors.As(err, &ee) && ee.ExitStatus() == 1 {
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
//
// The dial mechanics (signer loading, client config, TCP dial +
// bounded handshake, the ssh_proxyjump hop, per-op conn bounds) now
// live in platform/sshclient — shared with the nebulasign host.pub
// fetch that used to carry a second private copy. What stays here
// is hubsync's own contract: the Conn/Dialer seams, the sudo
// wrapping, streaming Write and ExitError.

// sshDialer is the real Dialer — a thin Config→sshclient splice.
// The signer is loaded inside Dial (sshclient.Config.LoadSigner
// runs per dial) so Syncer.New succeeds while the optional:true
// secret is not mounted yet, and a rotated key is picked up on the
// next dial without a pod restart.
type sshDialer struct {
	cfg sshclient.Config
	log *slog.Logger
}

// newSSHDialer only records the dial config — nothing touches the
// key path until Dial (see sshDialer above).
func newSSHDialer(keyPath string, port int, timeout time.Duration,
	log *slog.Logger) (*sshDialer, error) {
	if log == nil {
		log = logger()
	}
	return &sshDialer{
		cfg: sshclient.Config{
			KeyPath: keyPath,
			Port:    port,
			Timeout: timeout,
			// hubsync audit-logs every accepted host key — Log set.
			Log: log,
		},
		log: log,
	}, nil
}

func (d *sshDialer) Dial(ctx context.Context, t Target) (Conn, error) {
	link, err := d.cfg.Dial(ctx, t.SSHUser, t.IP, t.ProxyJump)
	if err != nil {
		return nil, err
	}
	return &sshConn{link: link, sudo: needsSudo(t.SSHUser),
		timeout: d.cfg.Timeout, log: d.log}, nil
}

// needsSudo reports whether remote ops on the target must escalate —
// hub_converge ran every task with become:true, so a resolved SSH
// user other than root (registry ssh_user / site-map entries like
// lanit→ubuntu) wraps every command in `sudo -n` and streams writes
// through `sudo -n tee`.
func needsSudo(user string) bool { return user != "" && user != "root" }

// splitUserHost parses "user@host[:port]" / "host" from
// ssh_proxyjump — the spec asserted by sync_test.go; the parse
// itself is sshclient.SplitUserHost (identical shape).
func splitUserHost(j string) (user, host, port string) {
	return sshclient.SplitUserHost(j)
}

// sshConn is hubsync's Conn over an established sshclient.Link —
// the sudo wrap, streaming Write and per-op conn bound are the
// converge-specific parts that stayed.
type sshConn struct {
	link    *sshclient.Link
	sudo    bool // non-root SSH user → wrap ops in sudo -n
	timeout time.Duration
	log     *slog.Logger
}

func (c *sshConn) Close() error { return c.link.Close() }

// newSession opens a session channel under a per-op conn deadline —
// NewSession can block indefinitely on a wedged target since the
// handshake cleared the conn deadline and the call takes no ctx.
// link.DeadlineConn picks the conn SetDeadline actually works on
// (the jump's TCP conn behind a bastion — see sshclient.Link).
func (c *sshConn) newSession(ctx context.Context) (*ssh.Session, error) {
	defer sshclient.BoundOp(ctx, c.log, c.link.DeadlineConn(), c.timeout)()
	return c.link.Client.NewSession()
}

func (c *sshConn) Run(ctx context.Context, cmd string) (string, error) {
	if c.sudo {
		cmd = "sudo -n " + cmd
	}
	sess, err := c.newSession(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = sess.Close() }()
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
	defer func() { _ = sess.Close() }()
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
		_ = stdin.Close()
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
		// The value is the sess.Wait() result — non-actionable on the
		// cancel path (ctx.Err() is what the caller gets) but worth a
		// debug line for post-mortems.
		if werr := <-done; werr != nil {
			c.log.Debug("hubsync: ssh write wait failed after cancel", "error", werr)
		}
		return ctx.Err()
	case err := <-done:
		return err
	}
}
