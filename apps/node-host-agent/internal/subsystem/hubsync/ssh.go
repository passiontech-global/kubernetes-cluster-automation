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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
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
	if _, err := c.Run(ctx, "test -d "+hostutil.ShellQuote(remotePath)); err == nil {
		return "", fmt.Errorf("%s is a directory", remotePath)
	}
	out, err := c.Run(ctx, "sha256sum "+hostutil.ShellQuote(remotePath))
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

// sha256sumCmdChunk bounds one sha256sum invocation's command line —
// 32KiB keeps every target's ARG_MAX (Linux ~2MiB) and any
// shell/sudo argv length limit comfortably clear even for the
// largest mirrors.
const sha256sumCmdChunk = 32 * 1024

// remoteSHA256All hashes many remote files in ONE SSH session per
// chunk — a single `sha256sum p1 p2 …` invocation (paths quoted,
// command line chunked at sha256sumCmdChunk) instead of one session
// per file, which over WAN round-trips dominated the sync. The
// per-file semantics remoteSHA256 documents are preserved exactly:
// an absent file produces no hash line (the coreutils "No such file
// or directory" note rides stderr through the combined output) and
// maps to "" — drift; a DIRECTORY is surfaced as an error naming
// the path (sha256sum reports "Is a directory" and exits 1 exactly
// like a missing file, and the follow-up `mv tmp path` would
// silently NEST the staging file inside the directory); any other
// non-zero exit (126/127 missing tool or denied exec, sudo/shell
// failures) and transport errors propagate — treating them as
// "absent" would re-upload on every cycle. Exit 1 from a chunk
// (absent and/or directory paths) still parses the hash lines the
// invocation did produce, so one stale path never blanks its
// siblings' results.
func remoteSHA256All(ctx context.Context, c Conn,
	paths []string) (map[string]string, error) {
	sums := make(map[string]string, len(paths))
	for _, chunk := range sha256sumChunks(paths) {
		out, err := c.Run(ctx, "sha256sum "+chunk)
		if err != nil {
			var ee ExitError
			if errors.As(err, &ee) && ee.ExitStatus() == 1 {
				if dir, isDir := directoryReport(out); isDir {
					return nil, fmt.Errorf("%s is a directory", dir)
				}
				parseSHA256Lines(out, sums)
				continue
			}
			return nil, err
		}
		parseSHA256Lines(out, sums)
	}
	return sums, nil
}

// sha256sumChunks splits the quoted-path command tail so no single
// invocation exceeds sha256sumCmdChunk; one oversized path gets its
// own chunk rather than being dropped.
func sha256sumChunks(paths []string) []string {
	var chunks []string
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			chunks = append(chunks, b.String())
			b.Reset()
		}
	}
	for _, p := range paths {
		q := hostutil.ShellQuote(p)
		if b.Len() > 0 && b.Len()+1+len(q) > sha256sumCmdChunk {
			flush()
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(q)
	}
	flush()
	return chunks
}

// parseSHA256Lines reads coreutils `sha256sum` output lines —
// `<64 hex>  <path>` in text mode, `<64 hex> *<path>` in binary
// mode — into sums. Anything else in the combined output (the
// per-file error notes for absent paths, warnings) carries no hash
// shape and is skipped.
func parseSHA256Lines(out string, sums map[string]string) {
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if len(ln) < 66 || ln[64] != ' ' || !isHexHash(ln[:64]) {
			continue
		}
		p := strings.TrimLeft(ln[65:], " *")
		if p != "" {
			sums[p] = ln[:64]
		}
	}
}

// isHexHash checks the 64-char sha256 hex prefix.
func isHexHash(s string) bool {
	for i := range len(s) {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// directoryReport scans sha256sum's combined output for its per-file
// "Is a directory" note and returns the offending path.
func directoryReport(out string) (string, bool) {
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if rest, ok := strings.CutPrefix(ln, "sha256sum: "); ok {
			if p, ok := strings.CutSuffix(rest, ": Is a directory"); ok && p != "" {
				return p, true
			}
		}
	}
	return "", false
}

// putAtomic streams r into <path>'s staging file, chmods it and
// atomically renames it over the destination — the order ansible's
// copy module + mv produced, and the ordering the tests assert.
func putAtomic(ctx context.Context, c Conn, remotePath string, r io.Reader, mode string) error {
	tmp := tmpPath(remotePath)
	// Secret material (0600 mode: tokens, .key files) must never
	// sit world-readable on the target — `cat >`/`tee` creates the
	// tmp file under the remote umask (~0644), so pre-create it at
	// 0600 BEFORE the upload: install(1) also fixes the mode of a
	// stale tmp left by an interrupted run, and the subsequent
	// `cat >`/`tee` only truncates — the inode keeps 0600.
	if mode == "0600" || isKeyMaterial(path.Base(remotePath)) {
		if _, err := c.Run(ctx, "install -m 600 /dev/null "+hostutil.ShellQuote(tmp)); err != nil {
			return fmt.Errorf("install %s: %w", tmp, err)
		}
	}
	if err := c.Write(ctx, tmp, r); err != nil {
		return fmt.Errorf("upload %s: %w", tmp, err)
	}
	if _, err := c.Run(ctx, "chmod "+mode+" "+hostutil.ShellQuote(tmp)); err != nil {
		return fmt.Errorf("chmod %s: %w", tmp, err)
	}
	// fsync the staged file before the mv — the SSH upload is plain
	// buffered writes; a crash after mv must not expose truncated
	// bytes at the target (the local writers' f.Sync() parity).
	if _, err := c.Run(ctx, "sync "+hostutil.ShellQuote(tmp)); err != nil {
		return fmt.Errorf("sync %s: %w", tmp, err)
	}
	if _, err := c.Run(ctx, "mv "+hostutil.ShellQuote(tmp)+" "+hostutil.ShellQuote(remotePath)); err != nil {
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

// newSession opens a session channel and returns it together with
// the body-deadline release func the caller MUST defer for the
// session's whole span. Two bounds apply: BoundOp covers just the
// channel-open (NewSession takes no ctx and a wedged target blocks
// it indefinitely), then BoundOpCtx re-arms the conn at the ctx
// budget for the SESSION BODY — Session.Close only sends an SSH
// channel-close, which a blackholed transport never drains, so
// CombinedOutput/io.Copy/Wait need a real transport deadline or
// they hang past ctx cancel. link.DeadlineConn picks the conn
// SetDeadline actually works on (the jump's TCP conn behind a
// bastion — see sshclient.Link).
func (c *sshConn) newSession(ctx context.Context) (*ssh.Session, func(), error) {
	clear := sshclient.BoundOp(ctx, c.log, c.link.DeadlineConn(), c.timeout)
	sess, err := c.link.Client.NewSession()
	clear()
	if err != nil {
		return nil, nil, err
	}
	return sess, sshclient.BoundOpCtx(ctx, c.log,
		c.link.DeadlineConn(), c.timeout), nil
}

func (c *sshConn) Run(ctx context.Context, cmd string) (string, error) {
	if c.sudo {
		cmd = "sudo -n " + cmd
	}
	sess, unbind, err := c.newSession(ctx)
	if err != nil {
		return "", err
	}
	defer unbind()
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
		// sess.Close alone CANNOT unblock a dead transport — it only
		// sends an SSH channel-close, which a blackholed conn never
		// drains, so CombinedOutput (and the <-done wait) would hang
		// forever and take the whole converge loop down. Closing the
		// LINK kills the transport conn: every session read/write
		// fails and done closes. The conn dies with this op anyway —
		// syncTarget dials per target and its deferred conn.Close is
		// idempotent.
		_ = c.link.Close()
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
	sess, unbind, err := c.newSession(ctx)
	if err != nil {
		return err
	}
	defer unbind()
	defer func() { _ = sess.Close() }()
	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	cmd := "cat > " + hostutil.ShellQuote(remotePath)
	if c.sudo {
		cmd = "sudo -n tee " + hostutil.ShellQuote(remotePath) + " >/dev/null"
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
		// Same dead-transport reasoning as Run: closing the link is
		// what actually unblocks the copy goroutine — sess.Close's
		// channel-close can't reach a blackholed peer.
		_ = c.link.Close()
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
