package hubsync

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/envnames"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/sshclient"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
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
	// StageSuffix is the per-connection staging nonce appended to
	// putAtomic's tmp path — "" keeps the deterministic
	// `.<name>.tmp` (test fakes); the real dialer returns a
	// per-dial nonce so two overlapping converge runs can never
	// write the same staging inode.
	StageSuffix() string
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
// (+ ".<nonce>" when the conn carries a StageSuffix — the real
// dialer stamps one per run so overlapping syncs never share a
// staging inode; the deterministic form stays for fakes).
func tmpPath(p, suffix string) string {
	tmp := path.Dir(p) + "/." + path.Base(p) + ".tmp"
	if suffix != "" {
		tmp += "." + suffix
	}
	return tmp
}

// newSSHDialer only records the dial config — nothing touches the
// key path until Dial (see sshDialer above). stateDir parents the
// TOFU known_hosts (<stateDir>/hubsync_known_hosts); "" disables
// TOFU. The operator known_hosts is the file next to the converge
// key (/etc/node-converge-ssh/known_hosts by default).
func newSSHDialer(keyPath string, port int, timeout time.Duration,
	hostKeySpec string, allowInsecureHostKey bool, stateDir string,
	log *slog.Logger) (*sshDialer, error) {
	if log == nil {
		log = logger()
	}
	knownHosts := sshclient.KnownHostsPath(keyPath)
	tofu := ""
	if stateDir != "" {
		tofu = filepath.Join(stateDir, "hubsync_known_hosts")
	}
	return &sshDialer{
		cfg: sshclient.Config{
			KeyPath: keyPath,
			Port:    port,
			Timeout: timeout,
			// hubsync audit-logs every accepted host key — Log set.
			Log: log,
		},
		policy: newHostKeyPolicy(hostKeySpec, knownHosts, tofu,
			port, allowInsecureHostKey, log),
		log: log,
	}, nil
}

func (d *sshDialer) Dial(ctx context.Context, t Target) (Conn, error) {
	// Fail closed when NO trust source exists — pins, a readable
	// known_hosts, a TOFU state dir, or the explicit insecure opt-out.
	// With TOFU configured an empty pin spec is no longer fatal:
	// first contact records the key instead of breaking prod.
	if d.policy == nil || !d.policy.active() {
		return nil, fmt.Errorf("ssh host key verification unavailable "+
			"(%s unset, no known_hosts next to the converge key, "+
			"no watchdog state dir for TOFU) — set the fingerprint, "+
			"mount known_hosts, or %s=1 to allow insecure acceptance "+
			"explicitly",
			envnames.EnvHubsyncSSHHostKeyFingerprint,
			envnames.EnvHubsyncSSHAllowInsecureHostKey)
	}
	// cfg is a per-dial copy: HostKeyVerify is policy state and
	// d.cfg is shared across concurrent target dials — mutating it
	// here would race.
	cfg := d.cfg
	cfg.HostKeyVerify = d.policy.verify
	var link *sshclient.Link
	var err error
	if t.ProxyJump == "" {
		link, err = cfg.Dial(ctx, t.SSHUser, t.IP, "")
	} else {
		link, err = d.dialViaBastion(ctx, &cfg, t)
	}
	if err != nil {
		return nil, err
	}
	return &sshConn{link: link, sudo: needsSudo(t.SSHUser),
		timeout: cfg.Timeout, log: d.log,
		nonce: nextStageNonce()}, nil
}

// dialViaBastion resolves (or opens) the cached Bastion for the
// target's ssh_proxyjump spec and dials the target through it. A
// channel-open/handshake failure evicts the cached bastion and
// retries once on a fresh one — a blackholed jump conn would
// otherwise fail every remaining target of the cycle.
func (d *sshDialer) dialViaBastion(ctx context.Context,
	cfg *sshclient.Config, t Target) (*sshclient.Link, error) {
	b, err := d.bastion(ctx, cfg, t.ProxyJump)
	if err != nil {
		return nil, err
	}
	link, err := cfg.DialVia(ctx, t.SSHUser, t.IP, b)
	if err == nil {
		return link, nil
	}
	d.dropBastion(t.ProxyJump, b)
	b2, err2 := d.bastion(ctx, cfg, t.ProxyJump)
	if err2 != nil {
		return nil, err
	}
	return cfg.DialVia(ctx, t.SSHUser, t.IP, b2)
}

// bastion returns the cached Bastion for spec, opening it on first
// use. The open itself runs outside the mutex (a WAN handshake must
// not serialize unrelated specs); a lost insert race keeps the
// first opener's conn and closes the duplicate.
func (d *sshDialer) bastion(ctx context.Context,
	cfg *sshclient.Config, spec string) (*sshclient.Bastion, error) {
	d.mu.Lock()
	if b := d.jumps[spec]; b != nil {
		d.mu.Unlock()
		return b, nil
	}
	d.mu.Unlock()
	b, err := cfg.OpenBastion(ctx, spec)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.jumps == nil {
		d.jumps = map[string]*sshclient.Bastion{}
	}
	if old := d.jumps[spec]; old != nil {
		_ = b.Close()
		return old, nil
	}
	d.jumps[spec] = b
	return b, nil
}

// dropBastion evicts b for spec — only when the cache still holds
// THIS conn (a concurrent redial may already have replaced it).
func (d *sshDialer) dropBastion(spec string, b *sshclient.Bastion) {
	d.mu.Lock()
	if d.jumps[spec] == b {
		delete(d.jumps, spec)
	}
	d.mu.Unlock()
	_ = b.Close()
}

// stageNonceSeq hands out per-dial staging suffixes — pid+counter
// keeps them unique across overlapping runs AND across agent
// restarts on the same target dir.
var stageNonceSeq atomic.Uint64

func nextStageNonce() string {
	return fmt.Sprintf("%d-%d", os.Getpid(), stageNonceSeq.Add(1))
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
	nonce   string // per-dial staging suffix (StageSuffix)
}

func (c *sshConn) Close() error { return c.link.Close() }

// StageSuffix returns this dial's staging nonce — putAtomic appends
// it to the tmp path so concurrent runs never share a staging inode.
func (c *sshConn) StageSuffix() string { return c.nonce }

func (c *sshConn) newSession(ctx context.Context) (*ssh.Session, func(), error) {
	return c.link.NewSession(ctx, c.log, c.timeout)
}

func (c *sshConn) Run(ctx context.Context, cmd string) (string, error) {
	if c.sudo {
		cmd = "sudo -n " + cmd
	}
	out, runErr := c.link.CombinedOutputCapped(ctx, c.log, c.timeout, cmd,
		sshclient.DefaultMaxOutputBytes)
	if runErr != nil && ctx.Err() != nil {
		return "", runErr
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
	cmd := "cat > " + fsx.ShellQuote(remotePath)
	if c.sudo {
		cmd = "sudo -n tee " + fsx.ShellQuote(remotePath) + " >/dev/null"
	}
	return c.streamCmd(ctx, cmd, r)
}

// PutAtomic is putAtomic's single-session fast path: ONE ssh
// session runs the whole stage→chmod→sync→mv chain under a shell
// `trap 'rm -f "$tmp"' EXIT` cleanup — the four separate c.Run
// sessions the fallback pays per file collapse into one, and an
// interrupted upload no longer leaves its staging file behind
// (the trap fires on every shell exit, success included — after
// mv the tmp path is already gone so rm -f is a no-op).
//
// Secret material keeps the old pre-create contract INSIDE the
// same script: `install -m 600 /dev/null "$tmp"` runs before cat
// so the staging inode is never world-readable during upload and
// a stale tmp from an interrupted run is re-moded first — cat >
// only truncates, preserving the 0600 inode.
//
// sudo targets wrap the whole script in `sudo -n sh -c` — one
// escalation for the chain replaces the per-op `sudo -n` wraps,
// and stdin still reaches cat through sudo+sh.
func (c *sshConn) PutAtomic(ctx context.Context, remotePath string,
	r io.Reader, mode string) error {
	tmp := tmpPath(remotePath, c.nonce)
	script := "tmp=" + fsx.ShellQuote(tmp) +
		"; trap 'rm -f \"$tmp\"' EXIT; "
	if mode == "0600" || isKeyMaterial(path.Base(remotePath)) {
		script += "install -m 600 /dev/null \"$tmp\" && "
	}
	script += "cat > \"$tmp\" && chmod " + mode +
		" \"$tmp\" && sync \"$tmp\" && mv \"$tmp\" " +
		fsx.ShellQuote(remotePath)
	cmd := "sh -c " + fsx.ShellQuote(script)
	if c.sudo {
		cmd = "sudo -n " + cmd
	}
	if err := c.streamCmd(ctx, cmd, r); err != nil {
		return fmt.Errorf("putAtomic %s: %w", remotePath, err)
	}
	return nil
}

// streamCmd runs cmd on one session with r piped to its stdin —
// the shared body of Write and PutAtomic.
func (c *sshConn) streamCmd(ctx context.Context, cmd string, r io.Reader) error {
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
