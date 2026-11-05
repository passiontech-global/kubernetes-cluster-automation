// Package hostexec is the agent's single seam for "run a binary on
// the host". The agent pod sees the host through a mounted host
// root: host binaries are wrapped in `nsenter -t 1 <flags> --` so
// they run inside host PID 1's namespaces and see the host's mount
// table, network stack and process tree — a plain in-container exec
// would fail (no /run/systemd/private) or worse, act on the wrong
// namespace. WHICH namespaces to enter is a per-call NS flag set:
// systemctl/journalctl need the lot (NSAll) while a ping or `ss`
// probe only needs the host network (NSNet) and a mount-table edit
// needs mount+net (NSMountNet). When the agent runs directly on the
// host (HostRoot "/") the wrapper is skipped regardless of flags.
//
// All commands go through Config.RunCmd / Config.RunCmdCombined —
// one seam that tests replace with a fake recorder, and that
// production wires to exec.CommandContext. Captured output is
// capped: a log storm (a journalctl snapshot on a sick node) must
// not push unbounded child output into the agent's heap — the rest
// is drained and discarded so the child can still exit cleanly.
package hostexec

import (
	"bytes"
	"context"
	"os/exec"
	"sync"
	"time"
)

// Defaults — containerized default is the DaemonSet host-root mount.
const (
	defaultHostRoot = "/host"
	defaultTimeout  = 30 * time.Second
	// maxCmdOutputBytes caps the stdout retained per spawned command —
	// a log storm (journalctl -10min snapshot on a sick node) must not
	// push unbounded child output into the agent's heap. The rest is
	// drained and discarded so the child can still exit cleanly.
	maxCmdOutputBytes = 16 << 20
	// cmdWaitDelay bounds the post-exit/kill wait for the child's I/O
	// pipes. A daemonized grandchild inheriting the stdout pipe holds
	// EOF open after CommandContext kills the child — without a bound,
	// the reader/Wait hang forever and Config.Timeout goes unenforced.
	// After the grace exec closes the pipes and Wait returns
	// ErrWaitDelay (wrapped in the returned error).
	cmdWaitDelay = 5 * time.Second
)

// NS selects which of host PID 1's namespaces a command enters via
// `nsenter -t 1` — a bitmask over the nsenter short flags. The flag
// set is a per-CALL choice: a host network probe must not also
// demand the mount namespace (a net-only container has no -m to
// give), and a full control-plane client wants every namespace
// systemd talks through. Bit order below matches the nsenter flag
// letters; argv emits them in declaration order (m, u, i, n, p) for
// a stable, greppable command line.
type NS int

const (
	NSMount NS = 1 << iota // -m: host mount namespace
	NSUTS                  // -u: host UTS namespace (hostname)
	NSIPC                  // -i: host IPC namespace
	NSNet                  // -n: host network namespace
	NSPID                  // -p: host PID namespace
)

// Named flag sets matching observed host-exec call shapes.
const (
	// NSNone runs the binary unwrapped — no nsenter prefix at all.
	// For commands that are container-local by design (or when the
	// caller manages its own boundary); HostRoot "/" also lands here
	// implicitly whatever the flags.
	NSNone NS = 0
	// NSAll enters every host PID-1 namespace (-m -u -i -n -p) — the
	// full host context systemd control (systemctl/journalctl) and
	// arbitrary host tooling need.
	NSAll = NSMount | NSUTS | NSIPC | NSNet | NSPID
	// NSMountNet enters mount + network (-m -n) — for commands that
	// touch the host mount table but must also see host networking
	// (e.g. a route-guard script resolving inside the host fs view).
	NSMountNet = NSMount | NSNet
)

// nsenterFlag orders the bitmask → argv mapping: declaration order
// is the emission order, so NSAll renders `-m -u -i -n -p`.
var nsenterFlag = []struct {
	bit NS
	opt string
}{
	{NSMount, "-m"},
	{NSUTS, "-u"},
	{NSIPC, "-i"},
	{NSNet, "-n"},
	{NSPID, "-p"},
}

// Config carries the exec seam — all test-injectable.
type Config struct {
	// HostRoot is where the host filesystem is mounted. "/" means the
	// process runs on the host already — commands run unwrapped
	// whatever the NS flags.
	HostRoot string
	// Timeout bounds every spawned command.
	Timeout time.Duration
	// RunCmd executes argv[0] argv[1:] and returns combined stdout.
	// nil → exec.CommandContext. The nsenter wrapping is applied to
	// argv BEFORE RunCmd sees it, so a fake runner observes the exact
	// production command line.
	RunCmd func(ctx context.Context, argv []string) (string, error)
	// RunCmdCombined is RunCmd with the child's STDERR folded into
	// the returned output — ExecCombined's seam. Needed for probes
	// whose evidence lives on stderr (journalctl prints
	// "File ... is corrupt" to stderr, not stdout). nil →
	// exec.CommandContext writing both streams into one capped
	// buffer.
	RunCmdCombined func(ctx context.Context, argv []string) (string, error)
}

func (c *Config) applyDefaults() {
	if c.HostRoot == "" {
		c.HostRoot = defaultHostRoot
	}
	if c.Timeout <= 0 {
		c.Timeout = defaultTimeout
	}
	if c.RunCmd == nil {
		c.RunCmd = func(ctx context.Context, argv []string) (string, error) {
			cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
			// WaitDelay bounds the post-exit/kill wait for I/O. It
			// only works on goroutine-copied pipes (an io.Writer
			// sink) — a StdoutPipe fd is only closed INSIDE Wait,
			// which a blocked pre-Wait ReadAll never reaches. So
			// stdout goes through the same capped sink as the
			// combined runner: a daemonized grandchild inheriting
			// the pipe holds EOF open after CommandContext kills
			// the child, and WaitDelay forces the pipe closed so
			// Run returns (ErrWaitDelay) instead of hanging past
			// Config.Timeout.
			cmd.WaitDelay = cmdWaitDelay
			var buf cappedBuffer
			cmd.Stdout = &buf
			// Run waits for the copy goroutine — buf is complete
			// once it returns. Partial output is returned alongside
			// the error just like exec.Cmd.Output (callers count
			// grep hits — truncated text is still useful evidence).
			err := cmd.Run()
			return buf.String(), err
		}
	}
	if c.RunCmdCombined == nil {
		c.RunCmdCombined = func(ctx context.Context, argv []string) (string, error) {
			cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
			// Same hang class as the stdout path: the internal
			// copy goroutines block on a pipe a grandchild holds —
			// WaitDelay closes them so Run cannot outlive the ctx.
			cmd.WaitDelay = cmdWaitDelay
			// Both streams share one capped sink — the child never
			// blocks on an unread stderr pipe, and output over the
			// cap is swallowed (same budget as the stdout path).
			var buf cappedBuffer
			cmd.Stdout = &buf
			cmd.Stderr = &buf
			// Run waits for the copy goroutines — buf is complete
			// once it returns (partial output alongside an error,
			// same contract as the stdout path).
			err := cmd.Run()
			return buf.String(), err
		}
	}
}

// cappedBuffer is a goroutine-safe io.Writer retaining at most
// maxCmdOutputBytes — the runners' stdout (+stderr) sink
// (exec copies each stream on its own goroutine; excess is
// swallowed so the child still exits cleanly).
type cappedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buf.Len() < maxCmdOutputBytes {
		b.buf.Write(p)
	}
	return len(p), nil
}

func (b *cappedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Runner executes binaries on the host — the one type every
// subsystem's host-command path funnels through.
type Runner struct {
	cfg Config
}

// New returns a Runner for cfg.
func New(cfg Config) *Runner {
	cfg.applyDefaults()
	return &Runner{cfg: cfg}
}

// Exec runs name args... on the host, entering the PID-1 namespaces
// selected by ns (when containerized — HostRoot "/" always runs
// unwrapped). Stdout is returned (capped at maxCmdOutputBytes);
// stderr goes to the child's stderr. ctx is additionally bounded by
// Config.Timeout.
func (r *Runner) Exec(ctx context.Context, ns NS, name string, args ...string) (string, error) {
	return r.ExecBounded(ctx, ns, r.cfg.Timeout, name, args...)
}

// ExecBounded is Exec with a per-call budget in place of
// Config.Timeout — for remediations whose bound is deliberately
// longer than the runner default (the apiserver wedge gate's
// `timeout 90 systemctl restart`). ctx still bounds the call from
// above. budget <= 0 falls back to Config.Timeout.
func (r *Runner) ExecBounded(ctx context.Context, ns NS, budget time.Duration, name string, args ...string) (string, error) {
	if budget <= 0 {
		budget = r.cfg.Timeout
	}
	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	return r.cfg.RunCmd(cctx, r.argv(ns, name, args))
}

// ExecCombined is Exec with the child's STDERR folded into the
// returned output — for probes whose evidence lives off stdout
// (journalctl reports corrupt journal files on STDERR; a
// stdout-only capture makes the "corrupt" substring check dead
// code). Callers that only want stdout keep Exec — the signature
// contract is unchanged.
func (r *Runner) ExecCombined(ctx context.Context, ns NS, name string, args ...string) (string, error) {
	return r.ExecCombinedBounded(ctx, ns, r.cfg.Timeout, name, args...)
}

// ExecCombinedBounded is ExecBounded with stderr folded into the
// returned output — the ExecCombined/ExecBounded pairing.
func (r *Runner) ExecCombinedBounded(ctx context.Context, ns NS, budget time.Duration, name string, args ...string) (string, error) {
	if budget <= 0 {
		budget = r.cfg.Timeout
	}
	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	return r.cfg.RunCmdCombined(cctx, r.argv(ns, name, args))
}

// argv applies the nsenter host-namespace wrap selected by ns —
// shared by Exec and ExecCombined. HostRoot "/" (agent already on
// the host) and NSNone both skip the wrap entirely.
func (r *Runner) argv(ns NS, name string, args []string) []string {
	argv := append([]string{name}, args...)
	if r.cfg.HostRoot == "/" || ns == NSNone {
		return argv
	}
	prefix := []string{"nsenter", "-t", "1"}
	for _, f := range nsenterFlag {
		if ns&f.bit != 0 {
			prefix = append(prefix, f.opt)
		}
	}
	return append(append(prefix, "--"), argv...)
}
