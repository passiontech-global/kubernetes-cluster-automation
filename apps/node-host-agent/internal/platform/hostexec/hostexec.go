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
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Defaults — containerized default is the DaemonSet host-root mount.
// Exported as the single source: systemd.Config is an alias of
// hostexec.Config, so the systemd client inherits these defaults
// through hostexec's own applyDefaults (it used to carry a private
// copy of the pair — the copies drifted risk-free only by luck).
const (
	// DefaultHostRoot is where the DaemonSet mounts the host fs.
	DefaultHostRoot = "/host"
	// DefaultTimeout bounds every spawned command when Config.Timeout
	// is unset.
	DefaultTimeout = 30 * time.Second
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
		c.HostRoot = DefaultHostRoot
	}
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.RunCmd == nil {
		c.RunCmd = func(ctx context.Context, argv []string) (string, error) {
			// newCmd carries the group-kill Cancel and WaitDelay.
			// WaitDelay only works on goroutine-copied pipes (an
			// io.Writer sink) — a StdoutPipe fd is only closed
			// INSIDE Wait, which a blocked pre-Wait ReadAll never
			// reaches. So stdout goes through the same capped sink
			// as the combined runner: a daemonized grandchild
			// inheriting the pipe holds EOF open after the group
			// kill, and WaitDelay forces the pipe closed so Run
			// returns (ErrWaitDelay) instead of hanging past
			// Config.Timeout.
			cmd := newCmd(ctx, argv)
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
			// Same container-side combined runner as the
			// package-level helper — one implementation of the
			// capped-buffer/WaitDelay contract.
			return RunCombined(ctx, argv...)
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
		// Keep only the head that fits under the cap — the FIRST
		// bytes of the stream are the useful prefix (an error banner,
		// the first journal lines), not the last. Writing the whole p
		// past the boundary would grow the buffer unbounded; dropping
		// all of it would lose the final usable chunk. len(p) is
		// always returned: the excess is drained (swallowed) so the
		// child never blocks on a full pipe.
		rem := maxCmdOutputBytes - b.buf.Len()
		if rem > len(p) {
			rem = len(p)
		}
		b.buf.Write(p[:rem])
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
	return r.execBounded(ctx, ns, 0, r.cfg.RunCmd, name, args...)
}

// ExecBounded is Exec with a per-call budget in place of
// Config.Timeout — for remediations whose bound is deliberately
// longer than the runner default (the apiserver wedge gate's
// `timeout 90 systemctl restart`). ctx still bounds the call from
// above. budget <= 0 falls back to Config.Timeout.
func (r *Runner) ExecBounded(ctx context.Context, ns NS, budget time.Duration, name string, args ...string) (string, error) {
	return r.execBounded(ctx, ns, budget, r.cfg.RunCmd, name, args...)
}

// ExecCombined is Exec with the child's STDERR folded into the
// returned output — for probes whose evidence lives off stdout
// (journalctl reports corrupt journal files on STDERR; a
// stdout-only capture makes the "corrupt" substring check dead
// code). Callers that only want stdout keep Exec — the signature
// contract is unchanged.
func (r *Runner) ExecCombined(ctx context.Context, ns NS, name string, args ...string) (string, error) {
	return r.execBounded(ctx, ns, 0, r.cfg.RunCmdCombined, name, args...)
}

// ExecCombinedBounded is ExecBounded with stderr folded into the
// returned output — the ExecCombined/ExecBounded pairing.
func (r *Runner) ExecCombinedBounded(ctx context.Context, ns NS, budget time.Duration, name string, args ...string) (string, error) {
	return r.execBounded(ctx, ns, budget, r.cfg.RunCmdCombined, name, args...)
}

// execBounded is the shared body of the Runner quartet: budget <= 0
// falls back to Config.Timeout, ctx is additionally bounded by that
// budget, and run picks the stdout-only vs stderr-combined seam.
func (r *Runner) execBounded(ctx context.Context, ns NS, budget time.Duration, run func(context.Context, []string) (string, error), name string, args ...string) (string, error) {
	if budget <= 0 {
		budget = r.cfg.Timeout
	}
	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	return run(cctx, r.argv(ns, name, args))
}

// argv applies the nsenter host-namespace wrap selected by ns —
// shared by Exec and ExecCombined. HostRoot "/" (agent already on
// the host) and NSNone both skip the wrap entirely.
func (r *Runner) argv(ns NS, name string, args []string) []string {
	argv := append([]string{name}, args...)
	if r.cfg.HostRoot == "/" || ns == NSNone {
		return argv
	}
	var flags []string
	for _, f := range nsenterFlag {
		if ns&f.bit != 0 {
			flags = append(flags, f.opt)
		}
	}
	prefix := append([]string{"nsenter", "-t", "1"}, flags...)
	return append(append(prefix, "--"), argv...)
}

// errEmptyArgv guards the package-level helpers — exec.CommandContext
// would index argv[0] on an empty slice and panic.
var errEmptyArgv = errors.New("hostexec: empty argv")

// newCmd is the package's one spawn shape: CommandContext (kill at
// ctx expiry), the child in its OWN process group, and a Cancel that
// SIGKILLs the whole group. CommandContext's default cancel kills
// only the direct child — a grandchild (`sh -c 'sleep 30 & wait'`,
// anything a probed script daemonizes) survives and keeps holding any
// inherited pipe until WaitDelay expires, or forever if it detached.
// Setpgid is applied by the fork before Start (no separate setpgid
// dance), so the negative-pid kill is race-free. linux-only by
// construction — this agent only builds for linux.
func newCmd(ctx context.Context, argv []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative pid = the process group. ESRCH means the group
		// is already gone — report done so Wait surfaces ctx.Err()
		// instead of the kill error.
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil &&
			errors.Is(err, syscall.ESRCH) {
			return nil
		} else if err != nil {
			return err
		}
		return nil
	}
	cmd.WaitDelay = cmdWaitDelay
	return cmd
}

// --- container-side package-level helpers ---
//
// Config.RunCmd/RunCmdCombined stay the seam for commands that want
// the nsenter wrap AND test injection. The helpers below serve the
// callers that deliberately exec CONTAINER-SIDE — the standalone
// systemd deployment (HostRoot "/" already lives in the host
// namespaces, an nsenter wrap would be wrong work), hostPath-prefixed
// binaries that only exist in the pod's mount view, and probes with
// no Config seam to inject through. They reuse the same
// cappedBuffer/WaitDelay contract the Config defaults implement so
// the safety properties (16MiB output cap, grandchild-pipe bound)
// stop depending on which entry point a caller picked; unlike the
// Config paths they apply NO extra timeout — ctx arrives already
// budgeted by the caller.

// RunCombined runs argv[0] argv[1:] container-side — no nsenter
// wrap — with stdout AND stderr folded into one stream capped at
// maxCmdOutputBytes. It is the shared form of the plain
// `exec.CommandContext(...).CombinedOutput()` the bespoke runners
// carried: same hang class too, so WaitDelay is set (a daemonized
// grandchild inheriting a pipe must not hold EOF open past ctx —
// Wait returns ErrWaitDelay instead of blocking forever). Run waits
// for the copy goroutines, so partial output is returned complete
// alongside an error. Callers keep any deadline on ctx themselves.
func RunCombined(ctx context.Context, argv ...string) (string, error) {
	return runCombined(ctx, nil, argv)
}

// RunCombinedEnv is RunCombined with the child's environment
// REPLACED by env (nil → inherit the agent's environ) — for the
// container-side exec that must scrub inherited daemon variables
// (controllerhygiene's NOTIFY_SOCKET/WATCHDOG_* drop) where the
// argv-level `env -u` trick cannot be assumed: it would resolve
// `env` against the pod image's own PATH.
func RunCombinedEnv(ctx context.Context, env []string, argv ...string) (string, error) {
	return runCombined(ctx, env, argv)
}

// runCombined is the shared combined-stream spawn behind RunCombined
// / RunCombinedEnv / Config.RunCmdCombined's default — both streams
// share one capped sink so the child never blocks on an unread
// stderr pipe and output over the cap is swallowed.
func runCombined(ctx context.Context, env []string, argv []string) (string, error) {
	if len(argv) == 0 {
		return "", errEmptyArgv
	}
	cmd := newCmd(ctx, argv)
	if env != nil {
		cmd.Env = env
	}
	var buf cappedBuffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// Run runs argv[0] argv[1:] container-side — no nsenter wrap —
// capturing stdout and stderr into SEPARATE capped buffers and
// feeding the child stdin when non-empty. Use it when stdout must
// stay machine-clean: a `psql` WARNING/NOTICE or etcdctl's
// "unrecognized environment variable ETCDCTL_API" line folded into
// stdout would poison the exact-match and `-w json` parsers. The
// caller owns the folding decision — stderr into the error on
// failure, a debug log (or nothing) on success; Run deliberately
// returns BOTH streams on the error path so partial output survives.
// Same WaitDelay contract as the Config runners.
func Run(ctx context.Context, argv []string, stdin string) (stdout, stderr string, err error) {
	return RunEnv(ctx, nil, argv, stdin)
}

// RunEnv is Run with extra child environment variables layered over
// the inherited environment — the way a secret (PGPASSWORD) reaches
// `docker exec -e PGPASSWORD` without ever appearing on the child's
// argv, where /proc/<pid>/cmdline would expose it to every process
// on the host.
func RunEnv(ctx context.Context, env []string, argv []string, stdin string) (stdout, stderr string, err error) {
	if len(argv) == 0 {
		return "", "", errEmptyArgv
	}
	cmd := newCmd(ctx, argv)
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, serr cappedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &serr
	err = cmd.Run()
	return out.String(), serr.String(), err
}
