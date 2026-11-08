package hostexec

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func newFake() *testutil.FakeExec {
	return testutil.NewFakeExec()
}

// TestArgvNsenterFlagSets: each NS value must render the exact
// nsenter prefix the call sites historically hardcoded — systemd's
// all-namespaces form, nethealth's net-only and mount+net forms.
func TestArgvNsenterFlagSets(t *testing.T) {
	for _, tc := range []struct {
		name string
		ns   NS
		want string
	}{
		{"all", NSAll,
			"nsenter -t 1 -m -u -i -n -p -- ip link show"},
		{"net only", NSNet,
			"nsenter -t 1 -n -- ip link show"},
		{"mount+net", NSMountNet,
			"nsenter -t 1 -m -n -- ip link show"},
		{"mount only", NSMount,
			"nsenter -t 1 -m -- ip link show"},
		{"net+pid", NSNet | NSPID,
			"nsenter -t 1 -n -p -- ip link show"},
		{"none runs unwrapped", NSNone,
			"ip link show"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			r := New(Config{HostRoot: "/host", RunCmd: f.Run})
			if _, err := r.Exec(context.Background(), tc.ns,
				"ip", "link", "show"); err != nil {
				t.Fatal(err)
			}
			if f.Count() != 1 || f.Nth(0) != tc.want {
				t.Fatalf("argv=%s want [%s]", f.Joined(), tc.want)
			}
		})
	}
}

// TestArgvPlainOnHost: HostRoot "/" means the process already lives
// in the host namespaces — no nsenter whatever the flags ask for.
func TestArgvPlainOnHost(t *testing.T) {
	f := newFake()
	r := New(Config{HostRoot: "/", RunCmd: f.Run})
	for _, ns := range []NS{NSAll, NSNet, NSMountNet, NSNone} {
		if _, err := r.Exec(context.Background(), ns,
			"systemctl", "daemon-reload"); err != nil {
			t.Fatal(err)
		}
	}
	want := "systemctl daemon-reload"
	if f.Count() != 4 {
		t.Fatalf("cmds=%s", f.Joined())
	}
	for i, cmd := range f.Cmds() {
		if got := strings.Join(cmd, " "); got != want {
			t.Fatalf("cmd[%d]=%q want %q — HostRoot / must never wrap", i, got, want)
		}
	}
}

// TestArgvEmptyHostRootDefaultsContainerized: an unset HostRoot
// takes the DaemonSet mount default — the wrap still applies.
func TestArgvEmptyHostRootDefaultsContainerized(t *testing.T) {
	f := newFake()
	r := New(Config{RunCmd: f.Run})
	if _, err := r.Exec(context.Background(), NSAll, "true"); err != nil {
		t.Fatal(err)
	}
	want := "nsenter -t 1 -m -u -i -n -p -- true"
	if f.Count() != 1 || f.Nth(0) != want {
		t.Fatalf("argv=%s want [%s]", f.Joined(), want)
	}
}

// TestExecCombinedUsesCombinedSeam: ExecCombined must route through
// RunCmdCombined — probes whose evidence lives on stderr (journald's
// corrupt-file notices) go dead on the stdout-only seam. The same
// nsenter wrap applies.
func TestExecCombinedUsesCombinedSeam(t *testing.T) {
	combined := newFake()
	combined.On("journalctl -n 1 --no-pager",
		"File /var/log/journal/a.journal is corrupt, ignoring journal files.\n")
	stdoutOnlyCalled := false
	r := New(Config{
		HostRoot: "/host",
		RunCmd: func(context.Context, []string) (string, error) {
			stdoutOnlyCalled = true
			return "", nil
		},
		RunCmdCombined: combined.Run,
	})
	out, err := r.ExecCombined(context.Background(), NSAll,
		"journalctl", "-n", "1", "--no-pager")
	if err != nil {
		t.Fatal(err)
	}
	if stdoutOnlyCalled {
		t.Fatal("ExecCombined must use the combined runner — stderr evidence is lost on Exec")
	}
	if !strings.Contains(out, "corrupt") {
		t.Fatalf("out=%q want the stderr corruption notice", out)
	}
	want := "nsenter -t 1 -m -u -i -n -p -- journalctl -n 1 --no-pager"
	if combined.Count() != 1 || combined.Nth(0) != want {
		t.Fatalf("argv=%s want [%s]", combined.Joined(), want)
	}
}

// TestExecBoundsContextByTimeout: every call gets a fresh ctx capped
// at Config.Timeout — a caller passing background must not spawn an
// unbounded child.
func TestExecBoundsContextByTimeout(t *testing.T) {
	var deadline time.Duration
	r := New(Config{
		HostRoot: "/",
		Timeout:  3 * time.Second,
		RunCmd: func(ctx context.Context, _ []string) (string, error) {
			dl, ok := ctx.Deadline()
			if !ok {
				t.Error("ctx has no deadline — Config.Timeout not applied")
				return "", nil
			}
			deadline = time.Until(dl)
			return "", nil
		},
	})
	if _, err := r.Exec(context.Background(), NSNone, "true"); err != nil {
		t.Fatal(err)
	}
	if deadline <= 0 || deadline > 3*time.Second {
		t.Fatalf("deadline=%v want (0, 3s]", deadline)
	}
}

// TestWaitDelayUnsticksInheritedPipe: a daemonized grandchild
// inheriting the stdout pipe holds EOF open after the child exits —
// without WaitDelay the runner blocks in ReadAll past the timeout.
// The real exec seam (nil RunCmd/RunCmdCombined) is exercised here,
// HostRoot "/" so no nsenter wrapper is needed.
func TestWaitDelayUnsticksInheritedPipe(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh on PATH")
	}
	r := New(Config{HostRoot: "/"})
	start := time.Now()
	// `sleep 10 &` keeps the stdout pipe open well past cmdWaitDelay
	// (5s) after sh exits; WaitDelay must force it closed,
	// surfacing ErrWaitDelay with the partial output intact.
	out, err := r.Exec(context.Background(), NSNone,
		"sh", "-c", "sleep 10 & echo done")
	if !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("exec err=%v want ErrWaitDelay", err)
	}
	if !strings.Contains(out, "done") {
		t.Fatalf("out=%q want partial output before the stuck pipe", out)
	}
	if took := time.Since(start); took > cmdWaitDelay+3*time.Second {
		t.Fatalf("took %v — pipe-close grace not enforced", took)
	}

	start = time.Now()
	out, err = r.ExecCombined(context.Background(), NSNone,
		"sh", "-c", "sleep 10 >&2 & echo done")
	if !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("execCombined err=%v want ErrWaitDelay", err)
	}
	if !strings.Contains(out, "done") {
		t.Fatalf("combined out=%q", out)
	}
	if took := time.Since(start); took > cmdWaitDelay+3*time.Second {
		t.Fatalf("combined took %v — pipe-close grace not enforced", took)
	}
}

// TestExecBoundedBudgetReplacesTimeout: the per-call budget lands on
// the child ctx in place of Config.Timeout (the apiserver wedge
// gate's `timeout 90 systemctl restart`); budget <= 0 falls back to
// Config.Timeout.
func TestExecBoundedBudgetReplacesTimeout(t *testing.T) {
	var deadline time.Duration
	r := New(Config{
		HostRoot: "/",
		Timeout:  2 * time.Second,
		RunCmd: func(ctx context.Context, _ []string) (string, error) {
			dl, ok := ctx.Deadline()
			if !ok {
				return "", errors.New("ctx has no deadline — budget not applied")
			}
			deadline = time.Until(dl)
			return "", nil
		},
	})
	if _, err := r.ExecBounded(context.Background(), NSNone, 90*time.Second, "true"); err != nil {
		t.Fatal(err)
	}
	if deadline <= 0 || deadline > 90*time.Second {
		t.Fatalf("budget deadline=%v want (0, 90s]", deadline)
	}

	if _, err := r.ExecBounded(context.Background(), NSNone, 0, "true"); err != nil {
		t.Fatal(err)
	}
	if deadline <= 0 || deadline > 2*time.Second {
		t.Fatalf("fallback deadline=%v want (0, 2s]", deadline)
	}
}

// TestExecCombinedBoundedUsesCombinedSeam: the bounded+combined
// pairing — the combined seam carries the stderr evidence and the
// per-call budget bounds it.
func TestExecCombinedBoundedUsesCombinedSeam(t *testing.T) {
	combined := newFake()
	combined.On("journalctl -n 1 --no-pager",
		"File /var/log/journal/a.journal is corrupt, ignoring journal files.\n")
	stdoutOnlyCalled := false
	var deadline time.Duration
	r := New(Config{
		HostRoot: "/",
		Timeout:  2 * time.Second,
		RunCmd: func(context.Context, []string) (string, error) {
			stdoutOnlyCalled = true
			return "", nil
		},
		RunCmdCombined: func(ctx context.Context, argv []string) (string, error) {
			dl, ok := ctx.Deadline()
			if !ok {
				return "", errors.New("ctx has no deadline — budget not applied")
			}
			deadline = time.Until(dl)
			return combined.Run(ctx, argv)
		},
	})
	out, err := r.ExecCombinedBounded(context.Background(), NSNone,
		45*time.Second, "journalctl", "-n", "1", "--no-pager")
	if err != nil {
		t.Fatal(err)
	}
	if stdoutOnlyCalled {
		t.Fatal("ExecCombinedBounded must use the combined runner — stderr evidence is lost on Exec")
	}
	if !strings.Contains(out, "corrupt") {
		t.Fatalf("out=%q want the stderr corruption notice", out)
	}
	if deadline <= 0 || deadline > 45*time.Second {
		t.Fatalf("budget deadline=%v want (0, 45s]", deadline)
	}
}

// TestRunCombinedEnvReplacesEnvironment: the container-side combined
// helper must REPLACE the child environ with env (the
// NOTIFY_SOCKET/WATCHDOG_* scrub), inheriting only when env is nil.
func TestRunCombinedEnvReplacesEnvironment(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh on PATH")
	}
	t.Setenv("HOSTEXEC_SCRUB_PROBE", "inherited")

	out, err := RunCombinedEnv(context.Background(),
		[]string{"HOSTEXEC_SCRUB_PROBE=replaced"},
		"sh", "-c", `echo "$HOSTEXEC_SCRUB_PROBE"`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != "replaced" {
		t.Fatalf("out=%q want the replaced value — env must not merge", out)
	}

	out, err = RunCombinedEnv(context.Background(), nil,
		"sh", "-c", `echo "$HOSTEXEC_SCRUB_PROBE"`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != "inherited" {
		t.Fatalf("out=%q want the inherited value on nil env", out)
	}

	// Empty argv would index argv[0] — must error, not panic.
	if _, err := RunCombinedEnv(context.Background(), nil); err == nil {
		t.Fatal("empty argv want error")
	}
}

// TestRunSeparatesStreamsAndFeedsStdin: the container-side Run keeps
// stdout machine-clean (stderr in its own buffer) and feeds stdin —
// the psql/etcdctl parser contract.
func TestRunSeparatesStreamsAndFeedsStdin(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh on PATH")
	}
	stdout, stderr, err := Run(context.Background(),
		[]string{"sh", "-c", "echo out; echo err >&2"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(stdout) != "out" || strings.TrimSpace(stderr) != "err" {
		t.Fatalf("stdout=%q stderr=%q — streams must stay separate", stdout, stderr)
	}

	stdout, stderr, err = Run(context.Background(), []string{"cat"}, "piped stdin")
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "piped stdin" || stderr != "" {
		t.Fatalf("stdout=%q stderr=%q — stdin not fed", stdout, stderr)
	}

	if _, _, err := Run(context.Background(), nil, ""); err == nil {
		t.Fatal("empty argv want error")
	}
}

// TestRunEnvLayersOverInherited: RunEnv APPENDS env to the inherited
// environ — the PGPASSWORD-to-docker-exec channel (a secret off the
// argv, the rest of the daemon environment intact).
func TestRunEnvLayersOverInherited(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh on PATH")
	}
	t.Setenv("HOSTEXEC_BASE_PROBE", "kept")

	stdout, _, err := RunEnv(context.Background(),
		[]string{"HOSTEXEC_SECRET_PROBE=secret"},
		[]string{"sh", "-c", `echo "$HOSTEXEC_BASE_PROBE $HOSTEXEC_SECRET_PROBE"`}, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(stdout) != "kept secret" {
		t.Fatalf("out=%q want inherited+layered values", stdout)
	}

	if _, _, err := RunEnv(context.Background(), nil, nil, ""); err == nil {
		t.Fatal("empty argv want error")
	}
}

// TestCtxExpiryKillsWholeProcessTree: CommandContext's default cancel
// kills only the direct child — a grandchild (`sleep 30 &` behind a
// `wait`) survives and keeps running. newCmd puts the child in its own
// process group and SIGKILLs the GROUP at ctx expiry, so the whole
// tree dies. The grandchild announces its pid on stdout; after Run
// returns on the timeout, that pid must be gone from /proc.
func TestCtxExpiryKillsWholeProcessTree(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh on PATH")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	out, err := RunCombined(ctx, "sh", "-c", `sleep 30 & echo $!; wait`)
	if err == nil {
		t.Fatal("expected the ctx deadline to fail the run")
	}
	pid := strings.TrimSpace(out)
	if pid == "" {
		t.Fatalf("grandchild pid missing from output %q", out)
	}
	if _, convErr := strconv.Atoi(pid); convErr != nil {
		t.Fatalf("output %q does not carry the grandchild pid: %v", out, convErr)
	}

	// SIGKILL delivery to a group member takes a moment after the
	// kill lands on the leader — poll briefly before declaring the
	// grandchild survived.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, serr := os.Stat("/proc/" + pid + "/cmdline"); os.IsNotExist(serr) {
			return // group kill took the grandchild with the child
		}
		if time.Now().After(deadline) {
			t.Fatalf("grandchild pid %s survived the group kill", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestCappedBufferKeepsHeadAcrossBoundary: the cap keeps the HEAD of
// the stream — a Write straddling the cap boundary lands only its
// fitting prefix (p[:rem]) and the rest is drained (reported as
// written so the child never blocks), while a Write past the cap
// adds nothing and never grows the buffer.
func TestCappedBufferKeepsHeadAcrossBoundary(t *testing.T) {
	var b cappedBuffer
	first := bytes.Repeat([]byte("a"), maxCmdOutputBytes-10)
	if n, err := b.Write(first); err != nil || n != len(first) {
		t.Fatalf("first write n=%d err=%v", n, err)
	}
	// Straddling write: only 10 bytes fit; the remaining 5 are
	// dropped but counted.
	straddle := bytes.Repeat([]byte("b"), 15)
	if n, err := b.Write(straddle); err != nil || n != len(straddle) {
		t.Fatalf("straddle write n=%d err=%v (must report the full drain)", n, err)
	}
	got := b.String()
	if len(got) != maxCmdOutputBytes {
		t.Fatalf("buffer len=%d, want exactly the cap %d", len(got), maxCmdOutputBytes)
	}
	if !strings.HasPrefix(got, string(first)) {
		t.Fatal("head prefix lost")
	}
	if !strings.HasSuffix(got, "bbbbbbbbbb") {
		t.Fatal("straddling write must land its fitting head (p[:rem])")
	}
	// Past the cap: nothing added, buffer stable.
	after := b.String()
	if _, err := b.Write(bytes.Repeat([]byte("c"), 1000)); err != nil {
		t.Fatalf("past-cap write err=%v", err)
	}
	if b.String() != after {
		t.Fatal("past-cap write must not change the retained buffer")
	}
}
