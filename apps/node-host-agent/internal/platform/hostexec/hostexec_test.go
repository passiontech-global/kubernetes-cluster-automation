package hostexec

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// fake records every argv the runner ran and serves canned replies
// keyed on a substring match of the joined command line.
type fake struct {
	cmds  [][]string
	reply map[string]string // substring → stdout
	fail  map[string]bool   // substring → error
}

func (f *fake) run(_ context.Context, argv []string) (string, error) {
	f.cmds = append(f.cmds, argv)
	joined := strings.Join(argv, " ")
	for k := range f.fail {
		if strings.Contains(joined, k) {
			return "", errors.New("exit 3")
		}
	}
	for k, v := range f.reply {
		if strings.Contains(joined, k) {
			return v, nil
		}
	}
	return "", nil
}

func newFake() *fake {
	return &fake{reply: map[string]string{}, fail: map[string]bool{}}
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
			r := New(Config{HostRoot: "/host", RunCmd: f.run})
			if _, err := r.Exec(context.Background(), tc.ns,
				"ip", "link", "show"); err != nil {
				t.Fatal(err)
			}
			if len(f.cmds) != 1 || strings.Join(f.cmds[0], " ") != tc.want {
				t.Fatalf("argv=%v want [%s]", f.cmds, tc.want)
			}
		})
	}
}

// TestArgvPlainOnHost: HostRoot "/" means the process already lives
// in the host namespaces — no nsenter whatever the flags ask for.
func TestArgvPlainOnHost(t *testing.T) {
	f := newFake()
	r := New(Config{HostRoot: "/", RunCmd: f.run})
	for _, ns := range []NS{NSAll, NSNet, NSMountNet, NSNone} {
		if _, err := r.Exec(context.Background(), ns,
			"systemctl", "daemon-reload"); err != nil {
			t.Fatal(err)
		}
	}
	want := "systemctl daemon-reload"
	if len(f.cmds) != 4 {
		t.Fatalf("cmds=%v", f.cmds)
	}
	for i, cmd := range f.cmds {
		if got := strings.Join(cmd, " "); got != want {
			t.Fatalf("cmd[%d]=%q want %q — HostRoot / must never wrap", i, got, want)
		}
	}
}

// TestArgvEmptyHostRootDefaultsContainerized: an unset HostRoot
// takes the DaemonSet mount default — the wrap still applies.
func TestArgvEmptyHostRootDefaultsContainerized(t *testing.T) {
	f := newFake()
	r := New(Config{RunCmd: f.run})
	if _, err := r.Exec(context.Background(), NSAll, "true"); err != nil {
		t.Fatal(err)
	}
	want := "nsenter -t 1 -m -u -i -n -p -- true"
	if len(f.cmds) != 1 || strings.Join(f.cmds[0], " ") != want {
		t.Fatalf("argv=%v want [%s]", f.cmds, want)
	}
}

// TestExecCombinedUsesCombinedSeam: ExecCombined must route through
// RunCmdCombined — probes whose evidence lives on stderr (journald's
// corrupt-file notices) go dead on the stdout-only seam. The same
// nsenter wrap applies.
func TestExecCombinedUsesCombinedSeam(t *testing.T) {
	combined := newFake()
	combined.reply["journalctl -n 1 --no-pager"] =
		"File /var/log/journal/a.journal is corrupt, ignoring journal files.\n"
	stdoutOnlyCalled := false
	r := New(Config{
		HostRoot: "/host",
		RunCmd: func(context.Context, []string) (string, error) {
			stdoutOnlyCalled = true
			return "", nil
		},
		RunCmdCombined: combined.run,
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
	if len(combined.cmds) != 1 || strings.Join(combined.cmds[0], " ") != want {
		t.Fatalf("argv=%v want [%s]", combined.cmds, want)
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
