// exec_test.go — the host-command/env plumbing: the NOTIFY_SOCKET/
// WATCHDOG_* scrub in both forms, the nil-tolerant systemd-client
// wrapper the HostExecFn default routes through, the sd_notify
// datagram sender's NotifyFn default, and the named host commands
// over the one HostExecFn seam (argv + budget + munging contract).
package cdeps

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostexec"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/subframe"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/systemd"
)

func TestScrubSystemdEnv(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"NOTIFY_SOCKET=/run/notify.sock",
		"NOTIFY_SOCKETX=keepme", // prefix-only match must not drop
		"WATCHDOG_PID=5",
		"WATCHDOG_USEC=1000",
		"HOME=/root",
	}
	want := []string{"PATH=/usr/bin", "NOTIFY_SOCKETX=keepme", "HOME=/root"}
	if got := ScrubSystemdEnv(env); !reflect.DeepEqual(got, want) {
		t.Fatalf("ScrubSystemdEnv=%v want %v", got, want)
	}
	// Empty/nil environments must not panic.
	if got := ScrubSystemdEnv(nil); len(got) != 0 {
		t.Fatalf("ScrubSystemdEnv(nil)=%v want empty", got)
	}
}

// fakeSeams records which hostexec seam ran and with what argv.
type fakeSeams struct {
	runArgv  []string
	combArgv []string
	runOut   string
	combOut  string
	runErr   error
	combErr  error
}

func newFakeSystemd(fs *fakeSeams) *systemd.Client {
	return systemd.New(hostexec.Config{
		HostRoot: "/", // unwrapped — the argv must be seen verbatim
		RunCmd: func(_ context.Context, argv []string) (string, error) {
			fs.runArgv = argv
			return fs.runOut, fs.runErr
		},
		RunCmdCombined: func(_ context.Context, argv []string) (string, error) {
			fs.combArgv = argv
			return fs.combOut, fs.combErr
		},
	})
}

func TestHostExecCtxBoundedNilClient(t *testing.T) {
	_, err := hostExecCtxBounded(context.Background(), nil,
		false, 0, "systemctl", "is-active", "x")
	if err == nil || !strings.Contains(err.Error(), "no systemd client wired") {
		t.Fatalf("nil client err=%v want 'no systemd client wired'", err)
	}
}

func TestHostExecCtxBoundedSelectsSeam(t *testing.T) {
	fs := &fakeSeams{runOut: "stdout\n", combOut: "combined\n"}
	sd := newFakeSystemd(fs)

	out, err := hostExecCtxBounded(context.Background(), sd,
		false, 0, "journalctl", "-n", "1")
	if err != nil || out != "stdout\n" {
		t.Fatalf("combined=false out=%q err=%v", out, err)
	}
	if fs.combArgv != nil {
		t.Fatalf("combined=false ran the combined seam: %v", fs.combArgv)
	}
	want := []string{"journalctl", "-n", "1"}
	if !reflect.DeepEqual(fs.runArgv, want) {
		t.Fatalf("argv=%v want %v", fs.runArgv, want)
	}

	fs.combArgv = nil
	out, err = hostExecCtxBounded(context.Background(), sd,
		true, 0, "journalctl", "-u", "u")
	if err != nil || out != "combined\n" {
		t.Fatalf("combined=true out=%q err=%v", out, err)
	}
	if fs.runArgv == nil || !reflect.DeepEqual(fs.combArgv,
		[]string{"journalctl", "-u", "u"}) {
		t.Fatalf("combined=true argv=%v", fs.combArgv)
	}
}

// execRecorder captures the HostExecFn seam calls the named
// host-command helpers make.
type execRecorder struct {
	combined bool
	budget   time.Duration
	name     string
	args     []string
	out      string
	err      error
}

func (r *execRecorder) fn(_ context.Context, combined bool,
	budget time.Duration, name string, args ...string) (string, error) {
	r.combined, r.budget, r.name, r.args = combined, budget, name, args
	return r.out, r.err
}

func TestDepRestart(t *testing.T) {
	rec := &execRecorder{}
	d := &Deps{Cfg: Config{}}
	d.Cfg.HostExecFn = rec.fn

	if err := d.Restart(context.Background(), "k0scontroller.service"); err != nil {
		t.Fatalf("Restart err=%v", err)
	}
	if !rec.combined || rec.name != "systemctl" ||
		!reflect.DeepEqual(rec.args, []string{"restart", "k0scontroller.service"}) {
		t.Fatalf("seam call combined=%v name=%s args=%v",
			rec.combined, rec.name, rec.args)
	}
	if rec.budget != defaultRestartBudget {
		t.Fatalf("restart budget=%s want %s", rec.budget, defaultRestartBudget)
	}

	rec.err = errors.New("boom")
	if err := d.Restart(context.Background(), "u"); err == nil {
		t.Fatal("Restart swallowed the exec error")
	}
}

func TestDepUnitProp(t *testing.T) {
	rec := &execRecorder{out: "  active\n"}
	d := &Deps{Cfg: Config{}}
	d.Cfg.HostExecFn = rec.fn

	got, err := d.UnitProp(context.Background(), "u.service", "MainPID")
	if err != nil || got != "active" {
		t.Fatalf("UnitProp=%q err=%v", got, err)
	}
	if rec.combined || rec.budget != 0 || rec.name != "systemctl" ||
		!reflect.DeepEqual(rec.args,
			[]string{"show", "u.service", "-p", "MainPID", "--value"}) {
		t.Fatalf("seam call combined=%v budget=%s args=%v",
			rec.combined, rec.budget, rec.args)
	}

	rec.err = errors.New("boom")
	if _, err := d.UnitProp(context.Background(), "u", "MainPID"); err == nil {
		t.Fatal("UnitProp swallowed the exec error")
	}
}

func TestDepUnitActiveState(t *testing.T) {
	d := &Deps{Cfg: Config{}}
	// is-active exits non-zero for inactive — the verdict is the
	// OUTPUT, the error is folded away.
	rec := &execRecorder{out: "inactive\n", err: errors.New("exit 3")}
	d.Cfg.HostExecFn = rec.fn
	if got := d.UnitActiveState(context.Background(), "u"); got != "inactive" {
		t.Fatalf("UnitActiveState=%q want inactive", got)
	}
	if rec.combined || rec.name != "systemctl" ||
		!reflect.DeepEqual(rec.args, []string{"is-active", "u"}) {
		t.Fatalf("seam call combined=%v args=%v", rec.combined, rec.args)
	}

	// A dead probe reads as "" the same way an absent unit does.
	rec2 := &execRecorder{out: "", err: errors.New("dbus down")}
	d.Cfg.HostExecFn = rec2.fn
	if got := d.UnitActiveState(context.Background(), "u"); got != "" {
		t.Fatalf("UnitActiveState=%q want empty on exec failure", got)
	}
}

func TestDepSSKill(t *testing.T) {
	var gotPort uint16
	var calls int
	wantErr := errors.New("sock_diag destroy: permission denied")
	d := &Deps{Cfg: Config{}}
	d.Cfg.SockDestroyFn = func(port uint16) (int, error) {
		calls++
		gotPort = port
		return 0, wantErr
	}

	// The seam error surfaces verbatim — SSKill adds no wrapping.
	if err := d.SSKill(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("SSKill err=%v want %v", err, wantErr)
	}
	if calls != 1 || gotPort != 6443 {
		t.Fatalf("SockDestroyFn calls=%d port=%d, want 1 call on 6443",
			calls, gotPort)
	}

	// Success path: the killed count is informational only.
	d.Cfg.SockDestroyFn = func(uint16) (int, error) { return 3, nil }
	if err := d.SSKill(context.Background()); err != nil {
		t.Fatalf("SSKill err=%v", err)
	}
}

func TestSdNotify(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "notify.sock")
	addr := &net.UnixAddr{Name: sock, Net: "unixgram"}
	srv, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	if err := sdNotify(sock, "WATCHDOG=1"); err != nil {
		t.Fatalf("sdNotify err=%v", err)
	}
	buf := make([]byte, 64)
	n, _, rerr := srv.ReadFromUnix(buf)
	if rerr != nil {
		t.Fatalf("datagram read err=%v", rerr)
	}
	if string(buf[:n]) != "WATCHDOG=1" {
		t.Fatalf("datagram=%q want WATCHDOG=1", buf[:n])
	}

	// A dead socket must error, never panic.
	if err := sdNotify(filepath.Join(t.TempDir(), "gone.sock"), "WATCHDOG=1"); err == nil {
		t.Fatal("sdNotify to an unbound socket returned nil")
	}
}

// The default HostExecFn routes through hostExecCtxBounded — argv
// reaches the systemd client verbatim: the env scrub lives inside
// the client's runners (Config.ScrubSystemdEnv), which the fake
// transport stands in for at the exec seam.
func TestDefaultHostExecFnPassesArgvVerbatim(t *testing.T) {
	fs := &fakeSeams{runOut: "ok"}
	c := Config{Base: subframe.Base{Systemd: newFakeSystemd(fs)}}
	c.ApplyDefaults()
	out, err := c.HostExecFn(context.Background(), false, 0,
		"systemctl", "is-active", "u")
	if err != nil || out != "ok" {
		t.Fatalf("HostExecFn out=%q err=%v", out, err)
	}
	want := []string{"systemctl", "is-active", "u"}
	if !reflect.DeepEqual(fs.runArgv, want) {
		t.Fatalf("argv=%v want %v", fs.runArgv, want)
	}
}
