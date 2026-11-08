// tasks_test.go — the shared /proc + containerd task helpers: the
// probe-series loop, liveness/age/cmdline/stat reads over the fake
// ProcDir, the raw state-dir probe, and the task-map build with its
// completeness + suspect-log contract.
package wdeps_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
)

// TestProbeHTTPSeries — retry loop: first success returns nil,
// failures retry up to attempts, an exhausted series returns the
// last error, and a cancelled ctx aborts between attempts.
func TestProbeHTTPSeries(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	url := "http://127.0.0.1:10248/healthz"

	// First-attempt success: exactly one probe.
	calls := 0
	e.D.Cfg.Seams.Probe.ProbeHTTP = func(context.Context, string, time.Duration) error {
		calls++
		return nil
	}
	if err := e.D.ProbeHTTPSeries(ctx, url, 3, 10*time.Millisecond, 0); err != nil || calls != 1 {
		t.Fatalf("err=%v calls=%d want nil/1", err, calls)
	}

	// Second-attempt success.
	calls = 0
	e.D.Cfg.Seams.Probe.ProbeHTTP = func(context.Context, string, time.Duration) error {
		calls++
		if calls == 1 {
			return errors.New("blip")
		}
		return nil
	}
	if err := e.D.ProbeHTTPSeries(ctx, url, 3, 10*time.Millisecond, 0); err != nil || calls != 2 {
		t.Fatalf("err=%v calls=%d want nil/2", err, calls)
	}

	// Exhausted attempts: the last error is the verdict.
	calls = 0
	last := errors.New("still down")
	e.D.Cfg.Seams.Probe.ProbeHTTP = func(context.Context, string, time.Duration) error {
		calls++
		return last
	}
	if err := e.D.ProbeHTTPSeries(ctx, url, 3, 10*time.Millisecond, 0); !errors.Is(err, last) || calls != 3 {
		t.Fatalf("err=%v calls=%d want %v/3", err, calls, last)
	}

	// ctx cancelled between attempts: the gap wait observes it.
	cctx, cancel := context.WithCancel(ctx)
	e.D.Cfg.Seams.Probe.ProbeHTTP = func(context.Context, string, time.Duration) error {
		cancel()
		return errors.New("down")
	}
	if err := e.D.ProbeHTTPSeries(cctx, url, 3, 10*time.Millisecond, time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want context.Canceled", err)
	}
}

// TestPidLive — liveness rides the KillFn seam: registered pids are
// alive, zombies and unknown pids are not, and a pid whose stat is
// unreadable counts live (fail toward not-killing).
func TestPidLive(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 1001, "S", "", "")
	if !e.D.PidLive(1001) {
		t.Fatal("live pid reported dead")
	}
	e.MkProc(t, 1002, "Z", "", "")
	if e.D.PidLive(1002) {
		t.Fatal("zombie reported live")
	}
	if e.D.PidLive(9999) {
		t.Fatal("unknown pid reported live")
	}
	if e.D.PidLive(0) || e.D.PidLive(-1) {
		t.Fatal("non-pid reported live")
	}
	// kill -0 ok but no stat file → live on uncertainty.
	e.Live[1003] = true
	if !e.D.PidLive(1003) {
		t.Fatal("stat-less pid must read live")
	}
}

// TestProcAge — the pid dir mtime against the Clock seam.
func TestProcAge(t *testing.T) {
	e := fixture(t)
	pid := 1005
	e.MkProc(t, pid, "S", "", "")
	born := time.Unix(1_800_000_000, 0)
	pidDir := filepath.Join(e.ProcDir, strconv.Itoa(pid))
	if err := os.Chtimes(pidDir, born, born); err != nil {
		t.Fatal(err)
	}
	e.Now = born.Add(5 * time.Minute)
	got := e.D.ProcAge(pid)
	if got < 5*time.Minute-time.Second || got > 5*time.Minute+time.Second {
		t.Fatalf("age=%v want ~5m", got)
	}
	if e.D.ProcAge(9999) != 0 {
		t.Fatal("missing pid must age 0")
	}
}

// TestPidsWithCmdline — the pkill -f replacement over the caller's
// pid snapshot; the joined-argv match must span NUL-separated args.
func TestPidsWithCmdline(t *testing.T) {
	e := fixture(t)
	e.MkProc(t, 2001, "S", "nginx: worker process\x00", "")
	e.MkProc(t, 2002, "S", "kube-apiserver\x00--flag\x00", "")
	got := e.D.PidsWithCmdline("nginx", []int{2001, 2002, 3000})
	if len(got) != 1 || got[0] != 2001 {
		t.Fatalf("pids=%v want [2001]", got)
	}
	// The join is with spaces, so a multi-arg needle matches.
	if got := e.D.PidsWithCmdline("apiserver --flag", []int{2002}); len(got) != 1 {
		t.Fatalf("joined match failed: %v", got)
	}
	if got := e.D.PidsWithCmdline("nothing", []int{2001, 2002}); len(got) != 0 {
		t.Fatalf("unexpected matches: %v", got)
	}
}

// TestProcStatStatePPID — state+ppid parsed after the LAST ')'
// (comm with spaces/parens), with the failure shapes.
func TestProcStatStatePPID(t *testing.T) {
	e := fixture(t)
	// The fixture's MkProc shape (ppid field 0) and a direct write
	// with a real parent both parse after the fields' contract.
	e.MkProc(t, 2100, "S", "", "")
	if state, ppid, ok := e.D.ProcStatStatePPID(2100); !ok || state != "S" || ppid != 0 {
		t.Fatalf("state=%q ppid=%d ok=%v", state, ppid, ok)
	}
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "2104", "stat"),
		"2104 (fakeproc) S 1 0 0\n")
	if state, ppid, ok := e.D.ProcStatStatePPID(2104); !ok || state != "S" || ppid != 1 {
		t.Fatalf("state=%q ppid=%d ok=%v", state, ppid, ok)
	}
	// comm holding parens and spaces — fields come after the last ')'.
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "2101", "stat"),
		"2101 (a (b) c) R 7 0 0\n")
	if state, ppid, ok := e.D.ProcStatStatePPID(2101); !ok || state != "R" || ppid != 7 {
		t.Fatalf("parens comm: state=%q ppid=%d ok=%v", state, ppid, ok)
	}
	if _, _, ok := e.D.ProcStatStatePPID(9999); ok {
		t.Fatal("missing pid must not parse")
	}
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "2102", "stat"), "2102 (x) Z -5 0 0\n")
	if _, _, ok := e.D.ProcStatStatePPID(2102); ok {
		t.Fatal("negative ppid must not parse")
	}
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "2105", "stat"), "2105 (x) S xx 0 0\n")
	if _, _, ok := e.D.ProcStatStatePPID(2105); ok {
		t.Fatal("non-numeric ppid must not parse")
	}
	wdepstest.WriteFile(t, filepath.Join(e.ProcDir, "2103", "stat"), "2103 (x)")
	if _, _, ok := e.D.ProcStatStatePPID(2103); ok {
		t.Fatal("field-less stat must not parse")
	}
}

// TestStateFileExists — RAW filename probes in the state dir (not
// state-* latches).
func TestStateFileExists(t *testing.T) {
	e := fixture(t)
	if e.D.StateFileExists("wedged-seen-x") {
		t.Fatal("absent marker reported present")
	}
	wdepstest.WriteFile(t, filepath.Join(e.StateDir, "wedged-seen-x"), "1\n")
	if !e.D.StateFileExists("wedged-seen-x") {
		t.Fatal("present marker reported absent")
	}
}

// TestBuildTaskMap — task dirs group by pod UID from both roots;
// unreadable runtime roots mark the map incomplete (fail closed for
// force-delete) while an absent sandbox root stays complete.
func TestBuildTaskMap(t *testing.T) {
	e := fixture(t)
	e.Live[300] = true
	e.Live[303] = true
	e.MkTask(t, wdepstest.UIDA, "app", 300)     // live init pid
	e.MkTask(t, wdepstest.UIDB, "sidecar", 301) // dead init pid
	wdepstest.WriteFile(t, filepath.Join(e.CtrDir, "bogus"), "not a dir")
	wdepstest.WriteFile(t, filepath.Join(e.CtrDir, "task-nocfg", "init.pid"), "302\n")
	// A sandbox-controller shim task in the second root.
	sbDir := filepath.Join(e.SbDir, "sb-"+wdepstest.UIDC[:8])
	wdepstest.WriteFile(t, filepath.Join(sbDir, "config.json"),
		fmt.Sprintf(`{"annotations":{"io.kubernetes.pod.uid":"%s","io.kubernetes.container.name":"POD"}}`,
			wdepstest.UIDC))
	wdepstest.WriteFile(t, filepath.Join(sbDir, "init.pid"), "303\n")
	// Annotation variations: uid without a container name → Name "",
	// a config without the uid annotation is not task evidence, and
	// a config without init.pid carries no pid.
	wdepstest.WriteFile(t, filepath.Join(e.CtrDir, "task-nocname", "config.json"),
		fmt.Sprintf(`{"annotations":{"io.kubernetes.pod.uid":"%s"}}`, wdepstest.UIDD))
	wdepstest.WriteFile(t, filepath.Join(e.CtrDir, "task-nouid", "config.json"), `{"no":"annotations"}`)
	wdepstest.WriteFile(t, filepath.Join(e.CtrDir, "task-nopid", "config.json"),
		fmt.Sprintf(`{"annotations":{"io.kubernetes.pod.uid":"%s","io.kubernetes.container.name":"x"}}`,
			wdepstest.UIDE))

	m, complete := e.D.BuildTaskMap()
	if !complete {
		t.Fatal("map incomplete on healthy roots")
	}
	if got := len(m[wdepstest.UIDA]); got != 1 {
		t.Fatalf("uidA tasks=%d", got)
	}
	a := m[wdepstest.UIDA][0]
	if a.Name != "app" || a.PID != 300 || !a.Live {
		t.Fatalf("uidA task=%+v", a)
	}
	if b := m[wdepstest.UIDB][0]; b.Live || b.PID != 301 {
		t.Fatalf("uidB task=%+v", b)
	}
	if c := m[wdepstest.UIDC][0]; c.Name != "POD" || !c.Live || c.PID != 303 {
		t.Fatalf("uidC task=%+v", c)
	}
	if d := m[wdepstest.UIDD][0]; d.Name != "" || d.PID != 0 || d.Live {
		t.Fatalf("uidD task=%+v want nameless pid-less dead", d)
	}
	if p := m[wdepstest.UIDE][0]; p.Name != "x" || p.PID != 0 || p.Live {
		t.Fatalf("uidE task=%+v want no init.pid", p)
	}
	if _, seen := m["no-annotations-task"]; seen {
		t.Fatal("uid-less config must not group")
	}
	if n := e.D.TaskMapBuilds; n != 1 {
		t.Fatalf("TaskMapBuilds=%d want 1", n)
	}
	e.D.BuildTaskMap()
	if e.D.TaskMapBuilds != 2 {
		t.Fatalf("TaskMapBuilds after 2 calls=%d want 2", e.D.TaskMapBuilds)
	}

	// Runtime root unreadable → incomplete, and the map claims
	// nothing. An ENOENT runtime root is suspect for force-delete
	// (the root must exist on a live worker) but stays quiet — only
	// real IO/permission errors log.
	e2 := fixture(t)
	if err := os.RemoveAll(e2.CtrDir); err != nil {
		t.Fatal(err)
	}
	if _, complete := e2.D.BuildTaskMap(); complete {
		t.Fatal("missing runtime root must be incomplete")
	}
	if strings.Contains(e2.LogLines(t), "unreadable") {
		t.Fatalf("ENOENT must not log:\n%s", e2.LogLines(t))
	}

	// A permission/IO-class error (the root replaced by a plain
	// file → ENOTDIR) marks the map incomplete AND appends the
	// suspect line.
	e3 := fixture(t)
	if err := os.RemoveAll(e3.CtrDir); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, e3.CtrDir, "a file, not a dir")
	if _, complete := e3.D.BuildTaskMap(); complete {
		t.Fatal("unreadable runtime root must be incomplete")
	}
	if !strings.Contains(e3.LogLines(t), "unreadable") {
		t.Fatalf("missing suspect line:\n%s", e3.LogLines(t))
	}

	// Absent sandbox root is normal (no shim dir layout) — complete.
	e4 := fixture(t)
	if err := os.RemoveAll(e4.SbDir); err != nil {
		t.Fatal(err)
	}
	if _, complete := e4.D.BuildTaskMap(); !complete {
		t.Fatal("absent sandbox root must stay complete")
	}
}

// TestCountLive — the force-delete precondition counts live tasks.
func TestCountLive(t *testing.T) {
	cases := []struct {
		tasks []wdeps.CtrTask
		want  int
	}{
		{nil, 0},
		{[]wdeps.CtrTask{{Live: true}, {Live: false}, {Live: true}}, 2},
		{[]wdeps.CtrTask{{Live: false}}, 0},
	}
	for i, tc := range cases {
		if got := wdeps.CountLive(tc.tasks); got != tc.want {
			t.Fatalf("case %d: got %d want %d", i, got, tc.want)
		}
	}
}
