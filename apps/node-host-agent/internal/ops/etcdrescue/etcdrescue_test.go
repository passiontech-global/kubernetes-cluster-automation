package etcdrescue

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
)

// recordedCall is one CmdRunner invocation (or a fake-temp-etcd
// lifecycle marker) — ordering assertions read the sequence.
type recordedCall struct {
	name string
	args string
}

// fakeEtcd answers etcdctl/systemctl calls like a scripted etcd.
type fakeEtcd struct {
	calls []recordedCall

	// statusJSON is a queue: each `endpoint status -w json` pops the
	// head; the last entry repeats once the queue drains.
	statusJSON []string
	alarms     string
	healthy    bool

	failCompact       bool
	failOnlineDefrag  bool // only the --command-timeout=120s call
	failOfflineDefrag bool // only the --command-timeout=180s call
	failDisarm        bool
	failPut           bool
	failDel           bool
	failStart         bool // systemctl start errors

	// onCall fires before responding — tests use it e.g. to remove
	// the fake /proc/<pid> dir when `systemctl stop` lands.
	onCall func(name string, args []string)
}

func (f *fakeEtcd) run(_ context.Context, name string,
	args ...string) ([]byte, error) {
	joined := strings.Join(args, " ")
	f.calls = append(f.calls, recordedCall{name: name, args: joined})
	if f.onCall != nil {
		f.onCall(name, args)
	}
	switch {
	case name == "systemctl":
		if len(args) > 0 && args[0] == "start" && f.failStart {
			return nil, errors.New("fake: start failed")
		}
		return nil, nil
	case strings.Contains(joined, "endpoint status") &&
		strings.Contains(joined, "-w json"):
		if len(f.statusJSON) == 0 {
			return nil, errors.New("fake: no canned status")
		}
		s := f.statusJSON[0]
		if len(f.statusJSON) > 1 {
			f.statusJSON = f.statusJSON[1:]
		}
		return []byte(s), nil
	case strings.Contains(joined, "endpoint status"):
		return []byte("+------------+---------+\n|  fake table  |\n"), nil
	case strings.Contains(joined, "endpoint health"):
		if !f.healthy {
			return nil, errors.New("fake: unhealthy")
		}
		return []byte("https://127.0.0.1:2379 is healthy\n"), nil
	case strings.Contains(joined, "alarm disarm"):
		if f.failDisarm {
			return nil, errors.New("fake: disarm failed")
		}
		return nil, nil
	case strings.Contains(joined, "alarm list"):
		return []byte(f.alarms), nil
	case strings.Contains(joined, "compact"):
		if f.failCompact {
			return nil, errors.New(
				"mvcc: required revision has been compacted")
		}
		return []byte("compacted revision\n"), nil
	case strings.Contains(joined, "defrag"):
		fail := f.failOnlineDefrag &&
			strings.Contains(joined, "--command-timeout=120s") ||
			f.failOfflineDefrag &&
				strings.Contains(joined, "--command-timeout=180s")
		if fail {
			return nil, errors.New("fake: defrag failed")
		}
		return []byte("Finished defragmenting etcd member\n"), nil
	case strings.Contains(joined, "put "+canaryKey):
		if f.failPut {
			return nil, errors.New("mvcc: database space exceeded")
		}
		return []byte("OK\n"), nil
	case strings.Contains(joined, "del "+canaryKey):
		if f.failDel {
			return nil, errors.New("fake: del failed")
		}
		return []byte("1\n"), nil
	}
	return nil, fmt.Errorf("fake: unexpected call: %s %s", name, joined)
}

// fakeStarter records the standalone-etcd spawn and returns a fake
// handle that logs its kill into the same call sequence.
type fakeStarter struct {
	calls  *[]recordedCall
	bin    string
	args   []string
	log    string
	err    error // injected Start failure
	killed bool
}

func (s *fakeStarter) start(_ context.Context, bin string,
	args []string, logPath string) (TempEtcd, error) {
	s.bin, s.args, s.log = bin, args, logPath
	*s.calls = append(*s.calls, recordedCall{
		name: "temp-etcd:start",
		args: strings.Join(append([]string{bin}, args...), " "),
	})
	if s.err != nil {
		return nil, s.err
	}
	return s, nil
}

func (s *fakeStarter) Kill() error {
	*s.calls = append(*s.calls, recordedCall{name: "temp-etcd:kill"})
	s.killed = true
	return nil
}

func (s *fakeStarter) Wait() error { return nil }

func statusJSON(rev, dbSize, inUse int64) string {
	return fmt.Sprintf(`[{"Endpoint":"https://127.0.0.1:2379",`+
		`"Status":{"header":{"revision":%d},"dbSize":%d,"dbSizeInUse":%d}}]`,
		rev, dbSize, inUse)
}

// fakeProc lays out a fake /proc: pid -> NUL-joined cmdline.
func fakeProc(t *testing.T, cmdlines map[int]string) string {
	t.Helper()
	root := t.TempDir()
	for pid, cl := range cmdlines {
		dir := filepath.Join(root, strconv.Itoa(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cmdline"),
			[]byte(cl), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const etcdProcCmdline = "/fake/k0s/bin/etcd\x00" +
	"--data-dir=/fake/k0s/etcd\x00" +
	"--quota-backend-bytes=8589934592\x00" +
	"--listen-client-urls=https://10.0.0.1:2379\x00" +
	"--advertise-client-urls=https://10.0.0.1:2379\x00"

// testRig wires a Config against the fakes; procRoot may be "" (no
// etcd process → findEtcdProcess fails).
func testRig(f *fakeEtcd, starter *fakeStarter, procRoot string) Config {
	return Config{
		K0sDir:        "/fake/k0s",
		Endpoint:      "https://127.0.0.1:2379",
		ProcRoot:      procRoot,
		CmdRunner:     f.run,
		StartTempEtcd: starter.start,
		SleepFn:       func(time.Duration) {},
	}
}

// callIndex finds the first recorded call whose name+args contains
// substr (-1 when absent).
func callIndex(calls []recordedCall, substr string) int {
	for i, c := range calls {
		if strings.Contains(c.name+" "+c.args, substr) {
			return i
		}
	}
	return -1
}

func TestParseStatusJSON(t *testing.T) {
	st, err := parseStatusJSON([]byte(statusJSON(1234, 2048, 1024)))
	if err != nil {
		t.Fatalf("parseStatusJSON err=%v want nil", err)
	}
	if st.Revision != 1234 || st.DBSize != 2048 || st.DBSizeInUse != 1024 {
		t.Fatalf("st=%+v want rev=1234 db=2048 inUse=1024", st)
	}
	if _, err := parseStatusJSON([]byte("not json")); err == nil {
		t.Fatal("parseStatusJSON(bad) err=nil want error")
	}
	if _, err := parseStatusJSON([]byte("[]")); err == nil {
		t.Fatal("parseStatusJSON([]) err=nil want error")
	}
}

func TestMatchEtcdCmdline(t *testing.T) {
	bin := "/fake/k0s/bin/etcd"
	if !matchEtcdCmdline([]byte(bin+"\x00--data-dir=/x\x00"), bin) {
		t.Fatal("exact etcd cmdline not matched")
	}
	if !matchEtcdCmdline([]byte(bin), bin) {
		t.Fatal("bare etcd cmdline not matched")
	}
	// Prefix alone must NOT match etcdctl — the script's pgrep -f
	// could hit it, the Go port must not.
	if matchEtcdCmdline([]byte(bin+"ctl\x00endpoint\x00status\x00"), bin) {
		t.Fatal("etcdctl cmdline wrongly matched as etcd")
	}
	if matchEtcdCmdline([]byte("/usr/bin/etcd\x00"), bin) {
		t.Fatal("foreign etcd path wrongly matched")
	}
}

func TestRunOnlineDefragSuccess(t *testing.T) {
	f := &fakeEtcd{
		healthy: true,
		statusJSON: []string{
			statusJSON(100, 1000, 800), // before
			statusJSON(100, 850, 800),  // post-defrag: 850 <= 1600
			statusJSON(100, 850, 800),  // [4/6] display
		},
	}
	starter := &fakeStarter{calls: &f.calls}
	var out strings.Builder
	err := Run(context.Background(), testRig(f, starter, ""), &out)
	if err != nil {
		t.Fatalf("Run err=%v want nil:\n%s", err, out.String())
	}
	// No offline machinery: no systemctl, no temp etcd.
	if i := callIndex(f.calls, "systemctl"); i >= 0 {
		t.Fatalf("unexpected systemctl call %d:\n%v", i, f.calls)
	}
	if i := callIndex(f.calls, "temp-etcd"); i >= 0 {
		t.Fatalf("unexpected temp-etcd call %d:\n%v", i, f.calls)
	}
	for _, want := range []string{
		"BEFORE RESCUE", "compact to revision 100",
		"trying online defrag", "alarm disarm", "WRITE OK",
		"AFTER RESCUE", "DONE",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output missing %q:\n%s", want, out.String())
		}
	}
	// Command ordering: compact -> online defrag -> disarm -> canary.
	seq := []string{"compact", "--command-timeout=120s defrag",
		"alarm disarm", "put " + canaryKey, "del " + canaryKey}
	prev := -1
	for _, s := range seq {
		i := callIndex(f.calls, s)
		if i < 0 || i <= prev {
			t.Fatalf("call %q at %d — want after %d:\n%v", s, i, prev, f.calls)
		}
		prev = i
	}
}

func TestRunCompactErrorTolerated(t *testing.T) {
	f := &fakeEtcd{
		healthy:     true,
		failCompact: true,
		statusJSON:  []string{statusJSON(100, 100, 90)},
	}
	starter := &fakeStarter{calls: &f.calls}
	var out strings.Builder
	if err := Run(context.Background(), testRig(f, starter, ""), &out); err != nil {
		t.Fatalf("Run err=%v want nil (compact tolerated):\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "skipping") {
		t.Fatalf("missing tolerate note:\n%s", out.String())
	}
}

// runOffline is the shared driver for the offline-defrag tests:
// bloated post-defrag status forces the fallback (or the caller
// pre-flags it via forceOff/failOnlineDefrag).
func runOffline(t *testing.T, f *fakeEtcd, forceOff bool) (
	*fakeStarter, string, error) {
	t.Helper()
	procRoot := fakeProc(t, map[int]string{4242: etcdProcCmdline})
	starter := &fakeStarter{calls: &f.calls}
	// The old etcd pid must disappear once the service stops —
	// waitPidExit polls /proc/4242.
	pidDir := filepath.Join(procRoot, "4242")
	f.onCall = func(name string, args []string) {
		if name == "systemctl" && len(args) > 0 && args[0] == "stop" {
			_ = os.RemoveAll(pidDir)
		}
	}
	cfg := testRig(f, starter, procRoot)
	cfg.ForceOffline = forceOff
	var out strings.Builder
	err := Run(context.Background(), cfg, &out)
	return starter, out.String(), err
}

// assertOfflineOrder checks the script's offline block ordering:
// systemctl stop -> standalone etcd -> defrag -> kill -> start.
func assertOfflineOrder(t *testing.T, calls []recordedCall) {
	t.Helper()
	seq := []struct{ substr, desc string }{
		{"systemctl stop", "service stop"},
		{"temp-etcd:start", "standalone etcd start"},
		{"--command-timeout=180s defrag", "offline defrag"},
		{"temp-etcd:kill", "standalone etcd kill"},
		{"systemctl start", "service start"},
	}
	prev := -1
	for _, s := range seq {
		i := callIndex(calls, s.substr)
		if i < 0 {
			t.Fatalf("missing %s (%q):\n%v", s.desc, s.substr, calls)
		}
		if i <= prev {
			t.Fatalf("%s (%q) at %d — want after index %d:\n%v",
				s.desc, s.substr, i, prev, calls)
		}
		prev = i
	}
}

func TestRunOfflineOnBloat(t *testing.T) {
	f := &fakeEtcd{
		healthy: true,
		statusJSON: []string{
			statusJSON(100, 5000, 1000), // before
			statusJSON(100, 5000, 1000), // post-defrag: 5000 > 2000
			statusJSON(100, 1500, 1000), // post-offline
		},
	}
	starter, out, err := runOffline(t, f, false)
	if err != nil {
		t.Fatalf("Run err=%v want nil:\n%s", err, out)
	}
	assertOfflineOrder(t, f.calls)
	// The captured live flags are reused VERBATIM for the standalone
	// (script: mapfile FLAGS + etcd "${FLAGS[@]}") — argv[0] dropped.
	if starter.bin != "/fake/k0s/bin/etcd" {
		t.Fatalf("starter bin=%q want /fake/k0s/bin/etcd", starter.bin)
	}
	joined := strings.Join(starter.args, " ")
	for _, want := range []string{
		"--data-dir=/fake/k0s/etcd",
		"--quota-backend-bytes=8589934592",
		"--listen-client-urls=",
		"--advertise-client-urls=",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("standalone args missing %q: %s", want, joined)
		}
	}
	for _, a := range starter.args {
		if a == "/fake/k0s/bin/etcd" {
			t.Fatalf("argv[0] leaked into standalone flags: %v", starter.args)
		}
	}
	if !starter.killed {
		t.Fatal("standalone etcd was not killed")
	}
	if !strings.Contains(out, "OFFLINE DEFRAG") {
		t.Fatalf("missing offline notice:\n%s", out)
	}
}

func TestRunOfflineOnDefragError(t *testing.T) {
	f := &fakeEtcd{
		healthy:          true,
		failOnlineDefrag: true, // only the 120s call errors
		statusJSON:       []string{statusJSON(100, 100, 90)},
	}
	if _, out, err := runOffline(t, f, false); err != nil {
		t.Fatalf("Run err=%v want nil:\n%s", err, out)
	}
	assertOfflineOrder(t, f.calls)
}

func TestRunForceOffline(t *testing.T) {
	f := &fakeEtcd{
		healthy:    true,
		statusJSON: []string{statusJSON(100, 100, 90)},
	}
	if _, _, err := runOffline(t, f, true); err != nil {
		t.Fatalf("Run err=%v want nil", err)
	}
	// --force-offline skips the online defrag attempt entirely.
	if i := callIndex(f.calls, "--command-timeout=120s"); i >= 0 {
		t.Fatalf("online defrag ran despite --force-offline:\n%v", f.calls)
	}
	assertOfflineOrder(t, f.calls)
}

func TestRunOfflineNoEtcdProcess(t *testing.T) {
	f := &fakeEtcd{
		healthy:    true,
		statusJSON: []string{statusJSON(100, 5000, 1000), statusJSON(100, 5000, 1000)},
	}
	procRoot := fakeProc(t, map[int]string{
		// An etcdctl process must not be mistaken for etcd.
		1111: "/fake/k0s/bin/etcdctl\x00endpoint\x00status\x00",
		2222: "/usr/bin/k0s\x00controller\x00",
	})
	starter := &fakeStarter{calls: &f.calls}
	var out strings.Builder
	err := Run(context.Background(), testRig(f, starter, procRoot), &out)
	if err == nil {
		t.Fatalf("Run err=nil want find-process error:\n%s", out.String())
	}
	if !strings.Contains(err.Error(), "no running etcd process") {
		t.Fatalf("err=%v want the script's not-found message", err)
	}
	// The service was never stopped — no systemctl calls.
	if i := callIndex(f.calls, "systemctl"); i >= 0 {
		t.Fatalf("systemctl ran without an etcd process:\n%v", f.calls)
	}
}

func TestRunOfflineErrorRestartsService(t *testing.T) {
	// Mid-block failure (temp-etcd start dies): the deferred
	// systemctl start MUST still run — the bash under set -e would
	// have left the control plane down.
	f := &fakeEtcd{
		healthy:    true,
		statusJSON: []string{statusJSON(100, 5000, 1000), statusJSON(100, 5000, 1000)},
	}
	starter, _, err := func() (*fakeStarter, string, error) {
		procRoot := fakeProc(t, map[int]string{4242: etcdProcCmdline})
		s := &fakeStarter{calls: &f.calls, err: errors.New("fake: etcd exploded")}
		pidDir := filepath.Join(procRoot, "4242")
		f.onCall = func(name string, args []string) {
			if name == "systemctl" && len(args) > 0 && args[0] == "stop" {
				_ = os.RemoveAll(pidDir)
			}
		}
		var out strings.Builder
		return s, out.String(), Run(context.Background(),
			testRig(f, s, procRoot), &out)
	}()
	if err == nil {
		t.Fatal("Run err=nil want temp-etcd start failure")
	}
	stop := callIndex(f.calls, "systemctl stop")
	start := callIndex(f.calls, "systemctl start")
	if start < 0 || start <= stop {
		t.Fatalf("systemctl start=%d want after stop=%d:\n%v",
			start, stop, f.calls)
	}
	if starter.killed {
		t.Fatal("handle killed despite never starting")
	}
}

func TestRunOfflineDefragErrorRestartsService(t *testing.T) {
	f := &fakeEtcd{
		healthy:           true,
		failOfflineDefrag: true, // the 180s defrag errors
		statusJSON: []string{
			statusJSON(100, 5000, 1000),
			statusJSON(100, 5000, 1000),
		},
	}
	starter, _, err := runOffline(t, f, false)
	if err == nil {
		t.Fatal("Run err=nil want offline defrag error")
	}
	if !strings.Contains(err.Error(), "offline defrag") {
		t.Fatalf("err=%v want offline defrag failure", err)
	}
	// The standalone is killed and the service restarted even so.
	if !starter.killed {
		t.Fatal("standalone etcd not killed after defrag failure")
	}
	kill := callIndex(f.calls, "temp-etcd:kill")
	start := callIndex(f.calls, "systemctl start")
	if start < 0 || start <= kill {
		t.Fatalf("start=%d want after kill=%d:\n%v", start, kill, f.calls)
	}
}

func TestRunCanaryFailures(t *testing.T) {
	statuses := []string{
		statusJSON(100, 100, 90), statusJSON(100, 90, 85),
	}
	for _, tc := range []struct {
		name    string
		failPut bool
		failDel bool
		want    string
	}{
		{"put fails", true, false, "put:"},
		{"del fails", false, true, "del:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeEtcd{
				healthy:    true,
				statusJSON: statuses,
				failPut:    tc.failPut,
				failDel:    tc.failDel,
			}
			starter := &fakeStarter{calls: &f.calls}
			var out strings.Builder
			err := Run(context.Background(), testRig(f, starter, ""), &out)
			if err == nil {
				t.Fatalf("Run err=nil want canary failure:\n%s", out.String())
			}
			if !strings.Contains(err.Error(), "WRITE STILL FAILING") {
				t.Fatalf("err=%v want the script's write-fail message", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v want %q", err, tc.want)
			}
		})
	}
}

// The standalone log path is predictable (/tmp/etcd-standalone.log)
// and opened as root — a planted symlink must be refused BEFORE
// O_TRUNC can clobber the target.
func TestStartTempEtcdRejectsSymlinkLog(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "victim")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "etcd-standalone.log")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := startTempEtcdExec(context.Background(),
		"/nonexistent/etcd", nil, link); err == nil {
		t.Fatal("expected refusal for symlinked log path")
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "keep" {
		t.Fatalf("symlink target clobbered: %q", body)
	}
}

// A regular log path is created 0600 (the exec then fails on the
// missing binary — this only proves the file side).
func TestStartTempEtcdCreatesLog0600(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "etcd-standalone.log")
	_, err := startTempEtcdExec(context.Background(),
		"/nonexistent/etcd", nil, logPath)
	if err == nil {
		t.Fatal("expected exec failure for missing etcd binary")
	}
	fi, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("log not created: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("log mode %o want 0600", fi.Mode().Perm())
	}
}

// --- OnlineOnly (background auto-maintenance: the offline path is
// forbidden — systemctl stop/start + standalone etcd never run) ---

func TestRunOnlineOnlySkipsOfflineOnBloat(t *testing.T) {
	f := &fakeEtcd{
		healthy: true,
		statusJSON: []string{
			statusJSON(100, 5000, 1000), // before
			statusJSON(100, 5000, 1000), // post-defrag: 5000 > 2000
			statusJSON(100, 5000, 1000), // [4/6] display
		},
	}
	procRoot := fakeProc(t, map[int]string{4242: etcdProcCmdline})
	starter := &fakeStarter{calls: &f.calls}
	cfg := testRig(f, starter, procRoot)
	cfg.OnlineOnly = true
	var out strings.Builder
	err := Run(context.Background(), cfg, &out)
	// The bloat could not be reclaimed online — Run reports the
	// required manual offline defrag as an error.
	if err == nil {
		t.Fatal("Run err=nil want offline-required error")
	}
	if !strings.Contains(err.Error(), "offline defrag") {
		t.Fatalf("err=%v want offline-defrag hint", err)
	}
	// The offline machinery NEVER ran: no systemctl, no temp etcd.
	if i := callIndex(f.calls, "systemctl"); i >= 0 {
		t.Fatalf("systemctl ran under OnlineOnly:\n%v", f.calls)
	}
	if i := callIndex(f.calls, "temp-etcd"); i >= 0 {
		t.Fatalf("standalone etcd spawned under OnlineOnly:\n%v", f.calls)
	}
	// The remaining online steps still completed: alarm disarm +
	// write canary must have run (they often restore writes).
	for _, want := range []string{"alarm disarm", "put " + canaryKey} {
		if i := callIndex(f.calls, want); i < 0 {
			t.Fatalf("missing %q under OnlineOnly:\n%v", want, f.calls)
		}
	}
	if !strings.Contains(out.String(), "ONLINE-ONLY") {
		t.Fatalf("missing online-only notice:\n%s", out.String())
	}
}

func TestRunOnlineOnlySkipsOfflineOnDefragError(t *testing.T) {
	f := &fakeEtcd{
		healthy:          true,
		failOnlineDefrag: true, // the 120s defrag errors → wants offline
		statusJSON:       []string{statusJSON(100, 100, 90)},
	}
	procRoot := fakeProc(t, map[int]string{4242: etcdProcCmdline})
	starter := &fakeStarter{calls: &f.calls}
	cfg := testRig(f, starter, procRoot)
	cfg.OnlineOnly = true
	var out strings.Builder
	err := Run(context.Background(), cfg, &out)
	if err == nil {
		t.Fatal("Run err=nil want offline-required error")
	}
	if i := callIndex(f.calls, "systemctl"); i >= 0 {
		t.Fatalf("systemctl ran under OnlineOnly:\n%v", f.calls)
	}
	if starter.killed {
		t.Fatal("standalone etcd touched under OnlineOnly")
	}
}

func TestRunOnlineOnlyForceOfflineIgnored(t *testing.T) {
	// ForceOffline + OnlineOnly is contradictory: OnlineOnly wins —
	// the run degrades to a plain online attempt.
	f := &fakeEtcd{
		healthy: true,
		statusJSON: []string{
			statusJSON(100, 1000, 800), // before
			statusJSON(100, 850, 800),  // post-defrag: 850 <= 1600
			statusJSON(100, 850, 800),  // [4/6] display
		},
	}
	procRoot := fakeProc(t, map[int]string{4242: etcdProcCmdline})
	starter := &fakeStarter{calls: &f.calls}
	cfg := testRig(f, starter, procRoot)
	cfg.ForceOffline = true
	cfg.OnlineOnly = true
	var out strings.Builder
	if err := Run(context.Background(), cfg, &out); err != nil {
		t.Fatalf("Run err=%v want nil:\n%s", err, out.String())
	}
	// The online defrag WAS attempted (ForceOffline ignored) and the
	// offline machinery never ran.
	if i := callIndex(f.calls, "--command-timeout=120s defrag"); i < 0 {
		t.Fatalf("online defrag not attempted:\n%v", f.calls)
	}
	if i := callIndex(f.calls, "systemctl"); i >= 0 {
		t.Fatalf("systemctl ran under OnlineOnly:\n%v", f.calls)
	}
}

func TestRunOnlineOnlySuccessNoError(t *testing.T) {
	// When the online defrag reclaims enough, OnlineOnly changes
	// nothing — the run completes cleanly.
	f := &fakeEtcd{
		healthy: true,
		statusJSON: []string{
			statusJSON(100, 1000, 800),
			statusJSON(100, 850, 800),
			statusJSON(100, 850, 800),
		},
	}
	starter := &fakeStarter{calls: &f.calls}
	cfg := testRig(f, starter, "")
	cfg.OnlineOnly = true
	var out strings.Builder
	if err := Run(context.Background(), cfg, &out); err != nil {
		t.Fatalf("Run err=%v want nil:\n%s", err, out.String())
	}
	if i := callIndex(f.calls, "systemctl"); i >= 0 {
		t.Fatalf("unexpected systemctl call:\n%v", f.calls)
	}
}

func TestCallTimeoutBoundsCommandCtx(t *testing.T) {
	// CallTimeout caps every spawned command's ctx — the
	// controllerhygiene guard relies on it to keep ~12 sequential
	// etcdctl calls near its own run budget instead of ~2h at the
	// 10m interactive default.
	for _, tc := range []struct {
		name string
		call time.Duration
		want time.Duration
	}{
		{"explicit cap", 42 * time.Second, 42 * time.Second},
		{"default", 0, defaultCallTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeEtcd{
				healthy: true,
				statusJSON: []string{
					statusJSON(100, 1000, 800),
					statusJSON(100, 850, 800),
					statusJSON(100, 850, 800),
				},
			}
			base := f.run
			var worst time.Duration
			cfg := testRig(f, &fakeStarter{calls: &f.calls}, "")
			cfg.CallTimeout = tc.call
			cfg.CmdRunner = func(ctx context.Context, name string,
				args ...string) ([]byte, error) {
				d, ok := ctx.Deadline()
				if !ok {
					t.Error("command ctx carries no deadline")
				} else if rem := time.Until(d); rem > worst {
					worst = rem
				}
				return base(ctx, name, args...)
			}
			var out strings.Builder
			if err := Run(context.Background(), cfg, &out); err != nil {
				t.Fatalf("Run err=%v want nil:\n%s", err, out.String())
			}
			if worst == 0 || worst > tc.want {
				t.Fatalf("command ctx deadline %s — want <= %s", worst, tc.want)
			}
		})
	}
}

func TestRunStatusFailureFatal(t *testing.T) {
	// Under set -e the bash died on the very first endpoint status —
	// the port does too.
	f := &fakeEtcd{statusJSON: []string{statusJSON(1, 1, 1)}}
	starter := &fakeStarter{calls: &f.calls}
	cfg := testRig(f, starter, "")
	cfg.CmdRunner = func(_ context.Context, name string,
		args ...string) ([]byte, error) {
		f.calls = append(f.calls, recordedCall{name: name,
			args: strings.Join(args, " ")})
		return nil, errors.New("fake: connection refused")
	}
	var out strings.Builder
	err := Run(context.Background(), cfg, &out)
	if err == nil {
		t.Fatalf("Run err=nil want status failure:\n%s", out.String())
	}
	if !strings.Contains(err.Error(), "endpoint status") {
		t.Fatalf("err=%v want endpoint status failure", err)
	}
}
