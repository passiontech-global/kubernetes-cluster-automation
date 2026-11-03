package workerhygiene

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-host-agent/internal/systemd"
)

// jenv is the janitor fixture: tempdir state dir + fake procfs + a
// recording systemd runner + a controllable clock. All seams are
// in-memory — no real processes, units or signals are touched.
type jenv struct {
	j       *Janitor
	state   string
	proc    string
	logFile string
	now     time.Time
	sdcmds  [][]string
	sdReply map[string]string // substring of joined argv → stdout
	kills   []killRecord
	live    map[int]bool // pids that answer signal-0
}

func (e *jenv) sdRun(_ context.Context, argv []string) (string, error) {
	e.sdcmds = append(e.sdcmds, argv)
	joined := strings.Join(argv, " ")
	for k, v := range e.sdReply {
		if strings.Contains(joined, k) {
			return v, nil
		}
	}
	// Mutating systemctl verbs succeed silently — only the READ side
	// (list-units) needs a canned reply.
	if len(argv) >= 2 && argv[0] == "systemctl" &&
		(argv[1] == "reset-failed" || argv[1] == "stop") {
		return "", nil
	}
	return "", syscall.ENOENT
}

func (e *jenv) sdRan(sub string) bool {
	for _, c := range e.sdcmds {
		if strings.Contains(strings.Join(c, " "), sub) {
			return true
		}
	}
	return false
}

func jfixture(t *testing.T) *jenv {
	t.Helper()
	root := t.TempDir()
	e := &jenv{
		now:     time.Now(),
		live:    map[int]bool{},
		sdReply: map[string]string{},
	}
	e.state = filepath.Join(root, "watchdog")
	e.proc = filepath.Join(root, "proc")
	e.logFile = filepath.Join(root, "watchdog.log")
	for _, d := range []string{e.state, e.proc} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sd := systemd.New(systemd.Config{HostRoot: "/", RunCmd: e.sdRun,
		ProcUptimeFile: filepath.Join(e.proc, "uptime")})
	j, err := NewJanitor(JanitorConfig{
		Enabled:          true,
		Interval:         time.Hour,
		WatchdogStateDir: e.state,
		WatchdogLogFile:  e.logFile,
		ProcRoot:         e.proc,
		LatchMaxAge:      24 * time.Hour,
		Systemd:          sd,
	}, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	j.cfg.killFn = func(pid int, sig syscall.Signal) error {
		if sig == 0 {
			if e.live[pid] {
				return nil
			}
			return syscall.ESRCH
		}
		e.kills = append(e.kills, killRecord{pid, sig})
		return nil
	}
	j.cfg.nowFn = func() time.Time { return e.now }
	e.j = j
	return e
}

// mkProc plants a fake process: <proc>/<pid>/cmdline (NUL-joined) and
// <proc>/<pid>/stat carrying the given ppid in field 4.
func (e *jenv) mkProc(t *testing.T, pid, ppid int, argv ...string) {
	t.Helper()
	e.live[pid] = true
	dir := filepath.Join(e.proc, fmt.Sprint(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "cmdline"),
		strings.Join(argv, "\x00")+"\x00")
	// "pid (comm) state ppid ..." — ppid is the first field after the
	// state char following the last ')'.
	writeFile(t, filepath.Join(dir, "stat"),
		fmt.Sprintf("%d (%s) S %d 0 0 0 -1 4194304 100 0 0 0 0 0 0 0 20 0 1 0 50 0 0 0\n",
			pid, filepath.Base(argv[0]), ppid))
}

// ageFile rewinds a file's mtime so the reaper sees it as old.
func ageFile(t *testing.T, path string, age time.Duration) {
	t.Helper()
	old := time.Now().Add(-age)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
}

func (e *jenv) logContains(t *testing.T, sub string) bool {
	t.Helper()
	data, err := os.ReadFile(e.logFile)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), sub)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// --- A: latch reaper ---

func TestJanitorReapsUnknownLatchImmediately(t *testing.T) {
	e := jfixture(t)
	// Fresh file, name no current check produces — the removed/
	// renamed-check case. Reaped regardless of age.
	writeFile(t, filepath.Join(e.state, "state-tinc-route-lost"), "1\n")
	e.j.Sweep(context.Background())
	if fileExists(filepath.Join(e.state, "state-tinc-route-lost")) {
		t.Fatal("unknown latch survived sweep")
	}
	if !e.logContains(t, "ACTION: reaped stale latch state-tinc-route-lost") {
		t.Fatal("missing ACTION reaped log line")
	}
}

func TestJanitorKnownLatchAgeGated(t *testing.T) {
	e := jfixture(t)
	fresh := filepath.Join(e.state, "state-node-overloaded")
	stale := filepath.Join(e.state, "state-conntrack-pressure")
	writeFile(t, fresh, "1\n")
	writeFile(t, stale, "1\n")
	ageFile(t, stale, 25*time.Hour) // the ~11h field case, past 24h

	e.j.Sweep(context.Background())

	if !fileExists(fresh) {
		t.Fatal("fresh known latch reaped — age gate broken")
	}
	if fileExists(stale) {
		t.Fatal("stale known latch (>maxage) survived")
	}
	if !e.logContains(t, "ACTION: reaped stale latch state-conntrack-pressure") {
		t.Fatal("missing ACTION reaped log line")
	}
}

func TestJanitorParameterizedPrefixLatch(t *testing.T) {
	e := jfixture(t)
	fresh := filepath.Join(e.state, "state-apiserver-backend-stale-10-0-0-1")
	stale := filepath.Join(e.state, "state-apiserver-backend-stale-10-0-0-2")
	writeFile(t, fresh, "1\n")
	writeFile(t, stale, "1\n")
	ageFile(t, stale, 48*time.Hour)

	e.j.Sweep(context.Background())

	if !fileExists(fresh) {
		t.Fatal("fresh parameterized latch reaped")
	}
	if fileExists(stale) {
		t.Fatal("aged parameterized latch survived")
	}
}

func TestJanitorPreservesNonStateFiles(t *testing.T) {
	e := jfixture(t)
	keep := []string{
		"last-restart",          // rate budget — deleting bypasses cooldowns
		"last-cilium-restart",   // rate budget
		"last-run",              // reporter heartbeat
		"installed",             // watchdog-installed marker
		"egress-state-10.1.2.3", // egress relay committed state
		"egress-ctr-10.1.2.3",   // egress hit counter
		"consecutive-sig13-gap", // consecutive counter
		"wedged-seen-deadbeef",  // ctr wedge marker
		"oomloop-seen",          // controllerhygiene marker
		"dnsfb-pin-8.8.8.8",     // dns fallback pin record
		".tmp-state-x",          // in-flight stateEnter tmp
		"apibe-gap-10-0-0-1",    // apiprober rv gap file
		"fail2ban-banned",       // jail counts for hostmetrics
	}
	for _, n := range keep {
		p := filepath.Join(e.state, n)
		writeFile(t, p, "1\n")
		ageFile(t, p, 96*time.Hour) // even very old non-state files stay
	}
	e.j.Sweep(context.Background())
	for _, n := range keep {
		if !fileExists(filepath.Join(e.state, n)) {
			t.Fatalf("non-state file %s removed", n)
		}
	}
}

func TestJanitorSkipsStateDirectory(t *testing.T) {
	e := jfixture(t)
	dir := filepath.Join(e.state, "state-weird-dir")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	e.j.Sweep(context.Background())
	if !fileExists(dir) {
		t.Fatal("state-* directory removed")
	}
	if !e.logContains(t, "suspect: state dir entry state-weird-dir is a directory") {
		t.Fatal("missing suspect log for state dir entry")
	}
}

func TestJanitorMissingStateDirAbortsCleanly(t *testing.T) {
	e := jfixture(t)
	if err := os.RemoveAll(e.state); err != nil {
		t.Fatal(err)
	}
	e.j.Sweep(context.Background()) // must not panic
	got := testutil.ToFloat64(
		e.j.cycles.WithLabelValues(checkLatchReaper, "abort"))
	if got != 1 {
		t.Fatalf("latch-reaper abort=%v want 1", got)
	}
}

func TestJanitorMetricsBumpOnReap(t *testing.T) {
	e := jfixture(t)
	writeFile(t, filepath.Join(e.state, "state-bogus-old-check"), "1\n")
	e.j.Sweep(context.Background())
	if got := testutil.ToFloat64(
		e.j.actions.WithLabelValues(checkLatchReaper, "reap")); got != 1 {
		t.Fatalf("reap action count=%v want 1", got)
	}
}

// --- B: ghost systemd units ---

func TestJanitorResetFailedGhostUnits(t *testing.T) {
	e := jfixture(t)
	e.sdReply["systemctl list-units"] = "" +
		"k0sworker.service              loaded    active   running k0s worker\n" +
		"node-watchdog.service          not-found failed   failed  node-watchdog.service\n" +
		"node-watchdog.timer            not-found failed   failed  node-watchdog.timer\n" +
		"nebula-route-guard.service     not-found active   running route guard\n" +
		"node-config-agent.service      not-found failed   failed  node-config-agent.service\n" +
		"unrelated-svc.service          not-found failed   failed  unrelated-svc.service\n" +
		"other.timer                    loaded    active   waiting other timer\n"

	e.j.Sweep(context.Background())

	for _, u := range []string{
		"node-watchdog.service", "node-watchdog.timer",
		"node-config-agent.service", "nebula-route-guard.service",
	} {
		if !e.sdRan("systemctl reset-failed " + u) {
			t.Fatalf("reset-failed missing for ghost unit %s (cmds=%v)", u, e.sdcmds)
		}
	}
	// The not-found-but-active ghost must be STOPPED (retired code
	// still running), then its residue cleared.
	if !e.sdRan("systemctl stop nebula-route-guard.service") {
		t.Fatalf("stop missing for active ghost unit (cmds=%v)", e.sdcmds)
	}
	// Non-legacy units are never touched — not even failed ones.
	if e.sdRan("reset-failed unrelated-svc.service") ||
		e.sdRan("stop unrelated-svc.service") {
		t.Fatalf("non-legacy unit touched (cmds=%v)", e.sdcmds)
	}
	if e.sdRan("k0sworker") && !e.sdRan("list-units") {
		t.Fatal("unrelated command ran")
	}
	if !e.logContains(t, "ACTION: reset-failed ghost unit node-watchdog.service") {
		t.Fatal("missing reset-failed ACTION log")
	}
	if !e.logContains(t, "ACTION: stopped ghost unit nebula-route-guard.service") {
		t.Fatal("missing stopped-ghost ACTION log")
	}
}

func TestJanitorUnitsSweepNoGhosts(t *testing.T) {
	e := jfixture(t)
	e.sdReply["systemctl list-units"] =
		"k0sworker.service loaded active running k0s worker\n" +
			"kubelet.service   loaded active running kubelet\n"

	e.j.Sweep(context.Background())

	if e.sdRan("reset-failed") || e.sdRan(" stop ") {
		t.Fatalf("ghost actions on a clean host (cmds=%v)", e.sdcmds)
	}
}

func TestJanitorUnitsSweepGatedWithoutSystemd(t *testing.T) {
	e := jfixture(t)
	j, err := NewJanitor(JanitorConfig{
		Enabled:          true,
		WatchdogStateDir: e.state,
		WatchdogLogFile:  e.logFile,
		ProcRoot:         e.proc,
		Systemd:          nil,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.j = j
	writeFile(t, filepath.Join(e.state, "state-ghost-from-old-check"), "1\n")

	e.j.Sweep(context.Background())

	// The units sweep gates but the latch sweep still works.
	if fileExists(filepath.Join(e.state, "state-ghost-from-old-check")) {
		t.Fatal("latch sweep skipped when systemd unwired")
	}
	if got := testutil.ToFloat64(
		e.j.cycles.WithLabelValues(checkLegacyUnits, "gated")); got != 1 {
		t.Fatalf("legacy-units gated=%v want 1", got)
	}
	if len(e.sdcmds) != 0 {
		t.Fatalf("systemd commands ran with nil client: %v", e.sdcmds)
	}
}

// --- B: orphan `ip monitor` ---

func TestJanitorKillsOrphanIPMonitor(t *testing.T) {
	e := jfixture(t)
	// The field case: `ip -ts monitor` reparented to init after the
	// retired route-guard unit was pruned.
	e.mkProc(t, 4242, 1, "/sbin/ip", "-ts", "monitor", "rule", "route")

	e.j.Sweep(context.Background())

	if len(e.kills) != 1 || e.kills[0].pid != 4242 || e.kills[0].sig != syscall.SIGKILL {
		t.Fatalf("kills=%v want one SIGKILL on pid 4242", e.kills)
	}
	if !e.logContains(t, "ACTION: killed orphan ip monitor pid=4242") {
		t.Fatal("missing orphan-kill ACTION log")
	}
}

func TestJanitorKillsLegacyScriptTree(t *testing.T) {
	e := jfixture(t)
	// The retired script itself still loops → kill the loop AND the
	// monitor so it can't respawn.
	e.mkProc(t, 5555, 1, "/bin/sh", "/usr/local/sbin/nebula-route-guard.sh")
	e.mkProc(t, 4343, 5555, "/usr/sbin/ip", "-ts", "monitor", "rule", "route")

	e.j.Sweep(context.Background())

	if len(e.kills) != 2 {
		t.Fatalf("kills=%v want 2 (parent + monitor)", e.kills)
	}
	got := map[int]bool{}
	for _, k := range e.kills {
		got[k.pid] = true
	}
	if !got[5555] || !got[4343] {
		t.Fatalf("kills=%v want pids 5555+4343", e.kills)
	}
}

func TestJanitorSkipsIPMonitorWithForeignParent(t *testing.T) {
	e := jfixture(t)
	// Ambiguous ownership → suspect, never kill.
	e.mkProc(t, 6666, 1, "/usr/sbin/NetworkManager", "--no-daemon")
	e.mkProc(t, 4444, 6666, "/sbin/ip", "monitor", "address")

	e.j.Sweep(context.Background())

	if len(e.kills) != 0 {
		t.Fatalf("kills=%v want none (foreign parent)", e.kills)
	}
	if !e.logContains(t, "suspect: ip monitor pid=4444 has non-legacy parent pid=6666") {
		t.Fatal("missing suspect log for foreign-parent monitor")
	}
}

func TestJanitorIgnoresNonMonitorIPCommands(t *testing.T) {
	e := jfixture(t)
	// `ip netns monitor` is a different subcommand — first non-flag
	// arg is "netns", not "monitor".
	e.mkProc(t, 4545, 1, "ip", "netns", "monitor", "/var/run/netns")
	e.mkProc(t, 4646, 1, "ip", "-o", "link", "show")
	// Not ip at all.
	e.mkProc(t, 4747, 1, "/usr/sbin/sshd", "-D")

	e.j.Sweep(context.Background())

	if len(e.kills) != 0 {
		t.Fatalf("kills=%v want none (no monitor processes)", e.kills)
	}
}

func TestJanitorRunDisabledIdles(t *testing.T) {
	j, err := NewJanitor(JanitorConfig{Enabled: false}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { j.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("disabled janitor Run did not return on ctx cancel")
	}
}
