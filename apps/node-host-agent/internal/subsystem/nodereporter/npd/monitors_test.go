// monitors_test.go — the NPD monitor suite, driven straight at the
// Monitor + fake Sink: the journald source (kubelet-stale monitor +
// kernel fallback), the kernel monitor (rule patterns, the kmsg
// tail, the backlog lookback, the permanent KernelDeadlock) and the
// readonly mounts monitor. The monitor→node-condition shipping half
// stays covered in the parent package's npd_ship_test.go.
package npd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/journalwatch"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/kmsg"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
)

// ---------------------------------------------------------------------------
// journald source (kubelet-stale monitor + kernel fallback)
// ---------------------------------------------------------------------------

func journalJSON(tsUS int64, msg string) string {
	m, _ := json.Marshal(msg)
	return fmt.Sprintf("{\"__REALTIME_TIMESTAMP\":\"%d\",\"MESSAGE\":%s}", tsUS, m)
}

// TestParseJournalJSON: MESSAGE arrives as a JSON string or a byte
// array (non-UTF8 payloads); malformed lines are skipped. The decode
// lives in platform/journalwatch — this keeps the monitor-side
// contract pinned.
func TestParseJournalJSON(t *testing.T) {
	data := journalJSON(1700000000000000, `err="node \"n1\" not found"`) + "\n" +
		"not-json-garbage\n" +
		`{"__REALTIME_TIMESTAMP":"1700000001000000","MESSAGE":[104,101,108,108,111]}` + "\n"
	got := journalwatch.ParseJSON(data)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(got), got)
	}
	if got[0].TSUS != 1700000000000000 || !strings.Contains(got[0].Msg, `not found`) {
		t.Fatalf("entry 0 = %+v", got[0])
	}
	if got[1].Msg != "hello" {
		t.Fatalf("byte-array MESSAGE decoded to %q", got[1].Msg)
	}
}

// TestKubeletJournalRulePatterns: the ported kubelet-stale patterns
// match the real klog-escaped spam signature plus the plain form,
// and ignore unrelated noise.
func TestKubeletJournalRulePatterns(t *testing.T) {
	cases := []struct {
		msg    string
		reason string
		want   bool
	}{
		{`err="node \"n1\" not found"`, "KubeletNodeNotFound", true},
		{`failed to get node: node "n1" not found`, "KubeletNodeNotFound", true},
		{`cannot get pod sandbox: node not registered yet`, "KubeletNodeNotFound", true},
		{`error syncing pod: object not registered`, "KubeletObjectNotRegistered", true},
		{`no relationship found between node "n1" and pod "x"`, "KubeletObjectNotRegistered", true},
		{`node "n1" not found`, "KubeletObjectNotRegistered", false},
		{`eviction manager: unexpected error`, "KubeletNodeNotFound", false},
		{`image garbage collection completed`, "KubeletObjectNotRegistered", false},
	}
	for _, c := range cases {
		for _, rule := range kubeletJournalRules {
			if rule.reason != c.reason {
				continue
			}
			if got := rule.re.MatchString(c.msg); got != c.want {
				t.Errorf("%s vs %q: match=%v, want %v", c.reason, c.msg, got, c.want)
			}
		}
	}
}

// TestKubeletJournalScan: matching journal lines bump
// problem_counter and emit Events.
func TestKubeletJournalScan(t *testing.T) {
	e := fixture(t)
	e.journalFetch = func(_ context.Context, args ...string) (string, error) {
		return journalJSON(e.now.UnixMicro(), `err="node \"n1\" not found"`) + "\n" +
			journalJSON(e.now.UnixMicro(), "unrelated kubelet noise") + "\n", nil
	}
	if err := e.m.SyncKubeletJournal(context.Background(), e.sink); err != nil {
		t.Fatal(err)
	}

	if got := e.sink.counter("KubeletNodeNotFound"); got != 1 {
		t.Fatalf("counter KubeletNodeNotFound = %v, want 1", got)
	}
	evs := e.sink.eventsByReason("KubeletNodeNotFound")
	if len(evs) != 1 {
		t.Fatalf("events = %+v, want one", evs)
	}
	if !strings.Contains(evs[0].note, `not found`) {
		t.Fatalf("note = %q", evs[0].note)
	}
}

// TestJournalCursorAdvancement: the µs cursor makes each fetch
// return only strictly-new entries — a journal line replayed at the
// boundary is not double-counted, a later line is.
func TestJournalCursorAdvancement(t *testing.T) {
	e := fixture(t)
	var calls [][]string
	payloads := []string{
		journalJSON(e.now.UnixMicro()-1000, `err="node \"n1\" not found"`),
		// Same entry re-shown at the boundary plus a new one.
		journalJSON(e.now.UnixMicro()-1000, `err="node \"n1\" not found"`) + "\n" +
			journalJSON(e.now.UnixMicro()+1000, "no relationship found between node \"n1\" and pod \"x\""),
	}
	i := 0
	e.journalFetch = func(_ context.Context, args ...string) (string, error) {
		calls = append(calls, args)
		out := payloads[i]
		if i < len(payloads)-1 {
			i++
		}
		return out, nil
	}
	if err := e.m.SyncKubeletJournal(context.Background(), e.sink); err != nil {
		t.Fatal(err)
	}
	if err := e.m.SyncKubeletJournal(context.Background(), e.sink); err != nil {
		t.Fatal(err)
	}

	if got := e.sink.counter("KubeletNodeNotFound"); got != 1 {
		t.Fatalf("counter = %v, want 1 (boundary replay filtered)", got)
	}
	if got := e.sink.counter("KubeletObjectNotRegistered"); got != 1 {
		t.Fatalf("counter = %v, want 1 (newer line counted)", got)
	}
	if len(calls) != 2 {
		t.Fatalf("journalFetch calls = %d, want 2", len(calls))
	}
	since1 := calls[0][len(calls[0])-4]
	since2 := calls[1][len(calls[1])-4]
	want1 := "@" + strconv.FormatInt(e.now.Add(-e.cfg.LogLookback).Unix(), 10)
	// The cursor parks on the newest KEPT entry's timestamp — it no
	// longer jumps to `now`, so the second window re-opens one sec
	// earlier and the <= cursor filter absorbs the replay.
	want2 := "@" + strconv.FormatInt((e.now.UnixMicro()-1000)/1e6, 10)
	if since1 != want1 || since2 != want2 {
		t.Fatalf("--since args = %q then %q, want %q then %q", since1, since2, want1, want2)
	}
}

// TestJournalFetchErrorKeepsCursor: a failed fetch does not advance
// the cursor — the window is retried next cycle.
func TestJournalFetchErrorKeepsCursor(t *testing.T) {
	e := fixture(t)
	fail := true
	e.journalFetch = func(_ context.Context, args ...string) (string, error) {
		if fail {
			return "", errors.New("journald busy")
		}
		return journalJSON(e.now.UnixMicro(), `err="node \"n1\" not found"`), nil
	}
	if err := e.m.SyncKubeletJournal(context.Background(), e.sink); err == nil {
		t.Fatal("expected fetch error")
	}
	if got := e.sink.counter("KubeletNodeNotFound"); got != 0 {
		t.Fatalf("counter = %v, want 0", got)
	}
	fail = false
	if err := e.m.SyncKubeletJournal(context.Background(), e.sink); err != nil {
		t.Fatal(err)
	}
	if got := e.sink.counter("KubeletNodeNotFound"); got != 1 {
		t.Fatalf("counter after retry = %v, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// kernel monitor
// ---------------------------------------------------------------------------

// TestKernelRulePatterns: each temporary kernel rule and the
// permanent KernelDeadlock pattern — match and no-match.
func TestKernelRulePatterns(t *testing.T) {
	cases := []struct {
		msg    string
		reason string
		want   bool
	}{
		{"Out of memory: Killed process 1234 (java) total-vm:8388608kB", "OOMKilling", true},
		{"Killed process 55 (nginx) out of memory under cgroup", "OOMKilling", true},
		{"memory cgroup out of memory: no killable process", "OOMKilling", false},
		{"INFO: task jbd2/vda1-8:439 blocked for more than 120 seconds.", "TaskHung", true},
		// Upstream allows task names containing spaces.
		{"INFO: task kworker u16:2:123 blocked for more than 120 seconds.", "TaskHung", true},
		{"INFO: task sync:12345 running normally", "TaskHung", false},
		{"BUG: unable to handle kernel NULL pointer dereference at 0000000000000010", "KernelOops", true},
		{"kernel BUG at fs/ext4/inode.c:1234!", "KernelOops", true},
		{"Oops: 0000 [#1] SMP NOPTI", "KernelOops", true},
		{"audit: type=1400 avc: denied { write }", "KernelOops", false},
		{"EXT4-fs error (device vda1): ext4_journal_start_sb: Detected aborted journal", "Ext4Error", true},
		{"EXT4-fs (vda1): mounted filesystem with ordered data mode", "Ext4Error", false},
		{"EXT4-fs warning (device vdb1): ext4_dx_add_entry: Directory index full!", "Ext4Warning", true},
		{"EXT4-fs (vdb1): re-mounted. Opts: (null)", "Ext4Warning", false},
		{"nf_conntrack: table full, dropping packet", "ConntrackTableFull", true},
		{"netfilter: conntrack entries=200000 of max=262144", "ConntrackTableFull", false},
		{"Buffer I/O error on dev sda1, logical block 1234567, async page read", "FilesystemIOError", true},
		{"XFS (dm-2): metadata I/O error in \"xlog_recover_iodone\" at daddr 0x121500 len 32 error 28", "FilesystemIOError", true},
		{"XFS (dm-2): Mounting V5 Filesystem", "FilesystemIOError", false},
		{"blk_update_request: I/O error, dev vda, sector 42 op 0x0:(READ)", "FilesystemIOError", false},
		// kernel-softlockup-monitor pair — the watchdog soft-lockup
		// and RCU-stall signatures.
		{"watchdog: BUG: soft lockup - CPU#2 stuck for 23s! [kworker/2:1:123]", "KernelSoftLockup", true},
		{"watchdog: BUG: soft lockup - CPU#0 stuck for 11s!", "KernelSoftLockup", true},
		{"watchdog: BUG: hard lockup detected on CPU#1", "KernelSoftLockup", false},
		{"INFO: rcu_sched detected stall on CPUs/tasks:", "KernelRCUStall", true},
		{"INFO: rcu_preempt self-detected stall on CPU { 3 }", "KernelRCUStall", true},
		{"INFO: rcu_bh detected stall on CPU 0 (t=12345 jiffies)", "KernelRCUStall", true},
		{"INFO: rcu_sched kthread starved for 100 jiffies", "KernelRCUStall", false},
	}
	for _, c := range cases {
		for _, rule := range kernelTempRules {
			if rule.reason != c.reason {
				continue
			}
			if got := rule.re.MatchString(c.msg); got != c.want {
				t.Errorf("%s vs %q: match=%v, want %v", c.reason, c.msg, got, c.want)
			}
		}
	}
	// Permanent rule: matches the hung-task INFO lines, not noise.
	if !kernelDeadlockRe.MatchString("INFO: task kworker/u16:2:12345 blocked for more than 120 seconds.") {
		t.Error("KernelDeadlock pattern did not match hung-task INFO line")
	}
	if kernelDeadlockRe.MatchString("INFO: task kworker started") {
		t.Error("KernelDeadlock pattern matched noise")
	}
	// The soft-lockup/RCU-stall signatures are the same deadlock
	// class — both must latch the permanent condition too.
	if !kernelDeadlockRe.MatchString("watchdog: BUG: soft lockup - CPU#2 stuck for 23s!") {
		t.Error("KernelDeadlock pattern did not match soft-lockup line")
	}
	if !kernelDeadlockRe.MatchString("INFO: rcu_preempt self-detected stall on CPU { 0 }") {
		t.Error("KernelDeadlock pattern did not match RCU-stall line")
	}
}

// TestKernelNewRulesEmit: the H2/H7 kernel reasons fire from
// representative kmsg records — one counter + one Event per match.
func TestKernelNewRulesEmit(t *testing.T) {
	e := fixture(t)
	e.appendKmsg(t,
		"6,1,3599000000,-;nf_conntrack: table full, dropping packet\n"+
			"3,2,3599000001,-;Buffer I/O error on dev vdb1, logical block 42, async page read\n"+
			"4,3,3599000002,-;XFS (dm-2): Metadata I/O error detected at xfs_buf_read_map")
	if err := e.m.SyncKernelMonitor(context.Background(), e.sink); err != nil {
		t.Fatal(err)
	}

	if got := e.sink.counter("ConntrackTableFull"); got != 1 {
		t.Fatalf("ConntrackTableFull = %v, want 1", got)
	}
	if got := e.sink.counter("FilesystemIOError"); got != 2 {
		t.Fatalf("FilesystemIOError = %v, want 2", got)
	}
	if n := len(e.sink.eventsByReason("ConntrackTableFull")); n != 1 {
		t.Fatalf("ConntrackTableFull events = %d, want 1", n)
	}
	if n := len(e.sink.eventsByReason("FilesystemIOError")); n != 2 {
		t.Fatalf("FilesystemIOError events = %d, want 2", n)
	}
}

// TestKmsgTail: records drained from the (fake) kmsg device bump
// counters and emit Events; the first drain replays only the
// lookback window via µs-since-boot vs /proc/uptime.
func TestKmsgTail(t *testing.T) {
	e := fixture(t)
	// uptime fixture is 3600s: records at 3599s are inside the 5m
	// lookback, a 60s-old-boot record is far outside.
	e.appendKmsg(t, "6,1,60000000,-;EXT4-fs error (device vda1): ancient\n"+
		"6,2,3599000000,-;EXT4-fs error (device vda1): recent\n")
	if err := e.m.SyncKernelMonitor(context.Background(), e.sink); err != nil {
		t.Fatal(err)
	}

	if got := e.sink.counter("Ext4Error"); got != 1 {
		t.Fatalf("Ext4Error = %v, want 1 (only in-lookback record)", got)
	}
	evs := e.sink.eventsByReason("Ext4Error")
	if len(evs) != 1 || evs[0].note != "EXT4-fs error (device vda1): recent" {
		t.Fatalf("events = %+v", evs)
	}

	// Live tail: new records emit without the replay filter, even
	// with old boot timestamps.
	e.appendKmsg(t, "4,3,99999,-;EXT4-fs warning (device vdb1): live tail")
	if err := e.m.SyncKernelMonitor(context.Background(), e.sink); err != nil {
		t.Fatal(err)
	}
	if got := e.sink.counter("Ext4Warning"); got != 1 {
		t.Fatalf("Ext4Warning = %v, want 1", got)
	}
}

// TestKmsgLookbackNeedsUptime: without a readable /proc/uptime the
// first drain drops the ring backlog instead of replaying it live —
// a later record still tails normally.
func TestKmsgLookbackNeedsUptime(t *testing.T) {
	e := fixture(t)
	if err := os.Remove(e.uptime); err != nil {
		t.Fatal(err)
	}
	e.appendKmsg(t, "6,1,3599000000,-;EXT4-fs error (device vda1): backlog")
	if err := e.m.SyncKernelMonitor(context.Background(), e.sink); err != nil {
		t.Fatal(err)
	}
	if got := e.sink.counter("Ext4Error"); got != 0 {
		t.Fatalf("Ext4Error = %v, want 0 (backlog dropped)", got)
	}
	e.appendKmsg(t, "6,2,3599000000,-;EXT4-fs error (device vda1): live")
	if err := e.m.SyncKernelMonitor(context.Background(), e.sink); err != nil {
		t.Fatal(err)
	}
	if got := e.sink.counter("Ext4Error"); got != 1 {
		t.Fatalf("Ext4Error live = %v, want 1", got)
	}
}

// TestKmsgLookbackArmedUntilCaughtUp: the first drain is capped at
// 4MiB — a backlog larger than the cap spans multiple cycles, and the
// lookback age filter must stay armed until the drain ends on EAGAIN,
// not after the first drain. Otherwise the remainder is processed as
// LIVE and a stale hung-task line permanently latches KernelDeadlock
// on a fresh agent start (the ring replays from oldest).
func TestKmsgLookbackArmedUntilCaughtUp(t *testing.T) {
	e := fixture(t)
	// >4MiB of hung-task spam timestamped boot+60s — past the
	// per-drain cap AND far outside the 5m lookback (uptime fixture
	// is 3600s → age ~3540s).
	var sb strings.Builder
	for i := 0; sb.Len() <= maxKmsgReadBytes+128<<10; i++ {
		fmt.Fprintf(&sb,
			"6,%d,60000000,-;INFO: task jbd2/vda1-8:%d blocked for more than 120 seconds.\n", i, i)
	}
	if err := os.WriteFile(e.kmsg, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := e.m.SyncKernelMonitor(context.Background(), e.sink); err != nil {
		t.Fatal(err)
	}
	if e.m.kmsgScanned {
		t.Fatal("lookback disarmed after a byte-capped drain")
	}
	if err := e.m.SyncKernelMonitor(context.Background(), e.sink); err != nil {
		t.Fatal(err)
	}
	if !e.m.kmsgScanned {
		t.Fatal("kmsgScanned still false after the ring drained to EOF")
	}
	if e.m.kernelDeadlock {
		t.Fatal("stale backlog latched a PERMANENT KernelDeadlock")
	}
	if got := e.sink.counter("TaskHung"); got != 0 {
		t.Fatalf("TaskHung=%v want 0 (all backlog outside lookback)", got)
	}
	if n := len(e.sink.eventsByReason("KernelDeadlock")); n != 0 {
		t.Fatalf("KernelDeadlock events=%d want 0", n)
	}

	// Caught up: a freshly appended record is processed live — even
	// with an old-looking timestamp there is no filter anymore.
	e.appendKmsg(t, "6,99999,60000000,-;EXT4-fs error (device vda1): live")
	if err := e.m.SyncKernelMonitor(context.Background(), e.sink); err != nil {
		t.Fatal(err)
	}
	if got := e.sink.counter("Ext4Error"); got != 1 {
		t.Fatalf("Ext4Error=%v want 1", got)
	}
}

// TestKmsgTailCaughtUpFlag: the tailer's drain reports CaughtUp when
// the source ran dry (EOF/EAGAIN); the byte-capped case is covered
// by TestKmsgLookbackArmedUntilCaughtUp above.
func TestKmsgTailCaughtUpFlag(t *testing.T) {
	e := fixture(t)
	tail := kmsg.NewTailer(kmsg.TailerOptions{
		Paths:    func() []string { return []string{e.kmsg} },
		DrainCap: maxKmsgReadBytes,
	})
	defer tail.Close()
	// Fixture kmsg is empty → EOF on first read → caught up.
	_, res, err := tail.Read()
	if err != nil || !res.CaughtUp {
		t.Fatalf("empty kmsg: CaughtUp=%v err=%v, want true,nil", res.CaughtUp, err)
	}
}

// TestKernelJournalFallback: when kmsg cannot be opened the monitor
// falls back to journalctl -k for the process lifetime.
func TestKernelJournalFallback(t *testing.T) {
	e := fixture(t)
	// Point both kmsg candidates at nonexistent paths — Cfg() is
	// re-read per sync, so the post-New re-point lands.
	e.cfg.KmsgFile = "/nonexistent/kmsg"
	var kernelCalls int
	e.journalFetch = func(_ context.Context, args ...string) (string, error) {
		for _, a := range args {
			if a == "-k" {
				kernelCalls++
				return journalJSON(e.now.UnixMicro(),
					"EXT4-fs error (device vda1): via journal"), nil
			}
		}
		return "", nil
	}
	if err := e.m.SyncKernelMonitor(context.Background(), e.sink); err != nil {
		t.Fatal(err)
	}
	if !e.m.kmsgJournalMode {
		t.Fatal("kmsgJournalMode not set after open failure")
	}
	if got := e.sink.counter("Ext4Error"); got != 1 {
		t.Fatalf("Ext4Error = %v, want 1 via journalctl -k", got)
	}
	if n := len(e.sink.eventsByReason("Ext4Error")); n != 1 {
		t.Fatalf("events = %d, want 1", n)
	}
	if kernelCalls != 1 {
		t.Fatalf("journalctl -k calls = %d, want 1", kernelCalls)
	}
}

// TestKernelDeadlockPermanent: an INFO hung-task line latches
// KernelDeadlock True permanently (NPD permanent-rule parity) —
// counter per match, but a single transition Event and the condition
// never flips back.
func TestKernelDeadlockPermanent(t *testing.T) {
	e := fixture(t)
	e.appendKmsg(t,
		"6,1,3599000000,-;INFO: task jbd2/vda1-8:439 blocked for more than 120 seconds.")
	if err := e.m.SyncKernelMonitor(context.Background(), e.sink); err != nil {
		t.Fatal(err)
	}

	c := condFor(t, e.m, "KernelDeadlock")
	if c.Status != corev1.ConditionTrue || c.Reason != "KernelDeadlock" {
		t.Fatalf("KernelDeadlock = {%s %s}, want True/KernelDeadlock", c.Status, c.Reason)
	}
	if !strings.Contains(c.Message, "jbd2/vda1-8") {
		t.Fatalf("message = %q, want the hung-task line", c.Message)
	}
	if c.GaugeReason != "KernelDeadlock" {
		t.Fatalf("gaugeReason = %q, want KernelDeadlock", c.GaugeReason)
	}
	// Same line also trips the temporary TaskHung rule.
	if got := e.sink.counter("TaskHung"); got != 1 {
		t.Fatalf("TaskHung = %v, want 1", got)
	}
	if got := e.sink.counter("KernelDeadlock"); got != 1 {
		t.Fatalf("KernelDeadlock counter = %v, want 1", got)
	}
	if n := len(e.sink.eventsByReason("KernelDeadlock")); n != 1 {
		t.Fatalf("transition events = %d, want 1", n)
	}

	// A second hung task bumps the counter but does not emit a new
	// Event — the latch is already set.
	e.appendKmsg(t,
		"6,2,3599000001,-;INFO: task kworker/u16:2:99 blocked for more than 240 seconds.")
	if err := e.m.SyncKernelMonitor(context.Background(), e.sink); err != nil {
		t.Fatal(err)
	}
	if got := e.sink.counter("KernelDeadlock"); got != 2 {
		t.Fatalf("KernelDeadlock counter = %v, want 2", got)
	}
	if n := len(e.sink.eventsByReason("KernelDeadlock")); n != 1 {
		t.Fatalf("events after second latch = %d, want 1 (permanent)", n)
	}
	if c := condFor(t, e.m, "KernelDeadlock"); c.Status != corev1.ConditionTrue {
		t.Fatalf("KernelDeadlock cleared: %s (permanent must latch)", c.Status)
	}
}

// TestKernelSoftLockupMonitor: a soft-lockup / RCU-stall kmsg line
// bumps its temporary-rule counter and emits its Event, latches the
// permanent KernelDeadlock (same deadlock class as the hung-task
// signature), and Enters its KernelHungTasks evidence latch — the
// parent's conditions.go altStateKeys turn that latch into the
// KernelHungTasks condition (covered by its own latch-table tests).
func TestKernelSoftLockupMonitor(t *testing.T) {
	for _, tc := range []struct {
		name   string
		line   string
		reason string
		latch  string
	}{
		{"softlockup",
			"watchdog: BUG: soft lockup - CPU#2 stuck for 23s! [kworker/2:1:123]",
			"KernelSoftLockup", "kernel-softlockup"},
		{"rcu-stall",
			"INFO: rcu_preempt self-detected stall on CPU { 3 }",
			"KernelRCUStall", "kernel-rcu-stall"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := fixture(t)
			e.appendKmsg(t, "4,1,3599000000,-;"+tc.line)
			if err := e.m.SyncKernelMonitor(context.Background(), e.sink); err != nil {
				t.Fatal(err)
			}

			if got := e.sink.counter(tc.reason); got != 1 {
				t.Fatalf("%s = %v, want 1", tc.reason, got)
			}
			if n := len(e.sink.eventsByReason(tc.reason)); n != 1 {
				t.Fatalf("%s events = %d, want 1", tc.reason, n)
			}
			// Same deadlock class → the permanent latch + counter.
			if got := e.sink.counter("KernelDeadlock"); got != 1 {
				t.Fatalf("KernelDeadlock counter = %v, want 1", got)
			}
			if !e.m.kernelDeadlock {
				t.Fatalf("%s did not latch KernelDeadlock", tc.reason)
			}
			// The evidence latch lands through the sink — the
			// parent's altStateKeys see it on eval.
			if ev, ok := e.sink.latches[tc.latch]; !ok || ev != tc.line {
				t.Fatalf("evidence latch %s = %q, want the signature line", tc.latch, ev)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// readonly monitor
// ---------------------------------------------------------------------------

// TestReadonlyTargets: ro on a watched mountpoint + watched fstype
// flags; rw, other fstypes, and absent targets pass.
func TestReadonlyTargets(t *testing.T) {
	mounts := procfs.LastByMountPoint(procfs.ParseMounts([]byte(
		"proc /proc proc rw,nosuid,nodev 0 0\n" +
			"/dev/vda1 / ext4 rw,relatime 0 0\n" +
			"/dev/vdb1 /var ext4 ro,relatime 0 0\n" +
			"/dev/vdc1 /var/lib/k0s xfs ro 0 0\n" +
			"tmpfs /var/openebs tmpfs ro 0 0\n" +
			"/dev/vdd1 /data btrfs rw 0 0\n")))
	got := readonlyTargets(mounts,
		[]string{"/", "/var", "/var/lib/k0s", "/var/openebs"},
		[]string{"ext4", "xfs", "btrfs"})
	want := []string{"/var (ext4)", "/var/lib/k0s (xfs)"}
	if len(got) != len(want) {
		t.Fatalf("ro targets = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ro[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestReadonlyCondition: an unexpectedly-ro watched mount latches
// ReadonlyFilesystem True (condition + transition Event); remount rw
// clears it again — the recovery the kmsg monitor couldn't express.
func TestReadonlyCondition(t *testing.T) {
	e := fixture(t)
	if err := e.m.SyncReadonlyMounts(context.Background(), e.sink); err != nil {
		t.Fatal(err)
	}
	c := condFor(t, e.m, "ReadonlyFilesystem")
	if c.Status != corev1.ConditionFalse || c.Reason != "FilesystemIsNotReadOnly" {
		t.Fatalf("baseline = {%s %s}", c.Status, c.Reason)
	}
	if c.GaugeReason != "FilesystemIsReadOnly" {
		t.Fatalf("baseline gaugeReason = %q", c.GaugeReason)
	}

	// Flip /var/lib/k0s ro.
	if err := os.WriteFile(e.mounts, []byte(
		"/dev/vda1 / ext4 rw,relatime 0 0\n"+
			"/dev/vdb1 /var/lib/k0s ext4 ro,relatime 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := e.m.SyncReadonlyMounts(context.Background(), e.sink); err != nil {
		t.Fatal(err)
	}
	c = condFor(t, e.m, "ReadonlyFilesystem")
	if c.Status != corev1.ConditionTrue || c.Reason != "FilesystemIsReadOnly" {
		t.Fatalf("ro = {%s %s}, want True/FilesystemIsReadOnly", c.Status, c.Reason)
	}
	if !strings.Contains(c.Message, "/var/lib/k0s") {
		t.Fatalf("message = %q, want the ro mountpoint", c.Message)
	}
	if n := len(e.sink.eventsByReason("FilesystemIsReadOnly")); n != 1 {
		t.Fatalf("transition events = %d, want 1", n)
	}

	// Staying ro does not re-emit the Event.
	if err := e.m.SyncReadonlyMounts(context.Background(), e.sink); err != nil {
		t.Fatal(err)
	}
	if n := len(e.sink.eventsByReason("FilesystemIsReadOnly")); n != 1 {
		t.Fatalf("steady-state events = %d, want 1", n)
	}

	// Remount rw → condition clears.
	if err := os.WriteFile(e.mounts, []byte(
		"/dev/vda1 / ext4 rw,relatime 0 0\n"+
			"/dev/vdb1 /var/lib/k0s ext4 rw,relatime 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := e.m.SyncReadonlyMounts(context.Background(), e.sink); err != nil {
		t.Fatal(err)
	}
	c = condFor(t, e.m, "ReadonlyFilesystem")
	if c.Status != corev1.ConditionFalse || c.Reason != "FilesystemIsNotReadOnly" {
		t.Fatalf("recovered = {%s %s}, want False/FilesystemIsNotReadOnly", c.Status, c.Reason)
	}
}

// TestReadonlyMissingMounts: a missing mounts file reports an error
// but keeps the previous condition state — it must not flap.
func TestReadonlyMissingMounts(t *testing.T) {
	e := fixture(t)
	if err := os.WriteFile(e.mounts, []byte(
		"/dev/vda1 / ext4 rw,relatime 0 0\n"+
			"/dev/vdb1 /var/lib/k0s ext4 ro 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := e.m.SyncReadonlyMounts(context.Background(), e.sink); err != nil {
		t.Fatal(err)
	}
	if c := condFor(t, e.m, "ReadonlyFilesystem"); c.Status != corev1.ConditionTrue {
		t.Fatalf("setup: ReadonlyFilesystem = %s, want True", c.Status)
	}
	if err := os.Remove(e.mounts); err != nil {
		t.Fatal(err)
	}
	if err := e.m.SyncReadonlyMounts(context.Background(), e.sink); err == nil {
		t.Fatal("expected read error")
	}
	if !e.m.readonlyFS {
		t.Fatal("readonlyFS cleared on read error — must keep previous state")
	}
}
