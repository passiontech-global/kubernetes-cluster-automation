package nodereporter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// ---------------------------------------------------------------------------
// journald source (kubelet-stale monitor + kernel fallback)
// ---------------------------------------------------------------------------

func journalJSON(tsUS int64, msg string) string {
	m, _ := json.Marshal(msg)
	return fmt.Sprintf("{\"__REALTIME_TIMESTAMP\":\"%d\",\"MESSAGE\":%s}", tsUS, m)
}

// TestParseJournalJSON: MESSAGE arrives as a JSON string or a byte
// array (non-UTF8 payloads); malformed lines are skipped.
func TestParseJournalJSON(t *testing.T) {
	data := journalJSON(1700000000000000, `err="node \"n1\" not found"`) + "\n" +
		"not-json-garbage\n" +
		`{"__REALTIME_TIMESTAMP":"1700000001000000","MESSAGE":[104,101,108,108,111]}` + "\n"
	got := parseJournalJSON(data)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(got), got)
	}
	if got[0].tsUS != 1700000000000000 || !strings.Contains(got[0].msg, `not found`) {
		t.Fatalf("entry 0 = %+v", got[0])
	}
	if got[1].msg != "hello" {
		t.Fatalf("byte-array MESSAGE decoded to %q", got[1].msg)
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
// problem_counter and emit Events attached to the node.
func TestKubeletJournalScan(t *testing.T) {
	e := fixture(t)
	e.r.cfg.journalFetch = func(_ context.Context, args ...string) (string, error) {
		return journalJSON(e.now.UnixMicro(), `err="node \"n1\" not found"`) + "\n" +
			journalJSON(e.now.UnixMicro(), "unrelated kubelet noise") + "\n", nil
	}
	e.cycle()

	if got := e.counter("KubeletNodeNotFound"); got != 1 {
		t.Fatalf("counter KubeletNodeNotFound = %v, want 1", got)
	}
	evs := eventsByReason(t, e, "KubeletNodeNotFound")
	if len(evs) != 1 || evs[0].Regarding.Name != "n1" {
		t.Fatalf("events = %+v, want one on n1", evs)
	}
	if !strings.Contains(evs[0].Note, `not found`) {
		t.Fatalf("note = %q", evs[0].Note)
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
	e.r.cfg.journalFetch = func(_ context.Context, args ...string) (string, error) {
		calls = append(calls, args)
		out := payloads[i]
		if i < len(payloads)-1 {
			i++
		}
		return out, nil
	}
	e.cycle()
	e.cycle()

	if got := e.counter("KubeletNodeNotFound"); got != 1 {
		t.Fatalf("counter = %v, want 1 (boundary replay filtered)", got)
	}
	if got := e.counter("KubeletObjectNotRegistered"); got != 1 {
		t.Fatalf("counter = %v, want 1 (newer line counted)", got)
	}
	if len(calls) != 2 {
		t.Fatalf("journalFetch calls = %d, want 2", len(calls))
	}
	since1 := calls[0][len(calls[0])-4]
	since2 := calls[1][len(calls[1])-4]
	want1 := "@" + fmt.Sprint(e.now.Add(-e.r.cfg.LogLookback).Unix())
	want2 := "@" + fmt.Sprint(e.now.Unix())
	if since1 != want1 || since2 != want2 {
		t.Fatalf("--since args = %q then %q, want %q then %q", since1, since2, want1, want2)
	}
}

// TestJournalFetchErrorKeepsCursor: a failed fetch does not advance
// the cursor — the window is retried next cycle.
func TestJournalFetchErrorKeepsCursor(t *testing.T) {
	e := fixture(t)
	fail := true
	e.r.cfg.journalFetch = func(_ context.Context, args ...string) (string, error) {
		if fail {
			return "", fmt.Errorf("journald busy")
		}
		return journalJSON(e.now.UnixMicro(), `err="node \"n1\" not found"`), nil
	}
	e.cycle() // error is logged, not fatal
	if got := e.counter("KubeletNodeNotFound"); got != 0 {
		t.Fatalf("counter = %v, want 0", got)
	}
	fail = false
	e.cycle()
	if got := e.counter("KubeletNodeNotFound"); got != 1 {
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
}

// TestParseKmsgRecord: pri,seq,usec,flags;msg split; a bare line
// passes through with an unknown timestamp.
func TestParseKmsgRecord(t *testing.T) {
	l := parseKmsgRecord([]byte("6,1234,9876543210,-;EXT4-fs error (device vda1): x"))
	if l.msg != "EXT4-fs error (device vda1): x" || l.usec != 9876543210 {
		t.Fatalf("parsed = %+v", l)
	}
	l = parseKmsgRecord([]byte("no header message"))
	if l.msg != "no header message" || l.usec != -1 {
		t.Fatalf("bare line = %+v", l)
	}
	l = parseKmsgRecord([]byte("6,1,notanum,-;broken ts"))
	if l.msg != "broken ts" || l.usec != -1 {
		t.Fatalf("bad ts = %+v", l)
	}
}

// appendKmsg appends one raw kmsg record line to the fake device file.
func (e *env) appendKmsg(t *testing.T, record string) {
	t.Helper()
	f, err := os.OpenFile(e.kmsg, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.WriteString(record + "\n")
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
	e.cycle()

	if got := e.counter("Ext4Error"); got != 1 {
		t.Fatalf("Ext4Error = %v, want 1 (only in-lookback record)", got)
	}
	evs := eventsByReason(t, e, "Ext4Error")
	if len(evs) != 1 || evs[0].Note != "EXT4-fs error (device vda1): recent" {
		t.Fatalf("events = %+v", evs)
	}

	// Live tail: new records emit without the replay filter, even
	// with old boot timestamps.
	e.appendKmsg(t, "4,3,99999,-;EXT4-fs warning (device vdb1): live tail")
	e.cycle()
	if got := e.counter("Ext4Warning"); got != 1 {
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
	e.cycle()
	if got := e.counter("Ext4Error"); got != 0 {
		t.Fatalf("Ext4Error = %v, want 0 (backlog dropped)", got)
	}
	e.appendKmsg(t, "6,2,3599000000,-;EXT4-fs error (device vda1): live")
	e.cycle()
	if got := e.counter("Ext4Error"); got != 1 {
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

	e.cycle() // drain 1: byte-capped → NOT caught up
	if e.r.kmsgScanned {
		t.Fatal("lookback disarmed after a byte-capped drain")
	}
	e.cycle() // drain 2: reaches EOF → caught up, still replay-filtered
	if !e.r.kmsgScanned {
		t.Fatal("kmsgScanned still false after the ring drained to EOF")
	}
	if e.r.kernelDeadlock {
		t.Fatal("stale backlog latched a PERMANENT KernelDeadlock")
	}
	if got := e.counter("TaskHung"); got != 0 {
		t.Fatalf("TaskHung=%v want 0 (all backlog outside lookback)", got)
	}
	if n := len(eventsByReason(t, e, "KernelDeadlock")); n != 0 {
		t.Fatalf("KernelDeadlock events=%d want 0", n)
	}

	// Caught up: a freshly appended record is processed live — even
	// with an old-looking timestamp there is no filter anymore.
	e.appendKmsg(t, "6,99999,60000000,-;EXT4-fs error (device vda1): live")
	e.cycle()
	if got := e.counter("Ext4Error"); got != 1 {
		t.Fatalf("Ext4Error=%v want 1", got)
	}
}

// TestReadKmsgAvailCaughtUpFlag: the drain reports caughtUp when the
// source ran dry (EOF/EAGAIN); the byte-capped case is covered by
// TestKmsgLookbackArmedUntilCaughtUp above.
func TestReadKmsgAvailCaughtUpFlag(t *testing.T) {
	e := fixture(t)
	f, err := os.Open(e.kmsg)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// Fixture kmsg is empty → EOF on first read → caught up.
	if _, caughtUp, err := readKmsgAvail(f); err != nil || !caughtUp {
		t.Fatalf("empty kmsg: caughtUp=%v err=%v, want true,nil", caughtUp, err)
	}
}

// TestKernelJournalFallback: when kmsg cannot be opened the monitor
// falls back to journalctl -k for the process lifetime.
func TestKernelJournalFallback(t *testing.T) {
	e := fixture(t)
	// Point both kmsg candidates at nonexistent paths.
	e.r.cfg.KmsgFile = "/nonexistent/kmsg"
	var kernelCalls int
	e.r.cfg.journalFetch = func(_ context.Context, args ...string) (string, error) {
		for _, a := range args {
			if a == "-k" {
				kernelCalls++
				return journalJSON(e.now.UnixMicro(),
					"EXT4-fs error (device vda1): via journal"), nil
			}
		}
		return "", nil
	}
	e.cycle()
	if !e.r.kmsgJournalMode {
		t.Fatal("kmsgJournalMode not set after open failure")
	}
	if got := e.counter("Ext4Error"); got != 1 {
		t.Fatalf("Ext4Error = %v, want 1 via journalctl -k", got)
	}
	if n := len(eventsByReason(t, e, "Ext4Error")); n != 1 {
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
	e.cycle()

	c := e.cond(t, "KernelDeadlock")
	if c.Status != corev1.ConditionTrue || c.Reason != "KernelDeadlock" {
		t.Fatalf("KernelDeadlock = {%s %s}, want True/KernelDeadlock", c.Status, c.Reason)
	}
	if !strings.Contains(c.Message, "jbd2/vda1-8") {
		t.Fatalf("message = %q, want the hung-task line", c.Message)
	}
	if got := e.gauge("KernelDeadlock", "KernelDeadlock"); got != 1 {
		t.Fatalf("problem_gauge = %v, want 1", got)
	}
	// Same line also trips the temporary TaskHung rule.
	if got := e.counter("TaskHung"); got != 1 {
		t.Fatalf("TaskHung = %v, want 1", got)
	}
	if got := e.counter("KernelDeadlock"); got != 1 {
		t.Fatalf("KernelDeadlock counter = %v, want 1", got)
	}
	if n := len(eventsByReason(t, e, "KernelDeadlock")); n != 1 {
		t.Fatalf("transition events = %d, want 1", n)
	}

	// A second hung task bumps the counter but does not emit a new
	// Event — the latch is already set.
	e.appendKmsg(t,
		"6,2,3599000001,-;INFO: task kworker/u16:2:99 blocked for more than 240 seconds.")
	e.cycle()
	if got := e.counter("KernelDeadlock"); got != 2 {
		t.Fatalf("KernelDeadlock counter = %v, want 2", got)
	}
	if n := len(eventsByReason(t, e, "KernelDeadlock")); n != 1 {
		t.Fatalf("events after second latch = %d, want 1 (permanent)", n)
	}
	e.cycle()
	if c := e.cond(t, "KernelDeadlock"); c.Status != corev1.ConditionTrue {
		t.Fatalf("KernelDeadlock cleared: %s (permanent must latch)", c.Status)
	}
}

// ---------------------------------------------------------------------------
// readonly monitor
// ---------------------------------------------------------------------------

// TestParseProcMounts + readonlyTargets: ro on a watched mountpoint +
// watched fstype flags; rw, other fstypes, and absent targets pass.
func TestReadonlyTargets(t *testing.T) {
	mounts := parseProcMounts([]byte(
		"proc /proc proc rw,nosuid,nodev 0 0\n" +
			"/dev/vda1 / ext4 rw,relatime 0 0\n" +
			"/dev/vdb1 /var ext4 ro,relatime 0 0\n" +
			"/dev/vdc1 /var/lib/k0s xfs ro 0 0\n" +
			"tmpfs /var/openebs tmpfs ro 0 0\n" +
			"/dev/vdd1 /data btrfs rw 0 0\n"))
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
// ReadonlyFilesystem True (condition + gauge + transition Event);
// remount rw clears it again — the recovery the kmsg monitor
// couldn't express.
func TestReadonlyCondition(t *testing.T) {
	e := fixture(t)
	e.cycle()
	if c := e.cond(t, "ReadonlyFilesystem"); c.Status != corev1.ConditionFalse ||
		c.Reason != "FilesystemIsNotReadOnly" {
		t.Fatalf("baseline = {%s %s}", c.Status, c.Reason)
	}
	if got := e.gauge("ReadonlyFilesystem", "FilesystemIsReadOnly"); got != 0 {
		t.Fatalf("baseline gauge = %v, want 0", got)
	}

	// Flip /var/lib/k0s ro.
	if err := os.WriteFile(e.mounts, []byte(
		"/dev/vda1 / ext4 rw,relatime 0 0\n"+
			"/dev/vdb1 /var/lib/k0s ext4 ro,relatime 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e.cycle()
	c := e.cond(t, "ReadonlyFilesystem")
	if c.Status != corev1.ConditionTrue || c.Reason != "FilesystemIsReadOnly" {
		t.Fatalf("ro = {%s %s}, want True/FilesystemIsReadOnly", c.Status, c.Reason)
	}
	if !strings.Contains(c.Message, "/var/lib/k0s") {
		t.Fatalf("message = %q, want the ro mountpoint", c.Message)
	}
	if got := e.gauge("ReadonlyFilesystem", "FilesystemIsReadOnly"); got != 1 {
		t.Fatalf("ro gauge = %v, want 1", got)
	}
	if n := len(eventsByReason(t, e, "FilesystemIsReadOnly")); n != 1 {
		t.Fatalf("transition events = %d, want 1", n)
	}

	// Staying ro does not re-emit the Event.
	e.cycle()
	if n := len(eventsByReason(t, e, "FilesystemIsReadOnly")); n != 1 {
		t.Fatalf("steady-state events = %d, want 1", n)
	}

	// Remount rw → condition + gauge clear.
	if err := os.WriteFile(e.mounts, []byte(
		"/dev/vda1 / ext4 rw,relatime 0 0\n"+
			"/dev/vdb1 /var/lib/k0s ext4 rw,relatime 0 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e.cycle()
	c = e.cond(t, "ReadonlyFilesystem")
	if c.Status != corev1.ConditionFalse || c.Reason != "FilesystemIsNotReadOnly" {
		t.Fatalf("recovered = {%s %s}, want False/FilesystemIsNotReadOnly", c.Status, c.Reason)
	}
	if got := e.gauge("ReadonlyFilesystem", "FilesystemIsReadOnly"); got != 0 {
		t.Fatalf("recovered gauge = %v, want 0", got)
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
	e.cycle()
	if c := e.cond(t, "ReadonlyFilesystem"); c.Status != corev1.ConditionTrue {
		t.Fatalf("setup: ReadonlyFilesystem = %s, want True", c.Status)
	}
	if err := os.Remove(e.mounts); err != nil {
		t.Fatal(err)
	}
	e.cycle() // read error → logged, previous state kept
	if !e.r.readonlyFS {
		t.Fatal("readonlyFS cleared on read error — must keep previous state")
	}
}
