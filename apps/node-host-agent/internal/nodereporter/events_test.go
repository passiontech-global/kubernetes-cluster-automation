package nodereporter

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// appendLog appends one watchdog log line: "<rfc3339> <msg>\n" —
// lib.sh log() parity.
func (e *env) appendLog(t *testing.T, msg string) {
	t.Helper()
	f, err := os.OpenFile(e.log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", e.now.Format(time.RFC3339), msg)
}

// appendRawLog appends bytes verbatim (rotation/partial-line tests).
func (e *env) appendRawLog(t *testing.T, data string) {
	t.Helper()
	f, err := os.OpenFile(e.log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.WriteString(data)
}

// events returns all EventsV1 objects in the event namespace.
func (e *env) events(t *testing.T) []eventsv1.Event {
	t.Helper()
	l, err := e.cs.EventsV1().Events("default").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return l.Items
}

func eventsByReason(t *testing.T, e *env, reason string) []eventsv1.Event {
	t.Helper()
	var out []eventsv1.Event
	for _, ev := range e.events(t) {
		if ev.Reason == reason {
			out = append(out, ev)
		}
	}
	return out
}

// TestEventEmittedOnMatch: a matching log line creates a Warning
// Event on Node/n1 in the default namespace and bumps the counter.
func TestEventEmittedOnMatch(t *testing.T) {
	e := fixture(t)
	e.appendLog(t, "ACTION: restarting k0sworker - informer-zombie hits=70/10min (persisted 2x)")
	e.cycle()

	if got := e.counter("K0sworkerRestarted"); got != 1 {
		t.Fatalf("problem_counter{K0sworkerRestarted} = %v, want 1", got)
	}
	evs := eventsByReason(t, e, "K0sworkerRestarted")
	if len(evs) != 1 {
		t.Fatalf("got %d K0sworkerRestarted events, want 1", len(evs))
	}
	ev := evs[0]
	if ev.Regarding.Kind != "Node" || ev.Regarding.Name != "n1" {
		t.Fatalf("event regarding = %s/%s, want Node/n1", ev.Regarding.Kind, ev.Regarding.Name)
	}
	if ev.Type != "Warning" || ev.ReportingController != "node-host-agent" {
		t.Fatalf("event type/reporter = %s/%s", ev.Type, ev.ReportingController)
	}
	wantNote := "ACTION: restarting k0sworker - informer-zombie hits=70/10min (persisted 2x)"
	if ev.Note != wantNote {
		t.Fatalf("note = %q, want %q", ev.Note, wantNote)
	}
}

// TestMultipleRulesOneLine: NPD fires every matching rule — one line
// matching two patterns yields two counters and two events.
func TestMultipleRulesOneLine(t *testing.T) {
	e := fixture(t)
	// Matches K0sworkerRestarted (ACTION: restarting k0sworker) AND
	// KubeletInformerZombie (informer-zombie).
	e.appendLog(t, "ACTION: restarting k0sworker - informer-zombie hits=70/10min")
	e.cycle()
	if got := e.counter("K0sworkerRestarted"); got != 1 {
		t.Fatalf("counter K0sworkerRestarted = %v", got)
	}
	if got := e.counter("KubeletInformerZombie"); got != 1 {
		t.Fatalf("counter KubeletInformerZombie = %v", got)
	}
	if n := len(eventsByReason(t, e, "KubeletInformerZombie")); n != 1 {
		t.Fatalf("KubeletInformerZombie events = %d", n)
	}
}

// TestEventDedup: an identical reason+message inside the TTL does not
// create a second Event — it series-patches count/lastObservedTime on
// the existing object. The counter still increments per line.
func TestEventDedup(t *testing.T) {
	e := fixture(t)
	e.appendLog(t, "ACTION: restarting nebula@interdc - nebula-isolated (persisted 2x)")
	e.cycle()
	e.appendLog(t, "ACTION: restarting nebula@interdc - nebula-isolated (persisted 2x)")
	e.cycle()

	if got := e.counter("NebulaRestarted"); got != 2 {
		t.Fatalf("counter = %v, want 2 (one per matched line)", got)
	}
	evs := eventsByReason(t, e, "NebulaRestarted")
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1 aggregated", len(evs))
	}
	if evs[0].Series == nil || evs[0].Series.Count != 2 {
		t.Fatalf("series = %+v, want count=2", evs[0].Series)
	}

	// A different message → a distinct Event.
	e.appendLog(t, "ACTION: restarting nebula@interdc - nebula-degraded (persisted 1x)")
	e.cycle()
	if n := len(eventsByReason(t, e, "NebulaRestarted")); n != 2 {
		t.Fatalf("got %d events after distinct message, want 2", n)
	}
}

// TestDedupTTLExpiry: past the aggregation TTL an identical line
// creates a fresh Event instead of patching the old one.
func TestDedupTTLExpiry(t *testing.T) {
	e := fixture(t)
	e.appendLog(t, "ACTION: heal egress 10.0.0.1 rule -> ip table 100 (was ip)")
	e.cycle()
	e.now = e.now.Add(2 * time.Hour) // beyond the 1h dedup TTL
	e.appendLog(t, "ACTION: heal egress 10.0.0.1 rule -> ip table 100 (was ip)")
	e.cycle()
	if n := len(eventsByReason(t, e, "TincEgressHeal")); n != 2 {
		t.Fatalf("got %d events after TTL, want 2", n)
	}
}

// TestReplayLookback: on the first scan only lines newer than the
// lookback window replay — older or timestamp-less lines are skipped.
func TestReplayLookback(t *testing.T) {
	e := fixture(t)
	old := e.now.Add(-time.Hour).Format(time.RFC3339)
	fresh := e.now.Add(-time.Minute).Format(time.RFC3339)
	raw := fmt.Sprintf("%s ACTION: restarting k0sworker - old\n", old) +
		"no-timestamp ACTION: restarting k0sworker - bad\n" +
		fmt.Sprintf("%s ACTION: restarting k0sworker - recent\n", fresh)
	e.appendRawLog(t, raw)
	e.cycle()

	if got := e.counter("K0sworkerRestarted"); got != 1 {
		t.Fatalf("counter = %v, want 1 (only the in-lookback line)", got)
	}
	evs := eventsByReason(t, e, "K0sworkerRestarted")
	if len(evs) != 1 || evs[0].Note != "ACTION: restarting k0sworker - recent" {
		t.Fatalf("replayed events = %+v", evs)
	}

	// After the first scan, new lines emit regardless of timestamp.
	e.appendLog(t, "ACTION: restarting k0sworker - new")
	e.cycle()
	if got := e.counter("K0sworkerRestarted"); got != 2 {
		t.Fatalf("counter after second cycle = %v, want 2", got)
	}
}

// TestPartialLine: a line split across two reads isn't half-matched —
// it emits only once the newline arrives.
func TestPartialLine(t *testing.T) {
	e := fixture(t)
	e.appendRawLog(t, e.now.Format(time.RFC3339)+" ACTION: restarting k0sworker - split")
	e.cycle()
	if n := len(eventsByReason(t, e, "K0sworkerRestarted")); n != 0 {
		t.Fatalf("partial line emitted %d events, want 0", n)
	}
	e.appendRawLog(t, " second half\n")
	e.cycle()
	if n := len(eventsByReason(t, e, "K0sworkerRestarted")); n != 1 {
		t.Fatalf("completed line emitted %d events, want 1", n)
	}
}

// TestLogRotation: when the file shrinks (watchdog caps it at ~1MB by
// rewrite) the offset resets and the rewritten content is scanned —
// the dedup map absorbs repeats already emitted.
func TestLogRotation(t *testing.T) {
	e := fixture(t)
	e.appendLog(t, "ACTION: restarting k0sworker - before-rotation")
	e.cycle()
	if n := len(eventsByReason(t, e, "K0sworkerRestarted")); n != 1 {
		t.Fatalf("pre-rotation events = %d", n)
	}
	if err := os.WriteFile(e.log, []byte(e.now.Format(time.RFC3339)+" ACTION: restarting k0sworker - after-rotation\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e.cycle()
	// Message differs → new event (dedup is reason+message keyed).
	if n := len(eventsByReason(t, e, "K0sworkerRestarted")); n != 2 {
		t.Fatalf("post-rotation events = %d, want 2", n)
	}
}

// TestFailedFirstReadKeepsReplay: a failed first read must NOT arm
// logScanned — otherwise the next successful read would replay the
// entire history as live lines (event storm + counter inflation).
func TestFailedFirstReadKeepsReplay(t *testing.T) {
	e := fixture(t)
	// Point the log path at a directory: Stat+Open+Seek succeed,
	// ReadAll fails ("is a directory") — the flag used to be armed
	// between Open and Read.
	e.r.cfg.WatchdogLogFile = e.dir
	e.cycle()

	// Restore a real log whose only line is far outside lookback —
	// with the bug it would scan as live and emit.
	e.r.cfg.WatchdogLogFile = e.log
	e.appendRawLog(t, e.now.Add(-time.Hour).Format(time.RFC3339)+
		" ACTION: restarting k0sworker - ancient\n")
	e.cycle()
	if got := e.counter("K0sworkerRestarted"); got != 0 {
		t.Fatalf("counter = %v, want 0 (replay filter must stay armed)", got)
	}
	if n := len(eventsByReason(t, e, "K0sworkerRestarted")); n != 0 {
		t.Fatalf("ancient line emitted %d events, want 0", n)
	}
}

// TestRotationRescanUsesLookback: a file-shrink rotation resets the
// offset and the retained tail is re-scanned through the replay
// filter — an old retained line must NOT re-increment the counter or
// re-emit an Event, while a fresh retained line still does.
func TestRotationRescanUsesLookback(t *testing.T) {
	e := fixture(t)
	e.appendLog(t, "ACTION: restarting k0sworker - l1")
	e.appendLog(t, "ACTION: restarting k0sworker - l2")
	e.appendLog(t, "ACTION: restarting k0sworker - l3")
	e.cycle()
	if got := e.counter("K0sworkerRestarted"); got != 3 {
		t.Fatalf("pre-rotation counter = %v, want 3", got)
	}

	// Watchdog rewrite: a smaller file retaining one old line
	// (outside lookback) plus one fresh line.
	old := e.now.Add(-time.Hour).Format(time.RFC3339)
	fresh := e.now.Format(time.RFC3339)
	rotated := old + " ACTION: restarting k0sworker - retained-old\n" +
		fresh + " ACTION: restarting k0sworker - retained-new\n"
	if err := os.WriteFile(e.log, []byte(rotated), 0o644); err != nil {
		t.Fatal(err)
	}
	e.cycle()

	if got := e.counter("K0sworkerRestarted"); got != 4 {
		t.Fatalf("post-rotation counter = %v, want 4 (retained-old must be filtered)", got)
	}
	evs := eventsByReason(t, e, "K0sworkerRestarted")
	if len(evs) != 4 {
		t.Fatalf("post-rotation events = %d, want 4", len(evs))
	}
	for _, ev := range evs {
		if strings.Contains(ev.Note, "retained-old") {
			t.Fatalf("old retained line re-emitted as live: %q", ev.Note)
		}
	}
}

// TestDedupKeyUsesTruncatedNote: two notes differing only past the
// maxEventNote truncation share one Event — the stored Note is
// identical, so the dedup key must be too.
func TestDedupKeyUsesTruncatedNote(t *testing.T) {
	e := fixture(t)
	pad := strings.Repeat("x", 1200)
	e.appendLog(t, "ACTION: restarting k0sworker - "+pad+"A")
	e.cycle()
	e.appendLog(t, "ACTION: restarting k0sworker - "+pad+"B")
	e.cycle()

	evs := eventsByReason(t, e, "K0sworkerRestarted")
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1 aggregated (identical truncated note)", len(evs))
	}
	if evs[0].Series == nil || evs[0].Series.Count != 2 {
		t.Fatalf("series = %+v, want count=2", evs[0].Series)
	}
	if len(evs[0].Note) != maxEventNote {
		t.Fatalf("note len = %d, want %d", len(evs[0].Note), maxEventNote)
	}
	if got := e.counter("K0sworkerRestarted"); got != 2 {
		t.Fatalf("counter = %v, want 2", got)
	}
}

// TestMissingLogFile: no watchdog log on this node → clean no-op.
func TestMissingLogFile(t *testing.T) {
	e := fixture(t)
	e.cycle() // must not error or panic
	if got := e.counter("K0sworkerRestarted"); got != 0 {
		t.Fatalf("counter = %v", got)
	}
}

// TestSelfHealActionReasons: the self-heal reasons called out by the
// NPD filelog rules fire from representative watchdog log lines.
func TestSelfHealActionReasons(t *testing.T) {
	e := fixture(t)
	lines := []struct {
		msg    string
		reason string
	}{
		{"ACTION: restarting k0sworker - kubelet-watch-wedge unseen-pods=3 (persisted 2x)", "K0sworkerRestarted"},
		{"ACTION: restarting nebula@interdc - nebula-isolated (persisted 1x)", "NebulaRestarted"},
		{"ACTION: ctr tasks delete -f ab12cd34 - wedged task dir dead >=5m", "CtrTaskWedged"},
		{"ACTION: rm orphaned task dir ab12cd34 - init dead, task not in containerd", "CtrTaskWedged"},
		{"KONNECTIVITY-IP-RESTART: recreating konnectivity-agent sandbox - stale identifier host=10.0.0.1 != node-ip=10.0.0.2", "KonnectivityStaleId"},
		{"POD-TEARDOWN-FORCE-DELETE: force-delete pod ns/name (uid deadbeef) - Terminating 900s, zero live tasks", "StuckPodForceDeleted"},
		{"ACTION: killed cilium-agent container - healthz down 2x (kubelet se restart)", "CiliumAgentDown"},
		{"suspect: dns-resolv-stale node-local-dns-abc12 (check 2/2)", "DnsResolvStale"},
		{"STATE-ENTER: module-failed-13-nebula-health rc=1", "WatchdogModuleFailed"},
		{"WATCHDOG-FAILED runner exit 1", "WatchdogRunFailed"},
		{"suspect: pod-teardown-wedged stuck=3 (check 2/2)", "PodTeardownWedged"},
		{"suspect: kubelet-runtime-stall phantom-pods poddirs=7 tasks=0", "KubeletRuntimeStall"},
		{"suspect: kubelet-runtime-stall informer-zombie hits=80/10min", "KubeletInformerZombie"},
		{"STATE-ENTER: nebula-isolated", "NebulaIsolatedEnter"},
		{"suspect: node-overloaded load15=42 ncpu=4", "NodeOverloaded"},
		{"STATE-ENTER: clock-unsync drift=+612ms esterror=900000", "ClockUnsynchronized"},
		{"ACTION: restarting systemd-timesyncd.service - clock unsynchronized (persisted 2x)", "ClockUnsynchronized"},
		{"ACTION: restarting chrony.service - clock unsynchronized (persisted 1x)", "ClockUnsynchronized"},
		{"STATE-ENTER: conntrack-pressure used=0.93 of 262144", "ConntrackPressure"},
		{"suspect: nf_conntrack: table full, dropping packet (dmesg)", "ConntrackPressure"},
		{"nf_conntrack: expectation table full, dropping packet", "ConntrackPressure"},
		{"STATE-ENTER: cilium-ipam-exhausted leaked=41 avail=1", "CiliumIPAMExhausted"},
		{"FailedCreatePodSandBox: Allocating IPv4: no more IPs available", "CiliumIPAMExhausted"},
		{"ACTION: removed corrupted image registry.local/app@sha256:dead - content digest not found", "CorruptedImageRemoved"},
		{"ACTION: removed corrupted image docker.io/library/nginx:1.25 - failed to extract layer", "CorruptedImageRemoved"},
	}
	for _, l := range lines {
		e.appendLog(t, l.msg)
	}
	e.cycle()
	for _, l := range lines {
		if got := e.counter(l.reason); got < 1 {
			t.Errorf("reason %s: counter = %v, want >=1 (line %q)", l.reason, got, l.msg)
		}
		if n := len(eventsByReason(t, e, l.reason)); n < 1 {
			t.Errorf("reason %s: %d events, want >=1 (line %q)", l.reason, n, l.msg)
		}
	}
}

// TestLogPendingCap: a line that never terminates cannot grow the
// carry buffer without bound — only the last maxLogPendingBytes are
// kept for the next cycle.
func TestLogPendingCap(t *testing.T) {
	e := fixture(t)
	e.appendRawLog(t, strings.Repeat("x", maxLogPendingBytes+1000))
	e.cycle()
	if got := len(e.r.logPending); got != maxLogPendingBytes {
		t.Fatalf("logPending = %d, want capped at %d", got, maxLogPendingBytes)
	}

	// Same cap on the partial line trailing a completed one.
	e.appendRawLog(t, "\n"+strings.Repeat("y", maxLogPendingBytes+1000))
	e.cycle()
	if got := len(e.r.logPending); got != maxLogPendingBytes {
		t.Fatalf("logPending after completed line = %d, want %d", got, maxLogPendingBytes)
	}
}

// TestOversizedFirstScanReadsTail: an unrotated log bigger than
// maxLogReadBytes is not slurped whole — the first scan jumps to the
// last maxLogReadBytes, drops the cut partial line, and still finds
// fresh events in the tail.
func TestOversizedFirstScanReadsTail(t *testing.T) {
	e := fixture(t)
	fresh := e.now.Format(time.RFC3339)
	var b strings.Builder
	for b.Len() < maxLogReadBytes+1024 {
		fmt.Fprintf(&b, "%s filler-%d\n", fresh, b.Len())
	}
	fmt.Fprintf(&b, "%s ACTION: restarting k0sworker - tail-line\n", fresh)
	e.appendRawLog(t, b.String())
	e.cycle()

	if got := e.counter("K0sworkerRestarted"); got != 1 {
		t.Fatalf("counter = %v, want 1 (tail line still detected)", got)
	}
	if n := len(eventsByReason(t, e, "K0sworkerRestarted")); n != 1 {
		t.Fatalf("events = %d, want 1", n)
	}
	fi, err := os.Stat(e.log)
	if err != nil {
		t.Fatal(err)
	}
	if e.r.logOffset != fi.Size() {
		t.Fatalf("logOffset = %d, want file size %d (full tail consumed)", e.r.logOffset, fi.Size())
	}
}

// TestEmittedEventsCap: after TTL pruning the dedup map is hard-capped
// at maxEmittedEvents — the least-recently-observed entries are
// evicted first so a flood of distinct reason+message pairs can't
// grow the map without limit.
func TestEmittedEventsCap(t *testing.T) {
	e := fixture(t)
	for i := 0; i < maxEmittedEvents+50; i++ {
		key := fmt.Sprintf("Reason\x1fmsg-%d", i)
		e.r.emittedEvts[key] = &emittedEvent{
			name: "n1.ev", count: 1,
			at: e.now.Add(-time.Duration(i) * time.Second),
		}
	}
	e.r.pruneEmitted()
	if got := len(e.r.emittedEvts); got != maxEmittedEvents {
		t.Fatalf("emittedEvts = %d, want capped at %d", got, maxEmittedEvents)
	}
	if _, ok := e.r.emittedEvts["Reason\x1fmsg-0"]; !ok {
		t.Fatal("freshest entry was evicted")
	}
	oldest := fmt.Sprintf("Reason\x1fmsg-%d", maxEmittedEvents+49)
	if _, ok := e.r.emittedEvts[oldest]; ok {
		t.Fatal("oldest entry was not evicted")
	}
}
