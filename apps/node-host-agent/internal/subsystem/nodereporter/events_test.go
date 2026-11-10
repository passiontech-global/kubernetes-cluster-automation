package nodereporter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	eventsv1 "k8s.io/api/events/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stesting "k8s.io/client-go/testing"
)

// appendLog appends one watchdog log line: "<rfc3339> <msg>\n" —
// lib.sh log() parity.
func (e *env) appendLog(t *testing.T, msg string) {
	t.Helper()
	f, err := os.OpenFile(e.log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	_, _ = fmt.Fprintf(f, "%s %s\n", e.now.Format(time.RFC3339), msg)
}

// appendRawLog appends bytes verbatim (rotation/partial-line tests).
func (e *env) appendRawLog(t *testing.T, data string) {
	t.Helper()
	f, err := os.OpenFile(e.log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	_, _ = f.WriteString(data)
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
	raw := old + " ACTION: restarting k0sworker - old\n" +
		"no-timestamp ACTION: restarting k0sworker - bad\n" +
		fresh + " ACTION: restarting k0sworker - recent\n"
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
		{"ACTION zombie-storm: pod_uid=11111111-2222-3333-4444-555555555555 zombies=640 ppid=777", "ZombieProcessStorm"},
		{"ACTION cilium-mtu-drift: cilium=1500 nebula=1300", "CiliumMTUExceedsOverlay"},
		{"ACTION d-state-storm: count=7 runtime=3 wchan=runc=umount_tree", "KernelHungTasks"},
		// infra latch→event surface — one Event per STATE-ENTER of
		// a latch that maps to a permanent NodeCondition.
		{"STATE-ENTER: nebula-degraded relays_only", "NebulaDegraded"},
		{"STATE-ENTER: cilium-envoy-down admin_ready_fails=2", "CiliumEnvoyDown"},
		{"STATE-ENTER: cilium-bpf-map-pressure cilium_ct4_global=950/1000", "CiliumBPFMapPressure"},
		{"STATE-ENTER: spegel-mirror-degraded pod=kube-system/spegel-x1 Ready=False", "SpegelMirrorDegraded"},
		{"STATE-ENTER: calico-veth-leak cali=63 pods=5", "CalicoVethLeak"},
		{"STATE-ENTER: calico-felix-down readiness_probe_fails=2", "CalicoFelixDown"},
		{"STATE-ENTER: fail2ban-down service=inactive", "Fail2banDown"},
		{"STATE-ENTER: kernel-keys-pressure usage=0.96", "KernelKeysPressure"},
		{"STATE-ENTER: cp-cert-reload-stale reload_age=7200s", "ControlPlaneCertReloadStale"},
		{"ACTION psi-memory-thrash: psi_full_avg60=30.0 mem_free=0.050 fails=2", "NodeMemoryPSIThrashing"},
		// leak-pressure latch→event surface.
		{"STATE-ENTER: kernel-slab-leak sunreclaim_ratio=0.412", "KernelSlabLeak"},
		{"STATE-ENTER: nebula-pmtu-blackhole target=10.8.0.1 df_size=1200", "NebulaPMTUBlackhole"},
		// kernel/host deep-failure + hygiene latch→event surface.
		{"STATE-ENTER: containerd-corrupt meta.db open failed: corrupt", "ContainerdCorrupt"},
		{"STATE-ENTER: fs-readonly mount=/var/lib/k0s fstype=ext4", "FilesystemReadOnly"},
		{"STATE-ENTER: pid-fd-pressure pid_ratio=0.95 fd_ratio=0.91", "KernelResourceExhaustion"},
		{"STATE-ENTER: clock-skew offset=+2.31s source=chronyc", "ClockSkewDetected"},
		{"STATE-ENTER: kubeconfig-cert-expiring kubeconfig-cert-expiring: embedded client cert expires in 9d", "KubeconfigCertExpiring"},
		{"STATE-ENTER: cpu-steal-pressure steal_ratio=0.41 fails=3", "CPUStealPressure"},
		{"STATE-ENTER: cgroup-dying-leak nr_dying_descendants=6200", "CgroupDyingLeak"},
		{"STATE-ENTER: systemd-session-bloat abandoned=24 dbus_latency=3.2s", "SystemdSessionBloat"},
		{"STATE-ENTER: kernel-net-shim-degraded shim-rss-high pid=777 rss=250MiB", "KernelNetShimDegraded"},
		// W21 latch→event surface — the three ACTION-entry rules.
		{"ACTION cilium-envoy-xds-reject: update_rejected=12 fails=3", "CiliumEnvoyXDSReject"},
		{"ACTION nebula-mtu-blackhole: peer=10.8.0.9 df_size=1200", "NebulaMTUBlackhole"},
		{"ACTION page-alloc-failure: page allocation failure: order:3", "KernelPageAllocFailure"},
		// sig13 watch-cache wedge latch — STATE-ENTER per episode.
		{"STATE-ENTER: apiserver-cache-wedged", "ApiserverWatchCacheWedged"},
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

// TestJournaldUnreadableEvent: the journalwatch STATE-ENTER line
// (one per latch entry) emits a JournaldUnreadable Event + counter —
// the bare "suspect: journal-unreadable" line must NOT match (it's
// the cadence-throttled re-reminder, not a new incident).
func TestJournaldUnreadableEvent(t *testing.T) {
	e := fixture(t)
	e.appendLog(t, "STATE-ENTER: journal-unreadable read failed: signal: killed")
	e.appendLog(t, "suspect: journal-unreadable read failed: signal: killed — 5 consecutive journal reads produced nothing")
	e.cycle()
	if got := e.counter("JournaldUnreadable"); got != 1 {
		t.Fatalf("problem_counter{JournaldUnreadable} = %v, want 1 (STATE-ENTER only)", got)
	}
	if n := len(eventsByReason(t, e, "JournaldUnreadable")); n != 1 {
		t.Fatalf("JournaldUnreadable events = %d, want 1", n)
	}
}

// appendRawTo appends bytes verbatim to an ARBITRARY watchdog-log
// generation path (the .1 rotation-tail test drives the rotated file
// directly).
func (e *env) appendRawTo(t *testing.T, path, data string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	_, _ = f.WriteString(data)
}

// TestRotationDrainsDotOneTail: the watchdog store rotates by rename
// (live → .1); lines appended to the old generation AFTER the last
// read live on in .1. On the shrink the reader must drain that tail
// FIRST and then the fresh file from offset 0 — the events it maps
// onto are neither lost nor reordered, the fresh lines still land,
// and the offset restarts at the fresh file's own coordinates (the
// drained tail's length must not shift it).
func TestRotationDrainsDotOneTail(t *testing.T) {
	e := fixture(t)
	e.appendLog(t, "ACTION: restarting k0sworker - pre-rotation")
	e.cycle()
	if got := e.counter("K0sworkerRestarted"); got != 1 {
		t.Fatalf("pre-rotation counter = %v, want 1", got)
	}
	// Advance the offset without a match — the tail that follows must
	// NOT re-deliver this filler.
	e.appendLog(t, "unmatched filler line")
	e.cycle()

	// Rotate exactly like the store: live → .1, then the old
	// generation grows one more line (the pre-rename append the
	// reader has not seen), then the fresh live file starts.
	if err := os.Rename(e.log, e.log+".1"); err != nil {
		t.Fatal(err)
	}
	e.appendRawTo(t, e.log+".1",
		e.now.Format(time.RFC3339)+" ACTION: restarting k0sworker - tail-of-old-generation\n")
	e.appendLog(t, "ACTION: restarting k0sworker - post-rotation")

	e.cycle()

	if got := e.counter("K0sworkerRestarted"); got != 3 {
		t.Fatalf("counter = %v, want 3 (tail + post-rotation both counted)", got)
	}
	evs := eventsByReason(t, e, "K0sworkerRestarted")
	if len(evs) != 3 {
		t.Fatalf("events = %d, want 3", len(evs))
	}
	if !strings.Contains(evs[1].Note, "tail-of-old-generation") ||
		!strings.Contains(evs[2].Note, "post-rotation") {
		t.Fatalf("tail lines out of order: %q then %q",
			evs[1].Note, evs[2].Note)
	}
	// The offset must sit at the FRESH file's end — the .1 tail's
	// bytes must not have shifted it (a shifted offset would skip a
	// window of the new file every cycle).
	fi, err := os.Stat(e.log)
	if err != nil {
		t.Fatal(err)
	}
	if e.r.logOffset != fi.Size() {
		t.Fatalf("logOffset = %d, want the fresh file size %d",
			e.r.logOffset, fi.Size())
	}
	// The next cycle must not re-emit the drained lines.
	e.cycle()
	if got := e.counter("K0sworkerRestarted"); got != 3 {
		t.Fatalf("counter after re-cycle = %v, want 3 (no re-delivery)", got)
	}
}

// TestRotationFreshLinesAreNotReplay: after a REAL rename rotation
// (non-empty .1 tail) with the scan already armed, only the
// OLD-generation bytes replay through the lookback filter — the
// fresh file's lines are live events even when the blanket replay
// flag of the pre-fix code would have filtered them (an unparseable
// timestamp, or one outside the lookback window). The stale .1 tail
// line (an hour old) must stay filtered.
func TestRotationFreshLinesAreNotReplay(t *testing.T) {
	e := fixture(t)
	e.appendLog(t, "ACTION: restarting k0sworker - pre")
	e.cycle()
	base := e.counter("K0sworkerRestarted")

	// Rotate like the store: live → .1; the old generation grows one
	// line the reader has not seen — timestamped OUTSIDE the lookback
	// window, so it must be replay-filtered; then the fresh live file
	// starts SHORTER than the old offset (the shrink is the rotation
	// signal) with a line whose timestamp does not parse at all (the
	// discriminator: replay=true drops ts-less lines, live counting
	// keeps them).
	if err := os.Rename(e.log, e.log+".1"); err != nil {
		t.Fatal(err)
	}
	e.appendRawTo(t, e.log+".1",
		e.now.Add(-time.Hour).Format(time.RFC3339)+
			" ACTION: restarting k0sworker - stale-tail padding padding\n")
	e.appendRawLog(t,
		"bad ACTION: restarting k0sworker - post-rotation\n")

	e.cycle()

	if got := e.counter("K0sworkerRestarted"); got != base+1 {
		t.Fatalf("counter = %v, want +%d (stale tail filtered, fresh "+
			"ts-less line counted as live)", got, 1)
	}
	for _, ev := range eventsByReason(t, e, "K0sworkerRestarted") {
		if strings.Contains(ev.Note, "stale-tail") {
			t.Fatalf("stale .1 tail line emitted as live: %q", ev.Note)
		}
	}
	found := false
	for _, ev := range eventsByReason(t, e, "K0sworkerRestarted") {
		if strings.Contains(ev.Note, "post-rotation") {
			found = true
		}
	}
	if !found {
		t.Fatal("fresh post-rotation line was replay-filtered and lost")
	}
	// The offset must sit at the fresh file's end (the tail's bytes
	// belong to the old generation's coordinates).
	fi, err := os.Stat(e.log)
	if err != nil {
		t.Fatal(err)
	}
	if e.r.logOffset != fi.Size() {
		t.Fatalf("logOffset = %d, want the fresh file size %d",
			e.r.logOffset, fi.Size())
	}
}

// TestInodePressureEvents: the inode-pressure inode-pressure latch's
// STATE-ENTER line emits a Warning Event (reason InodePressure, note
// carries the offending mount + ratio) and its STATE-EXIT line emits
// an informational (Normal) Event for the clean episode end.
func TestInodePressureEvents(t *testing.T) {
	e := fixture(t)
	e.appendLog(t, "STATE-ENTER: inode-pressure mount=/var/openebs/local ratio=0.970 >= 0.95")
	e.cycle()
	if got := e.counter("InodePressure"); got != 1 {
		t.Fatalf("problem_counter{InodePressure} = %v, want 1", got)
	}
	evs := eventsByReason(t, e, "InodePressure")
	if len(evs) != 1 {
		t.Fatalf("InodePressure events = %d, want 1", len(evs))
	}
	if evs[0].Type != "Warning" || !strings.Contains(evs[0].Note, "mount=/var/openebs/local") {
		t.Fatalf("entry event = %s/%q want Warning with mount detail",
			evs[0].Type, evs[0].Note)
	}
	e.appendLog(t, "STATE-EXIT: inode-pressure")
	e.cycle()
	healthy := eventsByReason(t, e, "FilesystemInodesHealthy")
	if len(healthy) != 1 {
		t.Fatalf("FilesystemInodesHealthy events = %d, want 1", len(healthy))
	}
	if healthy[0].Type != "Normal" {
		t.Fatalf("exit event type = %s, want Normal", healthy[0].Type)
	}
}

// --- dedup failure semantics (emitEvent's patch/create error paths) ---

// patchEventsReactor fails every Events patch with the given error.
func patchEventsReactor(e *env, err error) {
	e.cs.Fake.PrependReactor("patch", "events",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, err
		})
}

func createsCount(t *testing.T, e *env) int {
	t.Helper()
	n := 0
	for _, a := range e.cs.Actions() {
		if a.GetVerb() == "create" && a.GetResource().Resource == "events" {
			n++
		}
	}
	return n
}

// TestEmitEventPatchFailureKeepsEntry: a persistent non-NotFound
// patch failure reports the error and KEEPS the dedup entry —
// recreating a fresh object per occurrence would spam unbounded
// Events for as long as the failure lasts.
func TestEmitEventPatchFailureKeepsEntry(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	if err := e.r.emitEvent(ctx, "X", "same note", "Warning"); err != nil {
		t.Fatal(err)
	}
	patchEventsReactor(e, errors.New("apiserver wedged"))
	if err := e.r.emitEvent(ctx, "X", "same note", "Warning"); err == nil {
		t.Fatal("patch failure not reported")
	}
	if _, ok := e.r.emittedEvts["X\x1fsame note"]; !ok {
		t.Fatal("dedup entry dropped on a non-NotFound patch failure")
	}
	if n := createsCount(t, e); n != 1 {
		t.Fatalf("creates = %d, want 1 (no recreate under a patch failure)", n)
	}
}

// TestEmitEventNotFoundRecreates: a NotFound patch failure means the
// Event TTL'd away — the stale entry is dropped and the next
// occurrence recreates.
func TestEmitEventNotFoundRecreates(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()
	if err := e.r.emitEvent(ctx, "X", "same note", "Warning"); err != nil {
		t.Fatal(err)
	}
	patchEventsReactor(e, apierrors.NewNotFound(
		schema.GroupResource{Group: "events.k8s.io", Resource: "events"}, "gone"))
	if err := e.r.emitEvent(ctx, "X", "same note", "Warning"); err != nil {
		t.Fatalf("NotFound recreate failed: %v", err)
	}
	if n := createsCount(t, e); n != 2 {
		t.Fatalf("creates = %d, want 2 (stale entry recreated)", n)
	}
	if _, ok := e.r.emittedEvts["X\x1fsame note"]; !ok {
		t.Fatal("recreated event not tracked for dedup")
	}
}

// TestEmitEventCreateError: a failed create reports the error and
// stores no dedup entry — the next occurrence retries the create.
func TestEmitEventCreateError(t *testing.T) {
	e := fixture(t)
	e.cs.Fake.PrependReactor("create", "events",
		func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("quota exceeded")
		})
	err := e.r.emitEvent(context.Background(), "X", "note", "Warning")
	if err == nil || !strings.Contains(err.Error(), "create event") {
		t.Fatalf("create error = %v, want a wrapped create failure", err)
	}
	if len(e.r.emittedEvts) != 0 {
		t.Fatalf("failed create stored dedup entries: %v", e.r.emittedEvts)
	}
}

// TestEventNoteTruncated: notes past maxEventNote are truncated
// BEFORE keying, so oversized watchdog lines cannot fail the create
// or fork unbounded dedup entries.
func TestEventNoteTruncated(t *testing.T) {
	e := fixture(t)
	big := strings.Repeat("y", 3*maxEventNote)
	if err := e.r.emitEvent(context.Background(), "X", big, "Warning"); err != nil {
		t.Fatal(err)
	}
	evs := eventsByReason(t, e, "X")
	if len(evs) != 1 {
		t.Fatalf("events = %d, want 1", len(evs))
	}
	if len(evs[0].Note) != maxEventNote {
		t.Fatalf("note len = %d, want %d", len(evs[0].Note), maxEventNote)
	}
}

// --- log-tail mechanics ---

// TestProcessLogLineReplayRules: an empty line is a no-op; on the
// replay scan unparseable timestamps are skipped (a restart must not
// re-report history it cannot date), while live mode accepts the
// same undated line.
func TestProcessLogLineReplayRules(t *testing.T) {
	e := fixture(t)
	ctx := context.Background()

	e.r.processLogLine(ctx, nil, false) // empty — no-op, no panic

	e.r.processLogLine(ctx, []byte("not-a-timestamp node-overloaded hard"), true)
	if n := len(e.events(t)); n != 0 {
		t.Fatalf("replay emitted %d events from an undated line", n)
	}
	e.r.processLogLine(ctx, []byte("not-a-timestamp node-overloaded hard"), false)
	if n := len(e.events(t)); n != 1 {
		t.Fatalf("live undated line events = %d, want 1", n)
	}
}

// TestReadTailBytesEdges: the .1-generation drain is strictly
// best-effort — absence, a fully-consumed offset and an empty read
// all degrade to nil.
func TestReadTailBytesEdges(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "log.1")
	if got := readTailBytes(f, 0, 1024); got != nil {
		t.Fatalf("absent tail = %q, want nil", got)
	}
	if err := os.WriteFile(f, []byte("tail line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readTailBytes(f, 0, 1024); string(got) != "tail line\n" {
		t.Fatalf("tail = %q", got)
	}
	// Offset at/over the size → nothing unread.
	if got := readTailBytes(f, int64(len("tail line\n")), 1024); got != nil {
		t.Fatalf("consumed tail = %q, want nil", got)
	}
	if got := readTailBytes(f, 1<<20, 1024); got != nil {
		t.Fatalf("past-EOF tail = %q, want nil", got)
	}
}

// TestReadLogWindowStatError: a log path whose parent is a regular
// file surfaces as a stat error, not a silent empty window.
func TestReadLogWindowStatError(t *testing.T) {
	e := fixture(t)
	blocker := filepath.Join(e.root, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	e.r.cfg.WatchdogLogFile = filepath.Join(blocker, "log")
	if _, err := e.r.readLogWindow(); err == nil || !strings.Contains(err.Error(), "stat ") {
		t.Fatalf("err = %v, want a wrapped stat error", err)
	}
}

// TestReadLogWindowMidSeekNoNewline: the first scan of an oversized
// file with NO newline at all attributes nothing — the whole window
// is one unterminated partial line.
func TestReadLogWindowMidSeekNoNewline(t *testing.T) {
	e := fixture(t)
	if err := os.WriteFile(e.log,
		[]byte(strings.Repeat("z", maxLogReadBytes+10)), 0o644); err != nil {
		t.Fatal(err)
	}
	win, err := e.r.readLogWindow()
	if err != nil || win == nil {
		t.Fatalf("readLogWindow = %v, %v", win, err)
	}
	if len(win.data) != 0 {
		t.Fatalf("mid-seek kept %d bytes of an unterminated line", len(win.data))
	}
	if !e.r.logScanned {
		t.Fatal("first scan did not mark the replay scan done")
	}
}
