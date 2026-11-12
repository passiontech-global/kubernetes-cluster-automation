// fixture_test.go — the Monitor test fixture: a temp host tree
// (kmsg device file, mounts table, uptime) plus a fake Sink that
// records counter increments, emitted Events and entered latches.
package npd

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/journalwatch"
)

// fakeSink records everything the monitors report. The real
// emitEvent's dedup/aggregation and the node-facing Event object
// fields (Regarding, series patching) live in the parent package —
// covered by its own suite.
type fakeSink struct {
	counters map[string]int
	events   []sinkEvent
	latches  map[string]string
}

type sinkEvent struct {
	reason string
	note   string
}

func (s *fakeSink) EmitEvent(_ context.Context, reason, note string) error {
	s.events = append(s.events, sinkEvent{reason: reason, note: note})
	return nil
}

func (s *fakeSink) BumpCounter(reason string) { s.counters[reason]++ }

func (s *fakeSink) EnterLatch(name, evidence string) { s.latches[name] = evidence }

func (s *fakeSink) counter(reason string) int { return s.counters[reason] }

func (s *fakeSink) eventsByReason(reason string) []sinkEvent {
	var out []sinkEvent
	for _, e := range s.events {
		if e.reason == reason {
			out = append(out, e)
		}
	}
	return out
}

// env is the shared fixture — monitor + sink + the mutable seams
// the Deps closures re-read per sync (mirrors the parent's
// late-bound npdDeps: cfg/journalFetch edits land live).
type env struct {
	m            *Monitor
	sink         *fakeSink
	cfg          Config
	journalFetch journalwatch.ExecFunc
	kmsg         string
	mounts       string
	uptime       string
	now          time.Time
}

func fixture(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	e := &env{
		kmsg:   filepath.Join(root, "kmsg"),
		mounts: filepath.Join(root, "mounts"),
		uptime: filepath.Join(root, "uptime"),
		now:    time.Now().Truncate(time.Second),
		sink:   &fakeSink{counters: map[string]int{}, latches: map[string]string{}},
	}
	// Keep every sync hermetic: the kmsg tail and the journal seam
	// default to empty sources under t.TempDir, never the real host
	// /dev/kmsg or journalctl. The readonly fixtures mirror the
	// parent applyDefaults values.
	for _, f := range []struct{ path, body string }{
		{e.mounts, "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n" +
			"/dev/vda1 / ext4 rw,relatime 0 0\n" +
			"/dev/vdb1 /var/lib/k0s ext4 rw,relatime 0 0\n"},
		{e.uptime, "3600.00 7200.00\n"},
		{e.kmsg, ""}, // present-but-empty → kernel monitor tails it, no journald fallback
	} {
		if err := os.WriteFile(f.path, []byte(f.body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	e.journalFetch = func(context.Context, ...string) (string, error) { return "", nil }
	e.cfg = Config{
		KmsgFile:           e.kmsg,
		HostRoot:           root,
		ProcMountsFile:     e.mounts,
		ProcUptimeFile:     e.uptime,
		KubeletJournalUnit: "k0sworker.service",
		ReadonlyTargets:    []string{"/", "/var", "/var/lib/k0s", "/var/openebs"},
		ReadonlyFSTypes:    []string{"ext4", "xfs", "btrfs"},
		LogLookback:        5 * time.Minute,
	}
	e.m = New(Deps{
		Cfg: func() Config { return e.cfg },
		JournalFetch: func(ctx context.Context, args ...string) (string, error) {
			return e.journalFetch(ctx, args...)
		},
		Now: func() time.Time { return e.now },
	})
	// Negative PollEvery disables the mux's fetch throttle — every
	// Poll execs, so each sync maps to exactly one journalFetch
	// call like the pre-mux per-consumer cursors did. The sharing
	// half (one exec feeding both subscribers inside a window) is
	// journalwatch's own mux_test contract; production keeps the
	// 30s default.
	e.m.journal.PollEvery = -1
	t.Cleanup(e.m.Close)
	return e
}

// appendKmsg appends one raw kmsg record line to the fake device file.
func (e *env) appendKmsg(t *testing.T, record string) {
	t.Helper()
	f, err := os.OpenFile(e.kmsg, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	_, _ = f.WriteString(record + "\n")
}

// condFor returns the evaluated npd Cond for a condition Type.
func condFor(t *testing.T, m *Monitor, typ string) Cond {
	t.Helper()
	for _, c := range m.EvalConditions() {
		if string(c.Type) == typ {
			return c
		}
	}
	t.Fatalf("condition %s not in EvalConditions", typ)
	return Cond{}
}
