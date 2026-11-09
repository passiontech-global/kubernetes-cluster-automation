// journal_test.go — the journal-read plumbing: the journalctl argv
// over the HostExecFn seam, the error→empty mapping, the
// classify/note accounting that feeds the state-journal-unreadable
// blindness latch (enter/suspect-throttle/re-establish/exit).
package cdeps

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/journalwatch"
)

type execCall struct {
	name string
	args []string
}

// newJournalDeps wires a Deps with a 2-read blindness budget, a real
// journal storage dir, and a scripted exec seam. The returned
// dispatch re-scripts the unit-window and unfiltered answers; the
// recorded seam calls are readable through calls().
func newJournalDeps(t *testing.T) (d *Deps,
	script func(unitOut string, unitErr error, anyOut string, anyErr error),
	calls func() []execCall) {

	t.Helper()
	dir := t.TempDir()
	jdir := filepath.Join(dir, "journal")
	if err := os.MkdirAll(jdir, 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "watchdog.log")
	st := hoststate.New(filepath.Join(dir, "state"), log, nil, nil)
	if err := os.MkdirAll(st.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	d = &Deps{
		Cfg: Config{
			JournalUnit:             "k0scontroller",
			WatchdogStateDir:        st.Dir,
			WatchdogLogFile:         log,
			JournalDirs:             []string{jdir},
			JournalUnreadableNeeded: 2,
			SuspectLogCadence:       time.Hour,
		},
		State: st,
		Cycles: prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: "t_cycles"},
			[]string{"check", "result"}),
	}
	d.JournalReads = journalwatch.NewUnreadableTrackerForOwner(st,
		d.Cfg.JournalDirs, d.Cfg.JournalUnreadableNeeded,
		journalwatch.OwnerControllerHygiene)

	var (
		answers struct {
			unitOut, anyOut string
			unitErr, anyErr error
		}
		seen []execCall
	)
	script = func(unitOut string, unitErr error, anyOut string, anyErr error) {
		answers.unitOut, answers.unitErr = unitOut, unitErr
		answers.anyOut, answers.anyErr = anyOut, anyErr
	}
	calls = func() []execCall { return seen }
	d.Cfg.HostExecFn = func(_ context.Context, combined bool,
		budget time.Duration, name string, args ...string) (string, error) {
		if !combined {
			t.Errorf("journal exec must fold stderr in, combined=%v", combined)
		}
		seen = append(seen, execCall{name: name, args: args})
		switch {
		case name == "journalctl" && len(args) > 0 && args[0] == "-u":
			return answers.unitOut, answers.unitErr
		case name == "journalctl":
			return answers.anyOut, answers.anyErr
		}
		return "", errors.New("unscripted journal exec")
	}
	return d, script, calls
}

func journalLog(t *testing.T, d *Deps) string {
	t.Helper()
	b, err := os.ReadFile(d.State.LogFile)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestJournalReadArgv(t *testing.T) {
	d, _, calls := newJournalDeps(t)
	since := time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)
	out, err := d.journalRead(context.Background(), "k0scontroller", since)
	if err != nil || out != "" { // unscripted unit read → empty, no error
		t.Fatalf("journalRead out=%q err=%v", out, err)
	}
	want := execCall{"journalctl", []string{
		"-u", "k0scontroller", "--since", "2026-01-02 15:04:05", "--no-pager"}}
	if len(calls()) != 1 || !reflect.DeepEqual(calls()[0], want) {
		t.Fatalf("unit-window argv=%v want %v", calls(), want)
	}
}

func TestJournalAnyReadShape(t *testing.T) {
	d, script, calls := newJournalDeps(t)
	script("", nil, "journald was alive here\n", nil)
	out, err := d.journalAnyRead(context.Background())
	if err != nil || out != "journald was alive here\n" {
		t.Fatalf("journalAnyRead out=%q err=%v", out, err)
	}
	want := execCall{"journalctl", []string{"-n", "1", "--no-pager"}}
	if len(calls()) != 1 || !reflect.DeepEqual(calls()[0], want) {
		t.Fatalf("unfiltered argv=%v want %v", calls(), want)
	}
}

func TestJournalText(t *testing.T) {
	d, script, _ := newJournalDeps(t)
	since := time.Now()

	// A healthy read passes through and feeds the tracker an ok.
	script("INFO line one\n", nil, "", nil)
	if got := d.JournalText(context.Background(), since); got != "INFO line one\n" {
		t.Fatalf("JournalText=%q", got)
	}

	// A failed read maps to empty (`|| true` parity) and warns.
	script("", errors.New("signal: killed"), "", nil)
	if got := d.JournalText(context.Background(), since); got != "" {
		t.Fatalf("failed JournalText=%q want empty", got)
	}
	if !strings.Contains(journalLog(t, d), "journal read failed") {
		t.Fatal("failed journal read not warned")
	}
}

func TestClassifyJournalRead(t *testing.T) {
	cases := []struct {
		name     string
		out      string
		err      error
		anyOut   string
		anyErr   error
		wantOK   bool
		wantDtl  string
		wantAnyN int // unfiltered probe calls
	}{
		{"read error", "", errors.New("killed"), "", nil, false, "read failed", 0},
		{"files gone", "No journal files were found.\n", nil, "", nil, false, "no journal files", 0},
		{"quiet unit", "", nil, "-- No entries --\n", nil, true, "", 1},
		{"files gone probe", "", nil, "no journal files", nil, false, "no journal files", 1},
		{"probe error", "", nil, "", errors.New("killed"), false, "unfiltered probe failed", 1},
		{"wide empty", "", nil, "", nil, false, "journald-wide empty reply", 1},
		{"usable text", "some real lines\n", nil, "", nil, true, "", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, script, calls := newJournalDeps(t)
			script("", nil, c.anyOut, c.anyErr)
			ok, dtl := d.classifyJournalRead(context.Background(), c.out, c.err)
			if ok != c.wantOK || !strings.Contains(dtl, c.wantDtl) {
				t.Fatalf("classify=(%v,%q) want (%v,%q)", ok, dtl, c.wantOK, c.wantDtl)
			}
			if got := len(calls()); got != c.wantAnyN {
				t.Fatalf("unfiltered probe calls=%d want %d", got, c.wantAnyN)
			}
		})
	}
}

func TestNoteJournalReadLifecycle(t *testing.T) {
	d, script, _ := newJournalDeps(t)
	ctx := context.Background()
	latch := d.State.Path(StateJournalUnreadable)

	// Needed-1 failed reads stay below the budget.
	script("", errors.New("killed"), "", nil)
	d.noteJournalRead(ctx, "", errors.New("killed"))
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch entered before the budget")
	}

	// The budget-reaching read latches, logs STATE-ENTER + the
	// suspect line, and counts a journal_unreadable cycle.
	d.noteJournalRead(ctx, "", errors.New("killed"))
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("state-journal-unreadable not latched: %v", err)
	}
	log := journalLog(t, d)
	if !strings.Contains(log, "STATE-ENTER") ||
		!strings.Contains(log, "suspect: journal-unreadable") {
		t.Fatalf("latch log lines missing:\n%s", log)
	}

	// Held latch: the suspect line stays throttled by the cadence.
	d.noteJournalRead(ctx, "", errors.New("killed"))
	if n := strings.Count(journalLog(t, d), "suspect: journal-unreadable"); n != 1 {
		t.Fatalf("suspect repeated while latch held: %d", n)
	}

	// Re-establish after external removal while latched.
	if err := os.Remove(latch); err != nil {
		t.Fatal(err)
	}
	d.noteJournalRead(ctx, "", errors.New("killed"))
	if _, err := os.Stat(latch); err != nil {
		t.Fatalf("latch not re-established after external removal: %v", err)
	}

	// A good read exits and clears the latch + dedupe budget.
	script("healthy lines\n", nil, "", nil)
	d.noteJournalRead(ctx, "healthy lines\n", nil)
	if _, err := os.Stat(latch); !os.IsNotExist(err) {
		t.Fatal("latch not cleared on recovery")
	}
	log = journalLog(t, d)
	if !strings.Contains(log, "STATE-EXIT") {
		t.Fatalf("STATE-EXIT line missing:\n%s", log)
	}
	if _, err := os.Stat(filepath.Join(d.State.Dir,
		"last-suspect-"+StateJournalUnreadable)); !os.IsNotExist(err) {
		t.Fatal("suspect dedupe budget not dropped with the latch")
	}
}

func TestNoteJournalReadNoStorageNeverFires(t *testing.T) {
	// A host with no journal storage at all must never latch —
	// the tracker's config-gate, not a fault.
	d, script, _ := newJournalDeps(t)
	d.Cfg.JournalDirs = nil
	d.JournalReads.Dirs = nil
	script("", errors.New("killed"), "", nil)
	for range d.Cfg.JournalUnreadableNeeded + 2 {
		d.noteJournalRead(context.Background(), "", errors.New("killed"))
	}
	if _, err := os.Stat(d.State.Path(StateJournalUnreadable)); !os.IsNotExist(err) {
		t.Fatal("latched without journal storage")
	}
}

func TestJournalSinceLayout(t *testing.T) {
	// The wall-clock contract the shell probes share — the argv
	// must carry the plain "2006-01-02 15:04:05" form.
	ts := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	if got := ts.Format(journalSinceLayout); got != "2026-03-04 05:06:07" {
		t.Fatalf("since layout rendered %q", got)
	}
}
