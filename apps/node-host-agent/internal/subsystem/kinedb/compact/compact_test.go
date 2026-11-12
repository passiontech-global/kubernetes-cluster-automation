package compact

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func TestGuardTrigger(t *testing.T) {
	k, _, _ := fixture(t, nil)

	seen := func(head, crev, fz int64) guardState {
		return guardState{head: head, compactRev: crev, freeze: fz, seen: true}
	}
	cases := []struct {
		name                       string
		head, crev, rows, retained int64
		freeze                     int64
		prev                       guardState
		want                       bool
	}{
		{"quiet", 1000, 900, 5000, 100, 0, guardState{}, false},
		{"retained debt", 200000, 10000, 5000, 190000, 0, guardState{}, true},
		{"rows debt", 1000, 900, 500000, 100, 0, guardState{}, true},
		{"frozen fire", 10000, 5000, 6000, 5000, 4, seen(9700, 5000, 3), true},
		// freeze_cycles short of the threshold → quiet.
		{"frozen short", 10000, 5000, 6000, 5000, 3, seen(9700, 5000, 2), false},
		// head not advancing enough → no accumulating debt.
		{"frozen slow head", 9760, 5000, 6000, 4760, 4, seen(9700, 5000, 3), false},
		// retained below the frozen floor → nothing worth compacting.
		{"frozen no debt", 10000, 5000, 6000, 1000, 4, seen(9700, 5000, 3), false},
	}
	for _, c := range cases {
		got, _ := k.guardTrigger(c.head, c.crev, c.rows, c.retained, c.freeze, c.prev)
		if got != c.want {
			t.Fatalf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestGuardFreezeCounter(t *testing.T) {
	k, _, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "MAX(id)", Out: "300|50|1000|1\n"},
	})
	dir := k.d.Cfg.GuardStateDir
	// Previous run: head 100, compact_rev 50, 3 frozen cycles.
	kdeps.WriteIntFile(filepath.Join(dir, guardFileLastHead), 100)
	kdeps.WriteIntFile(filepath.Join(dir, guardFileLastCompactRev), 50)
	kdeps.WriteIntFile(filepath.Join(dir, guardFileFreeze), 3)

	res := k.Cycle(context.Background())
	if res.frozen != 4 {
		t.Fatalf("frozen=%d want 4", res.frozen)
	}
	// State persisted for the next run.
	st := k.readGuardState()
	if st.head != 300 || st.compactRev != 50 || st.freeze != 4 || !st.seen {
		t.Fatalf("state=%+v", st)
	}

	// compact_rev moved → counter resets.
	k.d.Cfg.Run = testutil.NewFakeExec(
		testutil.ExecRule{Substr: "inspect", Out: "true"},
		testutil.ExecRule{Substr: "MAX(id)", Out: "400|300|1000|1\n"},
	).RunStdin
	res = k.Cycle(context.Background())
	if res.frozen != 0 {
		t.Fatalf("frozen=%d want 0 after compact_rev advanced", res.frozen)
	}
}

func TestBuildCompactScript(t *testing.T) {
	k, _, _ := fixture(t, nil)
	// cur=100, target=450001 → chunks 100→150100→300100→450001 = 3.
	s := k.buildCompactScript(100, 450001)
	if got := strings.Count(s, "DO $$"); got != 3 {
		t.Fatalf("chunks=%d want 3:\n%s", got, s)
	}
	for _, want := range []string{
		"pg_try_advisory_lock(20260921)",
		"\\gset", "\\if :kcg_locked",
		`UPDATE "kine" SET prev_revision = 150100 WHERE name = 'compact_rev_key'`,
		"kp.prev_revision != 0",
		"kd.deleted != 0",
		`VACUUM (ANALYZE) "kine";`,
		"pg_advisory_unlock(20260921)",
		kdeps.LockBusyMarker,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("script missing %q:\n%s", want, s)
		}
	}
	// MaxChunks caps the loop.
	s = k.buildCompactScript(0, 100000000)
	if got := strings.Count(s, "DO $$"); got != 20 {
		t.Fatalf("chunks=%d want 20", got)
	}
	// Empty range → no chunks but still lock+vacuum+unlock.
	s = k.buildCompactScript(500, 500)
	if strings.Count(s, "DO $$") != 0 || !strings.Contains(s, "VACUUM") {
		t.Fatalf("empty range script:\n%s", s)
	}
}

var guardStatsRule = testutil.ExecRule{Substr: "MAX(id)", Out: "600000|100|700000|1\n"}

// guardAfterRule answers the post-compact re-read (compact_rev|rows)
// — the only query that opens with MAX(prev_revision).
var guardAfterRule = testutil.ExecRule{
	Substr: "SELECT COALESCE((SELECT MAX(prev_revision)",
	Out:    "599000|695000\n",
}

// compact-step-cap: the step cap clamps an over-wide compaction target so a
// single cycle cannot delete the whole watch-bookmark window.
func TestClampStepTarget(t *testing.T) {
	k, _, _ := fixture(t, nil)

	// Disabled (0 or negative) → the raw head-Tail target.
	k.d.Cfg.MaxStepRevisions = 0
	if got := k.clampStepTarget(100, 599000); got != 599000 {
		t.Fatalf("disabled: got %d want 599000", got)
	}
	k.d.Cfg.MaxStepRevisions = -5
	if got := k.clampStepTarget(100, 599000); got != 599000 {
		t.Fatalf("negative: got %d want 599000", got)
	}

	k.d.Cfg.MaxStepRevisions = 150000
	// Over-wide → clamped to crev + cap.
	if got := k.clampStepTarget(100, 599000); got != 150100 {
		t.Fatalf("capped: got %d want 150100", got)
	}
	// Boundary: exactly cap wide → unchanged.
	if got := k.clampStepTarget(100, 150100); got != 150100 {
		t.Fatalf("boundary: got %d want 150100", got)
	}
	// Narrow target → unchanged.
	if got := k.clampStepTarget(100, 500); got != 500 {
		t.Fatalf("narrow: got %d want 500", got)
	}
}

// compact-step-cap end-to-end: a triggered cycle under the cap compacts only
// up to crev + MaxStepRevisions, not the full head-Tail window.
func TestGuardCycleStepCap(t *testing.T) {
	k, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "ON_ERROR_STOP", Out: "NOTICE:  deleted=10\nUPDATE 1\n"},
		guardAfterRule,
		guardStatsRule,
	})
	k.d.Cfg.MaxStepRevisions = 100000
	// head=600000 crev=100 → retained 599900 fires; raw target
	// 599000, capped to 100100.
	res := k.Cycle(context.Background())
	if !res.ok || !res.fired {
		t.Fatalf("res=%+v", res)
	}
	if !strings.Contains(fr.LastStdin(), "prev_revision = 100100") {
		t.Fatalf("step cap not applied in compact script:\n%s", fr.LastStdin())
	}
}

func TestGuardCycleFiresAndLocks(t *testing.T) {
	k, fr, dir := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "ON_ERROR_STOP", Out: "NOTICE:  deleted=10\nNOTICE:  deleted=5\nUPDATE 1\n"},
		guardAfterRule,
		guardStatsRule,
	})
	res := k.Cycle(context.Background())
	if !res.ok || !res.fired {
		t.Fatalf("res=%+v", res)
	}
	// retained = 599900 > 150000 → fired; target = head-1000.
	script := fr.LastStdin()
	if !strings.Contains(script, "pg_try_advisory_lock(20260921)") {
		t.Fatalf("no advisory lock in session:\n%s", script)
	}
	if !strings.Contains(script, "prev_revision = 150100") {
		t.Fatalf("first chunk window wrong:\n%s", script)
	}
	if strings.Count(script, "DO $$") != 4 {
		// 599000-100 over 150K chunks = ceil(598900/150000) = 4.
		t.Fatalf("chunks=%d:\n%s", strings.Count(script, "DO $$"), script)
	}
	if res.deleted != 15 {
		t.Fatalf("deleted=%d", res.deleted)
	}
	// Post-compact re-read (bash parity): compact_rev and the fresh
	// row count after the chunk loop.
	if !res.revSeen || res.revAfter != 599000 || res.rows != 695000 {
		t.Fatalf("after=%+v", res)
	}
	// last compact timestamp persisted.
	ts, err := kdeps.ReadIntFile(filepath.Join(k.d.Cfg.GuardStateDir, guardFileCompactTS))
	if err != nil || ts != kdepstest.TestNow {
		t.Fatalf("compact ts=%d err=%v", ts, err)
	}
	content := kdepstest.ReadText(t, dir, "kine-compact-guard.prom")
	for _, want := range []string{
		"kine_db_guard_ok 1",
		"kine_db_guard_fired 1",
		"kine_db_rows 695000",
		"kine_db_guard_compact_rev_after 599000",
		"kine_db_guard_last_deleted_rows 15",
		"kine_db_guard_last_compact_timestamp_seconds 1700000000",
		"kine_db_guard_last_run_timestamp_seconds 1700000000",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("textfile missing %q:\n%s", want, content)
		}
	}
	// Script went down a single psql session with stdin.
	j := fr.Joined()
	if !strings.Contains(j, "psql -h 127.0.0.1 -U postgres -d postgres -v ON_ERROR_STOP=1 -f -") {
		t.Fatalf("compact session argv wrong:\n%s", j)
	}
}

func TestGuardCycleLockBusy(t *testing.T) {
	k, _, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "ON_ERROR_STOP", Out: kdeps.LockBusyMarker + "\n"},
		guardStatsRule,
	})
	res := k.Cycle(context.Background())
	if !res.ok {
		t.Fatalf("lock-busy should stay ok: %+v", res)
	}
	if res.fired {
		t.Fatal("fired while the lock was busy")
	}
	if res.deleted != 0 {
		t.Fatalf("deleted=%d", res.deleted)
	}
	if _, err := os.Stat(filepath.Join(k.d.Cfg.GuardStateDir, guardFileCompactTS)); err == nil {
		t.Fatal("compact ts written on a busy run")
	}
}

func TestGuardCycleQuiet(t *testing.T) {
	k, fr, dir := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "MAX(id)", Out: "2000|1000|3000|1\n"},
	})
	res := k.Cycle(context.Background())
	if !res.ok || res.fired {
		t.Fatalf("res=%+v", res)
	}
	if strings.Contains(fr.Joined(), "pg_try_advisory_lock") {
		t.Fatal("compact session ran on a quiet cycle")
	}
	content := kdepstest.ReadText(t, dir, "kine-compact-guard.prom")
	for _, want := range []string{
		// kine_db_rows lives in the guard file — the probe dropped
		// its per-2min COUNT(*).
		"kine_db_rows 3000",
		"kine_db_guard_fired 0",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("textfile missing %q:\n%s", want, content)
		}
	}
	// compact_rev_after only appears after a real compact run.
	if strings.Contains(content, "kine_db_guard_compact_rev_after") {
		t.Fatalf("compact_rev_after on a quiet cycle:\n%s", content)
	}
}

func TestGuardCycleScriptError(t *testing.T) {
	k, _, dir := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "ON_ERROR_STOP", Err: errors.New("psql error")},
		guardStatsRule,
	})
	res := k.Cycle(context.Background())
	if res.ok {
		t.Fatal("expected failure")
	}
	content := kdepstest.ReadText(t, dir, "kine-compact-guard.prom")
	if !strings.Contains(content, "kine_db_guard_ok 0") {
		t.Fatalf("textfile:\n%s", content)
	}
}

// --- Cycle gate paths: creds, container down, stats read ---

// Missing .env creds short-circuit the guard cycle — no query runs,
// the cycle reads failed.
func TestGuardCycleCredsMissing(t *testing.T) {
	k, fr, dir := fixture(t, nil)
	if err := os.WriteFile(filepath.Join(dir, ".env"),
		[]byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	res := k.Cycle(context.Background())
	if res.ok {
		t.Fatal("missing creds must read failed")
	}
	if !containsGuardNote(res.notes, "missing .env creds") {
		t.Fatalf("notes=%v", res.notes)
	}
	if fr.Ran("psql") {
		t.Fatalf("guard ran queries without creds:\n%s", fr.Joined())
	}
}

// A down postgres container short-circuits the same way.
func TestGuardCycleContainerDown(t *testing.T) {
	k, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Err: errors.New("no such container")},
		{Substr: "ps --format", Out: ""},
	})
	res := k.Cycle(context.Background())
	if res.ok {
		t.Fatal("down container must read failed")
	}
	if !containsGuardNote(res.notes, "postgres container kine-postgres down") {
		t.Fatalf("notes=%v", res.notes)
	}
	if fr.Ran("psql") {
		t.Fatalf("guard queried a down container:\n%s", fr.Joined())
	}
}

// A failed stats read fails the cycle without firing; an
// unparseable one does the same with its own note.
func TestGuardCycleStatsReadFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule testutil.ExecRule
		want string
	}{
		{"query fail", testutil.ExecRule{Substr: "MAX(id)",
			Err: errors.New("connection reset")}, "stats query fail"},
		{"unparsed", testutil.ExecRule{Substr: "MAX(id)",
			Out: "garbage\n"}, "stats unparsed"},
	} {
		k, _, _ := fixture(t, []testutil.ExecRule{
			{Substr: "inspect", Out: "true"},
			tc.rule,
		})
		res := k.Cycle(context.Background())
		if res.ok || res.statsOK {
			t.Fatalf("%s: res=%+v must stay failed+unseen", tc.name, res)
		}
		if !containsGuardNote(res.notes, tc.want) {
			t.Fatalf("%s: notes=%v want %q", tc.name, res.notes, tc.want)
		}
	}
}

// The marker-off-by-one hold: head-Tail at or under compact_rev
// holds the marker at crev (zero chunk windows — only the vacuum
// runs). The head <= Tail overshoot is covered by
// TestGuardCycleHeadWithinTailSkips.
func TestGuardCycleTargetHoldAndNeverCompacted(t *testing.T) {
	cases := []struct {
		name           string
		stats          string
		wantPrevTarget string // "prev_revision = N" in the chunk window
		wantChunks     int
	}{
		// head=5000, crev=4900, Tail=1000 → target 4000 <= crev →
		// hold at crev: no DO block, only the vacuum round.
		{"hold at crev", "5000|4900|500000|4900\n", "", 0},
	}
	for _, tc := range cases {
		k, fr, _ := fixture(t, []testutil.ExecRule{
			{Substr: "inspect", Out: "true"},
			{Substr: "ON_ERROR_STOP", Out: "NOTICE:  deleted=7\n"},
			guardAfterRule,
			{Substr: "MAX(id)", Out: tc.stats},
		})
		res := k.Cycle(context.Background())
		if !res.fired || !res.ok {
			t.Fatalf("%s: res=%+v notes=%v", tc.name, res, res.notes)
		}
		script := fr.LastStdin()
		got := strings.Count(script, "DO $$")
		if got != tc.wantChunks ||
			(tc.wantPrevTarget != "" && !strings.Contains(script, tc.wantPrevTarget)) {
			t.Fatalf("%s: chunks=%d want %d, prevTarget %q in:\n%s",
				tc.name, got, tc.wantChunks, tc.wantPrevTarget, script)
		}
	}
}

// rows-debt with the marker already at/ahead of head-Tail: the
// forward compact has no window to advance through, so the guard
// sweeps dead rows BELOW compact_rev in bounded chunks — the same
// shadowed/deleted-row DELETE semantics — WITHOUT the
// compact_rev_key UPDATE (there is no forward progress to record).
func TestGuardCycleBelowHorizonSweep(t *testing.T) {
	k, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "ON_ERROR_STOP", Out: "NOTICE:  deleted=42\n"},
		guardAfterRule,
		// head=5000 crev=4900 rows=500000 (>RowsMax) min_id=100
		// (<crev) → target 4000 <= crev → sweep [100,4900].
		{Substr: "MAX(id)", Out: "5000|4900|500000|100\n"},
	})
	res := k.Cycle(context.Background())
	if !res.ok || !res.fired {
		t.Fatalf("res=%+v notes=%v", res, res.notes)
	}
	script := fr.LastStdin()
	if !strings.Contains(script, "kp.id > 100 AND kp.id <= 4900") {
		t.Fatalf("sweep window wrong:\n%s", script)
	}
	if strings.Contains(script, "SET prev_revision") {
		t.Fatalf("below-horizon sweep must not advance compact_rev_key:\n%s", script)
	}
	if res.deleted != 42 {
		t.Fatalf("deleted=%d", res.deleted)
	}
}

// The same hold-at-crev shape WITHOUT the rows-debt backlog (min_id
// already at the marker) keeps the vacuum-only session — no sweep
// chunks, no marker move.
func TestGuardCycleHoldAtCrevNoBacklog(t *testing.T) {
	k, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "ON_ERROR_STOP", Out: "NOTICE:  deleted=7\n"},
		guardAfterRule,
		// min_id == crev → nothing below the horizon to sweep.
		{Substr: "MAX(id)", Out: "5000|4900|500000|4900\n"},
	})
	res := k.Cycle(context.Background())
	if !res.fired || !res.ok {
		t.Fatalf("res=%+v notes=%v", res, res.notes)
	}
	if got := strings.Count(fr.LastStdin(), "DO $$"); got != 0 {
		t.Fatalf("chunks=%d want 0:\n%s", got, fr.LastStdin())
	}
}

// head <= Tail leaves no safely-deletable range: the whole retained
// history already fits inside the watch tail, so the guard must not
// fire a compact session at all — even when a trigger (here
// rows-debt) evaluates true. The old crev==0 fallback used to
// compact to head and erase every revision a watcher could resume
// from.
func TestGuardCycleHeadWithinTailSkips(t *testing.T) {
	k, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "MAX(id)", Out: "1000|0|500000|0\n"}, // head=Tail, crev=0
	})
	res := k.Cycle(context.Background())
	if !res.ok || res.fired {
		t.Fatalf("head<=tail must skip cleanly: res=%+v notes=%v", res, res.notes)
	}
	if !containsGuardNote(res.notes, "nothing safely deletable") {
		t.Fatalf("missing skip note: %v", res.notes)
	}
	if script := fr.LastStdin(); strings.Contains(script, "ON_ERROR_STOP") {
		t.Fatalf("compact script must not run when head<=tail:\n%s", script)
	}
}

// The backup-health series render seen-gated into the guard
// textfile — valid and invalid dumps both render, an unmeasured
// cycle fabricates neither.
func TestEmitGuardBackupSeries(t *testing.T) {
	k, _, dir := fixture(t, nil)

	k.emitGuard(&Result{backupSeen: true, backupValid: true, backupAge: 42})
	content := kdepstest.ReadText(t, dir, "kine-compact-guard.prom")
	for _, want := range []string{
		"kine_db_backup_age_seconds 42",
		"kine_db_backup_valid 1",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("textfile missing %q:\n%s", want, content)
		}
	}

	k.emitGuard(&Result{backupSeen: true, backupValid: false, backupAge: 42})
	content = kdepstest.ReadText(t, dir, "kine-compact-guard.prom")
	if !strings.Contains(content, "kine_db_backup_valid 0") {
		t.Fatalf("invalid dump must render 0:\n%s", content)
	}

	k.emitGuard(&Result{})
	content = kdepstest.ReadText(t, dir, "kine-compact-guard.prom")
	if strings.Contains(content, "kine_db_backup_age_seconds") ||
		strings.Contains(content, "kine_db_backup_valid") {
		t.Fatalf("unseen backup fabricated series:\n%s", content)
	}
}

func containsGuardNote(notes []string, substr string) bool {
	for _, n := range notes {
		if strings.Contains(n, substr) {
			return true
		}
	}
	return false
}
