package kinedb

import (
	"context"
	"errors"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		{Substr: "MAX(id)", Out: "300|50|1000\n"},
	})
	dir := k.cfg.GuardStateDir
	// Previous run: head 100, compact_rev 50, 3 frozen cycles.
	writeIntFile(filepath.Join(dir, guardFileLastHead), 100)
	writeIntFile(filepath.Join(dir, guardFileLastCompactRev), 50)
	writeIntFile(filepath.Join(dir, guardFileFreeze), 3)

	res := k.guardCycle(context.Background())
	if res.frozen != 4 {
		t.Fatalf("frozen=%d want 4", res.frozen)
	}
	// State persisted for the next run.
	st := k.readGuardState()
	if st.head != 300 || st.compactRev != 50 || st.freeze != 4 || !st.seen {
		t.Fatalf("state=%+v", st)
	}

	// compact_rev moved → counter resets.
	k.cfg.run = testutil.NewFakeExec(
		testutil.ExecRule{Substr: "inspect", Out: "true"},
		testutil.ExecRule{Substr: "MAX(id)", Out: "400|300|1000\n"},
	).RunStdin
	res = k.guardCycle(context.Background())
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
		lockBusyMarker,
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

var guardStatsRule = testutil.ExecRule{Substr: "MAX(id)", Out: "600000|100|700000\n"}

// guardAfterRule answers the post-compact re-read (compact_rev|rows)
// — the only query that opens with MAX(prev_revision).
var guardAfterRule = testutil.ExecRule{
	Substr: "SELECT COALESCE((SELECT MAX(prev_revision)",
	Out:    "599000|695000\n",
}

func TestGuardCycleFiresAndLocks(t *testing.T) {
	k, fr, dir := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "ON_ERROR_STOP", Out: "NOTICE:  deleted=10\nNOTICE:  deleted=5\nUPDATE 1\n"},
		guardAfterRule,
		guardStatsRule,
	})
	res := k.guardCycle(context.Background())
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
	ts, err := readIntFile(filepath.Join(k.cfg.GuardStateDir, guardFileCompactTS))
	if err != nil || ts != testNow {
		t.Fatalf("compact ts=%d err=%v", ts, err)
	}
	content := readText(t, dir, "kine-compact-guard.prom")
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
		{Substr: "ON_ERROR_STOP", Out: lockBusyMarker + "\n"},
		guardStatsRule,
	})
	res := k.guardCycle(context.Background())
	if !res.ok {
		t.Fatalf("lock-busy should stay ok: %+v", res)
	}
	if res.fired {
		t.Fatal("fired while the lock was busy")
	}
	if res.deleted != 0 {
		t.Fatalf("deleted=%d", res.deleted)
	}
	if _, err := os.Stat(filepath.Join(k.cfg.GuardStateDir, guardFileCompactTS)); err == nil {
		t.Fatal("compact ts written on a busy run")
	}
}

func TestGuardCycleQuiet(t *testing.T) {
	k, fr, dir := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "MAX(id)", Out: "2000|1000|3000\n"},
	})
	res := k.guardCycle(context.Background())
	if !res.ok || res.fired {
		t.Fatalf("res=%+v", res)
	}
	if strings.Contains(fr.Joined(), "pg_try_advisory_lock") {
		t.Fatal("compact session ran on a quiet cycle")
	}
	content := readText(t, dir, "kine-compact-guard.prom")
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
	res := k.guardCycle(context.Background())
	if res.ok {
		t.Fatal("expected failure")
	}
	content := readText(t, dir, "kine-compact-guard.prom")
	if !strings.Contains(content, "kine_db_guard_ok 0") {
		t.Fatalf("textfile:\n%s", content)
	}
}
