package maint

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

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

func TestDeadTuplePct(t *testing.T) {
	if got := deadTuplePct(50, 50); got != 50 {
		t.Fatalf("50/50 → %d", got)
	}
	if got := deadTuplePct(1, 3); got != 25 {
		t.Fatalf("1/3 → %d", got)
	}
	if got := deadTuplePct(0, 0); got != 0 {
		t.Fatalf("empty → %d", got)
	}
	if got := deadTuplePct(0, 100); got != 0 {
		t.Fatalf("live-only → %d", got)
	}
}

// sizes: heap|indexes|dead|live (pg_relation_size|pg_indexes_size —
// the bash measured indexes directly; total−heap inflates on TOAST).
// dead 800000/(800000+800000) = 50%, heap 300MB > 200MB → repack
// fires.
var maintBloatRules = []testutil.ExecRule{
	{Substr: "inspect", Out: "true"},
	{Substr: "pg_repack -h", Out: "ok"},
	{Substr: "pg_repack", Out: "/usr/pgsql-16/bin/pg_repack\n"},
	// repackBinPath's ls probes: /usr lists a pgsql-16 dir, the
	// Debian root lists nothing, and the candidate probe hits the
	// pg_repack rule above (longest-match).
	{Substr: "ls /usr/lib/postgresql", Out: ""},
	{Substr: "ls /usr", Out: "bin\netc\nlib\npgsql-16\nsbin\nusr\n"},
	{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
	{Substr: "pg_indexes_size", Out: "300000000|14572800|800000|800000\n"},
	// kinedb-maintenance headroom gate: 0 WAL bytes, 100GiB free — ample for the
	// 300MB heap (needs >= 2.5*heap).
	{Substr: "pg_ls_waldir", Out: "0\n"},
	{Substr: "df", Out: "Avail\n107374182400\n"},
}

func TestMaintCycleRepacksWhenBloated(t *testing.T) {
	k, fr, dir := fixture(t, maintBloatRules)
	res := k.Cycle(context.Background())
	if !res.okReindex || !res.okRepack || res.repackState != "done" {
		t.Fatalf("res=%+v", res)
	}
	if res.heapBytes != 300000000 || res.indexBytes != 14572800 || res.deadPct != 50 {
		t.Fatalf("res=%+v", res)
	}
	j := fr.Joined()
	if !strings.Contains(j,
		"pg_repack -h 127.0.0.1 -U postgres -d postgres -t public.kine --no-superuser-check --no-order") {
		t.Fatalf("repack argv wrong:\n%s", j)
	}
	if !strings.Contains(j, "CREATE EXTENSION IF NOT EXISTS pg_repack") {
		t.Fatalf("missing extension creation:\n%s", j)
	}
	content := kdepstest.ReadText(t, dir, "kine-db-maint.prom")
	for _, want := range []string{
		`kine_db_maint_ok{check="reindex"} 1`,
		`kine_db_maint_ok{check="repack"} 1`,
		`kine_db_maint_relation_bytes{kind="heap"} 300000000`,
		`kine_db_maint_relation_bytes{kind="indexes"} 14572800`,
		`kine_db_maint_last_run_timestamp_seconds 1700000000`,
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("textfile missing %q:\n%s", want, content)
		}
	}
	for _, fam := range []string{"kine_db_maint_ok", "kine_db_maint_relation_bytes"} {
		if n := strings.Count(content, "# HELP "+fam+" "); n != 1 {
			t.Fatalf("duplicate HELP for %s (count=%d):\n%s", fam, n, content)
		}
		if n := strings.Count(content, "# TYPE "+fam+" "); n != 1 {
			t.Fatalf("duplicate TYPE for %s (count=%d):\n%s", fam, n, content)
		}
	}
}

func TestMaintCycleSkipsRepackBelowThreshold(t *testing.T) {
	k, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
		// dead 1% on a huge heap → no repack (autovacuum copes).
		{Substr: "pg_indexes_size", Out: "500000000|14572800|10000|800000\n"},
	})
	res := k.Cycle(context.Background())
	if res.repackState != "skipped" {
		t.Fatalf("repackState=%s", res.repackState)
	}
	if strings.Contains(fr.Joined(), "pg_repack") {
		t.Fatal("repack ran below threshold")
	}
}

func TestMaintCycleRepackMissingBinary(t *testing.T) {
	k, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
		{Substr: "pg_indexes_size", Out: "300000000|14572800|800000|800000\n"},
		// headroom gate passes, then repackBinPath's ls probes find
		// no pgsql-*/postresql version dirs → "" → no-binary.
		{Substr: "pg_ls_waldir", Out: "0\n"},
		{Substr: "df", Out: "Avail\n107374182400\n"},
		{Substr: "ls /usr/lib/postgresql", Out: ""},
		{Substr: "ls /usr", Out: "bin\netc\nlib\nsbin\nusr\n"},
	})
	res := k.Cycle(context.Background())
	if res.repackState != "no-binary" {
		t.Fatalf("repackState=%s", res.repackState)
	}
	if !res.okRepack {
		// no-binary is a warning state, not a failure — same as the
		// shell (ok_repack stays 1).
		t.Fatal("no-binary should keep repack ok")
	}
	if strings.Contains(fr.Joined(), " --no-superuser-check") {
		t.Fatal("repack ran without a binary")
	}
}

func TestMaintCycleRepackSkippedOnLowHeadroom(t *testing.T) {
	k, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
		{Substr: "pg_indexes_size", Out: "300000000|14572800|800000|800000\n"},
		{Substr: "pg_ls_waldir", Out: "50000000\n"},
		// 800MB free < 2.5*(300MB heap + 50MB wal) = 875MB →
		// VACUUM-only fallback, no repack.
		{Substr: "df", Out: "Avail\n800000000\n"},
	})
	res := k.Cycle(context.Background())
	if res.repackState != "skipped-headroom" {
		t.Fatalf("repackState=%s", res.repackState)
	}
	j := fr.Joined()
	if !strings.Contains(j, `VACUUM (ANALYZE) "kine"`) {
		t.Fatalf("fallback vacuum missing:\n%s", j)
	}
	if strings.Contains(j, "--no-superuser-check") {
		t.Fatal("pg_repack ran with insufficient headroom")
	}
}

func TestMaintCycleRepackFailure(t *testing.T) {
	k, _, dir := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "-t public.kine --no-superuser-check", Err: errors.New("exit 1")},
		{Substr: "pg_repack", Out: "/usr/pgsql-16/bin/pg_repack\n"},
		{Substr: "ls /usr/lib/postgresql", Out: ""},
		{Substr: "ls /usr", Out: "bin\netc\nlib\npgsql-16\nsbin\nusr\n"},
		{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
		{Substr: "pg_indexes_size", Out: "300000000|14572800|800000|800000\n"},
		{Substr: "pg_ls_waldir", Out: "0\n"},
		{Substr: "df", Out: "Avail\n107374182400\n"},
	})
	res := k.Cycle(context.Background())
	if res.okRepack || res.repackState != "fail" {
		t.Fatalf("res=%+v", res)
	}
	content := kdepstest.ReadText(t, dir, "kine-db-maint.prom")
	if !strings.Contains(content, `kine_db_maint_ok{check="repack"} 0`) {
		t.Fatalf("textfile:\n%s", content)
	}
}

func TestMaintCycleReindexFailure(t *testing.T) {
	k, _, dir := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		// The reindex rides the locked psql script — a script failure
		// (lock timeout etc.) aborts via ON_ERROR_STOP.
		{Substr: "ON_ERROR_STOP", Err: errors.New("lock timeout")},
		{Substr: "pg_indexes_size", Out: "100000000|4857600|10|90\n"},
	})
	res := k.Cycle(context.Background())
	if res.okReindex {
		t.Fatal("reindex should fail")
	}
	content := kdepstest.ReadText(t, dir, "kine-db-maint.prom")
	if !strings.Contains(content, `kine_db_maint_ok{check="reindex"} 0`) {
		t.Fatalf("textfile:\n%s", content)
	}
}

func TestMaintCycleContainerDown(t *testing.T) {
	k, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Err: errors.New("down")},
		{Substr: "ps --format", Out: ""},
	})
	res := k.Cycle(context.Background())
	if res.okReindex {
		t.Fatal("reindex must fail with the container down")
	}
	if strings.Contains(fr.Joined(), "REINDEX") {
		t.Fatal("reindex ran with the container down")
	}
}

// TestMaintCycleAssessFailGatesGauges: when the stats read fails the
// relation_bytes gauges must not emit fabricated zeros — the same
// statsOK gating emitGuard applies. The failure still reads as a
// repack check failure.
func TestMaintCycleAssessFailGatesGauges(t *testing.T) {
	k, _, dir := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
		{Substr: "pg_indexes_size", Err: errors.New("connection reset")},
	})
	res := k.Cycle(context.Background())
	if res.repackState != "assess-fail" || res.okRepack {
		t.Fatalf("res=%+v", res)
	}
	content := kdepstest.ReadText(t, dir, "kine-db-maint.prom")
	if strings.Contains(content, "kine_db_maint_relation_bytes") {
		t.Fatalf("fabricated relation_bytes on assess-fail:\n%s", content)
	}
	if !strings.Contains(content, `kine_db_maint_ok{check="repack"} 0`) {
		t.Fatalf("repack failure not emitted:\n%s", content)
	}
}

// invalid-index-reaper: the invalid-index reaper drops *_ccnew/*_ccold shells
// BEFORE the reindex and leaves other invalid indexes for an
// operator.
func TestMaintReapsInvalidIndexes(t *testing.T) {
	k, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		// regclass::text may be schema-qualified — the bare-name
		// suffix check must still fire.
		{Substr: "indisvalid", Out: "public.kine_name_prev_revision_uindex_ccnew\nkine_id_idx_ccold\nkine_other_idx\n"},
		{Substr: "DROP INDEX CONCURRENTLY", Out: "DROP INDEX\n"},
		{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
		{Substr: "pg_indexes_size", Out: "100000000|4857600|10|90\n"},
		{Substr: "datfrozenxid", Out: "1000000\n"},
	})
	res := k.Cycle(context.Background())
	if res.invalidDropped != 2 || res.invalidKept != 1 {
		t.Fatalf("res=%+v", res)
	}
	j := fr.Joined()
	for _, want := range []string{
		`DROP INDEX CONCURRENTLY IF EXISTS "kine_name_prev_revision_uindex_ccnew"`,
		`DROP INDEX CONCURRENTLY IF EXISTS "kine_id_idx_ccold"`,
	} {
		if !strings.Contains(j, want) {
			t.Fatalf("missing %q:\n%s", want, j)
		}
	}
	if strings.Contains(j, `DROP INDEX CONCURRENTLY IF EXISTS "kine_other_idx"`) {
		t.Fatalf("non-ccnew/ccold index was dropped:\n%s", j)
	}
	// Ordering: every drop precedes the locked heavy-script call
	// (the REINDEX rides that psql session's stdin now).
	dropIdx, reindexIdx := -1, -1
	for i, c := range fr.Cmds() {
		s := strings.Join(c, " ")
		if strings.Contains(s, "DROP INDEX CONCURRENTLY") && dropIdx < 0 {
			dropIdx = i
		}
		if strings.Contains(s, "ON_ERROR_STOP") && reindexIdx < 0 {
			reindexIdx = i
		}
	}
	if dropIdx < 0 || reindexIdx < 0 || dropIdx > reindexIdx {
		t.Fatalf("reaper ordering wrong (drop=%d reindex=%d)", dropIdx, reindexIdx)
	}
	if !strings.Contains(fr.LastStdin(), `REINDEX TABLE CONCURRENTLY "kine"`) {
		t.Fatalf("heavy script missing reindex:\n%s", fr.LastStdin())
	}
}

// A failed invalid-index listing is noted and skipped — the reindex
// still runs (best-effort reaper).
func TestMaintReaperSkipsOnListFailure(t *testing.T) {
	k, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "indisvalid", Err: errors.New("connection reset")},
		{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
		{Substr: "pg_indexes_size", Out: "100000000|4857600|10|90\n"},
	})
	res := k.Cycle(context.Background())
	if !res.okReindex || res.invalidDropped != 0 {
		t.Fatalf("res=%+v", res)
	}
	if strings.Contains(fr.Joined(), "DROP INDEX CONCURRENTLY") {
		t.Fatalf("drop ran despite the failed listing:\n%s", fr.Joined())
	}
}

// epochPath is the GuardStateDir heavy-block epoch file — the
// startup-skip contract under test.
func epochPath(t *testing.T, dir string) string {
	t.Helper()
	return filepath.Join(dir, "guard", "last-maint-run")
}

func writeEpoch(t *testing.T, dir string, age time.Duration) {
	t.Helper()
	sec := kdepstest.TestNow - int64(age.Seconds())
	if err := os.MkdirAll(filepath.Join(dir, "guard"), 0o755); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // test fixture path
	if err := os.WriteFile(epochPath(t, dir),
		[]byte(strconv.FormatInt(sec, 10)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A heavy block completed <24h ago (agent restart inside the window)
// skips REINDEX + VACUUM FREEZE + pg_repack but still refreshes the
// cheap gauges — sizes read, cycle counts ok.
func TestMaintEpochFreshSkipsHeavyBlock(t *testing.T) {
	k, fr, dir := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "pg_indexes_size", Out: "300000000|14572800|800000|800000\n"},
	})
	writeEpoch(t, dir, time.Hour)
	res := k.Cycle(context.Background())
	if !res.okReindex || res.freezeState != "skipped" ||
		res.repackState != "skipped" {
		t.Fatalf("res=%+v", res)
	}
	if res.heapBytes != 300000000 || !res.statsOK {
		t.Fatalf("cheap stats must still land: %+v", res)
	}
	// The heavy script rides psql stdin — LastStdin() empty proves no
	// REINDEX/FREEZE script ran; the repack exec would show on argv.
	if ls := fr.LastStdin(); ls != "" {
		t.Fatalf("heavy psql script ran inside the 24h window:\n%s", ls)
	}
	if j := fr.Joined(); strings.Contains(j, "pg_repack") ||
		strings.Contains(j, "VACUUM (") {
		t.Fatalf("heavy exec ran inside the 24h window:\n%s", j)
	}
	// The skip must not refresh the epoch — otherwise every cycle
	// would push the heavy block 24h further out, forever.
	sec, err := kdeps.ReadIntFile(epochPath(t, dir))
	if err != nil || sec != kdepstest.TestNow-int64(time.Hour.Seconds()) {
		t.Fatalf("epoch mutated by skip (err=%v sec=%d)", err, sec)
	}
}

// An epoch older than 24h does not gate the heavy block — and a
// successful heavy run stamps the epoch so the next startup skips.
func TestMaintEpochStaleRunsAndStamps(t *testing.T) {
	// Below-threshold repack rules: the heavy script is the only psql
	// stdin this cycle (the repack lock-probe would shadow LastStdin).
	k, fr, dir := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
		{Substr: "pg_indexes_size", Out: "100000000|4857600|10|90\n"},
	})
	writeEpoch(t, dir, 25*time.Hour)
	res := k.Cycle(context.Background())
	if !res.okReindex || res.repackState != "skipped" {
		t.Fatalf("res=%+v", res)
	}
	if ls := fr.LastStdin(); !strings.Contains(ls, `REINDEX TABLE CONCURRENTLY "kine"`) {
		t.Fatalf("stale epoch must not gate the heavy block:\n%s", ls)
	}
	sec, err := kdeps.ReadIntFile(epochPath(t, dir))
	if err != nil || sec != kdepstest.TestNow {
		t.Fatalf("heavy run did not stamp epoch (err=%v sec=%d)", err, sec)
	}
}

// No epoch file at all reads as "never ran" — the heavy block runs
// and stamps the first epoch.
func TestMaintEpochMissingRunsHeavy(t *testing.T) {
	k, fr, dir := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
		{Substr: "pg_indexes_size", Out: "100000000|4857600|10|90\n"},
	})
	res := k.Cycle(context.Background())
	if !res.okReindex {
		t.Fatalf("res=%+v", res)
	}
	if ls := fr.LastStdin(); !strings.Contains(ls, `REINDEX TABLE CONCURRENTLY "kine"`) {
		t.Fatalf("first run must go heavy:\n%s", ls)
	}
	sec, err := kdeps.ReadIntFile(epochPath(t, dir))
	if err != nil || sec != kdepstest.TestNow {
		t.Fatalf("epoch not stamped (err=%v sec=%d)", err, sec)
	}
}

// TestMaintEpochStampsAfterRepack: the epoch lands only after the
// FULL heavy block — during the pg_repack exec it must NOT exist
// yet, and it must exist once Cycle returns. Stamping after the
// reindex alone (the pre-fix behavior) let a restart mid-repack read
// a fresh epoch and park the unfinished repack — heap still bloated —
// for another full window.
func TestMaintEpochStampsAfterRepack(t *testing.T) {
	cfg, fr, dir := kdepstest.Config(t, maintBloatRules)
	repackSawEpoch := false
	inner := cfg.Run
	cfg.Run = func(ctx context.Context, env []string, argv []string,
		stdin string) (string, error) {
		if strings.Contains(strings.Join(argv, " "),
			"--no-superuser-check") {
			_, err := os.Stat(epochPath(t, dir))
			repackSawEpoch = err == nil
		}
		return inner(ctx, env, argv, stdin)
	}
	k := New(kdepstest.Deps(t, cfg))
	res := k.Cycle(context.Background())
	if !res.okReindex || res.repackState != "done" {
		t.Fatalf("res=%+v", res)
	}
	if fr.Count() == 0 || !fr.Ran("--no-superuser-check") {
		t.Fatalf("repack exec never ran:\n%s", fr.Joined())
	}
	if repackSawEpoch {
		t.Fatal("epoch stamped before the repack completed — a restart " +
			"mid-repack would skip the retry for another full window")
	}
	sec, err := kdeps.ReadIntFile(epochPath(t, dir))
	if err != nil || sec != kdepstest.TestNow {
		t.Fatalf("full run did not stamp epoch (err=%v sec=%d)", err, sec)
	}
}

// TestMaintEpochNotStampedOnReindexFailure: a heavy script that
// aborted (ON_ERROR_STOP) must not arm the stamp — the block replays
// next cycle instead of hiding behind a fresh epoch.
func TestMaintEpochNotStampedOnReindexFailure(t *testing.T) {
	k, _, dir := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "ON_ERROR_STOP", Err: errors.New("lock timeout")},
		{Substr: "pg_indexes_size", Out: "100000000|4857600|10|90\n"},
	})
	res := k.Cycle(context.Background())
	if res.okReindex {
		t.Fatal("reindex should fail")
	}
	if _, err := kdeps.ReadIntFile(epochPath(t, dir)); !os.IsNotExist(err) {
		t.Fatalf("failed heavy run stamped the epoch (err=%v)", err)
	}
}

// TestMaintEpochGraceRunsNearBoundary: the skip window is the
// interval MINUS the grace band (maintEpochWindow =
// kdeps.DefaultMaintInterval - maintEpochGrace = 22h). An epoch 23h
// old sits inside the OLD full-interval window — the cadence landing
// there used to SKIP and push real maintenance to ~47h — but must
// now RUN; 21h is still inside the window and skips.
func TestMaintEpochGraceRunsNearBoundary(t *testing.T) {
	rules := []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
		{Substr: "pg_indexes_size", Out: "100000000|4857600|10|90\n"},
	}

	// 23h old: inside the grace band → heavy block runs.
	k, fr, dir := fixture(t, rules)
	writeEpoch(t, dir,
		kdeps.DefaultMaintInterval-maintEpochGrace+time.Hour)
	res := k.Cycle(context.Background())
	if !res.okReindex || res.repackState != "skipped" {
		t.Fatalf("res=%+v", res)
	}
	if ls := fr.LastStdin(); !strings.Contains(ls, `REINDEX TABLE CONCURRENTLY "kine"`) {
		t.Fatalf("grace-band epoch must not gate the heavy block:\n%s", ls)
	}
	// Running it re-stamps — the boundary restart cannot loop.
	sec, err := kdeps.ReadIntFile(epochPath(t, dir))
	if err != nil || sec != kdepstest.TestNow {
		t.Fatalf("grace-band run did not stamp epoch (err=%v sec=%d)", err, sec)
	}

	// 21h old: still inside the window → skip.
	k2, fr2, dir2 := fixture(t, rules)
	writeEpoch(t, dir2, maintEpochGrace+19*time.Hour)
	res2 := k2.Cycle(context.Background())
	if res2.repackState != "skipped" || res2.freezeState != "skipped" {
		t.Fatalf("inside-window run must skip: %+v", res2)
	}
	if ls := fr2.LastStdin(); ls != "" {
		t.Fatalf("heavy script ran inside the skip window:\n%s", ls)
	}
}

// --- Cycle gate paths: creds, read-only stamp suppression ---

// A missing/unreadable .env short-circuits the whole cycle with a
// note — no psql session may run.
func TestMaintCycleCredsMissing(t *testing.T) {
	k, fr, dir := fixture(t, nil)
	if err := os.WriteFile(filepath.Join(dir, ".env"),
		[]byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	res := k.Cycle(context.Background())
	if !containsNote(res.notes, "missing .env creds") {
		t.Fatalf("notes=%v want missing-creds note", res.notes)
	}
	// Container discovery still runs, but no psql session may.
	if fr.Ran("psql") {
		t.Fatalf("cycle ran queries without creds:\n%s", fr.Joined())
	}
}

// The check-kine-db contract: a read-only maint cycle runs the work
// (diagnostics) but never stamps the heavy-block epoch — a CLI round
// must not park the daemon's daily block for 24h.
func TestMaintReadOnlySkipsEpochStamp(t *testing.T) {
	k, _, dir := fixture(t, maintBloatRules)
	k.d.Cfg.ReadOnly = true
	res := k.Cycle(context.Background())
	if !res.okReindex || res.repackState != "done" {
		t.Fatalf("read-only cycle did not run: %+v", res)
	}
	if _, err := kdeps.ReadIntFile(epochPath(t, dir)); !os.IsNotExist(err) {
		t.Fatalf("read-only cycle stamped the epoch (err=%v)", err)
	}
}

// --- repack gate paths: headroom fallback vacuum, lock probe, lookup, extension ---

// A failed VACUUM fallback after the headroom skip notes and keeps
// okRepack semantics (skipped-headroom, not a repack failure).
func TestMaintFallbackVacuumFail(t *testing.T) {
	k, _, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
		{Substr: "pg_indexes_size", Out: "300000000|14572800|800000|800000\n"},
		{Substr: "pg_ls_waldir", Out: "50000000\n"},
		{Substr: "df", Out: "Avail\n800000000\n"},
		{Substr: "datfrozenxid", Out: "1000000\n"},
	})
	k.d.Cfg.Run = failOn(k.d.Cfg.Run, `VACUUM (ANALYZE) "kine"`)
	res := k.Cycle(context.Background())
	if res.repackState != "skipped-headroom" {
		t.Fatalf("repackState=%s", res.repackState)
	}
	if !containsNote(res.notes, "fallback-vacuum-fail") {
		t.Fatalf("notes=%v want fallback-vacuum-fail", res.notes)
	}
}

// The advisory-lock probe failing is best-effort: note, then the
// repack still runs this cycle.
func TestMaintLockProbeFailContinues(t *testing.T) {
	k, fr, _ := fixture(t, maintBloatRules)
	fr.FailOn("ON_ERROR_STOP", errors.New("psql died"))
	res := k.Cycle(context.Background())
	if res.repackState != "done" || !res.okRepack {
		t.Fatalf("res=%+v", res)
	}
	if !containsNote(res.notes, "repack-lock-probe-fail") {
		t.Fatalf("notes=%v want repack-lock-probe-fail", res.notes)
	}
}

// A busy compact-guard lock skips ONLY the repack — heavy script
// untouched, repack state skipped-lock-busy, okRepack stays true.
func TestMaintLockBusySkipsRepack(t *testing.T) {
	k, fr, _ := fixture(t, maintBloatRules)
	fr.On("ON_ERROR_STOP", kdeps.LockBusyMarker+"\n")
	res := k.Cycle(context.Background())
	if res.repackState != "skipped-lock-busy" || !res.okRepack {
		t.Fatalf("res=%+v notes=%v", res, res.notes)
	}
	if strings.Contains(fr.Joined(), "--no-superuser-check") {
		t.Fatalf("pg_repack ran while the guard lock was busy:\n%s", fr.Joined())
	}
	if !containsNote(res.notes, "compact-guard advisory lock busy") {
		t.Fatalf("notes=%v", res.notes)
	}
}

// A failed repackBinPath lookup reads like a missing binary —
// noted, no-binary state, okRepack stays true.
func TestMaintRepackLookupFail(t *testing.T) {
	k, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
		{Substr: "pg_indexes_size", Out: "300000000|14572800|800000|800000\n"},
		{Substr: "pg_ls_waldir", Out: "0\n"},
		{Substr: "df", Out: "Avail\n107374182400\n"},
		{Substr: "datfrozenxid", Out: "1000000\n"},
	})
	// Both glob-root listings fail → the lookup reports the exec
	// error (the old sh -c nonzero exit's repack-lookup-fail note).
	fr.FailOn("ls /usr", errors.New("no such file"))
	res := k.Cycle(context.Background())
	if res.repackState != "no-binary" || !res.okRepack {
		t.Fatalf("res=%+v notes=%v", res, res.notes)
	}
	if !containsNote(res.notes, "repack-lookup-fail") {
		t.Fatalf("notes=%v want repack-lookup-fail", res.notes)
	}
}

// The pg_repack extension creation failing aborts the repack phase
// with repackState=fail and okRepack=false — the binary attempt
// would fail identically and only double the error noise.
func TestMaintRepackExtensionFail(t *testing.T) {
	k, fr, _ := fixture(t, maintBloatRules)
	fr.FailOn("CREATE EXTENSION", errors.New("permission denied"))
	res := k.Cycle(context.Background())
	if res.okRepack || res.repackState != "fail" {
		t.Fatalf("res=%+v notes=%v", res, res.notes)
	}
	if !containsNote(res.notes, "repack-ext-fail") {
		t.Fatalf("notes=%v want repack-ext-fail", res.notes)
	}
	if strings.Contains(fr.Joined(), "--no-superuser-check") {
		t.Fatal("pg_repack ran without its extension")
	}
}

// A garbage sizes row notes sizes-unparsed and keeps the gauges
// unseen — no fabricated zeros, repack stays below-threshold.
func TestMaintSizesUnparsed(t *testing.T) {
	k, _, dir := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
		{Substr: "pg_indexes_size", Out: "garbage\n"},
		{Substr: "datfrozenxid", Out: "1000000\n"},
	})
	res := k.Cycle(context.Background())
	if !containsNote(res.notes, "sizes-unparsed") {
		t.Fatalf("notes=%v want sizes-unparsed", res.notes)
	}
	if res.heapBytes != 0 || res.statsOK {
		t.Fatalf("res=%+v want unseen gauges", res)
	}
	content := kdepstest.ReadText(t, dir, "kine-db-maint.prom")
	if strings.Contains(content, "kine_db_maint_relation_bytes") {
		t.Fatalf("fabricated relation_bytes:\n%s", content)
	}
}

// --- invalid-index reaper edge paths ---

// An unsafe index name is skipped untouched; a failed DROP of a
// _ccnew shell is noted and retried next round.
func TestMaintInvalidIndexUnsafeNameAndDropFail(t *testing.T) {
	k, _, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "indisvalid", Out: "weird name; DROP TABLE\nkine_id_idx_ccnew\nkine_other_idx\n"},
		{Substr: "DROP INDEX CONCURRENTLY", Err: errors.New("tuple locked")},
		{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
		{Substr: "pg_indexes_size", Out: "100000000|4857600|10|90\n"},
		{Substr: "datfrozenxid", Out: "1000000\n"},
	})
	res := k.Cycle(context.Background())
	if res.invalidDropped != 0 || res.invalidKept != 1 {
		t.Fatalf("res=%+v", res)
	}
	if !containsNote(res.notes, `invalid-index "weird name; DROP TABLE" skipped (unsafe name)`) {
		t.Fatalf("notes=%v want unsafe-name skip", res.notes)
	}
	if !containsNote(res.notes, "drop-index-kine_id_idx_ccnew-fail") {
		t.Fatalf("notes=%v want drop failure note", res.notes)
	}
}

// --- freeze.go failure paths (direct calls) ---

// readXidAge: a failed or unparseable age read leaves xidSeen false
// and returns no-freeze.
func TestReadXidAgeFailurePaths(t *testing.T) {
	ctx := context.Background()
	k, _, _ := fixture(t, []testutil.ExecRule{
		{Substr: "datfrozenxid", Err: errors.New("connection reset")},
	})
	h := &Result{}
	var notes []string
	if k.readXidAge(ctx, "pg", "postgres", "secret", h,
		func(s string) { notes = append(notes, s) }) {
		t.Fatal("failed read must not trigger the freeze")
	}
	if h.xidSeen || len(notes) != 1 || !strings.Contains(notes[0], "xid-age-fail") {
		t.Fatalf("h=%+v notes=%v", h, notes)
	}
}

// repackHeadroom: every inconclusive shape must read ok=false (DON'T
// repack) with its own note.
func TestRepackHeadroomFailurePaths(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		rules []testutil.ExecRule
		want  string
	}{
		{"wal query fail", []testutil.ExecRule{
			{Substr: "pg_ls_waldir", Err: errors.New("down")},
		}, "wal-size-fail"},
		{"wal unparsed", []testutil.ExecRule{
			{Substr: "pg_ls_waldir", Out: "abc\n"},
		}, "wal-size-unparsed"},
		{"df fail", []testutil.ExecRule{
			{Substr: "pg_ls_waldir", Out: "0\n"},
			{Substr: "--output=avail", Err: errors.New("down")},
		}, "df-fail"},
		{"df unparsed", []testutil.ExecRule{
			{Substr: "pg_ls_waldir", Out: "0\n"},
			{Substr: "--output=avail", Out: "Avail\nnot-a-number\n"},
		}, "df-unparsed"},
	}
	for _, tc := range cases {
		k, _, _ := fixture(t, tc.rules)
		var notes []string
		free, wal, ok := k.repackHeadroom(ctx, "pg", "postgres", "secret",
			300000000, func(s string) { notes = append(notes, s) })
		if ok || free != 0 || wal != 0 {
			t.Fatalf("%s: free=%d wal=%d ok=%v want inconclusive", tc.name, free, wal, ok)
		}
		if len(notes) != 1 || !strings.Contains(notes[0], tc.want) {
			t.Fatalf("%s: notes=%v want %q", tc.name, notes, tc.want)
		}
	}
}

// failOn wraps a run seam so any command whose joined argv carries
// substr fails — the direct-failure knob for paths fr.On cannot
// target without collateral matches.
func failOn(next kdeps.Runner, substr string) kdeps.Runner {
	return func(ctx context.Context, env, argv []string, stdin string) (string, error) {
		if strings.Contains(strings.Join(argv, " "), substr) {
			return "", fmt.Errorf("forced failure: %s", substr)
		}
		return next(ctx, env, argv, stdin)
	}
}

func containsNote(notes []string, substr string) bool {
	for _, n := range notes {
		if strings.Contains(n, substr) {
			return true
		}
	}
	return false
}

func TestReapOrphanedMaint(t *testing.T) {
	ctx := context.Background()

	// n > 0 notes terminated count.
	k, _, _ := fixture(t, []testutil.ExecRule{
		{Substr: "pg_terminate_backend", Out: "t\nt\n"},
	})
	var notes []string
	k.reapOrphanedMaint(ctx, "pg", "postgres", "secret", func(s string) { notes = append(notes, s) })
	if !containsNote(notes, "terminated 2 orphaned maintenance backend(s)") {
		t.Fatalf("notes=%v want terminated count", notes)
	}

	// n == 0 produces no notes.
	k, _, _ = fixture(t, []testutil.ExecRule{
		{Substr: "pg_terminate_backend", Out: ""},
	})
	notes = nil
	k.reapOrphanedMaint(ctx, "pg", "postgres", "secret", func(s string) { notes = append(notes, s) })
	if len(notes) != 0 {
		t.Fatalf("n=0 notes=%v want empty", notes)
	}

	// Query error notes orphan-reap-fail.
	k, _, _ = fixture(t, []testutil.ExecRule{
		{Substr: "pg_terminate_backend", Err: errors.New("db down")},
	})
	notes = nil
	k.reapOrphanedMaint(ctx, "pg", "postgres", "secret", func(s string) { notes = append(notes, s) })
	if !containsNote(notes, "orphan-reap-fail") {
		t.Fatalf("err notes=%v want orphan-reap-fail", notes)
	}
}
