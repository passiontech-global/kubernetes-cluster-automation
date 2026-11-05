package kinedb

import (
	"context"
	"errors"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"strings"
	"testing"
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
	{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
	{Substr: "pg_indexes_size", Out: "300000000|14572800|800000|800000\n"},
	// W8-CP2 headroom gate: 0 WAL bytes, 100GiB free — ample for the
	// 300MB heap (needs >= 2.5*heap).
	{Substr: "pg_ls_waldir", Out: "0\n"},
	{Substr: "df", Out: "Avail\n107374182400\n"},
}

func TestMaintCycleRepacksWhenBloated(t *testing.T) {
	k, fr, dir := fixture(t, maintBloatRules)
	res := k.maintCycle(context.Background())
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
	content := readText(t, dir, "kine-db-maint.prom")
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
	res := k.maintCycle(context.Background())
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
		// headroom gate passes, then repackGlob finds nothing →
		// empty reply.
		{Substr: "pg_ls_waldir", Out: "0\n"},
		{Substr: "df", Out: "Avail\n107374182400\n"},
	})
	res := k.maintCycle(context.Background())
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
	res := k.maintCycle(context.Background())
	if res.repackState != "skipped-headroom" {
		t.Fatalf("repackState=%s", res.repackState)
	}
	j := fr.Joined()
	if !strings.Contains(j, "VACUUM (ANALYZE) kine") {
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
		{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
		{Substr: "pg_indexes_size", Out: "300000000|14572800|800000|800000\n"},
		{Substr: "pg_ls_waldir", Out: "0\n"},
		{Substr: "df", Out: "Avail\n107374182400\n"},
	})
	res := k.maintCycle(context.Background())
	if res.okRepack || res.repackState != "fail" {
		t.Fatalf("res=%+v", res)
	}
	content := readText(t, dir, "kine-db-maint.prom")
	if !strings.Contains(content, `kine_db_maint_ok{check="repack"} 0`) {
		t.Fatalf("textfile:\n%s", content)
	}
}

func TestMaintCycleReindexFailure(t *testing.T) {
	k, _, dir := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Out: "true"},
		{Substr: "REINDEX TABLE CONCURRENTLY", Err: errors.New("lock timeout")},
		{Substr: "pg_indexes_size", Out: "100000000|4857600|10|90\n"},
	})
	res := k.maintCycle(context.Background())
	if res.okReindex {
		t.Fatal("reindex should fail")
	}
	content := readText(t, dir, "kine-db-maint.prom")
	if !strings.Contains(content, `kine_db_maint_ok{check="reindex"} 0`) {
		t.Fatalf("textfile:\n%s", content)
	}
}

func TestMaintCycleContainerDown(t *testing.T) {
	k, fr, _ := fixture(t, []testutil.ExecRule{
		{Substr: "inspect", Err: errors.New("down")},
		{Substr: "ps --format", Out: ""},
	})
	res := k.maintCycle(context.Background())
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
	res := k.maintCycle(context.Background())
	if res.repackState != "assess-fail" || res.okRepack {
		t.Fatalf("res=%+v", res)
	}
	content := readText(t, dir, "kine-db-maint.prom")
	if strings.Contains(content, "kine_db_maint_relation_bytes") {
		t.Fatalf("fabricated relation_bytes on assess-fail:\n%s", content)
	}
	if !strings.Contains(content, `kine_db_maint_ok{check="repack"} 0`) {
		t.Fatalf("repack failure not emitted:\n%s", content)
	}
}
