// freeze_test.go — the maint-cycle VACUUM (FREEZE, ANALYZE) tests,
// lifted out of the flat package's wal_xid_hygiene_test.go.
package maint

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// maintXIDRules — below the repack gate so the cycle stays quiet
// except the freeze decision under test. The REINDEX + FREEZE run in
// the advisory-locked psql script (stdin), whose Miss is silent
// success.
var maintXIDRules = []testutil.ExecRule{
	{Substr: "inspect", Out: "true"},
	{Substr: "pg_indexes_size", Out: "100000000|4857600|10|90\n"},
	{Substr: "datfrozenxid", Out: "1000000\n"},
}

func TestMaintCycleXIDFreezeFires(t *testing.T) {
	k, fr, dir := fixture(t, maintXIDRules)
	fr.On("datfrozenxid", "200000000\n")
	res := k.Cycle(context.Background())
	if !res.xidSeen || res.freezeState != "done" || !res.okFreeze {
		t.Fatalf("res=%+v", res)
	}
	script := fr.LastStdin()
	for _, want := range []string{
		"pg_try_advisory_lock(20260921)",
		`REINDEX TABLE CONCURRENTLY "kine";`,
		`VACUUM (FREEZE, ANALYZE) "kine";`,
		"pg_advisory_unlock(20260921)",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("locked heavy script missing %q:\n%s", want, script)
		}
	}
	content := kdepstest.ReadText(t, dir, "kine-db-maint.prom")
	if !strings.Contains(content, `kine_db_maint_ok{check="vacuum_freeze"} 1`) {
		t.Fatalf("textfile:\n%s", content)
	}
}

func TestMaintCycleXIDFreezeSkipped(t *testing.T) {
	k, fr, dir := fixture(t, maintXIDRules)
	res := k.Cycle(context.Background())
	if res.freezeState != "skipped" || !res.okFreeze {
		t.Fatalf("res=%+v", res)
	}
	if strings.Contains(fr.LastStdin(), "FREEZE") {
		t.Fatalf("freeze vacuum ran below threshold:\n%s", fr.LastStdin())
	}
	content := kdepstest.ReadText(t, dir, "kine-db-maint.prom")
	if !strings.Contains(content, `kine_db_maint_ok{check="vacuum_freeze"} 1`) {
		t.Fatalf("skipped freeze must still read ok:\n%s", content)
	}
}

func TestMaintCycleXIDFreezeFailure(t *testing.T) {
	// ON_ERROR_STOP aborts the locked heavy script — the reindex and
	// the freeze both fail with it.
	k, fr, dir := fixture(t, append(append([]testutil.ExecRule{}, maintXIDRules...),
		testutil.ExecRule{Substr: "ON_ERROR_STOP", Err: errors.New("lock timeout")},
	))
	fr.On("datfrozenxid", "200000000\n")
	res := k.Cycle(context.Background())
	if res.okFreeze || res.freezeState != "fail" {
		t.Fatalf("res=%+v", res)
	}
	content := kdepstest.ReadText(t, dir, "kine-db-maint.prom")
	if !strings.Contains(content, `kine_db_maint_ok{check="vacuum_freeze"} 0`) {
		t.Fatalf("textfile:\n%s", content)
	}
}

// A busy advisory lock (compact guard mid-run) skips the heavy
// block for this cycle without failing the maint run — the same
// skip-counts-as-ok parity the repack gates use.
func TestMaintHeavyBlockLockBusy(t *testing.T) {
	k, fr, dir := fixture(t, maintXIDRules)
	fr.On("datfrozenxid", "200000000\n")
	fr.On("ON_ERROR_STOP", kdeps.LockBusyMarker+"\n")
	res := k.Cycle(context.Background())
	if !res.okReindex || !res.okFreeze || res.freezeState != "skipped" {
		t.Fatalf("busy lock must skip without failing: %+v", res)
	}
	script := fr.LastStdin()
	if !strings.Contains(script, "pg_try_advisory_lock(20260921)") ||
		!strings.Contains(script, kdeps.LockBusyMarker) {
		t.Fatalf("script missing lock guard/marker:\n%s", script)
	}
	content := kdepstest.ReadText(t, dir, "kine-db-maint.prom")
	if !strings.Contains(content, `kine_db_maint_ok{check="reindex"} 1`) {
		t.Fatalf("busy skip must still read ok:\n%s", content)
	}
}

// The heavy script must carry the compact guard's advisory lock
// around the REINDEX even when the freeze does not fire.
func TestMaintHeavyScriptAlwaysLocked(t *testing.T) {
	k, fr, _ := fixture(t, maintXIDRules)
	res := k.Cycle(context.Background())
	if !res.okReindex {
		t.Fatalf("res=%+v", res)
	}
	script := fr.LastStdin()
	for _, want := range []string{
		"pg_try_advisory_lock(20260921)",
		`REINDEX TABLE CONCURRENTLY "kine";`,
		"pg_advisory_unlock(20260921)",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
	}
}
