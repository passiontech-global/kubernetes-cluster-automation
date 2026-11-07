// freeze_test.go — the maint-cycle VACUUM (FREEZE, ANALYZE) tests,
// lifted out of the flat package's wal_xid_hygiene_test.go.
package maint

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// maintXIDRules — below the repack gate so the cycle stays quiet
// except the freeze decision under test.
var maintXIDRules = []testutil.ExecRule{
	{Substr: "inspect", Out: "true"},
	{Substr: "REINDEX TABLE CONCURRENTLY", Out: "REINDEX\n"},
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
	if !strings.Contains(fr.Joined(), `VACUUM (FREEZE, ANALYZE) "kine"`) {
		t.Fatalf("freeze vacuum did not run:\n%s", fr.Joined())
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
	if strings.Contains(fr.Joined(), "FREEZE") {
		t.Fatalf("freeze vacuum ran below threshold:\n%s", fr.Joined())
	}
	content := kdepstest.ReadText(t, dir, "kine-db-maint.prom")
	if !strings.Contains(content, `kine_db_maint_ok{check="vacuum_freeze"} 1`) {
		t.Fatalf("skipped freeze must still read ok:\n%s", content)
	}
}

func TestMaintCycleXIDFreezeFailure(t *testing.T) {
	k, fr, dir := fixture(t, append(append([]testutil.ExecRule{}, maintXIDRules...),
		testutil.ExecRule{Substr: "FREEZE", Err: errors.New("lock timeout")},
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
