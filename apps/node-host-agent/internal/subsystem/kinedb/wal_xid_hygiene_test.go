package kinedb

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
)

// hygieneRules is probeOKRules plus canned replies for the
// kine-pg-hygiene + WAL archive guard queries — 2 idle-in-tx
// sessions, a quiet dead-tuple ratio, healthy XID age, 1GiB WAL on
// a 100GiB filesystem, clean archiver and no inactive slots.
var hygieneRules = append(append([]testutil.ExecRule{}, probeOKRules...),
	testutil.ExecRule{Substr: "pg_terminate_backend", Out: "t\nt\n"},
	testutil.ExecRule{Substr: "COUNT(pid)", Out: "2\n"},
	testutil.ExecRule{Substr: "n_dead_tup, n_live_tup", Out: "100|1000\n"},
	testutil.ExecRule{Substr: "datfrozenxid", Out: "5000000\n"},
	testutil.ExecRule{Substr: "pg_ls_waldir", Out: "1073741824\n"},
	testutil.ExecRule{Substr: "--output=size", Out: "Size\n107374182400\n"},
	testutil.ExecRule{Substr: "pg_stat_archiver", Out: "0\n"},
	testutil.ExecRule{Substr: "pg_replication_slots", Out: ""},
)

func TestProbeCycleHygieneEmitsAllSeries(t *testing.T) {
	k, fr, dir := fixture(t, hygieneRules)
	res := k.probeCycle(context.Background())
	if !res.succeeded {
		t.Fatalf("probe failed: %v", res.notes)
	}
	h := res.hyg
	if h == nil {
		t.Fatal("hygiene block did not run")
	}
	if h.idleInTx != 2 || !h.idleSeen {
		t.Fatalf("idle=%+v", h)
	}
	if !h.deadSeen || h.deadRatio != 0.1 {
		t.Fatalf("dead=%+v", h)
	}
	if h.xidAge != 5000000 || !h.xidSeen {
		t.Fatalf("xid=%+v", h)
	}
	if h.walBytes != 1073741824 || !h.walSeen {
		t.Fatalf("wal=%+v", h)
	}
	if !h.walDiskSeen || h.walDiskRatio != 0.01 {
		t.Fatalf("wal ratio=%+v", h)
	}
	if h.archiveStale != 0 || !h.archiveSeen {
		t.Fatalf("archiver=%+v", h)
	}
	if h.slotRetained != 0 || !h.slotSeen || h.slotsDropped != 0 {
		t.Fatalf("slots=%+v", h)
	}
	content := readText(t, dir, "kine-db.prom")
	for _, want := range []string{
		"kine_db_idle_in_tx_sessions 2",
		"node_agent_kine_pg_idle_in_tx_sessions 2",
		"node_agent_kine_pg_dead_tuple_ratio 0.1",
		"kine_db_xid_age_transactions 5000000",
		"kine_db_wal_bytes 1073741824",
		"kine_db_wal_disk_ratio 0.01",
		"kine_db_wal_archive_stale 0",
		"kine_db_inactive_slot_retained_bytes 0",
		// The reaper killed 2 backends this round.
		"node_agent_kine_pg_idle_in_tx_terminated_total 2",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("textfile missing %q:\n%s", want, content)
		}
	}
	// The reaper now covers the real backend database ('postgres')
	// not just a hypothetical 'kine' datname.
	if !strings.Contains(fr.Joined(), "datname IN ('postgres', 'kine')") {
		t.Fatalf("reaper did not target both databases:\n%s", fr.Joined())
	}
}

// A failed hygiene query gates only its own series — the probe
// still succeeds and the unaffected series still emit.
func TestProbeHygieneDegradesOnQueryFailure(t *testing.T) {
	k, _, dir := fixture(t, append(append([]testutil.ExecRule{}, probeOKRules...),
		testutil.ExecRule{Substr: "pg_ls_waldir", Err: errors.New("connection reset")},
		testutil.ExecRule{Substr: "pg_stat_archiver", Err: errors.New("connection reset")},
	))
	res := k.probeCycle(context.Background())
	if !res.succeeded {
		t.Fatalf("probe failed: %v", res.notes)
	}
	if res.hyg.walSeen || res.hyg.walDiskSeen || res.hyg.archiveSeen {
		t.Fatalf("failed reads must stay unseen: %+v", res.hyg)
	}
	content := readText(t, dir, "kine-db.prom")
	for _, absent := range []string{
		"kine_db_wal_bytes", "kine_db_wal_disk_ratio", "kine_db_wal_archive_stale",
	} {
		if strings.Contains(content, absent) {
			t.Fatalf("fabricated %s on query failure:\n%s", absent, content)
		}
	}
}

// The emergency vacuum fires only past BOTH gates: ratio > 0.5 and
// n_dead_tup > 50000. 60000 dead / 30000 live = ratio 2.0.
func TestDeadTupleVacuumFiresAndCoolsDown(t *testing.T) {
	k, fr, _ := fixture(t, append(append([]testutil.ExecRule{}, hygieneRules...),
		testutil.ExecRule{Substr: "ON_ERROR_STOP", Out: "VACUUM\n"},
	))
	fr.On("n_dead_tup, n_live_tup", "60000|30000\n")
	res := k.probeCycle(context.Background())
	if !res.hyg.vacuumFired {
		t.Fatalf("vacuum did not fire: notes=%v", res.notes)
	}
	script := fr.LastStdin()
	for _, want := range []string{
		"pg_try_advisory_lock(20260921)",
		`VACUUM (ANALYZE) "kine";`,
		"pg_advisory_unlock(20260921)",
		lockBusyMarker,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("vacuum script missing %q:\n%s", want, script)
		}
	}
	// The cooldown budget file landed under GuardStateDir.
	if _, err := os.Stat(filepath.Join(k.cfg.GuardStateDir, deadTupleVacuumFile)); err != nil {
		t.Fatalf("cooldown file missing: %v", err)
	}

	// Second round inside the 30m budget → no script session at all.
	fr.ClearLog()
	res = k.probeCycle(context.Background())
	if res.hyg.vacuumFired {
		t.Fatal("vacuum fired inside the cooldown window")
	}
	if strings.Contains(fr.Joined(), "ON_ERROR_STOP") {
		t.Fatalf("script session ran inside cooldown:\n%s", fr.Joined())
	}
}

// A busy advisory lock (compact guard running) skips the vacuum —
// the compact session ends in VACUUM itself.
func TestDeadTupleVacuumLockBusy(t *testing.T) {
	k, fr, _ := fixture(t, hygieneRules)
	fr.On("n_dead_tup, n_live_tup", "60000|30000\n")
	fr.On("ON_ERROR_STOP", lockBusyMarker+"\n")
	res := k.probeCycle(context.Background())
	if res.hyg.vacuumFired {
		t.Fatal("vacuum reported fired while the lock was busy")
	}
	found := false
	for _, n := range res.notes {
		if strings.Contains(n, "lock busy") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no lock-busy note: %v", res.notes)
	}
}

func TestDeadTupleVacuumSkippedBelowThreshold(t *testing.T) {
	k, fr, _ := fixture(t, hygieneRules) // ratio 0.1 — quiet
	res := k.probeCycle(context.Background())
	if res.hyg.vacuumFired {
		t.Fatal("vacuum fired below threshold")
	}
	if strings.Contains(fr.Joined(), "ON_ERROR_STOP") {
		t.Fatalf("script session ran below threshold:\n%s", fr.Joined())
	}
}

func TestParseSlotRows(t *testing.T) {
	slots := parseSlotRows("wal-g|1073741824\nbroken|\nno-pipe-line\n\n")
	if len(slots) != 1 || slots[0].name != "wal-g" || slots[0].retained != 1073741824 {
		t.Fatalf("slots=%+v", slots)
	}
	if parseSlotRows("") != nil {
		t.Fatal("empty output must give no slots")
	}
}

// An inactive slot past the 10GiB critical threshold is dropped;
// between 5 and 10GiB it only warns.
func TestInactiveSlotDropAndWarn(t *testing.T) {
	k, fr, dir := fixture(t, hygieneRules)
	fr.On("pg_replication_slots", "slot-old|16106127360\nslot-warn|7516192768\n")
	res := k.probeCycle(context.Background())
	h := res.hyg
	if !h.slotSeen || h.slotsDropped != 1 {
		t.Fatalf("slots=%+v notes=%v", h, res.notes)
	}
	if h.slotRetained != 16106127360+7516192768 {
		t.Fatalf("retained=%d", h.slotRetained)
	}
	j := fr.Joined()
	if !strings.Contains(j, "pg_drop_replication_slot('slot-old')") {
		t.Fatalf("critical slot not dropped:\n%s", j)
	}
	if strings.Contains(j, "pg_drop_replication_slot('slot-warn')") {
		t.Fatalf("warn-level slot was dropped:\n%s", j)
	}
	content := readText(t, dir, "kine-db.prom")
	if !strings.Contains(content, "kine_db_inactive_slot_retained_bytes 23622320128") {
		t.Fatalf("textfile:\n%s", content)
	}
}

func TestProbeArchiveStaleEmitsOne(t *testing.T) {
	k, fr, dir := fixture(t, hygieneRules)
	fr.On("pg_stat_archiver", "1\n")
	k.probeCycle(context.Background())
	content := readText(t, dir, "kine-db.prom")
	if !strings.Contains(content, "kine_db_wal_archive_stale 1") {
		t.Fatalf("textfile:\n%s", content)
	}
}

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
	res := k.maintCycle(context.Background())
	if !res.xidSeen || res.freezeState != "done" || !res.okFreeze {
		t.Fatalf("res=%+v", res)
	}
	if !strings.Contains(fr.Joined(), `VACUUM (FREEZE, ANALYZE) "kine"`) {
		t.Fatalf("freeze vacuum did not run:\n%s", fr.Joined())
	}
	content := readText(t, dir, "kine-db-maint.prom")
	if !strings.Contains(content, `kine_db_maint_ok{check="vacuum_freeze"} 1`) {
		t.Fatalf("textfile:\n%s", content)
	}
}

func TestMaintCycleXIDFreezeSkipped(t *testing.T) {
	k, fr, dir := fixture(t, maintXIDRules)
	res := k.maintCycle(context.Background())
	if res.freezeState != "skipped" || !res.okFreeze {
		t.Fatalf("res=%+v", res)
	}
	if strings.Contains(fr.Joined(), "FREEZE") {
		t.Fatalf("freeze vacuum ran below threshold:\n%s", fr.Joined())
	}
	content := readText(t, dir, "kine-db-maint.prom")
	if !strings.Contains(content, `kine_db_maint_ok{check="vacuum_freeze"} 1`) {
		t.Fatalf("skipped freeze must still read ok:\n%s", content)
	}
}

func TestMaintCycleXIDFreezeFailure(t *testing.T) {
	k, fr, dir := fixture(t, append(append([]testutil.ExecRule{}, maintXIDRules...),
		testutil.ExecRule{Substr: "FREEZE", Err: errors.New("lock timeout")},
	))
	fr.On("datfrozenxid", "200000000\n")
	res := k.maintCycle(context.Background())
	if res.okFreeze || res.freezeState != "fail" {
		t.Fatalf("res=%+v", res)
	}
	content := readText(t, dir, "kine-db-maint.prom")
	if !strings.Contains(content, `kine_db_maint_ok{check="vacuum_freeze"} 0`) {
		t.Fatalf("textfile:\n%s", content)
	}
}

// --- item 5: multiXact age ---

func TestProbeHygieneMultiXactEmits(t *testing.T) {
	k, _, dir := fixture(t, append(append([]testutil.ExecRule{}, hygieneRules...),
		testutil.ExecRule{Substr: "datminmxid", Out: "250000\n"},
	))
	res := k.probeCycle(context.Background())
	if !res.succeeded {
		t.Fatalf("probe failed: %v", res.notes)
	}
	if res.hyg.mxidAge != 250000 || !res.hyg.mxidSeen {
		t.Fatalf("mxid=%+v", res.hyg)
	}
	content := readText(t, dir, xactPromFile)
	if !strings.Contains(content, "kine_db_multixact_age_transactions 250000") {
		t.Fatalf("textfile:\n%s", content)
	}
}

// A failed mxid read gates only its own series — headers-only in
// the xact textfile, probe still succeeds.
func TestProbeHygieneMultiXactQueryFailure(t *testing.T) {
	k, _, dir := fixture(t, append(append([]testutil.ExecRule{}, hygieneRules...),
		testutil.ExecRule{Substr: "datminmxid", Err: errors.New("connection reset")},
	))
	res := k.probeCycle(context.Background())
	if !res.succeeded {
		t.Fatalf("probe failed: %v", res.notes)
	}
	if res.hyg.mxidSeen {
		t.Fatal("failed mxid read must stay unseen")
	}
	content := readText(t, dir, xactPromFile)
	if !strings.Contains(content, "# TYPE kine_db_multixact_age_transactions") {
		t.Fatalf("header missing:\n%s", content)
	}
	for _, l := range strings.Split(content, "\n") {
		if strings.HasPrefix(l, "kine_db_multixact_age_transactions ") {
			t.Fatalf("fabricated a sample on query failure:\n%s", content)
		}
	}
}

// --- item 6: orphaned prepared transactions ---

// Orphans listed by pg_prepared_xacts are rolled back in place and
// counted — gid reaches SQL as a safely-quoted literal.
func TestOrphanPreparedXactsRolledBack(t *testing.T) {
	k, fr, dir := fixture(t, hygieneRules)
	fr.On("pg_prepared_xacts", "gid-orphan-1\ngid'quo\n")
	fr.On("ROLLBACK PREPARED", "ROLLBACK PREPARED\n")
	before := preparedXactRolledBackTotal.Load()
	res := k.probeCycle(context.Background())
	h := res.hyg
	if !h.preparedSeen || h.preparedXacts != 2 || h.preparedRolled != 2 {
		t.Fatalf("prepared=%+v notes=%v", h, res.notes)
	}
	j := fr.Joined()
	if !strings.Contains(j, "ROLLBACK PREPARED 'gid-orphan-1'") {
		t.Fatalf("orphan gid not rolled back:\n%s", j)
	}
	// A quote inside the gid doubles per SQL literal rules — it
	// must not break the statement.
	if !strings.Contains(j, "ROLLBACK PREPARED 'gid''quo'") {
		t.Fatalf("gid quoting wrong:\n%s", j)
	}
	if got := preparedXactRolledBackTotal.Load() - before; got != 2 {
		t.Fatalf("rolled-back total delta=%d want 2", got)
	}
	content := readText(t, dir, xactPromFile)
	for _, want := range []string{
		"kine_db_orphan_prepared_xacts 2",
		"kine_db_orphan_prepared_xacts_rolled_back_total ",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("textfile missing %q:\n%s", want, content)
		}
	}
}

// A failed rollback is absorbed (note + retry next round) — the
// sibling orphans still roll back and the probe still succeeds.
func TestOrphanPreparedXactsPartialFailure(t *testing.T) {
	k, fr, _ := fixture(t, hygieneRules)
	fr.On("pg_prepared_xacts", "gid-bad\ngid-good\n")
	fr.On("ROLLBACK PREPARED 'gid-good'", "ROLLBACK PREPARED\n")
	fr.FailOn("ROLLBACK PREPARED 'gid-bad'", errors.New("already aborted"))
	res := k.probeCycle(context.Background())
	h := res.hyg
	if !h.preparedSeen || h.preparedXacts != 2 || h.preparedRolled != 1 {
		t.Fatalf("prepared=%+v notes=%v", h, res.notes)
	}
	found := false
	for _, n := range res.notes {
		if strings.Contains(n, "rollback-prepared-gid-bad-fail") {
			found = true
		}
	}
	if !found {
		t.Fatalf("failed rollback not noted: %v", res.notes)
	}
}

// An empty prepared-xacts read emits a real zero gauge and never
// runs a rollback.
func TestNoOrphanPreparedXacts(t *testing.T) {
	k, fr, dir := fixture(t, hygieneRules) // pg_prepared_xacts unmatched → ""
	res := k.probeCycle(context.Background())
	h := res.hyg
	if !h.preparedSeen || h.preparedXacts != 0 || h.preparedRolled != 0 {
		t.Fatalf("prepared=%+v", h)
	}
	if strings.Contains(fr.Joined(), "ROLLBACK PREPARED") {
		t.Fatalf("rollback ran with no orphans:\n%s", fr.Joined())
	}
	content := readText(t, dir, xactPromFile)
	if !strings.Contains(content, "kine_db_orphan_prepared_xacts 0") {
		t.Fatalf("textfile:\n%s", content)
	}
}
