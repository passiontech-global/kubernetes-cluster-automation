package probe

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

// hygieneRules is kdepstest.ProbeOKRules plus canned replies for the
// kine-pg-hygiene + WAL archive guard queries — 2 idle-in-tx
// sessions, a quiet dead-tuple ratio, healthy XID age, 1GiB WAL on
// a 100GiB filesystem, clean archiver and no inactive slots.
var hygieneRules = append(append([]testutil.ExecRule{}, kdepstest.ProbeOKRules...),
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
	res := k.Cycle(context.Background())
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
	content := kdepstest.ReadText(t, dir, "kine-db.prom")
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
	k, _, dir := fixture(t, append(append([]testutil.ExecRule{}, kdepstest.ProbeOKRules...),
		testutil.ExecRule{Substr: "pg_ls_waldir", Err: errors.New("connection reset")},
		testutil.ExecRule{Substr: "pg_stat_archiver", Err: errors.New("connection reset")},
	))
	res := k.Cycle(context.Background())
	if !res.succeeded {
		t.Fatalf("probe failed: %v", res.notes)
	}
	if res.hyg.walSeen || res.hyg.walDiskSeen || res.hyg.archiveSeen {
		t.Fatalf("failed reads must stay unseen: %+v", res.hyg)
	}
	content := kdepstest.ReadText(t, dir, "kine-db.prom")
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
	res := k.Cycle(context.Background())
	if !res.hyg.vacuumFired {
		t.Fatalf("vacuum did not fire: notes=%v", res.notes)
	}
	script := fr.LastStdin()
	for _, want := range []string{
		"pg_try_advisory_lock(20260921)",
		`VACUUM (ANALYZE) "kine";`,
		"pg_advisory_unlock(20260921)",
		kdeps.LockBusyMarker,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("vacuum script missing %q:\n%s", want, script)
		}
	}
	// The cooldown budget file landed under GuardStateDir.
	if _, err := os.Stat(filepath.Join(k.d.Cfg.GuardStateDir, deadTupleVacuumFile)); err != nil {
		t.Fatalf("cooldown file missing: %v", err)
	}

	// Second round inside the 30m budget → no script session at all.
	fr.ClearLog()
	res = k.Cycle(context.Background())
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
	fr.On("ON_ERROR_STOP", kdeps.LockBusyMarker+"\n")
	res := k.Cycle(context.Background())
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
	res := k.Cycle(context.Background())
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
	res := k.Cycle(context.Background())
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
	content := kdepstest.ReadText(t, dir, "kine-db.prom")
	if !strings.Contains(content, "kine_db_inactive_slot_retained_bytes 23622320128") {
		t.Fatalf("textfile:\n%s", content)
	}
}

func TestProbeArchiveStaleEmitsOne(t *testing.T) {
	k, fr, dir := fixture(t, hygieneRules)
	fr.On("pg_stat_archiver", "1\n")
	k.Cycle(context.Background())
	content := kdepstest.ReadText(t, dir, "kine-db.prom")
	if !strings.Contains(content, "kine_db_wal_archive_stale 1") {
		t.Fatalf("textfile:\n%s", content)
	}
}

// --- item 5: multiXact age ---

func TestProbeHygieneMultiXactEmits(t *testing.T) {
	k, _, dir := fixture(t, append(append([]testutil.ExecRule{}, hygieneRules...),
		// The catalog exec answers all three censuses in one
		// multi-statement output: mxid line, invalid-index line,
		// seq_scan|seq_tup_read line.
		testutil.ExecRule{Substr: "datminmxid", Out: "250000\n1\n7|40000\n"},
	))
	res := k.Cycle(context.Background())
	if !res.succeeded {
		t.Fatalf("probe failed: %v", res.notes)
	}
	if res.hyg.mxidAge != 250000 || !res.hyg.mxidSeen {
		t.Fatalf("mxid=%+v", res.hyg)
	}
	content := kdepstest.ReadText(t, dir, xactPromFile)
	if !strings.Contains(content, "kine_db_multixact_age_transactions 250000") {
		t.Fatalf("textfile:\n%s", content)
	}
}

// A failed catalog exec gates every census it carries — the mxid
// series goes headers-only in the xact textfile, probe still
// succeeds.
func TestProbeHygieneMultiXactQueryFailure(t *testing.T) {
	k, _, dir := fixture(t, append(append([]testutil.ExecRule{}, hygieneRules...),
		testutil.ExecRule{Substr: "datminmxid", Err: errors.New("connection reset")},
	))
	res := k.Cycle(context.Background())
	if !res.succeeded {
		t.Fatalf("probe failed: %v", res.notes)
	}
	if res.hyg.mxidSeen {
		t.Fatal("failed mxid read must stay unseen")
	}
	content := kdepstest.ReadText(t, dir, xactPromFile)
	if !strings.Contains(content, "# TYPE kine_db_multixact_age_transactions") {
		t.Fatalf("header missing:\n%s", content)
	}
	for l := range strings.SplitSeq(content, "\n") {
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
	before := k.preparedXactRolledBack.Load()
	res := k.Cycle(context.Background())
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
	if got := k.preparedXactRolledBack.Load() - before; got != 2 {
		t.Fatalf("rolled-back total delta=%d want 2", got)
	}
	content := kdepstest.ReadText(t, dir, xactPromFile)
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
	res := k.Cycle(context.Background())
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
	res := k.Cycle(context.Background())
	h := res.hyg
	if !h.preparedSeen || h.preparedXacts != 0 || h.preparedRolled != 0 {
		t.Fatalf("prepared=%+v", h)
	}
	if strings.Contains(fr.Joined(), "ROLLBACK PREPARED") {
		t.Fatalf("rollback ran with no orphans:\n%s", fr.Joined())
	}
	content := kdepstest.ReadText(t, dir, xactPromFile)
	if !strings.Contains(content, "kine_db_orphan_prepared_xacts 0") {
		t.Fatalf("textfile:\n%s", content)
	}
}

// --- item 7: invalid-index-reaper invalid-index census + seq-scan guard ---

func TestProbeInvalidIndexCensusEmits(t *testing.T) {
	k, _, dir := fixture(t, append(append([]testutil.ExecRule{}, hygieneRules...),
		// The catalog exec answers all three censuses in one
		// multi-statement output: mxid line, invalid-index line.
		testutil.ExecRule{Substr: "indisvalid", Out: "9\n2\n"}))
	res := k.Cycle(context.Background())
	if !res.succeeded {
		t.Fatalf("probe failed: %v", res.notes)
	}
	if res.hyg.invalidIdx != 2 || !res.hyg.invalidSeen {
		t.Fatalf("invalid=%+v", res.hyg)
	}
	content := kdepstest.ReadText(t, dir, "kine-db.prom")
	if !strings.Contains(content, "kine_db_invalid_indexes 2") {
		t.Fatalf("textfile:\n%s", content)
	}
}

// seq_tup_read deltas: first read only baselines; +600K trips the
// 500K gate → ANALYZE under the 30m last-kine-analyze budget; a
// further spike inside the budget is eaten by the cooldown.
func TestProbeSeqScanEmitsAndAnalyzeFires(t *testing.T) {
	k, fr, dir := fixture(t, hygieneRules)
	// The catalog exec's three-statement output: mxid, invalid
	// indexes, seq_scan|seq_tup_read.
	fr.On("seq_tup_read", "9\n0\n120|100000\n")
	res := k.Cycle(context.Background())
	if !res.succeeded {
		t.Fatalf("probe failed: %v", res.notes)
	}
	if res.hyg.seqScans != 120 || res.hyg.seqTupRead != 100000 || !res.hyg.seqSeen {
		t.Fatalf("seq=%+v", res.hyg)
	}
	if res.hyg.analyzeFired {
		t.Fatal("ANALYZE fired on the baseline read")
	}
	content := kdepstest.ReadText(t, dir, "kine-db.prom")
	for _, want := range []string{
		"kine_db_seq_scans_total 120",
		"kine_db_seq_tuples_read_total 100000",
		"# TYPE kine_db_seq_scans_total counter",
		"# TYPE kine_db_seq_tuples_read_total counter",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("textfile missing %q:\n%s", want, content)
		}
	}

	// Second probe: +600K tuples read via seq scan → the planner
	// regressed; ANALYZE runs immediately, budgeted.
	fr.On("seq_tup_read", "9\n0\n180|700000\n")
	res = k.Cycle(context.Background())
	if !res.hyg.analyzeFired {
		t.Fatalf("ANALYZE did not fire on a 600K delta: %v", res.notes)
	}
	if !strings.Contains(fr.Joined(), `ANALYZE "kine"`) {
		t.Fatalf("ANALYZE missing from command log:\n%s", fr.Joined())
	}
	if _, err := os.Stat(filepath.Join(k.d.Cfg.GuardStateDir, kineAnalyzeFile)); err != nil {
		t.Fatalf("analyze budget file missing: %v", err)
	}

	// Third probe still spikes but inside the 30m budget → cooldown.
	fr.ClearLog()
	fr.On("seq_tup_read", "9\n0\n200|1400000\n")
	res = k.Cycle(context.Background())
	if res.hyg.analyzeFired {
		t.Fatal("ANALYZE re-fired inside the 30m budget")
	}
	if strings.Contains(fr.Joined(), `ANALYZE "kine"`) {
		t.Fatalf("ANALYZE ran inside the cooldown:\n%s", fr.Joined())
	}
}

// A delta at or under 500K is normal kine churn — no ANALYZE.
func TestProbeSeqScanBelowDeltaNoAnalyze(t *testing.T) {
	k, fr, _ := fixture(t, hygieneRules)
	fr.On("seq_tup_read", "9\n0\n50|400000\n")
	res := k.Cycle(context.Background())
	if res.hyg.analyzeFired {
		t.Fatal("ANALYZE fired on the baseline read")
	}
	fr.On("seq_tup_read", "9\n0\n55|890000\n") // +490K — under the trip line
	res = k.Cycle(context.Background())
	if res.hyg.analyzeFired {
		t.Fatalf("ANALYZE fired under the delta gate: %v", res.notes)
	}
	if strings.Contains(fr.Joined(), `ANALYZE "kine"`) {
		t.Fatalf("ANALYZE ran below the delta gate:\n%s", fr.Joined())
	}
}

// A failed catalog exec gates all three censuses it carries — the
// probe still succeeds and no fabricated counters land in the
// textfile.
func TestProbeSeqScanDegradesOnQueryFailure(t *testing.T) {
	k, _, dir := fixture(t, append(append([]testutil.ExecRule{}, hygieneRules...),
		testutil.ExecRule{Substr: "seq_tup_read", Err: errors.New("connection reset")}))
	res := k.Cycle(context.Background())
	if !res.succeeded {
		t.Fatalf("probe failed: %v", res.notes)
	}
	if res.hyg.seqSeen || res.hyg.invalidSeen || res.hyg.mxidSeen {
		t.Fatalf("failed reads must stay unseen: %+v", res.hyg)
	}
	content := kdepstest.ReadText(t, dir, "kine-db.prom")
	for _, absent := range []string{
		"kine_db_invalid_indexes",
		"kine_db_multixact_age_transactions ",
		"kine_db_seq_scans_total",
		"kine_db_seq_tuples_read_total",
	} {
		if strings.Contains(content, absent) {
			t.Fatalf("fabricated %s on query failure:\n%s", absent, content)
		}
	}
}

// TestProbeHygieneReadOnlyDiagnostics: the check-kine-db contract —
// every mutating hygiene path stays read-only. Orphaned prepared
// xacts are only counted, the dead-tuple VACUUM is suppressed, an
// oversized inactive slot is only reported, the churn watermark and
// seq-scan baseline are not rebased, and kine-db-xact.prom is never
// written.
func TestProbeHygieneReadOnlyDiagnostics(t *testing.T) {
	k, fr, dir := fixture(t, hygieneRules)
	k.d.Cfg.ReadOnly = true
	fr.On("pg_prepared_xacts", "gid-one\ngid-two\n")
	fr.On("n_dead_tup, n_live_tup", "60000|30000\n")
	fr.On("pg_replication_slots", "slot-orphan|16106127360\n") // 15GiB > 10GiB gate
	fr.On("SHOW POOLS", `database|user|cl_active|cl_waiting|sv_active|sv_idle|sv_used|sv_tested|sv_login|maxwait|maxwait_us|pool_mode
postgres|postgres|4|50|3|7|0|0|0|0|0|transaction
`)
	res := k.Cycle(context.Background())
	// Saturation legitimately zeroes the pools check — containers,
	// wire, e2e and backend_env must still pass.
	if res.Checks[CheckContainers] != 1 || res.Checks[CheckWire] != 1 ||
		res.Checks[CheckE2EAuth] != 1 || res.Checks[CheckBackendEnv] != 1 {
		t.Fatalf("checks=%v", res.Checks)
	}
	h := res.hyg
	if h.preparedXacts != 2 || h.preparedRolled != 0 {
		t.Fatalf("prepared=%+v want counted-not-rolled", h)
	}
	if h.vacuumFired {
		t.Fatal("read-only probe fired the dead-tuple VACUUM")
	}
	if h.slotsDropped != 0 {
		t.Fatal("read-only probe dropped a slot")
	}
	joined := strings.Join(res.notes, "\n")
	for _, want := range []string{
		"read-only: 2 orphaned prepared xact(s) left in place",
		"read-only: dead-tuple VACUUM (ANALYZE) suppressed",
		"read-only: inactive slot slot-orphan pins",
		"read-only: pgbouncer saturated cl_waiting=50>20",
		"pool-queue=50>20",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("notes missing %q:\n%s", want, joined)
		}
	}
	j := fr.Joined()
	for _, absent := range []string{
		"ROLLBACK PREPARED", "pg_drop_replication_slot", "pg_terminate_backend",
		"split_part(name", // churn watermark must not be sampled
		"OCTET_LENGTH",    // the large-keys census detoast must not run
	} {
		if strings.Contains(j, absent) {
			t.Fatalf("read-only probe ran mutating/forbidden %q:\n%s", absent, j)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "textfile", xactPromFile)); !os.IsNotExist(err) {
		t.Fatal("read-only probe wrote kine-db-xact.prom")
	}
}

// hygieneSeqScan in read-only mode: the delta is reported but the
// baseline file is not rebased and no ANALYZE runs.
func TestProbeSeqScanReadOnlyKeepsBaseline(t *testing.T) {
	k, fr, dir := fixture(t, hygieneRules)
	k.d.Cfg.ReadOnly = true
	fr.On("seq_tup_read", "9\n0\n120|100000\n")
	res := k.Cycle(context.Background())
	if !res.hyg.seqSeen || res.hyg.seqTupRead != 100000 {
		t.Fatalf("seq=%+v", res.hyg)
	}
	if _, err := os.Stat(filepath.Join(dir, "guard", seqTupReadFile)); !os.IsNotExist(err) {
		t.Fatal("read-only probe rebased the seq-scan baseline")
	}
	if fr.Ran(`ANALYZE "kine"`) {
		t.Fatal("read-only probe ran ANALYZE")
	}
}

// A failed ANALYZE exec is noted and analyzeFired stays false — the
// next probe retries (the budget was spent on the attempt).
func TestProbeSeqScanAnalyzeFailure(t *testing.T) {
	k, fr, _ := fixture(t, hygieneRules)
	fr.On("seq_tup_read", "9\n0\n120|100000\n")
	k.Cycle(context.Background()) // baseline
	fr.On("seq_tup_read", "9\n0\n180|700000\n")
	fr.FailOn(`ANALYZE "kine"`, errors.New("statement timeout"))
	res := k.Cycle(context.Background())
	if res.hyg.analyzeFired {
		t.Fatal("analyzeFired set despite the failed exec")
	}
	found := false
	for _, n := range res.notes {
		if strings.Contains(n, "kine-analyze-fail") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no analyze-fail note: %v", res.notes)
	}
}

// Query failures in the remaining hygiene items each note and gate
// only their own series — driven per item so the failure rule cannot
// hit a sibling query sharing a prefix.
func TestHygieneItemQueryFailures(t *testing.T) {
	ctx := context.Background()
	errDown := errors.New("connection reset")
	cases := []struct {
		name string
		rule string
		want string
		run  func(*Probe, *hygieneResult, func(string))
	}{
		{"prepared", "pg_prepared_xacts", "prepared-xacts-fail",
			func(p *Probe, h *hygieneResult, n func(string)) {
				p.hygienePreparedXacts(ctx, "pg", "postgres", "secret", h, n)
			}},
		{"idle", "idle in transaction", "idle-tx-fail",
			func(p *Probe, h *hygieneResult, n func(string)) {
				p.hygieneIdleInTx(ctx, "pg", "postgres", "secret", h, n)
			}},
		{"dead", "n_dead_tup, n_live_tup", "dead-tuple-fail",
			func(p *Probe, h *hygieneResult, n func(string)) {
				p.hygieneDeadTuple(ctx, "pg", "postgres", "secret", h, n)
			}},
		{"xid", "datfrozenxid", "xid-age-fail",
			func(p *Probe, h *hygieneResult, n func(string)) {
				p.hygieneXID(ctx, "pg", "postgres", "secret", h, n)
			}},
		{"slots", "pg_replication_slots", "slots-fail",
			func(p *Probe, h *hygieneResult, n func(string)) {
				p.hygieneWAL(ctx, "pg", "postgres", "secret", h, n)
			}},
		{"wal-df", "--output=size", "wal-df-fail",
			func(p *Probe, h *hygieneResult, n func(string)) {
				p.hygieneWAL(ctx, "pg", "postgres", "secret", h, n)
			}},
		{"wal-df-unparsed", "--output=size", "wal-df-unparsed",
			func(p *Probe, h *hygieneResult, n func(string)) {
				p.hygieneWAL(ctx, "pg", "postgres", "secret", h, n)
			}},
		{"large-keys", "OCTET_LENGTH", "large-keys-fail",
			func(p *Probe, h *hygieneResult, n func(string)) {
				p.hygieneLargeKeys(ctx, "pg", "postgres", "secret", h, n)
			}},
	}
	for _, tc := range cases {
		k, fr, _ := fixture(t, hygieneRules)
		switch tc.name {
		case "wal-df":
			fr.FailOn(tc.rule, errDown)
		case "wal-df-unparsed":
			fr.On(tc.rule, "Size\nnot-a-number\n")
		default:
			fr.FailOn(tc.rule, errDown)
		}
		h := &hygieneResult{}
		var notes []string
		tc.run(k, h, func(s string) { notes = append(notes, s) })
		if len(notes) != 1 || !strings.Contains(notes[0], tc.want) {
			t.Fatalf("%s: notes=%v want %q", tc.name, notes, tc.want)
		}
	}
}

// A past-threshold inactive slot whose drop statement fails is noted
// and retried next round — slotRetained already counted the bytes.
func TestInactiveSlotDropFailure(t *testing.T) {
	k, fr, _ := fixture(t, hygieneRules)
	fr.On("pg_replication_slots", "slot-old|16106127360\n")
	fr.FailOn("pg_drop_replication_slot", errors.New("replication in use"))
	res := k.Cycle(context.Background())
	h := res.hyg
	if h.slotsDropped != 0 || h.slotRetained != 16106127360 {
		t.Fatalf("slots=%+v", h)
	}
	found := false
	for _, n := range res.notes {
		if strings.Contains(n, "drop-slot-slot-old-fail") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no drop-fail note: %v", res.notes)
	}
}

// A failed vacuum script session notes and reads not-fired — the
// next probe past the cooldown retries.
func TestDeadTupleVacuumScriptFailure(t *testing.T) {
	k, fr, _ := fixture(t, hygieneRules)
	fr.On("n_dead_tup, n_live_tup", "60000|30000\n")
	fr.FailOn("ON_ERROR_STOP", errors.New("vacuum aborted"))
	var notes []string
	if k.deadTupleVacuum(context.Background(), "pg", "postgres", "secret",
		func(s string) { notes = append(notes, s) }) {
		t.Fatal("failed script must not read fired")
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "dead-tuple-vacuum-fail") {
		t.Fatalf("notes=%v", notes)
	}
}

// emitXactTextfile with nothing seen: the HELP/TYPE headers still
// land (a vanished series breaks scrapes) but no fabricated samples.
func TestEmitXactTextfileHeadersWithoutSamples(t *testing.T) {
	k, _, dir := fixture(t, nil)
	k.emitXactTextfile(&hygieneResult{})
	content := kdepstest.ReadText(t, dir, xactPromFile)
	for _, want := range []string{
		"# HELP kine_db_multixact_age_transactions",
		"# HELP kine_db_orphan_prepared_xacts",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("textfile missing %q:\n%s", want, content)
		}
	}
	// Header only: no sample line may carry a value (the counter's
	// longer name contains the gauge's name as a prefix — match the
	// "name value" line shape, not a bare substring).
	for _, name := range []string{
		"kine_db_multixact_age_transactions",
		"kine_db_orphan_prepared_xacts",
		"kine_db_large_object_bytes",
	} {
		for line := range strings.SplitSeq(content, "\n") {
			if strings.HasPrefix(line, name+" ") {
				t.Fatalf("sample %q emitted without aSeen flag:\n%s", line, content)
			}
		}
	}
}

// Item 8: the large-key census queries the top-5 live keys over
// 512KiB and exports them as kine_db_large_object_bytes{key=...}.
// The first probe spends the 15m budget and runs the DISTINCT ON
// scan; a second probe inside the window re-emits the cached rows
// without re-querying.
func TestProbeLargeKeysCensusEmitsAndCoolsDown(t *testing.T) {
	k, fr, dir := fixture(t, hygieneRules)
	fr.On("OCTET_LENGTH(value)",
		"1048576|/registry/secrets/default/db-tls\n"+
			"786432|/registry/configmaps/kube-system/coredns-custom\n")
	res := k.Cycle(context.Background())
	if !res.succeeded {
		t.Fatalf("probe failed: %v", res.notes)
	}
	if !res.hyg.largeSeen || len(res.hyg.largeKeys) != 2 {
		t.Fatalf("largeKeys=%+v", res.hyg.largeKeys)
	}
	if res.hyg.largeKeys[0].key != "/registry/secrets/default/db-tls" ||
		res.hyg.largeKeys[0].bytes != 1048576 {
		t.Fatalf("top row=%+v", res.hyg.largeKeys[0])
	}
	if !strings.Contains(fr.Joined(), "DISTINCT ON (name)") ||
		!strings.Contains(fr.Joined(), "OCTET_LENGTH(value) > 524288") ||
		!strings.Contains(fr.Joined(), "LIMIT 5") {
		t.Fatalf("census query missing DISTINCT ON/OCTET_LENGTH/LIMIT:\n%s", fr.Joined())
	}
	if _, err := os.Stat(filepath.Join(k.d.Cfg.GuardStateDir, largeKeysFile)); err != nil {
		t.Fatalf("large-keys budget file missing: %v", err)
	}
	content := kdepstest.ReadText(t, dir, xactPromFile)
	for _, want := range []string{
		`kine_db_large_object_bytes{key="/registry/secrets/default/db-tls"} 1048576`,
		`kine_db_large_object_bytes{key="/registry/configmaps/kube-system/coredns-custom"} 786432`,
		"# TYPE kine_db_large_object_bytes gauge",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("textfile missing %q:\n%s", want, content)
		}
	}

	// Second probe inside the 15m budget: the query must NOT run
	// again, but the cached census still emits.
	fr.ClearLog()
	fr.Clear("OCTET_LENGTH(value)")
	res = k.Cycle(context.Background())
	if !res.succeeded {
		t.Fatalf("second probe failed: %v", res.notes)
	}
	if strings.Contains(fr.Joined(), "DISTINCT ON") {
		t.Fatalf("census re-ran inside the 15m budget:\n%s", fr.Joined())
	}
	if !res.hyg.largeSeen || len(res.hyg.largeKeys) != 2 {
		t.Fatalf("cached census lost: %+v", res.hyg.largeKeys)
	}
	content = kdepstest.ReadText(t, dir, xactPromFile)
	if !strings.Contains(content, `key="/registry/secrets/default/db-tls"} 1048576`) {
		t.Fatalf("cached census not re-emitted:\n%s", content)
	}
}

// A failed census keeps the previous cache (none on first run →
// header-only family, no fabricated samples).
func TestProbeLargeKeysQueryFailure(t *testing.T) {
	k, _, dir := fixture(t, append(append([]testutil.ExecRule{}, hygieneRules...),
		testutil.ExecRule{Substr: "OCTET_LENGTH(value)", Err: errors.New("connection reset")}))
	res := k.Cycle(context.Background())
	if !res.succeeded {
		t.Fatalf("probe failed: %v", res.notes)
	}
	if res.hyg.largeSeen {
		t.Fatal("failed census marked seen")
	}
	joined := strings.Join(res.notes, "\n")
	if !strings.Contains(joined, "large-keys-fail") {
		t.Fatalf("notes missing large-keys-fail:\n%s", joined)
	}
	content := kdepstest.ReadText(t, dir, xactPromFile)
	if !strings.Contains(content, "# HELP kine_db_large_object_bytes") {
		t.Fatalf("header-only family missing:\n%s", content)
	}
	for line := range strings.SplitSeq(content, "\n") {
		if strings.HasPrefix(line, "kine_db_large_object_bytes{") {
			t.Fatalf("fabricated sample on census failure:\n%s", content)
		}
	}
}

// Key names containing label-hostile characters are escaped; a
// successful empty census still emits the family header.
func TestProbeLargeKeysEmptyAndEscaped(t *testing.T) {
	k, fr, dir := fixture(t, hygieneRules)
	fr.On("OCTET_LENGTH(value)", "600000|/registry/configmaps/ns/a\"b\\c\n")
	res := k.Cycle(context.Background())
	if !res.succeeded {
		t.Fatalf("probe failed: %v", res.notes)
	}
	content := kdepstest.ReadText(t, dir, xactPromFile)
	if !strings.Contains(content, `key="/registry/configmaps/ns/a\"b\\c"} 600000`) {
		t.Fatalf("escaped label missing:\n%s", content)
	}

	// Fresh fixture: census succeeds with zero rows → headers only.
	k2, fr2, dir2 := fixture(t, hygieneRules)
	fr2.On("OCTET_LENGTH(value)", "")
	res = k2.Cycle(context.Background())
	if !res.succeeded {
		t.Fatalf("probe failed: %v", res.notes)
	}
	if !res.hyg.largeSeen || len(res.hyg.largeKeys) != 0 {
		t.Fatalf("empty census=%+v", res.hyg.largeKeys)
	}
	content = kdepstest.ReadText(t, dir2, xactPromFile)
	if !strings.Contains(content, "# HELP kine_db_large_object_bytes") {
		t.Fatalf("empty census dropped the family header:\n%s", content)
	}
	for line := range strings.SplitSeq(content, "\n") {
		if strings.HasPrefix(line, "kine_db_large_object_bytes{") {
			t.Fatalf("phantom sample on empty census:\n%s", content)
		}
	}
}

// ReadOnly never spends the census budget nor runs the DISTINCT ON
// scan — and never writes the textfile.
func TestProbeLargeKeysReadOnly(t *testing.T) {
	k, fr, _ := fixture(t, hygieneRules)
	k.d.Cfg.ReadOnly = true
	res := k.Cycle(context.Background())
	if !res.succeeded {
		t.Fatalf("probe failed: %v", res.notes)
	}
	if strings.Contains(fr.Joined(), "DISTINCT ON") {
		t.Fatalf("read-only probe ran the census scan:\n%s", fr.Joined())
	}
	if _, err := os.Stat(filepath.Join(k.d.Cfg.GuardStateDir, largeKeysFile)); !os.IsNotExist(err) {
		t.Fatal("read-only probe spent the census budget")
	}
}

// Malformed census lines are skipped, never fatal; the `bytes|name`
// field order keeps a key containing '|' parseable (Cut takes the
// first separator — the name lands last by design).
func TestProbeLargeKeysParseSkipsGarbage(t *testing.T) {
	k, _, dir := fixture(t, append(append([]testutil.ExecRule{}, hygieneRules...),
		testutil.ExecRule{Substr: "OCTET_LENGTH(value)", Out: strings.Join([]string{
			"notanum|/bad-int",
			"no-separator",
			"700000|/registry/with|pipe",
			"",
			"  ",
			"600000|/ok",
		}, "\n") + "\n"},
	))
	res := k.Cycle(context.Background())
	if !res.succeeded {
		t.Fatalf("probe failed: %v", res.notes)
	}
	h := res.hyg
	if !h.largeSeen || len(h.largeKeys) != 2 {
		t.Fatalf("largeKeys=%+v", h.largeKeys)
	}
	if h.largeKeys[0].key != "/registry/with|pipe" || h.largeKeys[0].bytes != 700000 ||
		h.largeKeys[1].key != "/ok" || h.largeKeys[1].bytes != 600000 {
		t.Fatalf("largeKeys=%+v", h.largeKeys)
	}
	content := kdepstest.ReadText(t, dir, xactPromFile)
	if !strings.Contains(content, `kine_db_large_object_bytes{key="/registry/with|pipe"} 700000`) {
		t.Fatalf("pipe-key label wrong:\n%s", content)
	}
}
