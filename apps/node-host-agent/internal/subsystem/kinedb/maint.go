// maint.go — the daily maintenance job (kine-db-maint.sh port).
//
// Why it exists (incident 2026-09-28): the kine table's index bloat
// made `SELECT MAX(id)` take seconds, pushing kine init past the k0s
// health-check window and crash-looping remote controllers.
// autovacuum only reclaims dead tuples — it never reindexes and never
// shrinks the heap — so this job runs:
//
//	reindex  REINDEX TABLE CONCURRENTLY kine — always (cheap on a
//	         small table, SHARE UPDATE EXCLUSIVE lock). W12-CP2:
//	         preceded by the invalid-index reaper — an interrupted
//	         REINDEX CONCURRENTLY / pg_repack leaves *_ccnew / *_ccold
//	         shells with indisvalid=false; they cost every INSERT,
//	         serve no query, and trip the next reindex, so they are
//	         dropped first (DROP INDEX CONCURRENTLY).
//	repack   pg_repack --no-superuser-check --no-order -t public.kine
//	         — ONLY when the heap is genuinely bloated
//	         (dead_tuple_percent > 40 AND heap > 200MB, measured via
//	         pg_stat_user_tables + pg_relation_size). Online shadow
//	         copy, needs ~2x table space transiently.
package kinedb

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
)

// deadTuplePct returns n_dead_tup as a percentage of estimated rows —
// 0 when the stats view has no rows for the table (fresh stats or an
// empty table never triggers repack).
func deadTuplePct(dead, live int64) int64 {
	total := dead + live
	if total <= 0 {
		return 0
	}
	return dead * 100 / total
}

// maintResult captures one maintenance run for emission + tests.
type maintResult struct {
	okReindex   bool
	okRepack    bool   // skip counts as ok — a ran-and-failed repack (or a failed assessment) flips it
	okFreeze    bool   // same for the XID freeze vacuum
	repackState string // skipped|done|fail|no-binary|assess-fail
	freezeState string // ""|skipped|done|fail — "" until the XID read lands
	xidAge      int64
	xidSeen     bool // MAX(age(datfrozenxid)) was actually read this run
	heapBytes   int64
	indexBytes  int64
	deadPct     int64
	statsOK     bool // sizes/dead-tuple stats were actually read this run
	// W12-CP2 invalid-index reaper tallies.
	invalidDropped int
	invalidKept    int // non-ccnew/ccold invalids left for an operator
	notes          []string
}

// maintCycle runs one maintenance round and emits metrics +
// textfile. Returns the result for tests.
func (k *KineDB) maintCycle(ctx context.Context) *maintResult {
	res := &maintResult{okRepack: true, okFreeze: true, repackState: "skipped"}
	note := func(s string) { res.notes = append(res.notes, s) }

	user, pass, credOK := k.creds()
	pg := k.pgContainerName(ctx)
	switch {
	case !credOK:
		note(fmt.Sprintf("missing .env creds (%s)", k.cfg.EnvFile))
	case !k.containerRunning(ctx, pg):
		note(fmt.Sprintf("postgres container %s down", pg))
	default:
		k.maintRun(ctx, pg, user, pass, res, note)
	}
	k.emitMaint(res)
	sum := fmt.Sprintf("reindex=%v repack=%s freeze=%s heap=%dB idx=%dB "+
		"dead=%d%% xid=%s",
		res.okReindex, res.repackState, reasonOrDash(res.freezeState),
		res.heapBytes, res.indexBytes, res.deadPct,
		intOrNA(res.xidSeen, res.xidAge))
	if res.okReindex && res.okRepack && res.okFreeze {
		logger().Info("kine-db-maint OK: " + sum)
		k.m.cycles.WithLabelValues("maint", "ok").Inc()
	} else {
		logger().Warn("kine-db-maint FAIL: "+sum, "notes", strings.Join(res.notes, " "))
		k.m.cycles.WithLabelValues("maint", "fail").Inc()
	}
	return res
}

func (k *KineDB) maintRun(ctx context.Context, pg, user, pass string,
	res *maintResult, note func(string)) {

	// (a0) W12-CP2 invalid-index reaper — BEFORE the reindex: an
	// interrupted REINDEX CONCURRENTLY or pg_repack leaves *_ccnew /
	// *_ccold shells with indisvalid=false, and those shells make
	// the next reindex error out ("cannot reindex invalid index")
	// while still taxing every INSERT. Best-effort: a failed
	// listing or drop only notes, never fails the maint run.
	k.reapInvalidIndexes(ctx, pg, user, pass, res, note)

	// (a) REINDEX CONCURRENTLY — always, cheap on a small table.
	if _, err := k.execLongEnv(ctx, psqlPassEnv(pass), k.psqlArgs(pg, user, false,
		"-qc", "REINDEX TABLE CONCURRENTLY "+sqlIdent(k.cfg.Table)), ""); err == nil {
		res.okReindex = true
	} else {
		note(fmt.Sprintf("reindex-fail: %v", err))
	}

	// (b) XID wraparound — VACUUM (FREEZE, ANALYZE) when
	// MAX(age(datfrozenxid)) crosses 150M. Runs before the repack
	// gate so a failing stats read cannot skip it.
	k.xidFreezeCheck(ctx, pg, user, pass, res, note)

	// (c) sizes + dead-tuple estimate from pg_stat_user_tables.
	// Indexes via pg_indexes_size like the bash — total−heap would
	// count TOAST as index bytes.
	out, err := k.psqlQuery(ctx, pg, user, pass, fmt.Sprintf(
		"SELECT pg_relation_size(%[1]s), pg_indexes_size(%[1]s), "+
			"COALESCE((SELECT n_dead_tup FROM pg_stat_user_tables WHERE relname=%[1]s),0), "+
			"COALESCE((SELECT n_live_tup FROM pg_stat_user_tables WHERE relname=%[1]s),0)",
		sqlQuote(k.cfg.Table)))
	if err == nil {
		heap, idx, dead, live, perr := parseQuad(out)
		if perr == nil {
			res.heapBytes = heap
			res.indexBytes = idx
			res.deadPct = deadTuplePct(dead, live)
			res.statsOK = true
		} else {
			note(fmt.Sprintf("sizes-unparsed: %v", perr))
		}
	} else {
		note(fmt.Sprintf("sizes-fail: %v", err))
	}
	if !res.statsOK {
		// deadPct=0 + heapBytes=0 reads as "not bloated" — a failed
		// assessment must not skip repack and still report OK.
		res.okRepack = false
		res.repackState = "assess-fail"
		return
	}

	// (d) pg_repack ONLY when the heap is genuinely bloated —
	// autovacuum keeps it roughly compact, so this fires rarely.
	if res.deadPct <= k.cfg.RepackDeadPct ||
		res.heapBytes <= k.cfg.RepackMinHeapBytes {
		return
	}
	// W8-CP2 item 3: repack shadows the heap + WAL churn — require
	// free >= 2.5*(heap+wal) on the data fs first; otherwise run
	// only a VACUUM (ANALYZE) and warn (repack would fill the disk).
	free, wal, headroom := k.repackHeadroom(ctx, pg, user, pass,
		res.heapBytes, note)
	if !headroom {
		note(fmt.Sprintf("repack-skipped-insufficient-headroom (free=%dB heap=%dB wal=%dB)",
			free, res.heapBytes, wal))
		logger().Warn("kinedb: pg_repack skipped — insufficient disk headroom, VACUUM only",
			"free", free, "heap", res.heapBytes, "wal", wal)
		res.repackState = "skipped-headroom"
		if _, err := k.execLongEnv(ctx, psqlPassEnv(pass), k.psqlArgs(pg, user, false,
			"-qc", "VACUUM (ANALYZE) "+sqlIdent(k.cfg.Table)), ""); err != nil {
			note(fmt.Sprintf("fallback-vacuum-fail: %v", err))
		}
		return
	}
	repackBin, rerr := k.exec(ctx, []string{k.cfg.Runtime, "exec", pg,
		"sh", "-c", repackGlob}, "")
	if rerr != nil {
		// A failed lookup reads identically to "no binary
		// installed" below — record which it was.
		note(fmt.Sprintf("repack-lookup-fail: %v", rerr))
	}
	repackBin = strings.TrimSpace(repackBin)
	if repackBin == "" {
		res.repackState = "no-binary"
		note(fmt.Sprintf(
			"repack-needed-no-binary (heap=%dB dead=%d%%)", res.heapBytes, res.deadPct))
		return
	}
	if _, err := k.execEnv(ctx, psqlPassEnv(pass), k.psqlArgs(pg, user, false,
		"-qc", "CREATE EXTENSION IF NOT EXISTS pg_repack"), ""); err != nil {
		// pg_repack cannot run without the extension — attempting
		// it anyway fails identically and doubles the error noise.
		res.okRepack = false
		res.repackState = "fail"
		note(fmt.Sprintf("repack-ext-fail: %v", err))
		return
	}
	if _, err := k.execLongEnv(ctx, psqlPassEnv(pass), []string{k.cfg.Runtime, "exec",
		"-e", "PGPASSWORD", pg, repackBin,
		"-h", "127.0.0.1", "-U", user, "-d", "postgres",
		"-t", "public." + k.cfg.Table,
		"--no-superuser-check", "--no-order"}, ""); err == nil {
		res.repackState = "done"
	} else {
		res.okRepack = false
		res.repackState = "fail"
		note(fmt.Sprintf("repack-fail: %v", err))
	}
}

// reapInvalidIndexes — W12-CP2: drop the invalid index shells an
// interrupted REINDEX CONCURRENTLY / pg_repack leaves on the kine
// table. Only the *_ccnew / *_ccold names PostgreSQL itself mints
// are auto-dropped — any other invalid index is noted and kept for
// an operator (dropping a live application's index would be data
// loss of a different kind). DROP INDEX CONCURRENTLY cannot run in
// a transaction, so each drop is its own -qc statement under the
// long budget (CONCURRENTLY waits on concurrent snapshots).
func (k *KineDB) reapInvalidIndexes(ctx context.Context, pg, user, pass string,
	res *maintResult, note func(string)) {
	out, err := k.psqlQuery(ctx, pg, user, pass, fmt.Sprintf(
		"SELECT indexrelid::regclass::text FROM pg_index "+
			"WHERE NOT indisvalid AND indrelid = %s::regclass",
		sqlQuote(k.cfg.Table)))
	if err != nil {
		note(fmt.Sprintf("invalid-index-list-fail: %v", err))
		return
	}
	for _, idx := range parseGIDs(out) {
		// regclass::text may be schema-qualified (public.foo) or
		// double-quoted — the suffix + identifier checks apply to
		// the bare index name.
		base := idx
		if i := strings.LastIndexByte(base, '.'); i >= 0 {
			base = base[i+1:]
		}
		base = strings.Trim(base, `"`)
		switch {
		case !reTableIdent.MatchString(base):
			note(fmt.Sprintf("invalid-index %q skipped (unsafe name)", idx))
		case !strings.HasSuffix(base, "_ccnew") &&
			!strings.HasSuffix(base, "_ccold"):
			note(fmt.Sprintf("invalid-index %s kept (not a _ccnew/_ccold orphan)", base))
			res.invalidKept++
			logger().Warn("kinedb: invalid index on kine table kept (not a reindex orphan)",
				"index", base)
		default:
			if _, derr := k.execLongEnv(ctx, psqlPassEnv(pass), k.psqlArgs(pg, user, false,
				"-qc", "DROP INDEX CONCURRENTLY IF EXISTS "+
					sqlIdent(base)), ""); derr != nil {
				note(fmt.Sprintf("drop-index-%s-fail: %v", base, derr))
				continue
			}
			res.invalidDropped++
			note("dropped invalid index " + base)
			logger().Warn("kinedb: dropped orphaned invalid index",
				"index", base)
		}
	}
}

// backupVerify is the W13-ST2/Gap#4 physical-backup verifier: the
// newest *.dump in BackupDir must be younger than BackupInterval
// AND header-valid. A stale (or absent) dump is refreshed with
// `pg_dump -Fc` inside the postgres container + `pg_restore -l`
// validation, then `podman|docker cp`'d to the host dir — but only
// while the backup filesystem keeps >30% free (a full disk must
// not make it worse). Pre-existing dumps get the cheap PGDMP
// magic sniff; agent-created dumps are verified with a full
// pg_restore -l listing at creation time.
func (k *KineDB) backupVerify(ctx context.Context, pg, user, pass string,
	res *guardResult, note func(string)) {

	newest, mtime := newestDump(k.cfg.BackupDir)
	if mtime > 0 {
		res.backupSeen = true
		res.backupAge = k.cfg.Clock.Now().Unix() - mtime
		res.backupValid = dumpValidMagic(newest)
	}
	if res.backupSeen && res.backupAge < int64(k.cfg.BackupInterval.Seconds()) {
		return // fresh enough — nothing to create
	}
	if err := os.MkdirAll(k.cfg.BackupDir, 0o750); err != nil {
		note(fmt.Sprintf("backup-mkdir-fail: %v", err))
		return
	}
	// Stale/absent: only create when the fs has headroom.
	if st, err := k.cfg.statfsFn(k.cfg.BackupDir); err != nil ||
		st <= backupMinFreeRatio {
		note("backup-skipped-low-free")
		return
	}
	// Dump inside the container to its /tmp, verify with
	// pg_restore -l, then cp to the host dir — streaming the
	// dump through stdout would hit the runner capture cap.
	// pg_dump runs under the LONG budget: a bloated kine table
	// outlasts the 2-minute execEnv cap (same class of work as
	// VACUUM/REINDEX).
	tmp := "/tmp/kine-backup.dump"
	if _, err := k.execLongEnv(ctx, psqlPassEnv(pass), []string{k.cfg.Runtime,
		"exec", "-e", "PGPASSWORD", pg,
		"pg_dump", "-Fc", "-U", user, "-d", "postgres", "-f", tmp}, ""); err != nil {
		note(fmt.Sprintf("pg_dump-fail: %v", err))
		// A failed pg_dump can leave a partial file in the
		// container — drop it like the validate-fail path does.
		_, _ = k.exec(ctx, []string{k.cfg.Runtime, "exec", pg, "rm", "-f", tmp}, "")
		return
	}
	if _, err := k.exec(ctx, []string{k.cfg.Runtime, "exec", pg,
		"pg_restore", "-l", tmp}, ""); err != nil {
		note(fmt.Sprintf("pg_restore-validate-fail: %v", err))
		_, _ = k.exec(ctx, []string{k.cfg.Runtime, "exec", pg, "rm", "-f", tmp}, "")
		return
	}
	dest := filepath.Join(k.cfg.BackupDir,
		fmt.Sprintf("kine-%d.dump", k.cfg.Clock.Now().Unix()))
	// cp lands on a .tmp sibling first, then os.Rename publishes —
	// an interrupted cp would leave a truncated file that still
	// passes the 5-byte PGDMP sniff, and newestDump would call it
	// fresh (kine_db_backup_valid=1) for a whole BackupInterval.
	// The .tmp suffix keeps partials invisible to the *.dump glob.
	destTmp := dest + ".tmp"
	if _, err := k.exec(ctx, []string{k.cfg.Runtime, "cp",
		pg + ":" + tmp, destTmp}, ""); err != nil {
		note(fmt.Sprintf("backup-cp-fail: %v", err))
		_ = os.Remove(destTmp)
	} else if err := os.Rename(destTmp, dest); err != nil {
		note(fmt.Sprintf("backup-rename-fail: %v", err))
		_ = os.Remove(destTmp)
	} else {
		res.backupSeen = true
		res.backupAge = 0
		res.backupValid = true
		note("backup-created " + filepath.Base(dest))
		// One fresh dump every BackupInterval with no expiry
		// would fill the backup fs — keep only the newest few.
		pruneDumps(k.cfg.BackupDir)
	}
	_, _ = k.exec(ctx, []string{k.cfg.Runtime, "exec", pg, "rm", "-f", tmp}, "")
}

// backupKeepDumps is the *.dump retention bound under BackupDir —
// at the default 6h cadence four dumps cover the last 24h.
const backupKeepDumps = 4

// pruneDumps deletes all but the newest backupKeepDumps *.dump
// files under dir — oldest first by mtime — plus any *.tmp
// partial a crashed cp never published. Best-effort: an
// unremovable file is skipped, never fatal to the verify.
func pruneDumps(dir string) {
	// *.dump.tmp partials are never valid dumps — always sweep.
	if tmps, err := filepath.Glob(filepath.Join(dir, "*.tmp")); err == nil {
		for _, f := range tmps {
			_ = os.Remove(f)
		}
	}
	m, err := filepath.Glob(filepath.Join(dir, "*.dump"))
	if err != nil || len(m) <= backupKeepDumps {
		return
	}
	type aged struct {
		path string
		mt   int64
	}
	dumps := make([]aged, 0, len(m))
	for _, f := range m {
		if fi, err := os.Stat(f); err == nil {
			dumps = append(dumps, aged{f, fi.ModTime().Unix()})
		}
	}
	if len(dumps) <= backupKeepDumps {
		return
	}
	slices.SortFunc(dumps, func(a, b aged) int {
		return cmp.Compare(b.mt, a.mt) // newest first
	})
	for _, d := range dumps[backupKeepDumps:] {
		_ = os.Remove(d.path)
	}
}

// newestDump returns the newest *.dump file under dir.
func newestDump(dir string) (string, int64) {
	m, err := filepath.Glob(filepath.Join(dir, "*.dump"))
	if err != nil || len(m) == 0 {
		return "", 0
	}
	var best string
	var mt int64
	for _, f := range m {
		if fi, err := os.Stat(f); err == nil && fi.ModTime().Unix() > mt {
			best, mt = f, fi.ModTime().Unix()
		}
	}
	return best, mt
}

// dumpValidMagic reports whether the file starts with the pg_dump
// custom-format magic ("PGDMP").
func dumpValidMagic(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	var hdr [5]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return false
	}
	return string(hdr[:]) == "PGDMP"
}

// statfsFree returns the free-byte ratio of the fs holding path.
func statfsFree(path string) (float64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil || st.Blocks == 0 {
		return 0, fmt.Errorf("statfs %s", path)
	}
	return float64(st.Bavail) / float64(st.Blocks), nil
}

// emitMaint renders the textfile and updates the collectors.
func (k *KineDB) emitMaint(res *maintResult) {
	var p promfile.Builder
	reindex, repack := 0.0, 0.0
	if res.okReindex {
		reindex = 1
	}
	if res.okRepack {
		repack = 1
	}
	p.GaugeLabels("kine_db_maint_ok",
		"Maintenance job result on the kine DB (1 = ok/skip, 0 = fail)",
		`check="reindex"`, reindex)
	p.GaugeLabels("kine_db_maint_ok",
		"Maintenance job result on the kine DB (1 = ok/skip, 0 = fail)",
		`check="repack"`, repack)
	k.m.maintOK.WithLabelValues("reindex").Set(reindex)
	k.m.maintOK.WithLabelValues("repack").Set(repack)
	// vacuum_freeze only appears once the XID read landed — same
	// seen-gating as relation_bytes: an unmeasured cycle must not
	// fabricate a passing check.
	if res.xidSeen {
		freeze := 1.0
		if res.freezeState == "fail" {
			freeze = 0
		}
		p.GaugeLabels("kine_db_maint_ok",
			"Maintenance job result on the kine DB (1 = ok/skip, 0 = fail)",
			`check="vacuum_freeze"`, freeze)
		k.m.maintOK.WithLabelValues("vacuum_freeze").Set(freeze)
	}
	ts := float64(k.cfg.Clock.Now().Unix())
	p.Gauge("kine_db_maint_last_run_timestamp_seconds",
		"Last maintenance run", ts)
	k.m.maintLastRun.Set(ts)
	// relation_bytes comes out of the stats read — emitGuard's
	// statsOK gating applied here too: on assess-fail a fabricated
	// 0 overwriting a meaningful size is worse than a stale gauge.
	if res.statsOK {
		p.GaugeLabels("kine_db_maint_relation_bytes",
			"Heap/index size of the kine table", `kind="heap"`,
			float64(res.heapBytes))
		p.GaugeLabels("kine_db_maint_relation_bytes",
			"Heap/index size of the kine table", `kind="indexes"`,
			float64(res.indexBytes))
		k.m.maintRelBytes.WithLabelValues("heap").Set(float64(res.heapBytes))
		k.m.maintRelBytes.WithLabelValues("indexes").Set(float64(res.indexBytes))
	}
	k.emitTextfile("kine-db-maint.prom", &p)
}
