// seq_widen.go — Wave-3 #1: Kine PostgreSQL int4 (2.1B) sequence cliff
// auto-widen guard. When kine.id is already int8 (atttypid=20) but its
// backing sequence is still integer/smallint (max_value <= 2147483647),
// widens the sequence to bigint under the shared advisory lock. When kine.id
// itself is still int4 (atttypid=23), refuses to run a table-locking ALTER
// TABLE and records a P0 warning once utilization reaches 50%.
package maint

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
)

const (
	pgTypeInt8 int64 = 20
	pgTypeInt4 int64 = 23
	int4MaxVal int64 = 2147483647
	bigintMax  int64 = 9223372036854775807
)

func (m *Maint) checkAndWidenSequence(ctx context.Context, pg, user, pass string,
	res *Result, note func(string)) {
	if m.d.Cfg.ReadOnly {
		logger().Debug("kinedb: seq-widen skipped (read-only mode)",
			"table", m.d.Cfg.Table)
		return
	}
	if !m.d.Cfg.SeqWidenEnabled {
		return
	}
	tblQ := kdeps.SQLQuote(m.d.Cfg.Table)
	seqFallbackQ := kdeps.SQLQuote(m.d.Cfg.Table + "_id_seq")
	// Resolve the sequence by OID (regclass cast) instead of parsing the
	// string from pg_get_serial_sequence — a name with double quotes or a
	// dot cannot survive that substring. pg_class.relname is the raw name.
	seqByOID := "(SELECT c.relname FROM pg_class c WHERE c.oid = " +
		"pg_get_serial_sequence(" + tblQ + ", 'id')::regclass)"
	// kine.id frequently has no OWNED BY link (manual bigint migrations,
	// restored dumps), so pg_get_serial_sequence() returns NULL. The SELECT
	// list already falls back to <table>_id_seq; the pg_sequences WHERE MUST
	// use the SAME expression or it matches zero rows and MAX(max_value)
	// parses as a misleading 0 — silently disabling the widen guard.
	seqNameExpr := "COALESCE(" + seqByOID + ", " + seqFallbackQ + ")"
	sql := "SELECT COALESCE((SELECT a.atttypid::bigint FROM pg_attribute a " +
		"JOIN pg_class c ON c.oid = a.attrelid " +
		"JOIN pg_namespace n ON n.oid = c.relnamespace " +
		"WHERE n.nspname = current_schema() AND c.relname = " + tblQ +
		" AND a.attname = 'id' AND NOT a.attisdropped), 0), " +
		seqNameExpr + "; " +
		// One catalog read for all three columns (the old three correlated
		// subqueries read pg_sequences three times). MAX() keeps the row
		// count at exactly one even when the sequence is absent.
		"SELECT COALESCE(MAX(last_value),0), COALESCE(MAX(max_value),0), " +
		"COALESCE(MAX(data_type::text),'') FROM pg_sequences " +
		"WHERE schemaname = current_schema() AND sequencename = " + seqNameExpr + ";"

	out, err := m.d.PsqlQuery(ctx, pg, user, pass, kdeps.AppNameMaint, sql)
	if err != nil {
		note(fmt.Sprintf("seq-widen-probe-fail: %v", err))
		return
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 2 {
		return
	}
	colParts := strings.Split(strings.TrimSpace(lines[0]), "|")
	seqParts := strings.Split(strings.TrimSpace(lines[1]), "|")
	if len(colParts) != 2 || len(seqParts) != 3 {
		return
	}
	attType, err := strconv.ParseInt(strings.TrimSpace(colParts[0]), 10, 64)
	if err != nil || attType == 0 {
		return
	}
	// pg_get_serial_sequence may hand back a quoted identifier; the raw
	// relname from pg_class is plain, but normalise defensively before the
	// final SQLIdent re-quote so a doubled quote cannot be double-escaped.
	seqName := kdeps.UnquoteSQLIdent(strings.TrimSpace(colParts[1]))
	lastVal, err := strconv.ParseInt(strings.TrimSpace(seqParts[0]), 10, 64)
	if err != nil {
		return
	}
	maxVal, err := strconv.ParseInt(strings.TrimSpace(seqParts[1]), 10, 64)
	if err != nil || maxVal <= 0 {
		return
	}
	dataType := strings.TrimSpace(seqParts[2])

	if attType == pgTypeInt4 {
		effectiveCeiling := maxVal
		if effectiveCeiling > int4MaxVal {
			effectiveCeiling = int4MaxVal
		}
		util := float64(lastVal) / float64(effectiveCeiling)
		m.d.M.IDInt4Hazard.Set(1)
		m.d.M.SeqUtilRatio.Set(util)
		if util >= 0.50 {
			msg := fmt.Sprintf("P0 CRITICAL: kine.id column is int4 at %.1f%% (%d/%d) — manual ALTER TABLE migration to bigint required",
				util*100, lastVal, effectiveCeiling)
			note(msg)
			logger().Error("kinedb: P0 kine.id int4 cliff hazard",
				"table", m.d.Cfg.Table, "last_value", lastVal,
				"ceiling", effectiveCeiling, "utilization", util)
		} else {
			msg := fmt.Sprintf("WARNING: kine.id column is int4 (%.1f%% of 2.1B ceiling) — manual bigint migration recommended",
				util*100)
			note(msg)
			logger().Warn("kinedb: kine.id column is int4",
				"table", m.d.Cfg.Table, "last_value", lastVal,
				"ceiling", effectiveCeiling, "utilization", util)
		}
		return
	}

	if attType != pgTypeInt8 {
		return
	}
	if dataType == "bigint" && maxVal > int4MaxVal {
		return
	}
	// SQLIdent escapes embedded quotes, so quoted/spaced names are safe;
	// only reject empty, over-long or control-char names.
	if seqName == "" || len(seqName) > 63 ||
		strings.ContainsAny(seqName, "\x00\n\r\t") {
		note(fmt.Sprintf("seq-widen-skipped: unsafe sequence identifier %q", seqName))
		return
	}

	// The ALTER takes an ACCESS EXCLUSIVE lock. Without bounded waits it
	// queues behind (and then blocks) the kube-apiserver's nextval() — a
	// frozen Kine/APIServer. The timeouts are set immediately before the
	// DDL so a busy lock fails fast instead of freezing the control plane.
	stmt := fmt.Sprintf(
		"SET lock_timeout = '2s';\nSET statement_timeout = '5s';\n"+
			"ALTER SEQUENCE %s AS bigint MAXVALUE %d;\n",
		kdeps.SQLIdent(seqName), bigintMax)
	script := kdeps.WrapAdvisoryLockScript(m.d.Cfg.AdvisoryLockID, "kw_locked", stmt)
	sout, serr := m.d.PsqlScript(ctx, pg, user, pass, kdeps.AppNameMaint, script)
	if serr != nil {
		note(fmt.Sprintf("seq-widen-fail: %v", serr))
		logger().Warn("kinedb: ALTER SEQUENCE AS bigint failed", "seq", seqName, "err", serr)
		return
	}
	if strings.Contains(sout, kdeps.LockBusyMarker) {
		note("seq-widen-skipped: compact-guard advisory lock busy")
		return
	}
	res.seqWidened = true
	m.d.M.IDInt4Hazard.Set(0)
	note(fmt.Sprintf("ACTION: widened sequence %s to bigint (was type=%s max=%d)",
		seqName, dataType, maxVal))
	logger().Warn("kinedb: ACTION widened kine id sequence to bigint",
		"seq", seqName, "prev_type", dataType, "prev_max", maxVal)
}
