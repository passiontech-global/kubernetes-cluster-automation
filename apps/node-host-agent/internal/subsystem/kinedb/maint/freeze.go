// freeze.go — the maint-cycle remediations that were lifted out of
// the probe-side files: the XID-wraparound VACUUM (FREEZE, ANALYZE)
// half of wal_xid_hygiene.go's item 3 (the gauge stays probe-side —
// the freeze is a full-table rewrite storm that belongs inside the
// daily serialisation window) and the W8-CP2 item-3 pg_repack
// headroom gate from kine_self_healing.go.
package maint

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
)

const (
	// xidFreezeAge — MAX(age(datfrozenxid)) past which the maint
	// cycle forces VACUUM (FREEZE, ANALYZE): ~7% of the 2^31
	// wraparound horizon, far ahead of the autovacuum-freeze panic
	// zone yet early enough that the freeze storm finishes in the
	// daily window.
	xidFreezeAge = 150_000_000

	// repackHeadroomFactor — free space must cover this multiple of
	// (heap + WAL) before pg_repack may run.
	repackHeadroomFactor = 2.5

	// repackGlob finds a pg_repack binary inside the postgres
	// container — the percona/pgsql versioned-path glob the bash
	// maint script used.
	repackGlob = `ls /usr/pgsql-*/bin/pg_repack /usr/lib/postgresql/*/bin/pg_repack 2>/dev/null | head -1`
)

// xidFreezeCheck is the maint-cycle half of the wraparound item: the
// probe owns the kine_db_xid_age_transactions series (2-minute
// freshness); the freeze remediation runs here where the daily
// cadence already serialises the heavy reindex/repack work — a
// FREEZE vacuum is a full-table rewrite freeze storm, not a
// probe-time action.
func (m *Maint) xidFreezeCheck(ctx context.Context, pg, user, pass string,
	res *Result, note func(string)) {
	out, err := m.d.PsqlQuery(ctx, pg, user, pass,
		"SELECT COALESCE(MAX(age(datfrozenxid)),0) FROM pg_database")
	if err != nil {
		note(fmt.Sprintf("xid-age-fail: %v", err))
		return
	}
	age, perr := strconv.ParseInt(kdeps.FirstLine(out), 10, 64)
	if perr != nil {
		note(fmt.Sprintf("xid-age-unparsed: %v", perr))
		return
	}
	res.xidAge, res.xidSeen = age, true
	res.freezeState = "skipped"
	m.d.M.XidAge.Set(float64(age))
	if age <= xidFreezeAge {
		return
	}
	note(fmt.Sprintf("xid-age=%d>%d — VACUUM (FREEZE, ANALYZE)", age, xidFreezeAge))
	logger().Warn("kinedb: XID age past freeze threshold — VACUUM (FREEZE, ANALYZE)",
		"xid_age", age, "threshold", xidFreezeAge)
	if _, verr := m.d.ExecLongEnv(ctx, kdeps.PsqlPassEnv(pass), m.d.PsqlArgs(pg, user, false,
		"-qc", "VACUUM (FREEZE, ANALYZE) "+kdeps.SQLIdent(m.d.Cfg.Table)), ""); verr != nil {
		res.okFreeze = false
		res.freezeState = "fail"
		note(fmt.Sprintf("freeze-vacuum-fail: %v", verr))
		return
	}
	res.freezeState = "done"
}

// repackHeadroom checks whether the postgres data filesystem has
// >= 2.5*(heap+wal) free before pg_repack — W8-CP2 item 3. walBytes
// comes from pg_ls_waldir; free bytes from `df -B1 <datadir>` inside
// the container. Returns ok=false (and a note) when the check itself
// can't run — inconclusive means DON'T repack, same as assess-fail.
func (m *Maint) repackHeadroom(ctx context.Context, pg, user, pass string,
	heapBytes int64, note func(string)) (free, wal int64, ok bool) {
	dataDir := m.d.Cfg.PGDataDir
	if dataDir == "" {
		dataDir = kdeps.DefaultPGDataDir
	}
	out, err := m.d.PsqlQuery(ctx, pg, user, pass,
		"SELECT COALESCE((SELECT SUM(size) FROM pg_ls_waldir()),0)")
	if err != nil {
		note(fmt.Sprintf("wal-size-fail: %v", err))
		return 0, 0, false
	}
	wal, err = strconv.ParseInt(kdeps.FirstLine(out), 10, 64)
	if err != nil {
		note(fmt.Sprintf("wal-size-unparsed: %v", err))
		return 0, 0, false
	}
	df, err := m.d.Exec(ctx, []string{m.d.Cfg.Runtime, "exec", pg,
		"df", "-B1", "--output=avail", dataDir}, "")
	if err != nil {
		note(fmt.Sprintf("df-fail: %v", err))
		return 0, 0, false
	}
	// df --output=avail prints a header line then the number.
	var lastLine string
	for _, l := range strings.Split(strings.TrimSpace(df), "\n") {
		lastLine = strings.TrimSpace(l)
	}
	free, err = strconv.ParseInt(lastLine, 10, 64)
	if err != nil {
		note(fmt.Sprintf("df-unparsed: %v", err))
		return 0, 0, false
	}
	need := int64(repackHeadroomFactor * float64(heapBytes+wal))
	if free < need {
		return free, wal, false
	}
	return free, wal, true
}
