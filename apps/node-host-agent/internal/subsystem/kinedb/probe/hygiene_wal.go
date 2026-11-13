// hygiene_wal.go — item 4: the WAL archive guard — pg_ls_waldir
// bytes, wal/datafs ratio, pg_stat_archiver staleness, and inactive
// replication-slot retention with the orphan-slot drop.
package probe

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/kinedb/kdeps"
)

// hygieneWAL — item 4: pg_wal size, wal/datafs ratio, archiver
// staleness and inactive-slot retention (with the orphan-slot drop).
func (p *Probe) hygieneWAL(ctx context.Context, pg, user, pass string,
	h *hygieneResult, note func(string)) {

	// (a) total WAL bytes — same pg_ls_waldir read repackHeadroom does.
	out, err := p.d.PsqlQuery(ctx, pg, user, pass,
		"SELECT COALESCE((SELECT SUM(size) FROM pg_ls_waldir()),0)")
	if err != nil {
		note(fmt.Sprintf("wal-size-fail: %v", err))
	} else if wal, perr := strconv.ParseInt(kdeps.FirstLine(out), 10, 64); perr != nil {
		note(fmt.Sprintf("wal-size-unparsed: %v", perr))
	} else {
		h.walBytes, h.walSeen = wal, true
	}

	// (b) WAL as a fraction of the data filesystem capacity —
	// --output=size (total, not avail: the ratio measures retention
	// pressure, not remaining headroom). Only meaningful when the
	// WAL read succeeded.
	if h.walSeen {
		dataDir := p.d.Cfg.PGDataDir
		if dataDir == "" {
			dataDir = kdeps.DefaultPGDataDir
		}
		df, derr := p.d.Exec(ctx, []string{p.d.Cfg.Runtime, "exec", pg,
			"df", "-B1", "--output=size", dataDir}, "")
		if derr != nil {
			note(fmt.Sprintf("wal-df-fail: %v", derr))
		} else {
			var lastLine string
			for l := range strings.SplitSeq(strings.TrimSpace(df), "\n") {
				lastLine = strings.TrimSpace(l)
			}
			if size, perr := strconv.ParseInt(lastLine, 10, 64); perr != nil {
				note(fmt.Sprintf("wal-df-unparsed: %v", perr))
			} else if size > 0 {
				h.walDiskRatio = float64(h.walBytes) / float64(size)
				h.walDiskSeen = true
			}
		}
	}

	// (c) archiver staleness — a failed attempt newer than the last
	// success is "failing"; it only counts as STALE once the last
	// success (or, when it never archived, the stats reset) is >30m
	// old. A recent failure that then succeeded reads clean.
	out, err = p.d.PsqlQuery(ctx, pg, user, pass, fmt.Sprintf(
		"SELECT CASE WHEN failed_count > 0 "+
			"AND last_failed_time > COALESCE(last_archived_time, '-infinity'::timestamptz) "+
			"AND EXTRACT(EPOCH FROM now() - COALESCE(last_archived_time, stats_reset)) > %d "+
			"THEN 1 ELSE 0 END FROM pg_stat_archiver", archiveStaleSecs))
	if err != nil {
		note(fmt.Sprintf("archiver-fail: %v", err))
	} else if v, perr := strconv.ParseInt(kdeps.FirstLine(out), 10, 64); perr != nil {
		note(fmt.Sprintf("archiver-unparsed: %v", perr))
	} else {
		h.archiveStale, h.archiveSeen = v, true
	}

	// (d) inactive replication slots — retained WAL since restart_lsn.
	out, err = p.d.PsqlQuery(ctx, pg, user, pass,
		"SELECT slot_name, "+
			"COALESCE(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn),0)::bigint "+
			"FROM pg_replication_slots WHERE NOT active")
	if err != nil {
		note(fmt.Sprintf("slots-fail: %v", err))
		return
	}
	h.slotSeen = true // a successful empty read = no inactive slots
	for _, s := range parseSlotRows(out) {
		h.slotRetained += s.retained
		switch {
		case s.retained > slotRetainedDrop:
			// Past the critical threshold the slot is an orphan
			// pinning the disk to PANIC — drop it and let the
			// consumer resync from scratch if it ever returns.
			if p.d.Cfg.ReadOnly {
				note(fmt.Sprintf("read-only: inactive slot %s pins %dB WAL (>%dGiB) — drop suppressed",
					s.name, s.retained, slotRetainedDrop>>30))
				continue
			}
			note(fmt.Sprintf("inactive slot %s pins %dB WAL (>%dGiB) — dropping",
				s.name, s.retained, slotRetainedDrop>>30))
			if _, derr := p.d.PsqlQuery(ctx, pg, user, pass, fmt.Sprintf(
				"SELECT pg_drop_replication_slot(%s)", kdeps.SQLQuote(s.name))); derr != nil {
				note(fmt.Sprintf("drop-slot-%s-fail: %v", s.name, derr))
			} else {
				h.slotsDropped++
				logger().Warn("kinedb: dropped inactive replication slot",
					"slot", s.name, "retained_bytes", s.retained)
			}
		case s.retained > slotRetainedWarn:
			note(fmt.Sprintf("inactive slot %s pins %dB WAL (>%dGiB)",
				s.name, s.retained, slotRetainedWarn>>30))
		}
	}
}

// parseSlotRows parses the `name|bytes` rows of the inactive-slot
// query — unparseable lines are skipped, never fatal.
func parseSlotRows(out string) []inactiveSlot {
	var slots []inactiveSlot
	for l := range strings.SplitSeq(out, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		f := strings.SplitN(l, "|", 2)
		if len(f) < 2 {
			continue
		}
		v, err := strconv.ParseInt(strings.TrimSpace(f[1]), 10, 64)
		if err != nil {
			continue
		}
		slots = append(slots, inactiveSlot{
			name: strings.TrimSpace(f[0]), retained: v})
	}
	return slots
}
