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

// hygieneWAL — item 4's REMAINDER: the wal-bytes and archiver
// reads moved into hygieneScalarStats' merged census (h.walBytes/
// h.walSeen/h.archiveStale/h.archiveSeen are already filled); this
// function keeps the parts that are NOT single-row reads — the
// wal/datafs ratio df probe and the inactive replication-slot
// census with the orphan-slot drop.
func (p *Probe) hygieneWAL(ctx context.Context, pg, user, pass string,
	h *hygieneResult, note func(string)) {
	p.hygieneWALWithBatch(ctx, pg, user, pass, h, nil, 1, note)
}

func (p *Probe) hygieneWALWithBatch(ctx context.Context, pg, user, pass string,
	h *hygieneResult, batch *probeBatch, backendEnv int64, note func(string)) {

	// (b) WAL as a fraction of the data filesystem capacity —
	// --output=size (total, not avail: the ratio measures retention
	// pressure, not remaining headroom). Only meaningful when the
	// WAL read succeeded.
	if h.walSeen {
		df, derr := p.d.PGDataDF(ctx, pg, "size")
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

	// (c) archiver staleness moved into hygieneScalarStats — the
	// CASE...END single-row read is one of its five merged
	// statements (h.archiveStale/h.archiveSeen already filled).

	// (d) inactive replication slots — retained WAL since restart_lsn.
	var out string
	switch {
	case batch != nil && batch.err == nil && batch.slotsSeen:
		out = strings.Join(batch.slotLines, "\n")
	case batch == nil || batch.canFallback(ctx, backendEnv):
		var err error
		out, err = p.d.PsqlQuery(ctx, pg, user, pass, kdeps.AppNameProbe,
			"SELECT slot_name, "+
				"COALESCE(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn),0)::bigint "+
				"FROM pg_replication_slots WHERE NOT active")
		if err != nil {
			note(fmt.Sprintf("slots-fail: %v", err))
			return
		}
	default:
		note(fmt.Sprintf("slots-fail: %v", batch.err))
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
			if _, derr := p.d.PsqlQuery(ctx, pg, user, pass, kdeps.AppNameProbe, fmt.Sprintf(
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
