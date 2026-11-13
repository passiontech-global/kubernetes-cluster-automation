// kmsg.go — kernel-dmesg checkKernelDmesg: the /dev/kmsg tail
// session and its drain loop. The kernel-log plumbing outgrew one
// file, so the concern set is split per concern across this
// package's files (same package, pure moves):
//
//	kmsg.go         — the kmsg session + drain (this file)
//	kmsg_cursor.go  — the persisted resume cursor (kmsg/dmesgT/dmesgRaw)
//	kmsg_dmesg.go   — the no-/dev/kmsg dmesg fallback + its line parsing
//	kmsg_markers.go — the evidence-marker writers + handlers the drain
//	                  dispatches into (OOM victim, fs-error, page-alloc,
//	                  clocksource, the nf_conntrack_max bump)
//
// The classifier half — the detector regexes and the line→detector
// dispatch — lives in kmsg_rules.go. workerhygiene consumes the OOM
// markers for the SystemOOMVictim node event. The kernelfail
// contract overview lives in kernelfail.go.
package kernelfail

import (
	"context"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/kmsg"
)

// --- kmsg session (kernel-dmesg) ---

const (
	// kmsgDrainCap bounds one tick's ring read — a printk flood
	// can't stall the 30s latch ticker.
	kmsgDrainCap = 8 << 20
	// kmsgMaxPending bounds the partial-line carry.
	kmsgMaxPending = 1 << 20
)

// kernelScanState is the per-Runner scanner state — the kmsg
// tail session plus the cross-line OOM pairing. It lives as a
// Runner field (kernelfail.go's kscan): the parent's Latches
// wrapper is recreated per call, so a keyed side-map would never
// release the session — the old sync.Map leaked both the entry and
// the /dev/kmsg fd for the process lifetime.
type kernelScanState struct {
	sess       *kmsgSession // nil until the session is (re)built
	oomPending *oomKillCtx  // constraint line awaiting its kill line
}

// kmsgSession is the consumer half of the /dev/kmsg tail: the
// kmsg.Tailer underneath owns the fd, the partial-line carry and
// the backlog gates — only seq (resume-cursor dedup) is consumer
// state. The fd stays open across ticks: each drain reads only NEW
// records (the kernel advances the read offset), so the kmsg-cursor
// file only matters across agent restarts.
type kmsgSession struct {
	tail *kmsg.Tailer
	seq  uint64 // highest record seq consumed (resume dedup)
}

// checkKernelDmesg runs one scan tick: prefer the persistent /dev/kmsg
// fd (non-blocking, position-tracked by the kernel), fall back to
// `dmesg -T` (timestamps) then plain `dmesg` (line-count cursor) when
// the device can't be opened. An unreadable kernel log is
// inconclusive — no markers, no latch movement.
func (r *Runner) checkKernelDmesg(ctx context.Context) {
	st := &r.kscan
	if st.sess == nil {
		st.sess = r.newKmsgSession()
	}
	if r.drainKmsg(st) {
		return
	}
	// Read/open failure — drop the session; the dmesg fallback
	// covers this tick and kmsg is retried next tick.
	r.closeKMSSession(st)
	r.drainDmesg(ctx, st)
}

// newKmsgSession builds the tail session — the Tailer opens the
// device lazily on its first Read, so a missing /dev/kmsg surfaces
// as kmsg.ErrNoDevice inside drainKmsg on the same tick a failed
// open used to.
func (r *Runner) newKmsgSession() *kmsgSession {
	return &kmsgSession{tail: kmsg.NewTailer(kmsg.TailerOptions{
		// Re-evaluated per (re)open — Deps.KmsgDevicePaths is the
		// test seam that points the session at a fixture file.
		Paths: func() []string {
			return r.deps.KmsgDevicePaths(r.deps.HostRoot)
		},
		// The pending carry counts against the tick's drain budget —
		// the cap bounds pending+fresh bytes, not just the fd reads.
		DrainCap:             kmsgDrainCap,
		DrainIncludesPending: true,
		PendingCap:           kmsgMaxPending,
		// One record can't sanely exceed the cap — drop the carry.
		PendingTrimTail: false,
		// Bytes delivered before a hard error still classify.
		KeepPartialOnError: true,
	})}
}

func (r *Runner) closeKMSSession(st *kernelScanState) {
	if st.sess != nil {
		st.sess.tail.Close()
		st.sess = nil
	}
}

// drainKmsg reads every record the kernel currently offers (bounded
// by the tailer's kmsgDrainCap), classifies the new ones and
// advances the cursor. Returns false when the device itself fails —
// the caller falls back.
func (r *Runner) drainKmsg(st *kernelScanState) bool {
	sess := st.sess
	cur := r.readKmsgCursor()
	bootID := r.kernelBootID()
	// Resume only on a cursor from THIS boot — a stale cursor after
	// reboot would skip every new record (seqs restart low).
	resume := cur != nil && cur.mode == "kmsg" &&
		cur.bootID != "" && cur.bootID == bootID
	var minSeq uint64
	if resume {
		minSeq = cur.seq
		// Park the session at the cursor position — a drain that
		// sees no new records must not rewrite the cursor backwards
		// to seq 0 (that would replay the whole retained ring after
		// the next agent restart).
		sess.seq = cur.seq
	}

	recs, res, maxSeq, maxUsec, err := r.readKmsgAvail(sess)
	if err != nil {
		return false
	}
	if res.Backlog && !resume {
		// Backlog replay (first open, post-reboot, or a drain cut at
		// the cap that will continue next tick): the ring holds
		// retained history — discard and park at the tail so only
		// NEW records classify. The gate is Backlog, not First:
		// First fires on the first read alone, so a backlog bigger
		// than one DrainCap replayed chunks 2..N as fresh records —
		// re-emitting the whole retained ring as alert news on
		// every agent start. (A valid resume cursor skips by seq
		// instead — those old records were already processed
		// pre-restart.)
		// The cursor is only persisted once a parsed record anchors
		// it (maxSeq>0): an empty ring on the first open has no tail
		// to park at — writing seq=0 there would resume-from-0 after
		// a restart instead of re-priming the (then-populated) ring.
		sess.seq = maxSeq
		if maxSeq > 0 {
			r.writeKmsgCursor(&kmsgCursor{
				mode: "kmsg", bootID: bootID, seq: sess.seq, usec: maxUsec})
		}
		return true
	}
	for _, rec := range recs {
		if resume && (!rec.Parsed || rec.Seq <= minSeq) {
			continue
		}
		r.classifyKernelLine(rec.Msg, st)
	}
	// Advance the persisted position past everything consumed —
	// including records skipped by the resume filter. Write ONLY on
	// real progress (maxSeq > sess.seq): an idle tick used to take
	// the `|| resume` branch and rewrite the cursor with usec=0 —
	// clobbering the stored timestamp AND paying WriteFileAtomic's
	// two fsyncs every scan interval on a quiet node.
	if maxSeq > sess.seq {
		r.writeKmsgCursor(&kmsgCursor{
			mode: "kmsg", bootID: bootID, seq: maxSeq, usec: maxUsec})
	}
	return true
}

// readKmsgAvail drains the fd until EAGAIN/EOF/cap through the
// session's Tailer (it owns the pending carry) and returns the
// parsed records, the read's place in the handle lifecycle (the
// First gate is the backlog-disposition check), and the highest
// seq/usec seen (0 when nothing parsed). Records come back as
// kmsg.Record — the strict-decode gate (ParseRecord's Parsed flag)
// is what makes a record cursor-eligible; a parsed record's Msg is
// whitespace-trimmed for the classifiers.
func (r *Runner) readKmsgAvail(sess *kmsgSession) (
	[]kmsg.Record, kmsg.ReadResult, uint64, int64, error) {
	raw, res, err := sess.tail.Read()
	if err != nil {
		return nil, res, 0, 0, err
	}
	var recs []kmsg.Record
	var maxSeq uint64
	var maxUsec int64
	for _, lb := range raw {
		rec := kmsg.ParseRecord(lb)
		if !rec.Parsed {
			// Header-less line — keep the raw text for the
			// classifiers (Parsed=false keeps it out of resume
			// mode, same as the old seq-0 gate).
			recs = append(recs, kmsg.Record{Msg: string(lb)})
			continue
		}
		rec.Msg = strings.TrimSpace(rec.Msg)
		recs = append(recs, rec)
		if rec.Seq > maxSeq {
			maxSeq = rec.Seq
		}
		if rec.Usec > maxUsec {
			maxUsec = rec.Usec
		}
	}
	return recs, res, maxSeq, maxUsec, nil
}
