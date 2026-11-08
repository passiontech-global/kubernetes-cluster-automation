// kmsg.go — W10-KR1 checkKernelDmesg: the /dev/kmsg + dmesg
// kernel-log drain plumbing (session/cursor, marker writes, the
// sysctl bump) → stateDir evidence markers. The classifier half —
// the detector regexes and the line→detector dispatch — lives in
// kmsg_rules.go. workerhygiene consumes the OOM markers for the
// SystemOOMVictim node event; this file owns the latches + counters.
// The Wave-10 contract overview lives in kernelfail.go.
package kernelfail

import (
	"context"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/kmsg"
)

// --- kmsg/dmesg drain constants (W10-KR1) ---

const (
	// conntrackBumpEvery rate-limits the nf_conntrack_max doubling —
	// table-full bursts must not ratchet the sysctl every tick.
	conntrackBumpEvery = 30 * time.Minute
	// conntrackMaxCeiling caps the sysctl bump (nf_conntrack_max).
	conntrackMaxCeiling = 4 << 20
	// kmsgDrainCap bounds one tick's ring read — a printk flood
	// can't stall the 30s latch ticker.
	kmsgDrainCap = 8 << 20
	// kmsgMaxPending bounds the partial-line carry.
	kmsgMaxPending = 1 << 20
)

// Marker/state file names inside the watchdog state dir — shared
// with workerhygiene (the SystemOOMVictim consumer) by convention.
const (
	kmsgCursorFile          = "kmsg-cursor"
	kmsgConntrackDropsFile  = "kmsg-conntrack-drops"
	kmsgOOMVictimFile       = "kmsg-host-oom-victim"
	kmsgOOMCountFile        = "kmsg-host-oom-count"
	conntrackBumpBudgetFile = "last-conntrack-bump"
)

// The kernel-message detector regexes, the oomKillCtx pairing
// context and classifyKernelLine itself live in kmsg_rules.go —
// this file keeps the plumbing they dispatch into.

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

// kmsgCursor is the persisted resume position — one line in
// kmsg-cursor:
//
//	kmsg <bootid> <seq> <usec>        — /dev/kmsg mode
//	dmesgT <unixTs> <consumedAtTs>    — dmesg -T fallback
//	dmesgRaw <lineCount> <lineHash>   — plain dmesg last resort
//
// bootid+usec detect a reboot the seq counter can't (kmsg seqs
// restart at a low value every boot). dmesgT's second field counts
// same-second records already consumed (dmesg -T has 1s
// granularity); dmesgRaw's hash anchors on the last processed line
// because a saturated ring holds a CONSTANT line count — a pure
// count cursor would go permanently blind.
type kmsgCursor struct {
	mode   string
	bootID string
	seq    uint64
	usec   int64
	unixTS int64
	lines  int
	hash   uint64
}

// kernelBootID reads /proc/sys/kernel/random/boot_id under ProcRoot.
func (r *Runner) kernelBootID() string {
	b, err := os.ReadFile(filepath.Join(r.deps.ProcRoot,
		"sys/kernel/random/boot_id"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (r *Runner) readKmsgCursor() *kmsgCursor {
	b, err := os.ReadFile(r.statePath(kmsgCursorFile))
	if err != nil {
		return nil
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return nil
	}
	cur := &kmsgCursor{mode: f[0]}
	switch cur.mode {
	case "kmsg":
		if len(f) < 4 {
			return nil
		}
		cur.bootID = f[1]
		cur.seq, _ = strconv.ParseUint(f[2], 10, 64)
		cur.usec, _ = strconv.ParseInt(f[3], 10, 64)
	case "dmesgT":
		if len(f) < 2 {
			return nil
		}
		cur.unixTS, _ = strconv.ParseInt(f[1], 10, 64)
		if len(f) >= 3 {
			cur.lines, _ = strconv.Atoi(f[2])
		} else {
			// Legacy "dmesgT <ts>" cursor — the same-second
			// consumed count is unknowable; -1 makes drainDmesg
			// skip ALL same-second lines rather than risk a
			// one-time double count.
			cur.lines = -1
		}
	case "dmesgRaw":
		if len(f) < 2 {
			return nil
		}
		cur.lines, _ = strconv.Atoi(f[1])
		if len(f) >= 3 {
			cur.hash, _ = strconv.ParseUint(f[2], 10, 64)
		}
	default:
		return nil
	}
	return cur
}

func (r *Runner) writeKmsgCursor(cur *kmsgCursor) {
	var content string
	switch cur.mode {
	case "kmsg":
		content = fmt.Sprintf("kmsg %s %d %d\n", cur.bootID, cur.seq, cur.usec)
	case "dmesgT":
		content = fmt.Sprintf("dmesgT %d %d\n", cur.unixTS, cur.lines)
	case "dmesgRaw":
		content = fmt.Sprintf("dmesgRaw %d %d\n", cur.lines, cur.hash)
	}
	p := r.statePath(kmsgCursorFile)
	if err := hostutil.WriteFileAtomicBytes(p, []byte(content)); err != nil {
		logger().Debug("hostmetrics: kmsg cursor write failed",
			"path", p, "error", err)
	}
}

// checkKernelDmesg runs one scan tick: prefer the persistent /dev/kmsg
// fd (non-blocking, position-tracked by the kernel), fall back to
// `dmesg -T` (timestamps) then plain `dmesg` (line-count cursor) when
// the device can't be opened. An unreadable kernel log is
// inconclusive — no markers, no latch movement.
func (r *Runner) checkKernelDmesg() {
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
	r.drainDmesg(st)
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
	if res.First && !resume {
		// First-ever open (or post-reboot): the ring holds the whole
		// retained backlog — history, not news. Discard it and park
		// the position at the tail so only NEW records classify.
		// (A valid resume cursor skips by seq instead — those old
		// records were already processed pre-restart.)
		sess.seq = maxSeq
		r.writeKmsgCursor(&kmsgCursor{
			mode: "kmsg", bootID: bootID, seq: sess.seq, usec: maxUsec})
		return true
	}
	for _, rec := range recs {
		if resume && (!rec.Parsed || rec.Seq <= minSeq) {
			continue
		}
		r.classifyKernelLine(rec.Msg, st)
	}
	// Advance the persisted position past everything consumed —
	// including records skipped by the resume filter.
	newSeq := sess.seq
	if maxSeq > newSeq {
		newSeq = maxSeq
	}
	if newSeq > 0 || resume {
		r.writeKmsgCursor(&kmsgCursor{
			mode: "kmsg", bootID: bootID, seq: newSeq, usec: maxUsec})
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

// noteHostOOMKill classifies one "Out of memory: Killed process"
// record: host-level when the victim's memcg sits OUTSIDE the
// kubepods hierarchy, or the victim comm is a host daemon
// (containerd/k0s/kubelet). Pod-cgroup kills are routine kubelet
// eviction traffic — they must not fire SystemOOMVictim.
func (r *Runner) noteHostOOMKill(msg string, st *kernelScanState) {
	m := oomKillRe.FindStringSubmatch(msg)
	if m == nil {
		return
	}
	comm := m[1]
	ctx := st.oomPending
	st.oomPending = nil
	host := false
	if ctx != nil && ctx.memcg != "" {
		host = !strings.Contains(ctx.memcg, "kubepods")
	}
	if isHostOOMComm(comm) || (ctx != nil && isHostOOMComm(ctx.comm)) {
		host = true
	}
	if !host {
		return
	}
	r.deps.Store.Incr(kmsgOOMCountFile)
	now := r.deps.Clock.Now()
	p := r.statePath(kmsgOOMVictimFile)
	content := strconv.FormatInt(now.Unix(), 10) + " " + comm + "\n"
	if err := hostutil.WriteFileAtomicBytes(p, []byte(content)); err != nil {
		logger().Warn("hostmetrics: host-oom victim marker write failed",
			"path", p, "error", err)
	}
	logger().Warn("hostmetrics: host-level OOM kill observed",
		"comm", comm, "memcg", ctxMemcg(ctx))
}

// noteKernelFsError records the latest kernel filesystem/block error —
// updateFSReadonlyEvidence turns a fresh marker into state-fs-readonly.
func (r *Runner) noteKernelFsError(msg string) {
	detail := msg
	if len(detail) > 200 {
		detail = detail[:200]
	}
	p := r.statePath(kmsgFsErrorFile)
	content := strconv.FormatInt(r.deps.Clock.Now().Unix(), 10) + " " +
		detail + "\n"
	if err := hostutil.WriteFileAtomicBytes(p, []byte(content)); err != nil {
		logger().Warn("hostmetrics: kmsg fs-error marker write failed",
			"path", p, "error", err)
	}
}

// notePageAllocFailure latches state-page-alloc-failure on a
// higher-order (order>=1) page allocation failure — fragmentation
// evidence: MemAvailable can still read GBs free while the buddy
// allocator fails to find a contiguous block for sk_buff,
// WireGuard (cilium_wg0) or XFS metadata. The latch is the
// hostmetrics→workerhygiene hand-off for the kernel-pressure
// vm.compact_memory trigger (the compact itself + its cooldown live
// in workerhygiene); Enter is idempotent, so repeat failure lines
// only refresh the latch mtime and never spam STATE-ENTER lines —
// the latch exits when workerhygiene's compaction or the janitor's
// max-age reaper clears it, which is also the re-arm for the next
// fragmentation episode.
func (r *Runner) notePageAllocFailure(msg string) {
	detail := msg
	if len(detail) > 200 {
		detail = detail[:200]
	}
	r.deps.Store.Enter(latchdefs.LatchPageAllocFailure,
		"page allocation failure: "+detail)
}

// noteClocksourceUnstable latches state-clocksource-unstable on a
// kernel clocksource-unstable kmsg record — the kernel
// demoted its clock (typically tsc) to a slower fallback, so every
// vDSO clock_gettime degrades and clock-skew false positives follow.
// Like the nodereporter soft-lockup evidence latches this is a
// permanent-class latch: Enter is idempotent (repeat records only
// refresh the mtime) and only the janitor's max-age reaper clears it
// once the signature stops recurring.
func (r *Runner) noteClocksourceUnstable(msg string) {
	detail := msg
	if len(detail) > 200 {
		detail = detail[:200]
	}
	r.deps.Store.Enter(latchdefs.LatchClocksourceUnstable,
		"clocksource unstable: "+detail)
}

// noteConntrackFull counts table-full records and — bounded by
// the rate budget + ceiling — doubles nf_conntrack_max so the table
// stops dropping packets. A failed sysctl write is a Warn, never
// fatal (read-only /proc/sys in unprivileged pods just logs).
func (r *Runner) noteConntrackFull() {
	r.deps.Store.Incr(kmsgConntrackDropsFile)
	r.maybeBumpConntrackMax()
}

// maybeBumpConntrackMax doubles ConntrackMaxFile when a table-full
// record lands — rate-limited and ceiling-capped. The write targets
// the sysctl path directly; containerized agents without a writable
// /proc/sys get a Warn and move on.
func (r *Runner) maybeBumpConntrackMax() {
	if !r.deps.Store.RateOK(conntrackBumpBudgetFile, conntrackBumpEvery) {
		return
	}
	cur, ok := hostutil.ReadUintFile(r.deps.ConntrackMaxFile)
	if !ok || cur == 0 || cur >= conntrackMaxCeiling {
		return
	}
	next := cur * 2
	if next > conntrackMaxCeiling {
		next = conntrackMaxCeiling
	}
	if err := os.WriteFile(r.deps.ConntrackMaxFile,
		[]byte(strconv.FormatUint(next, 10)+"\n"), 0o644); err != nil {
		logger().Warn("hostmetrics: nf_conntrack_max bump failed",
			"path", r.deps.ConntrackMaxFile, "error", err)
		return
	}
	r.deps.Store.RateSpend(conntrackBumpBudgetFile)
	logger().Warn("hostmetrics: nf_conntrack table full — bumped "+
		"nf_conntrack_max",
		"from", cur, "to", next)
}

// --- dmesg fallback (W10-KR1) ---

// drainDmesg is the no-/dev/kmsg path: `dmesg -T` carries parseable
// timestamps (cursor = last unix ts + same-second consumed count);
// plain `dmesg` has no wall clock (cursor = fnv hash of the last
// processed line — a saturated ring holds a constant line count, so
// a count cursor would go permanently blind; a lost anchor skips
// the tick and re-anchors at the tail rather than reprocessing the
// whole retained ring).
func (r *Runner) drainDmesg(st *kernelScanState) {
	out, err := r.deps.RunHostCmd(context.Background(), "dmesg", "-T")
	mode := "dmesgT"
	if err != nil {
		out, err = r.deps.RunHostCmd(context.Background(), "dmesg")
		mode = "dmesgRaw"
	}
	if err != nil {
		// No kernel-log access at all — inconclusive, not an error.
		return
	}
	lines := strings.Split(out, "\n")
	cur := r.readKmsgCursor()
	// First sighting in this mode (no cursor, or a cursor from the
	// OTHER fallback mode): dmesg output is the whole retained ring
	// — history, not news. Prime the cursor at the tail and
	// classify nothing, exactly like the kmsg first-open path.
	if cur == nil || cur.mode != mode {
		switch mode {
		case "dmesgT":
			newest := int64(0)
			atNewest := 0
			for _, ln := range lines {
				ts, ok := parseDmesgTimestamp(ln)
				if !ok {
					continue
				}
				if ts > newest {
					newest = ts
					atNewest = 0
				}
				if ts == newest {
					atNewest++
				}
			}
			if newest > 0 {
				r.writeKmsgCursor(&kmsgCursor{
					mode: "dmesgT", unixTS: newest, lines: atNewest})
			}
		default:
			r.writeKmsgCursor(&kmsgCursor{
				mode: "dmesgRaw", lines: len(lines),
				hash: dmesgTailHash(lines)})
		}
		return
	}
	var fresh []string
	var maxTS int64
	switch mode {
	case "dmesgT":
		lastTS := cur.unixTS
		pending := cur.lines // same-second records already consumed
		if pending < 0 {
			pending = len(lines) + 1 // legacy cursor — boundary unknown
		}
		atLast, atMax := 0, 0
		for _, ln := range lines {
			ts, ok := parseDmesgTimestamp(ln)
			if !ok {
				continue // can't order it — never reprocess blindly
			}
			if ts > lastTS {
				fresh = append(fresh, dmesgMessage(ln))
				if ts > maxTS {
					maxTS = ts
					atMax = 0
				}
				if ts == maxTS {
					atMax++
				}
			} else if ts == lastTS {
				atLast++
				if atLast > pending {
					fresh = append(fresh, dmesgMessage(ln))
				}
			}
		}
		switch {
		case maxTS > 0:
			r.writeKmsgCursor(&kmsgCursor{
				mode: "dmesgT", unixTS: maxTS, lines: atMax})
		case atLast > pending:
			// Only same-second arrivals — advance the consumed
			// count so they aren't reprocessed next tick.
			r.writeKmsgCursor(&kmsgCursor{
				mode: "dmesgT", unixTS: lastTS, lines: atLast})
		}
	default: // dmesgRaw — content-anchored, see drainDmesg doc.
		trimmed := lines
		for len(trimmed) > 0 && trimmed[len(trimmed)-1] == "" {
			trimmed = trimmed[:len(trimmed)-1]
		}
		if len(trimmed) == 0 {
			break
		}
		tail := dmesgLineHash(trimmed[len(trimmed)-1])
		anchor := -1
		if cur.hash != 0 {
			for i := len(trimmed) - 1; i >= 0; i-- {
				if dmesgLineHash(trimmed[i]) == cur.hash {
					anchor = i
					break
				}
			}
		}
		if anchor < 0 {
			// Anchor evicted (ring wrapped past it) or a legacy
			// line-count cursor — can't order the retained window.
			// Skip this tick and re-anchor at the tail: missed
			// detections beat double-counted ones.
			r.writeKmsgCursor(&kmsgCursor{
				mode: "dmesgRaw", lines: len(lines), hash: tail})
			break
		}
		fresh = trimmed[anchor+1:]
		r.writeKmsgCursor(&kmsgCursor{
			mode: "dmesgRaw", lines: len(lines), hash: tail})
	}
	for _, msg := range fresh {
		if msg == "" {
			continue
		}
		r.classifyKernelLine(msg, st)
	}
}

// dmesgLineHash fingerprints one dmesg output line for the cursor
// anchor — fnv-1a, collision odds are irrelevant at ring sizes.
func dmesgLineHash(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

// dmesgTailHash hashes the last non-empty dmesg line — the anchor
// the next drain resumes after. 0 when output is empty.
func dmesgTailHash(lines []string) uint64 {
	for i := len(lines) - 1; i >= 0; i-- {
		if lines[i] != "" {
			return dmesgLineHash(lines[i])
		}
	}
	return 0
}

// dmesgTSLayout is `dmesg -T`'s "[Thu Oct 30 12:34:56 2025]" prefix.
const dmesgTSLayout = "Mon Jan _2 15:04:05 2006"

// parseDmesgTimestamp extracts the bracketed timestamp dmesg -T
// prepends; ok=false for unparseable/missing prefixes.
func parseDmesgTimestamp(line string) (int64, bool) {
	if !strings.HasPrefix(line, "[") {
		return 0, false
	}
	end := strings.IndexByte(line, ']')
	if end < 0 {
		return 0, false
	}
	t, err := time.Parse(dmesgTSLayout, strings.TrimSpace(line[1:end]))
	if err != nil {
		return 0, false
	}
	return t.Unix(), true
}

// dmesgMessage strips the "[timestamp] " prefix, returning the raw
// kernel message.
func dmesgMessage(line string) string {
	if i := strings.IndexByte(line, ']'); i >= 0 {
		return strings.TrimSpace(line[i+1:])
	}
	return strings.TrimSpace(line)
}
