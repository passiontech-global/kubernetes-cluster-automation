// kmsg.go — W10-KR1 checkKernelDmesg: the /dev/kmsg + dmesg
// kernel-log classifiers (filesystem/block errors, nf_conntrack
// table-full drops, host-level OOM kills) → stateDir evidence
// markers. workerhygiene consumes the OOM markers for the
// SystemOOMVictim node event; this file owns the latches + counters.
// The Wave-10 contract overview lives in kernel_failure_latches.go.
package hostmetrics

import (
	"context"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

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

// Marker/state file names inside WatchdogStateDir — shared with
// workerhygiene (the SystemOOMVictim consumer) by convention.
const (
	kmsgCursorFile          = "kmsg-cursor"
	kmsgConntrackDropsFile  = "kmsg-conntrack-drops"
	kmsgOOMVictimFile       = "kmsg-host-oom-victim"
	kmsgOOMCountFile        = "kmsg-host-oom-count"
	conntrackBumpBudgetFile = "last-conntrack-bump"
)

// kmsgDevicePaths returns the /dev/kmsg candidates — a package var
// so tests point it at a fixture instead of the real device (the
// DaemonSet bind-mounts host /dev/kmsg; <HostRoot>/dev/kmsg covers
// standalone layouts where only the host tree is mounted).
var kmsgDevicePaths = func(hostRoot string) []string {
	return kmsg.DevicePaths("/dev/kmsg", hostRoot)
}

// --- kernel-message detectors (W10-KR1) ---

var (
	// Filesystem/block error signatures — the plan's literal set.
	fsErrorRe = regexp.MustCompile(
		`blk_update_request: I/O error|Buffer I/O error on dev|` +
			`EXT4-fs error|XFS \([^)]*\): Metadata I/O error|XFS_ERROR`)
	// nf_conntrack table-full — packets are being DROPPED.
	conntrackFullRe = regexp.MustCompile(`nf_conntrack: table full`)
	// "Out of memory: Killed process <pid> (<comm>) ..." — global
	// OOM — and "Memory cgroup out of memory: Killed process ..."
	// — the memcg variant the kernel prints for cgroup OOMs, which
	// is the COMMON case under kubepods pressure.
	oomKillRe = regexp.MustCompile(
		`(?i)(?:memory cgroup )?out of memory: killed process \d+ \(([^)]+)\)`)
	// The constraint line printed just before the kill line —
	// carries oom_memcg/task_memcg, the cgroup verdict's evidence.
	oomConstraintRe = regexp.MustCompile(`oom-kill:constraint=`)
	oomMemcgRe      = regexp.MustCompile(`(?:oom_memcg|task_memcg)=([^\s,]+)`)
	oomTaskRe       = regexp.MustCompile(`(?:^|,)task=([^\s,]+)`)
)

// oomKillCtx is the pending constraint-line state — the kernel prints
// "oom-kill:constraint=..." immediately before "Out of memory:
// Killed process ..."; the pair classifies one kill event.
type oomKillCtx struct {
	memcg string // first memcg path seen (oom_memcg preferred)
	comm  string // task= comm when present
}

// kernelScanState is the per-Collector scanner state — the kmsg
// tail session plus the cross-line OOM pairing. NetHealth-style
// keyed state because the Latches wrapper is recreated per call —
// the Collector underneath is the stable identity.
type kernelScanState struct {
	sess       *kmsgSession // nil until the session is (re)built
	oomPending *oomKillCtx  // constraint line awaiting its kill line
}

var kernelScanStates sync.Map // *Collector → *kernelScanState

func (l *Latches) kernelScan() *kernelScanState {
	if v, ok := kernelScanStates.Load(l.c); ok {
		return v.(*kernelScanState)
	}
	st := &kernelScanState{}
	actual, _ := kernelScanStates.LoadOrStore(l.c, st)
	return actual.(*kernelScanState)
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

// kmsgRecord is one parsed kmsg record — seq/usec for cursor resume,
// msg for the classifiers. parsed=false marks lines without a
// "pri,seq,usec,flags;" header (kept for the classifiers but never
// cursor-eligible).
type kmsgRecord struct {
	seq    uint64
	usec   int64
	msg    string
	parsed bool
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
func (l *Latches) kernelBootID() string {
	b, err := os.ReadFile(filepath.Join(l.c.cfg.ProcRoot,
		"sys/kernel/random/boot_id"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (l *Latches) readKmsgCursor() *kmsgCursor {
	b, err := os.ReadFile(l.statePath(kmsgCursorFile))
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

func (l *Latches) writeKmsgCursor(cur *kmsgCursor) {
	var content string
	switch cur.mode {
	case "kmsg":
		content = fmt.Sprintf("kmsg %s %d %d\n", cur.bootID, cur.seq, cur.usec)
	case "dmesgT":
		content = fmt.Sprintf("dmesgT %d %d\n", cur.unixTS, cur.lines)
	case "dmesgRaw":
		content = fmt.Sprintf("dmesgRaw %d %d\n", cur.lines, cur.hash)
	}
	p := l.statePath(kmsgCursorFile)
	if err := hostutil.WriteFileAtomicBytes(p, []byte(content)); err != nil {
		logger().Debug("hostmetrics: kmsg cursor write failed",
			"path", p, "error", err)
	}
}

// parseKmsgRecord splits "<pri>,<seq>,<usec>,<flags>;<msg>" — the
// strict-decode gate (platform/kmsg.ParseRecord's Parsed flag) is
// what makes a record cursor-eligible; the msg is whitespace-trimmed
// for the classifiers.
func parseKmsgRecord(line string) (kmsgRecord, bool) {
	r := kmsg.ParseRecord([]byte(line))
	if !r.Parsed {
		return kmsgRecord{}, false
	}
	return kmsgRecord{
		seq: r.Seq, usec: r.Usec,
		msg: strings.TrimSpace(r.Msg), parsed: true,
	}, true
}

// checkKernelDmesg runs one scan tick: prefer the persistent /dev/kmsg
// fd (non-blocking, position-tracked by the kernel), fall back to
// `dmesg -T` (timestamps) then plain `dmesg` (line-count cursor) when
// the device can't be opened. An unreadable kernel log is
// inconclusive — no markers, no latch movement.
func (l *Latches) checkKernelDmesg() {
	st := l.kernelScan()
	if st.sess == nil {
		st.sess = l.newKmsgSession()
	}
	if l.drainKmsg(st) {
		return
	}
	// Read/open failure — drop the session; the dmesg fallback
	// covers this tick and kmsg is retried next tick.
	l.closeKMSSession(st)
	l.drainDmesg(st)
}

// newKmsgSession builds the tail session — the Tailer opens the
// device lazily on its first Read, so a missing /dev/kmsg surfaces
// as kmsg.ErrNoDevice inside drainKmsg on the same tick a failed
// open used to.
func (l *Latches) newKmsgSession() *kmsgSession {
	return &kmsgSession{tail: kmsg.NewTailer(kmsg.TailerOptions{
		// Re-evaluated per (re)open — kmsgDevicePaths is the test
		// seam that points the session at a fixture file.
		Paths: func() []string {
			return kmsgDevicePaths(l.c.cfg.HostRoot)
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

func (l *Latches) closeKMSSession(st *kernelScanState) {
	if st.sess != nil {
		st.sess.tail.Close()
		st.sess = nil
	}
}

// drainKmsg reads every record the kernel currently offers (bounded
// by the tailer's kmsgDrainCap), classifies the new ones and
// advances the cursor. Returns false when the device itself fails —
// the caller falls back.
func (l *Latches) drainKmsg(st *kernelScanState) bool {
	sess := st.sess
	cur := l.readKmsgCursor()
	bootID := l.kernelBootID()
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

	recs, res, maxSeq, maxUsec, err := l.readKmsgAvail(sess)
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
		l.writeKmsgCursor(&kmsgCursor{
			mode: "kmsg", bootID: bootID, seq: sess.seq, usec: maxUsec})
		return true
	}
	for _, r := range recs {
		if resume && (!r.parsed || r.seq <= minSeq) {
			continue
		}
		l.classifyKernelLine(r.msg, st)
	}
	// Advance the persisted position past everything consumed —
	// including records skipped by the resume filter.
	newSeq := sess.seq
	if maxSeq > newSeq {
		newSeq = maxSeq
	}
	if newSeq > 0 || resume {
		l.writeKmsgCursor(&kmsgCursor{
			mode: "kmsg", bootID: bootID, seq: newSeq, usec: maxUsec})
	}
	return true
}

// readKmsgAvail drains the fd until EAGAIN/EOF/cap through the
// session's Tailer (it owns the pending carry) and returns the
// parsed records, the read's place in the handle lifecycle (the
// First gate is the backlog-disposition check), and the highest
// seq/usec seen (0 when nothing parsed).
func (l *Latches) readKmsgAvail(sess *kmsgSession) (
	[]kmsgRecord, kmsg.ReadResult, uint64, int64, error) {
	raw, res, err := sess.tail.Read()
	if err != nil {
		return nil, res, 0, 0, err
	}
	var recs []kmsgRecord
	var maxSeq uint64
	var maxUsec int64
	for _, lb := range raw {
		line := string(lb)
		if r, ok := parseKmsgRecord(line); ok {
			recs = append(recs, r)
			if r.seq > maxSeq {
				maxSeq = r.seq
			}
			if r.usec > maxUsec {
				maxUsec = r.usec
			}
		} else {
			// Header-less line — keep the raw text for the
			// classifiers (seq 0 keeps it out of resume mode).
			recs = append(recs, kmsgRecord{msg: line})
		}
	}
	return recs, res, maxSeq, maxUsec, nil
}

// classifyKernelLine feeds one kernel message into the detectors.
// Order matters: the oom-kill constraint line is captured as pending
// context for the kill line that follows it.
func (l *Latches) classifyKernelLine(msg string, st *kernelScanState) {
	switch {
	case oomConstraintRe.MatchString(msg):
		st.oomPending = parseOOMConstraint(msg)
	case oomKillRe.MatchString(msg):
		l.noteHostOOMKill(msg, st)
	case fsErrorRe.MatchString(msg):
		l.noteKernelFsError(msg)
	case conntrackFullRe.MatchString(msg):
		l.noteConntrackFull()
	}
}

// parseOOMConstraint extracts the memcg + task fields from an
// "oom-kill:constraint=..." line.
func parseOOMConstraint(msg string) *oomKillCtx {
	ctx := &oomKillCtx{}
	if m := oomMemcgRe.FindStringSubmatch(msg); m != nil {
		ctx.memcg = m[1]
	}
	if m := oomTaskRe.FindStringSubmatch(msg); m != nil {
		ctx.comm = m[1]
	}
	return ctx
}

// isHostOOMComm reports whether comm names a host-level daemon —
// the plan's containerd/k0s/kubelet set. comm is TASK_COMM_LEN
// truncated (15 chars), so prefix/substring matching is required.
func isHostOOMComm(comm string) bool {
	return comm == "kubelet" || strings.HasPrefix(comm, "k0s") ||
		strings.Contains(comm, "containerd")
}

// noteHostOOMKill classifies one "Out of memory: Killed process"
// record: host-level when the victim's memcg sits OUTSIDE the
// kubepods hierarchy, or the victim comm is a host daemon
// (containerd/k0s/kubelet). Pod-cgroup kills are routine kubelet
// eviction traffic — they must not fire SystemOOMVictim.
func (l *Latches) noteHostOOMKill(msg string, st *kernelScanState) {
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
	l.c.state.Incr(kmsgOOMCountFile)
	now := l.c.cfg.nowFn()
	p := l.statePath(kmsgOOMVictimFile)
	content := strconv.FormatInt(now.Unix(), 10) + " " + comm + "\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		logger().Warn("hostmetrics: host-oom victim marker write failed",
			"path", p, "error", err)
	}
	logger().Warn("hostmetrics: host-level OOM kill observed",
		"comm", comm, "memcg", ctxMemcg(ctx))
}

func ctxMemcg(ctx *oomKillCtx) string {
	if ctx == nil {
		return ""
	}
	return ctx.memcg
}

// noteKernelFsError records the latest kernel filesystem/block error —
// updateFSReadonlyEvidence turns a fresh marker into state-fs-readonly.
func (l *Latches) noteKernelFsError(msg string) {
	detail := msg
	if len(detail) > 200 {
		detail = detail[:200]
	}
	p := l.statePath(kmsgFsErrorFile)
	content := strconv.FormatInt(l.c.cfg.nowFn().Unix(), 10) + " " +
		detail + "\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		logger().Warn("hostmetrics: kmsg fs-error marker write failed",
			"path", p, "error", err)
	}
}

// noteConntrackFull counts table-full records and — bounded by
// the rate budget + ceiling — doubles nf_conntrack_max so the table
// stops dropping packets. A failed sysctl write is a Warn, never
// fatal (read-only /proc/sys in unprivileged pods just logs).
func (l *Latches) noteConntrackFull() {
	l.c.state.Incr(kmsgConntrackDropsFile)
	l.maybeBumpConntrackMax()
}

// maybeBumpConntrackMax doubles ConntrackMaxFile when a table-full
// record lands — rate-limited and ceiling-capped. The write targets
// the sysctl path directly; containerized agents without a writable
// /proc/sys get a Warn and move on.
func (l *Latches) maybeBumpConntrackMax() {
	if !l.c.state.RateOK(conntrackBumpBudgetFile, conntrackBumpEvery) {
		return
	}
	cur, ok := hostutil.ReadUintFile(l.c.cfg.ConntrackMaxFile)
	if !ok || cur == 0 || cur >= conntrackMaxCeiling {
		return
	}
	next := cur * 2
	if next > conntrackMaxCeiling {
		next = conntrackMaxCeiling
	}
	if err := os.WriteFile(l.c.cfg.ConntrackMaxFile,
		[]byte(strconv.FormatUint(next, 10)+"\n"), 0o644); err != nil {
		logger().Warn("hostmetrics: nf_conntrack_max bump failed",
			"path", l.c.cfg.ConntrackMaxFile, "error", err)
		return
	}
	l.c.state.RateSpend(conntrackBumpBudgetFile)
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
func (l *Latches) drainDmesg(st *kernelScanState) {
	out, err := runHostCmd(context.Background(), "dmesg", "-T")
	mode := "dmesgT"
	if err != nil {
		out, err = runHostCmd(context.Background(), "dmesg")
		mode = "dmesgRaw"
	}
	if err != nil {
		// No kernel-log access at all — inconclusive, not an error.
		return
	}
	lines := strings.Split(out, "\n")
	cur := l.readKmsgCursor()
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
				l.writeKmsgCursor(&kmsgCursor{
					mode: "dmesgT", unixTS: newest, lines: atNewest})
			}
		default:
			l.writeKmsgCursor(&kmsgCursor{
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
			l.writeKmsgCursor(&kmsgCursor{
				mode: "dmesgT", unixTS: maxTS, lines: atMax})
		case atLast > pending:
			// Only same-second arrivals — advance the consumed
			// count so they aren't reprocessed next tick.
			l.writeKmsgCursor(&kmsgCursor{
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
			l.writeKmsgCursor(&kmsgCursor{
				mode: "dmesgRaw", lines: len(lines), hash: tail})
			break
		}
		fresh = trimmed[anchor+1:]
		l.writeKmsgCursor(&kmsgCursor{
			mode: "dmesgRaw", lines: len(lines), hash: tail})
	}
	for _, msg := range fresh {
		if msg == "" {
			continue
		}
		l.classifyKernelLine(msg, st)
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
