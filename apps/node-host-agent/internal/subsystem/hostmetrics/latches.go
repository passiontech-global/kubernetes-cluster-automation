// latches.go — W8 latch maintenance (BUG-H5/H6, W8-KR3).
//
// hostmetrics was a pure scrape-time collector: the watchdog-state
// file contract (state-node-overloaded, state-filesystem-readonly,
// state-nebula-cert-expiring, state-kernel-keys-pressure) only moved
// when Prometheus scraped — a DaemonSet pod that isn't scraped every
// 30s (or at all) left stale or missing latches for the file
// consumers (nodereporter conditions, the restart gates). Run() is
// the scrape-independent 30s ticker that keeps them fresh — it runs
// in BOTH modes (Standalone only changes where series are rendered,
// not who owns the latches).
//
// While a latch stays held its mtime is refreshed (BUG-H6) so the
// janitor's 24h reap can't retire an active signal.
package hostmetrics

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
)

// Name identifies the subsystem for the agent loop.
func (c *Collector) Name() string { return "hostmetrics" }

// Run drives the latch-maintenance ticker until ctx is cancelled.
func (c *Collector) Run(ctx context.Context) {
	c.refreshLatches()
	t := time.NewTicker(c.cfg.LatchInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.refreshLatches()
		}
	}
}

// refreshLatches re-evaluates every file-contract latch once — the
// same logic Collect runs per scrape, decoupled from scrapes
// (BUG-H5). Each updater is already idempotent + hysteresis-safe.
func (c *Collector) refreshLatches() {
	if avg60, ok := c.psiAvg60(); ok {
		c.updateOverloadLatch(avg60)
	}
	days, certOK := c.nebulaCertDaysLeft()
	c.updateCertLatch(days, certOK)
	// Filesystem read-only: probe each target like collectFilesystem
	// but only for the latch (metrics are scrape-side).
	anyRO, probed := false, false
	for _, mount := range c.cfg.FilesystemTargets {
		st, _, ok := c.probeFS(mount)
		if !ok {
			continue
		}
		probed = true
		if st.Flags&1 != 0 { // unix.ST_RDONLY without importing unix twice
			anyRO = true
		}
	}
	c.updateFSReadonlyLatch(anyRO, probed)
	// W8-KR3: kernel keyring quota pressure.
	if ratio, ok := c.kernelKeysUsedRatio(); ok {
		c.updateKernelKeysLatch(ratio)
	}
	// W10-KR1: kernel dmesg/kmsg deep-error scan — filesystem/block
	// errors, conntrack table-full drops, host-level OOM kills.
	// Writes evidence markers (kmsg-fs-error, kmsg-conntrack-drops,
	// kmsg-host-oom-*) that the latches below and workerhygiene's
	// SystemOOMVictim emitter consume. Ticker-only: a scrape-side
	// drain would steal records from this loop.
	c.checkKernelDmesg()
	// W10-KR2: pid/thread/fd utilization → state-pid-fd-pressure
	// plus the node_agent_*_utilization_ratio textfile gauges.
	c.updatePidFDPressure()
	// W10-KR5: chronyc/adjtimex clock-skew probe → state-clock-skew
	// + rate-limited chronyc makestep.
	c.checkClockSkewW10()
	// W10-ST1+KR1: the state-fs-readonly evidence latch — a fresh
	// kernel fs error OR an ro ext4/xfs/btrfs mount under a PVC
	// dir, ahead of statfs ever reporting ST_RDONLY.
	c.updateFSReadonlyW10()
	// BUG-H6: while a latch stays held keep its mtime fresh so the
	// janitor's LatchMaxAge reap can't retire an active signal.
	for _, name := range []string{
		"state-node-overloaded",
		"state-filesystem-readonly",
		"state-nebula-cert-expiring",
		"state-kernel-keys-pressure",
		// W10 maintained latches — same reap protection.
		"state-fs-readonly",
		"state-pid-fd-pressure",
		"state-clock-skew",
	} {
		p := filepath.Join(c.cfg.WatchdogStateDir, name)
		if _, err := os.Stat(p); err == nil {
			now := c.cfg.nowFn()
			if cerr := os.Chtimes(p, now, now); cerr != nil {
				logger().Debug("hostmetrics: latch touch failed",
					"path", p, "error", cerr)
			}
		}
	}
}

// --- W8-KR3: /proc/key-users kernel keyring quota ---

// kernelKeysUsedRatio returns the highest fill ratio across the
// per-UID rows of /proc/key-users ("uid: usage nkeys nikeys maxkeys
// maxbytes" — nikeys vs maxkeys is the enforced quota). ok=false on
// a missing/unparseable file (kernel keyring disabled or proc
// absent) — inconclusive evidence must not move the latch.
func (c *Collector) kernelKeysUsedRatio() (float64, bool) {
	data, err := os.ReadFile(c.cfg.KeyUsersFile)
	if err != nil {
		return 0, false
	}
	best := -1.0
	seen := false
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		// Fields after the "uid:" label: usage nkeys nikeys maxkeys
		// maxbytes — column order of proc_key_users_show.
		nikeys, errN := strconv.ParseFloat(f[3], 64)
		maxkeys, errM := strconv.ParseFloat(f[4], 64)
		if errN != nil || errM != nil || maxkeys <= 0 {
			continue
		}
		seen = true
		if r := nikeys / maxkeys; r > best {
			best = r
		}
	}
	if !seen {
		return 0, false
	}
	return best, true
}

// updateKernelKeysLatch drives state-kernel-keys-pressure (W8-KR3):
// set above 0.80 of the enforced quota — a full keyring fails
// keyctl_join/add_key silently for new sessions.
func (c *Collector) updateKernelKeysLatch(ratio float64) {
	p := filepath.Join(c.cfg.WatchdogStateDir, "state-kernel-keys-pressure")
	_, err := os.Stat(p)
	switch {
	case ratio > kernelKeysPressureRatio && err != nil:
		content := strconv.FormatInt(c.cfg.nowFn().Unix(), 10) + "\n"
		tmp := filepath.Join(filepath.Dir(p), ".tmp-"+filepath.Base(p))
		if werr := os.WriteFile(tmp, []byte(content), 0o644); werr != nil {
			logger().Warn("hostmetrics: kernel-keys-pressure latch write failed",
				"path", p, "error", werr)
		} else if rerr := os.Rename(tmp, p); rerr != nil {
			logger().Warn("hostmetrics: kernel-keys-pressure latch install failed",
				"path", p, "error", rerr)
		} else {
			logger().Warn("hostmetrics: kernel-keys-pressure latch set",
				"ratio", ratio, "threshold", kernelKeysPressureRatio, "path", p)
		}
	case ratio <= kernelKeysPressureRatio && err == nil:
		if rerr := os.Remove(p); rerr != nil {
			logger().Warn("hostmetrics: kernel-keys-pressure latch remove failed",
				"path", p, "error", rerr)
		} else {
			logger().Info("hostmetrics: kernel-keys-pressure latch cleared",
				"ratio", ratio, "path", p)
		}
	}
}

// collectKernelKeys emits the W8-KR3 used-ratio gauge — absent when
// the file doesn't parse (no fake 0).
func (c *Collector) collectKernelKeys(ch chan<- prometheus.Metric) {
	ratio, ok := c.kernelKeysUsedRatio()
	if !ok {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.descKernelKeys,
		prometheus.GaugeValue, ratio, c.cfg.NodeName)
}

// ===========================================================================
// Wave-10 — kernel deep-failure modes (W10-KR1/KR2/KR5, W10-ST1)
//
// The sections below extend the latch ticker with the Wave-10 contract:
//
//   - W10-KR1 checkKernelDmesg: /dev/kmsg drain (dmesg -T fallback)
//     classifying filesystem/block errors, nf_conntrack table-full
//     drops and host-level OOM kills into stateDir evidence markers.
//     workerhygiene consumes the OOM markers for the SystemOOMVictim
//     node event; this file owns the latches + counters.
//   - W10-KR2 updatePidFDPressure: pid/thread/fd utilization ratios
//     → state-pid-fd-pressure (KernelResourceExhaustion) + the
//     node_agent_*_utilization_ratio textfile gauges (the W10 metric
//     channel — same convention controllerhygiene's cpwave.go uses;
//     prometheus descs can't be added outside hostmetrics.go's New()).
//   - W10-KR5 checkClockSkewW10: chronyc tracking (adjtimex offset
//     fallback) → state-clock-skew (ClockSkewDetected) + a
//     rate-limited `chronyc makestep`.
//   - W10-ST1 updateFSReadonlyW10: ro ext4/xfs/btrfs mounts under the
//     PVC provisioner roots parsed out of /proc/<pid>/mounts →
//     state-fs-readonly (FilesystemReadOnly) ahead of statfs.
// ===========================================================================

// --- shared Wave-10 constants ---

const (
	// fsErrorLatchTTL bounds state-fs-readonly's kernel-error
	// evidence: a marker older than this no longer holds the latch
	// (a single ext4 error from a transient USB reset must not
	// latch FilesystemReadOnly forever).
	fsErrorLatchTTL = 30 * time.Minute
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
	// kernelProcPressureRatio/Needed arm state-pid-fd-pressure —
	// 90% utilization for 3 consecutive latch ticks.
	kernelProcPressureRatio  = 0.90
	kernelProcPressureNeeded = 3
	// clockSkew thresholds (W10-KR5): makestep fires above 0.5s or
	// on "Not synchronised"; the latch needs >2.0s for 5 ticks.
	clockSkewStepOffset  = 0.5
	clockSkewLatchOffset = 2.0
	clockSkewLatchNeeded = 5
	clockSkewMakestepGap = 10 * time.Minute
)

// Marker/state file names inside WatchdogStateDir — shared with
// workerhygiene (the SystemOOMVictim consumer) by convention.
const (
	w10KmsgCursorFile     = "kmsg-cursor"
	w10KmsgFSErrorFile    = "kmsg-fs-error"
	w10KmsgCtDropsFile    = "kmsg-conntrack-drops"
	w10KmsgOOMVictimFile  = "kmsg-host-oom-victim"
	w10KmsgOOMCountFile   = "kmsg-host-oom-count"
	w10PidFDCountFile     = "pid-fd-pressure-count"
	w10ClockSkewCountFile = "clock-skew-count"
	w10ConntrackBumpFile  = "last-conntrack-bump"
	w10ClockStepFile      = "last-clock-makestep"
)

// kmsgDevicePaths returns the /dev/kmsg candidates — a package var
// so tests point it at a fixture instead of the real device (the
// DaemonSet bind-mounts host /dev/kmsg; <HostRoot>/dev/kmsg covers
// standalone layouts where only the host tree is mounted).
var kmsgDevicePaths = func(hostRoot string) []string {
	return []string{"/dev/kmsg", filepath.Join(hostRoot, "dev/kmsg")}
}

// w10RunCmd executes a host binary for the Wave-10 probes that have
// no Config seam (chronyc, dmesg) — a package var so tests stub it.
// The 30s cap matches the nethealth runHostCmd convention.
var w10RunCmd = func(ctx context.Context, argv ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, argv[0], argv[1:]...).CombinedOutput()
	return string(out), err
}

// w10TextfileDirOverride wins over the HostRoot-derived textfile
// dir in tests (controllerhygiene's kineTextfileDirOverride parity).
var w10TextfileDirOverride string

// --- kernel-message detectors (W10-KR1) ---

var (
	// Filesystem/block error signatures — the plan's literal set.
	w10FSErrorRe = regexp.MustCompile(
		`blk_update_request: I/O error|Buffer I/O error on dev|` +
			`EXT4-fs error|XFS \([^)]*\): Metadata I/O error|XFS_ERROR`)
	// nf_conntrack table-full — packets are being DROPPED.
	w10ConntrackFullRe = regexp.MustCompile(`nf_conntrack: table full`)
	// "Out of memory: Killed process <pid> (<comm>) ..." — global
	// OOM — and "Memory cgroup out of memory: Killed process ..."
	// — the memcg variant the kernel prints for cgroup OOMs, which
	// is the COMMON case under kubepods pressure.
	w10OOMKillRe = regexp.MustCompile(
		`(?i)(?:memory cgroup )?out of memory: killed process \d+ \(([^)]+)\)`)
	// The constraint line printed just before the kill line —
	// carries oom_memcg/task_memcg, the cgroup verdict's evidence.
	w10OOMConstraintRe = regexp.MustCompile(`oom-kill:constraint=`)
	w10OOMMemcgRe      = regexp.MustCompile(`(?:oom_memcg|task_memcg)=([^\s,]+)`)
	w10OOMTaskRe       = regexp.MustCompile(`(?:^|,)task=([^\s,]+)`)
)

// w10OOMCtx is the pending constraint-line state — the kernel prints
// "oom-kill:constraint=..." immediately before "Out of memory:
// Killed process ..."; the pair classifies one kill event.
type w10OOMCtx struct {
	memcg string // first memcg path seen (oom_memcg preferred)
	comm  string // task= comm when present
}

// w10KernelState is the per-Collector scanner state — the kmsg fd
// session plus the cross-line OOM pairing. NetHealth-style keyed
// state because Collector's struct lives in hostmetrics.go.
type w10KernelState struct {
	sess       *w10KMSSession // nil until /dev/kmsg opens
	oomPending *w10OOMCtx     // constraint line awaiting its kill line
}

var w10KernelStates sync.Map // *Collector → *w10KernelState

func (c *Collector) w10Kernel() *w10KernelState {
	if v, ok := w10KernelStates.Load(c); ok {
		return v.(*w10KernelState)
	}
	st := &w10KernelState{}
	actual, _ := w10KernelStates.LoadOrStore(c, st)
	return actual.(*w10KernelState)
}

// w10KMSSession is the open /dev/kmsg handle + ring position. The fd
// stays open across ticks: each drain reads only NEW records (the
// kernel advances the read offset), so the kmsg-cursor file only
// matters across agent restarts.
type w10KMSSession struct {
	f       *os.File
	pending []byte // partial-line carry between reads
	primed  bool   // first-open backlog disposition decided
	seq     uint64 // highest record seq consumed (resume dedup)
}

// w10KmsgRec is one parsed kmsg record — seq/usec for cursor resume,
// msg for the classifiers. parsed=false marks lines without a
// "pri,seq,usec,flags;" header (kept for the classifiers but never
// cursor-eligible).
type w10KmsgRec struct {
	seq    uint64
	usec   int64
	msg    string
	parsed bool
}

// w10KmsgCursor is the persisted resume position — one line in
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
type w10KmsgCursor struct {
	mode   string
	bootID string
	seq    uint64
	usec   int64
	unixTs int64
	lines  int
	hash   uint64
}

// kernelBootID reads /proc/sys/kernel/random/boot_id under ProcRoot.
func (c *Collector) kernelBootID() string {
	b, err := os.ReadFile(filepath.Join(c.cfg.ProcRoot,
		"sys/kernel/random/boot_id"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (c *Collector) w10StatePath(name string) string {
	return filepath.Join(c.cfg.WatchdogStateDir, name)
}

func (c *Collector) readKmsgCursor() *w10KmsgCursor {
	b, err := os.ReadFile(c.w10StatePath(w10KmsgCursorFile))
	if err != nil {
		return nil
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return nil
	}
	cur := &w10KmsgCursor{mode: f[0]}
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
		cur.unixTs, _ = strconv.ParseInt(f[1], 10, 64)
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

func (c *Collector) writeKmsgCursor(cur *w10KmsgCursor) {
	var content string
	switch cur.mode {
	case "kmsg":
		content = fmt.Sprintf("kmsg %s %d %d\n", cur.bootID, cur.seq, cur.usec)
	case "dmesgT":
		content = fmt.Sprintf("dmesgT %d %d\n", cur.unixTs, cur.lines)
	case "dmesgRaw":
		content = fmt.Sprintf("dmesgRaw %d %d\n", cur.lines, cur.hash)
	}
	p := c.w10StatePath(w10KmsgCursorFile)
	tmp := filepath.Join(filepath.Dir(p), ".tmp-"+filepath.Base(p))
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		logger().Debug("hostmetrics: kmsg cursor write failed",
			"path", p, "error", err)
		return
	}
	if err := os.Rename(tmp, p); err != nil {
		logger().Debug("hostmetrics: kmsg cursor install failed",
			"path", p, "error", err)
	}
}

// parseKmsgRecord splits "<pri>,<seq>,<usec>,<flags>;<msg>".
func parseKmsgRecord(line string) (w10KmsgRec, bool) {
	i := strings.IndexByte(line, ';')
	if i < 0 {
		return w10KmsgRec{}, false
	}
	hdr := strings.Split(line[:i], ",")
	if len(hdr) < 3 {
		return w10KmsgRec{}, false
	}
	seq, errS := strconv.ParseUint(hdr[1], 10, 64)
	usec, errU := strconv.ParseInt(hdr[2], 10, 64)
	if errS != nil || errU != nil {
		return w10KmsgRec{}, false
	}
	return w10KmsgRec{
		seq: seq, usec: usec,
		msg: strings.TrimSpace(line[i+1:]), parsed: true,
	}, true
}

// checkKernelDmesg runs one scan tick: prefer the persistent /dev/kmsg
// fd (non-blocking, position-tracked by the kernel), fall back to
// `dmesg -T` (timestamps) then plain `dmesg` (line-count cursor) when
// the device can't be opened. An unreadable kernel log is
// inconclusive — no markers, no latch movement.
func (c *Collector) checkKernelDmesg() {
	st := c.w10Kernel()
	if st.sess != nil || c.openKMSSession(st) {
		if c.drainKmsg(st) {
			return
		}
		// Read/open failure — drop the session; the dmesg fallback
		// covers this tick and kmsg is retried next tick.
		c.closeKMSSession(st)
	}
	c.drainDmesg(st)
}

// openKMSSession tries the kmsgDevicePaths candidates and parks the
// first openable fd on the state.
func (c *Collector) openKMSSession(st *w10KernelState) bool {
	for _, p := range kmsgDevicePaths(c.cfg.HostRoot) {
		f, err := os.OpenFile(p,
			os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err != nil {
			continue
		}
		st.sess = &w10KMSSession{f: f}
		return true
	}
	return false
}

func (c *Collector) closeKMSSession(st *w10KernelState) {
	if st.sess != nil {
		_ = st.sess.f.Close()
		st.sess = nil
	}
}

// drainKmsg reads every record the kernel currently offers (bounded
// by kmsgDrainCap), classifies the new ones and advances the cursor.
// Returns false when the fd itself fails — the caller falls back.
func (c *Collector) drainKmsg(st *w10KernelState) bool {
	sess := st.sess
	cur := c.readKmsgCursor()
	bootID := c.kernelBootID()
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

	recs, maxSeq, maxUsec, err := c.readKmsgAvail(sess)
	if err != nil {
		return false
	}
	if !sess.primed && !resume {
		// First-ever open (or post-reboot): the ring holds the whole
		// retained backlog — history, not news. Discard it and park
		// the position at the tail so only NEW records classify.
		// (A valid resume cursor skips by seq instead — those old
		// records were already processed pre-restart.)
		sess.seq = maxSeq
		sess.primed = true
		c.writeKmsgCursor(&w10KmsgCursor{
			mode: "kmsg", bootID: bootID, seq: sess.seq, usec: maxUsec})
		return true
	}
	sess.primed = true
	for _, r := range recs {
		if resume && (!r.parsed || r.seq <= minSeq) {
			continue
		}
		c.classifyKernelLine(r.msg, st)
	}
	// Advance the persisted position past everything consumed —
	// including records skipped by the resume filter.
	newSeq := sess.seq
	if maxSeq > newSeq {
		newSeq = maxSeq
	}
	if newSeq > 0 || resume {
		c.writeKmsgCursor(&w10KmsgCursor{
			mode: "kmsg", bootID: bootID, seq: newSeq, usec: maxUsec})
	}
	return true
}

// readKmsgAvail drains the fd until EAGAIN/EOF/cap, carrying a
// partial trailing line in sess.pending. Returns the parsed records
// plus the highest seq/usec seen (0 when nothing parsed).
func (c *Collector) readKmsgAvail(sess *w10KMSSession) (
	[]w10KmsgRec, uint64, int64, error) {
	data := sess.pending
	sess.pending = nil
	buf := make([]byte, 32*1024)
	for len(data) < kmsgDrainCap {
		n, err := sess.f.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
		}
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) ||
				errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
				break
			}
			if n == 0 {
				return nil, 0, 0, err
			}
			break // delivered bytes + a sticky error — keep them
		}
		if n == 0 {
			break
		}
	}
	var recs []w10KmsgRec
	var maxSeq uint64
	var maxUsec int64
	for {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			break
		}
		line := string(data[:i])
		data = data[i+1:]
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
			recs = append(recs, w10KmsgRec{msg: line})
		}
	}
	if len(data) > kmsgMaxPending {
		// A single record can't exceed this sanely — drop the
		// carry rather than grow without bound.
		data = nil
	}
	sess.pending = data
	return recs, maxSeq, maxUsec, nil
}

// classifyKernelLine feeds one kernel message into the detectors.
// Order matters: the oom-kill constraint line is captured as pending
// context for the kill line that follows it.
func (c *Collector) classifyKernelLine(msg string, st *w10KernelState) {
	switch {
	case w10OOMConstraintRe.MatchString(msg):
		st.oomPending = parseW10OOMConstraint(msg)
	case w10OOMKillRe.MatchString(msg):
		c.noteW10OOMKill(msg, st)
	case w10FSErrorRe.MatchString(msg):
		c.noteW10FSError(msg)
	case w10ConntrackFullRe.MatchString(msg):
		c.noteW10ConntrackFull()
	}
}

// parseW10OOMConstraint extracts the memcg + task fields from an
// "oom-kill:constraint=..." line.
func parseW10OOMConstraint(msg string) *w10OOMCtx {
	ctx := &w10OOMCtx{}
	if m := w10OOMMemcgRe.FindStringSubmatch(msg); m != nil {
		ctx.memcg = m[1]
	}
	if m := w10OOMTaskRe.FindStringSubmatch(msg); m != nil {
		ctx.comm = m[1]
	}
	return ctx
}

// w10HostOOMComm reports whether comm names a host-level daemon —
// the plan's containerd/k0s/kubelet set. comm is TASK_COMM_LEN
// truncated (15 chars), so prefix/substring matching is required.
func w10HostOOMComm(comm string) bool {
	return comm == "kubelet" || strings.HasPrefix(comm, "k0s") ||
		strings.Contains(comm, "containerd")
}

// noteW10OOMKill classifies one "Out of memory: Killed process"
// record: host-level when the victim's memcg sits OUTSIDE the
// kubepods hierarchy, or the victim comm is a host daemon
// (containerd/k0s/kubelet). Pod-cgroup kills are routine kubelet
// eviction traffic — they must not fire SystemOOMVictim.
func (c *Collector) noteW10OOMKill(msg string, st *w10KernelState) {
	m := w10OOMKillRe.FindStringSubmatch(msg)
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
	if w10HostOOMComm(comm) || (ctx != nil && w10HostOOMComm(ctx.comm)) {
		host = true
	}
	if !host {
		return
	}
	c.bumpW10Counter(w10KmsgOOMCountFile)
	now := c.cfg.nowFn()
	p := c.w10StatePath(w10KmsgOOMVictimFile)
	content := strconv.FormatInt(now.Unix(), 10) + " " + comm + "\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		logger().Warn("hostmetrics: host-oom victim marker write failed",
			"path", p, "error", err)
	}
	logger().Warn("hostmetrics: host-level OOM kill observed",
		"comm", comm, "memcg", ctxMemcg(ctx))
}

func ctxMemcg(ctx *w10OOMCtx) string {
	if ctx == nil {
		return ""
	}
	return ctx.memcg
}

// noteW10FSError records the latest kernel filesystem/block error —
// updateFSReadonlyW10 turns a fresh marker into state-fs-readonly.
func (c *Collector) noteW10FSError(msg string) {
	detail := msg
	if len(detail) > 200 {
		detail = detail[:200]
	}
	p := c.w10StatePath(w10KmsgFSErrorFile)
	content := strconv.FormatInt(c.cfg.nowFn().Unix(), 10) + " " +
		detail + "\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		logger().Warn("hostmetrics: kmsg fs-error marker write failed",
			"path", p, "error", err)
	}
}

// noteW10ConntrackFull counts table-full records and — bounded by
// the rate budget + ceiling — doubles nf_conntrack_max so the table
// stops dropping packets. A failed sysctl write is a Warn, never
// fatal (read-only /proc/sys in unprivileged pods just logs).
func (c *Collector) noteW10ConntrackFull() {
	c.bumpW10Counter(w10KmsgCtDropsFile)
	c.maybeBumpConntrackMax()
}

// bumpW10Counter increments a decimal counter file in the state dir
// and returns the new value (missing/corrupt → starts at 1).
func (c *Collector) bumpW10Counter(name string) int64 {
	p := c.w10StatePath(name)
	var n int64 = 1
	if b, err := os.ReadFile(p); err == nil {
		if v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil {
			n = v + 1
		}
	}
	if err := os.WriteFile(p,
		[]byte(strconv.FormatInt(n, 10)+"\n"), 0o644); err != nil {
		logger().Debug("hostmetrics: kmsg counter write failed",
			"file", name, "error", err)
	}
	return n
}

// maybeBumpConntrackMax doubles ConntrackMaxFile when a table-full
// record lands — rate-limited and ceiling-capped. The write targets
// the sysctl path directly; containerized agents without a writable
// /proc/sys get a Warn and move on.
func (c *Collector) maybeBumpConntrackMax() {
	if !c.w10RateOK(w10ConntrackBumpFile, conntrackBumpEvery) {
		return
	}
	cur, ok := readUintFile(c.cfg.ConntrackMaxFile)
	if !ok || cur == 0 || cur >= conntrackMaxCeiling {
		return
	}
	next := cur * 2
	if next > conntrackMaxCeiling {
		next = conntrackMaxCeiling
	}
	if err := os.WriteFile(c.cfg.ConntrackMaxFile,
		[]byte(strconv.FormatUint(next, 10)+"\n"), 0o644); err != nil {
		logger().Warn("hostmetrics: nf_conntrack_max bump failed",
			"path", c.cfg.ConntrackMaxFile, "error", err)
		return
	}
	c.w10RateSpend(w10ConntrackBumpFile)
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
func (c *Collector) drainDmesg(st *w10KernelState) {
	out, err := w10RunCmd(context.Background(), "dmesg", "-T")
	mode := "dmesgT"
	if err != nil {
		out, err = w10RunCmd(context.Background(), "dmesg")
		mode = "dmesgRaw"
	}
	if err != nil {
		// No kernel-log access at all — inconclusive, not an error.
		return
	}
	lines := strings.Split(out, "\n")
	cur := c.readKmsgCursor()
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
				c.writeKmsgCursor(&w10KmsgCursor{
					mode: "dmesgT", unixTs: newest, lines: atNewest})
			}
		default:
			c.writeKmsgCursor(&w10KmsgCursor{
				mode: "dmesgRaw", lines: len(lines),
				hash: w10DmesgTailHash(lines)})
		}
		return
	}
	var fresh []string
	var maxTs int64
	switch mode {
	case "dmesgT":
		lastTs := cur.unixTs
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
			if ts > lastTs {
				fresh = append(fresh, dmesgMessage(ln))
				if ts > maxTs {
					maxTs = ts
					atMax = 0
				}
				if ts == maxTs {
					atMax++
				}
			} else if ts == lastTs {
				atLast++
				if atLast > pending {
					fresh = append(fresh, dmesgMessage(ln))
				}
			}
		}
		switch {
		case maxTs > 0:
			c.writeKmsgCursor(&w10KmsgCursor{
				mode: "dmesgT", unixTs: maxTs, lines: atMax})
		case atLast > pending:
			// Only same-second arrivals — advance the consumed
			// count so they aren't reprocessed next tick.
			c.writeKmsgCursor(&w10KmsgCursor{
				mode: "dmesgT", unixTs: lastTs, lines: atLast})
		}
	default: // dmesgRaw — content-anchored, see drainDmesg doc.
		trimmed := lines
		for len(trimmed) > 0 && trimmed[len(trimmed)-1] == "" {
			trimmed = trimmed[:len(trimmed)-1]
		}
		if len(trimmed) == 0 {
			break
		}
		tail := w10LineHash(trimmed[len(trimmed)-1])
		anchor := -1
		if cur.hash != 0 {
			for i := len(trimmed) - 1; i >= 0; i-- {
				if w10LineHash(trimmed[i]) == cur.hash {
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
			c.writeKmsgCursor(&w10KmsgCursor{
				mode: "dmesgRaw", lines: len(lines), hash: tail})
			break
		}
		fresh = trimmed[anchor+1:]
		c.writeKmsgCursor(&w10KmsgCursor{
			mode: "dmesgRaw", lines: len(lines), hash: tail})
	}
	for _, msg := range fresh {
		if msg == "" {
			continue
		}
		c.classifyKernelLine(msg, st)
	}
}

// w10LineHash fingerprints one dmesg output line for the cursor
// anchor — fnv-1a, collision odds are irrelevant at ring sizes.
func w10LineHash(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

// w10DmesgTailHash hashes the last non-empty dmesg line — the anchor
// the next drain resumes after. 0 when output is empty.
func w10DmesgTailHash(lines []string) uint64 {
	for i := len(lines) - 1; i >= 0; i-- {
		if lines[i] != "" {
			return w10LineHash(lines[i])
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

// --- W10-KR2: pid/thread/fd exhaustion ---

// kernelProcRatios computes the three utilization ratios the
// state-pid-fd-pressure latch and the node_agent_* textfile gauges
// share:
//
//	pids    — live /proc/<pid> dirs / pid_max
//	threads — loadavg "running/total" entities / threads-max
//	filefd  — file-nr allocated / max
//
// Each ratio carries its own ok flag — a source that didn't parse
// must not emit a fake 0 gauge (the collectFileFD rule); ok=false
// overall means NO source parsed — inconclusive evidence must not
// move the latch (the kernelKeysUsedRatio rule).
func (c *Collector) kernelProcRatios() (pids, threads, filefd float64,
	pidsOK, threadsOK, fdOK, ok bool) {
	seen := false
	if entries, err := os.ReadDir(c.cfg.ProcRoot); err == nil {
		tasks := 0
		for _, e := range entries {
			if e.IsDir() && pidDirRe.MatchString(e.Name()) {
				tasks++
			}
		}
		if max, mok := c.readProcFloat("sys/kernel/pid_max"); mok && max > 0 {
			pids, pidsOK, seen = float64(tasks)/max, true, true
		}
	}
	if b, err := os.ReadFile(filepath.Join(c.cfg.ProcRoot, "loadavg")); err == nil {
		if f := strings.Fields(string(b)); len(f) >= 4 {
			if pair := strings.Split(f[3], "/"); len(pair) == 2 {
				if total, err := strconv.ParseFloat(pair[1], 64); err == nil {
					if max, mok := c.readProcFloat("sys/kernel/threads-max"); mok && max > 0 {
						threads, threadsOK, seen = total/max, true, true
					}
				}
			}
		}
	}
	if b, err := os.ReadFile(c.cfg.FileNRFile); err == nil {
		if f := strings.Fields(string(b)); len(f) >= 3 {
			alloc, errA := strconv.ParseFloat(f[0], 64)
			max, errM := strconv.ParseFloat(f[2], 64)
			if errA == nil && errM == nil && max > 0 {
				filefd, fdOK, seen = alloc/max, true, true
			}
		}
	}
	return pids, threads, filefd, pidsOK, threadsOK, fdOK, seen
}

// readProcFloat reads one numeric file under ProcRoot.
func (c *Collector) readProcFloat(elem string) (float64, bool) {
	b, err := os.ReadFile(filepath.Join(c.cfg.ProcRoot, elem))
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// updatePidFDPressure drives state-pid-fd-pressure (W10-KR2 →
// KernelResourceExhaustion): the WORST of the pid/thread/fd ratios
// above 0.90 for kernelProcPressureNeeded consecutive latch ticks.
// The count persists in the state dir so an agent restart keeps the
// streak; any sub-threshold or inconclusive-free tick resets it.
// The node_agent_*_utilization_ratio gauges ride the same evaluation
// into the node-exporter textfile.
func (c *Collector) updatePidFDPressure() {
	pids, threads, filefd, pidsOK, threadsOK, fdOK, ok := c.kernelProcRatios()
	if !ok {
		return // inconclusive — leave count, latch and gauges alone
	}
	c.writeW10KernelProm(pids, threads, filefd, pidsOK, threadsOK, fdOK)
	worst, what := -1.0, ""
	for _, r := range []struct {
		v    float64
		ok   bool
		name string
	}{{pids, pidsOK, "pids"}, {threads, threadsOK, "threads"}, {filefd, fdOK, "file-nr"}} {
		if r.ok && r.v > worst {
			worst, what = r.v, r.name
		}
	}
	countPath := c.w10StatePath(w10PidFDCountFile)
	latchPath := c.w10StatePath("state-pid-fd-pressure")
	if worst > kernelProcPressureRatio {
		n := int64(1)
		if b, err := os.ReadFile(countPath); err == nil {
			if v, perr := strconv.ParseInt(
				strings.TrimSpace(string(b)), 10, 64); perr == nil {
				n = v + 1
			}
		}
		if err := os.WriteFile(countPath,
			[]byte(strconv.FormatInt(n, 10)+"\n"), 0o644); err != nil {
			logger().Debug("hostmetrics: pid-fd count write failed",
				"path", countPath, "error", err)
		}
		if n >= kernelProcPressureNeeded {
			c.ensureW10Latch(latchPath, "state-pid-fd-pressure",
				fmt.Sprintf("%s ratio=%.3f", what, worst))
		} else if _, err := os.Stat(latchPath); err == nil {
			// A latch from an earlier episode outliving a fresh
			// sub-threshold streak can't happen (the else branch
			// clears it) — remove defensively anyway.
			_ = os.Remove(latchPath)
		}
		return
	}
	// Below threshold — reset the streak and release the latch.
	_ = os.Remove(countPath)
	if _, err := os.Stat(latchPath); err == nil {
		if rerr := os.Remove(latchPath); rerr != nil {
			logger().Warn("hostmetrics: pid-fd-pressure latch remove failed",
				"path", latchPath, "error", rerr)
		} else {
			logger().Info("hostmetrics: pid-fd-pressure latch cleared",
				"worst", what, "ratio", worst, "path", latchPath)
		}
	}
}

// ensureW10Latch installs a state latch when absent (epoch content,
// atomic tmp+rename — the updateKernelKeysLatch pattern) and logs
// the transition once; BUG-H6's refresh loop owns the mtime while
// held.
func (c *Collector) ensureW10Latch(path, name, evidence string) {
	if _, err := os.Stat(path); err == nil {
		return
	}
	content := strconv.FormatInt(c.cfg.nowFn().Unix(), 10) + "\n"
	tmp := filepath.Join(filepath.Dir(path), ".tmp-"+filepath.Base(path))
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		logger().Warn("hostmetrics: "+name+" latch write failed",
			"path", path, "error", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		logger().Warn("hostmetrics: "+name+" latch install failed",
			"path", path, "error", err)
		return
	}
	logger().Warn("hostmetrics: "+name+" latch set — "+evidence,
		"path", path)
}

// --- W10-KR5: clock skew ---

// clockSkewProbe returns (offsetSeconds, synchronized, ok). Primary
// source is `chronyc tracking` — its "System time" offset is the
// measured skew and "Leap status" the sync verdict. Fallback is a
// read-only adjtimex: Timex.Offset (µs) is the kernel's offset
// estimate and STA_UNSYNC the sync verdict — enough to makestep and
// (when the estimate exceeds 2s) to latch.
func (c *Collector) clockSkewProbe() (float64, bool, bool) {
	out, err := w10RunCmd(context.Background(), "chronyc", "tracking")
	if err == nil {
		if off, synced, ok := parseChronycTracking(out); ok {
			return off, synced, true
		}
	}
	var tx unix.Timex
	if _, err := c.cfg.adjtimexFn(&tx); err != nil {
		return 0, false, false
	}
	return float64(tx.Offset) / 1e6,
		tx.Status&unix.STA_UNSYNC == 0, true
}

// chronycSystemTimeRe parses "System time     : 0.0012 seconds fast
// of NTP time" — signed seconds, fast positive.
var chronycSystemTimeRe = regexp.MustCompile(
	`System time\s*:\s*([0-9.]+)\s+seconds\s+(fast|slow)`)

// parseChronycTracking extracts offset + sync state; ok=false when
// the output lacks the expected fields (wrong chronyc version,
// partial capture).
func parseChronycTracking(out string) (float64, bool, bool) {
	var off float64
	found := false
	for _, ln := range strings.Split(out, "\n") {
		if m := chronycSystemTimeRe.FindStringSubmatch(ln); m != nil {
			v, err := strconv.ParseFloat(m[1], 64)
			if err != nil {
				continue
			}
			if m[2] == "slow" {
				v = -v
			}
			off, found = v, true
		}
	}
	if !found {
		return 0, false, false
	}
	synced := !strings.Contains(out, "Not synchronised")
	return off, synced, true
}

// checkClockSkewW10 drives state-clock-skew (W10-KR5 →
// ClockSkewDetected): |offset| > 2.0s for clockSkewLatchNeeded
// consecutive ticks. A >0.5s offset OR an unsynchronised clock earns
// a `chronyc makestep` — rate-limited to one per 10m. Inconclusive
// probes (no chronyc, adjtimex failure) leave count+latch alone.
func (c *Collector) checkClockSkewW10() {
	off, synced, ok := c.clockSkewProbe()
	if !ok {
		return
	}
	if (!synced || math.Abs(off) > clockSkewStepOffset) &&
		c.w10RateTrySpend(w10ClockStepFile, clockSkewMakestepGap) {
		out, err := w10RunCmd(context.Background(), "chronyc", "makestep")
		if err != nil {
			logger().Warn("hostmetrics: chronyc makestep failed",
				"error", err, "out", strings.TrimSpace(out))
		} else {
			logger().Warn("hostmetrics: ACTION chronyc makestep — "+
				"clock offset beyond step threshold",
				"offset", off, "synced", synced)
		}
	}
	countPath := c.w10StatePath(w10ClockSkewCountFile)
	latchPath := c.w10StatePath("state-clock-skew")
	if math.Abs(off) > clockSkewLatchOffset {
		n := int64(1)
		if b, err := os.ReadFile(countPath); err == nil {
			if v, perr := strconv.ParseInt(
				strings.TrimSpace(string(b)), 10, 64); perr == nil {
				n = v + 1
			}
		}
		if err := os.WriteFile(countPath,
			[]byte(strconv.FormatInt(n, 10)+"\n"), 0o644); err != nil {
			logger().Debug("hostmetrics: clock-skew count write failed",
				"path", countPath, "error", err)
		}
		if n >= clockSkewLatchNeeded {
			c.ensureW10Latch(latchPath, "state-clock-skew",
				fmt.Sprintf("offset=%.3fs synced=%v", off, synced))
		}
		return
	}
	_ = os.Remove(countPath)
	if _, err := os.Stat(latchPath); err == nil {
		if rerr := os.Remove(latchPath); rerr != nil {
			logger().Warn("hostmetrics: clock-skew latch remove failed",
				"path", latchPath, "error", rerr)
		} else {
			logger().Info("hostmetrics: clock-skew latch cleared",
				"offset", off, "path", latchPath)
		}
	}
}

// --- W10-ST1: read-only mounts under PVC dirs ---

// w10FSTypes are the journaled filesystems a PVC backing mount
// realistically uses — the plan's ext4/xfs plus btrfs (same failure
// class, same ro-remount signature).
var w10FSTypes = map[string]bool{
	"ext4": true, "xfs": true, "btrfs": true,
}

// w10ROExcludeRe filters the EXPECTED read-only binds Kubernetes
// creates under pod volume dirs — configmap/secret/projected/
// downwardapi/serviceaccount mounts are ro by design and must never
// count as filesystem faults.
var w10ROExcludeRe = regexp.MustCompile(
	`kubernetes\.io~(configmap|secret|projected|downwardapi)|` +
		`kubernetes\.io/serviceaccount`)

// w10Mount is one parsed /proc/*/mounts line.
type w10Mount struct {
	mp     string
	fstype string
	src    string
	ro     bool
}

// parseProcMountsW10 parses mount-table content —
// "src mp fstype opts dump pass" per line, octal escapes ignored
// (mountpoints with spaces are rare under the PVC roots and a
// missed escape only narrows matching, never widens it).
func parseProcMountsW10(data []byte) []w10Mount {
	var out []w10Mount
	for _, ln := range strings.Split(string(data), "\n") {
		f := strings.Fields(ln)
		if len(f) < 4 {
			continue
		}
		opts := strings.Split(f[3], ",")
		m := w10Mount{src: f[0], mp: f[1], fstype: f[2]}
		for _, o := range opts {
			if o == "ro" {
				m.ro = true
			}
		}
		out = append(out, m)
	}
	return out
}

// pvcMountRoots returns the host-side roots whose submounts are PVC
// backing volumes — OpenEBS LocalPV, local-path-provisioner, and the
// kubelet pods dir (hostPath + PVC bind mounts alike). The mount
// table reports HOST paths, so these are literal host paths —
// OpenEBSLocalDir already follows that convention.
func (c *Collector) pvcMountRoots() []string {
	return []string{
		c.cfg.OpenEBSLocalDir,
		"/opt/local-path-provisioner",
		"/var/lib/k0s/kubelet/pods",
	}
}

// roPVCMounts returns "mp (fstype)" for every ro ext4/xfs/btrfs
// mount under a PVC root that isn't an expected Kubernetes ro bind.
func (c *Collector) roPVCMounts() []string {
	// /proc/1/mounts is the host mount table under hostPID (the
	// DaemonSet contract); ProcRoot/mounts covers odd layouts.
	var data []byte
	var err error
	for _, p := range []string{
		filepath.Join(c.cfg.ProcRoot, "1", "mounts"),
		filepath.Join(c.cfg.ProcRoot, "mounts"),
	} {
		if data, err = os.ReadFile(p); err == nil {
			break
		}
	}
	if err != nil {
		return nil
	}
	roots := c.pvcMountRoots()
	var out []string
	for _, m := range parseProcMountsW10(data) {
		if !m.ro || !w10FSTypes[m.fstype] {
			continue
		}
		under := false
		for _, r := range roots {
			if r == "" {
				continue
			}
			if m.mp == r || strings.HasPrefix(m.mp, r+"/") {
				under = true
				break
			}
		}
		if !under {
			continue
		}
		if w10ROExcludeRe.MatchString(m.mp) ||
			w10ROExcludeRe.MatchString(m.src) {
			continue
		}
		out = append(out, m.mp+" ("+m.fstype+")")
	}
	return out
}

// updateFSReadonlyW10 drives state-fs-readonly — the Wave-10
// evidence latch feeding FilesystemReadOnly. Two evidence sources,
// either sufficient:
//
//   - a kmsg-fs-error marker younger than fsErrorLatchTTL (kernel
//     saw a filesystem/block error — the fs may already be remounted
//     ro or heading there), and
//   - an ro ext4/xfs/btrfs mount under a PVC root in the host mount
//     table (W10-ST1 — catches the remount statfs hasn't probed).
//
// The latch clears only when BOTH evidences are absent; an
// unreadable mounts file contributes nothing (fail-safe, not
// fail-latch).
func (c *Collector) updateFSReadonlyW10() {
	p := c.w10StatePath("state-fs-readonly")
	_, lerr := os.Stat(p)
	evidence := ""
	if b, err := os.ReadFile(c.w10StatePath(w10KmsgFSErrorFile)); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if epoch, perr := strconv.ParseInt(f[0], 10, 64); perr == nil {
				age := c.cfg.nowFn().Unix() - epoch
				if age >= 0 && age < int64(fsErrorLatchTTL.Seconds()) {
					evidence = "kernel-fs-error"
				} else {
					_ = os.Remove(c.w10StatePath(w10KmsgFSErrorFile))
				}
			}
		}
	}
	if ros := c.roPVCMounts(); len(ros) > 0 {
		if evidence != "" {
			evidence += " + "
		}
		evidence += "ro-mount: " + strings.Join(ros, ", ")
	}
	switch {
	case evidence != "" && lerr != nil:
		c.ensureW10Latch(p, "state-fs-readonly", evidence)
	case evidence == "" && lerr == nil:
		if rerr := os.Remove(p); rerr != nil {
			logger().Warn("hostmetrics: fs-readonly latch remove failed",
				"path", p, "error", rerr)
		} else {
			logger().Info("hostmetrics: fs-readonly latch cleared — "+
				"no fresh kernel fs errors, no ro PVC mounts",
				"path", p)
		}
	}
}

// --- W10 textfile metrics (node-exporter channel) ---

// w10TextfileDir resolves the node-exporter textfile drop dir —
// <HostRoot>/var/lib/node-exporter/textfile (controllerhygiene's
// wave10TextfileDir parity: K0sDir's sibling under the same
// convention).
func (c *Collector) w10TextfileDir() string {
	if w10TextfileDirOverride != "" {
		return w10TextfileDirOverride
	}
	return filepath.Join(c.cfg.HostRoot,
		"var", "lib", "node-exporter", "textfile")
}

// writeW10Prom atomically installs content as <dir>/<name> — tmp +
// rename so node_exporter never reads a partial file (the .tmp
// suffix stays outside its *.prom glob). Failures log at Debug:
// refreshLatches runs every 30s and an unwritable mount must not
// spam the watchdog tail.
func (c *Collector) writeW10Prom(name, content string) {
	dir := c.w10TextfileDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		logger().Debug("hostmetrics: wave10 textfile mkdir failed",
			"dir", dir, "error", err)
		return
	}
	tmp := filepath.Join(dir, "."+name+".tmp")
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		logger().Debug("hostmetrics: wave10 textfile write failed",
			"path", tmp, "error", err)
		return
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		logger().Debug("hostmetrics: wave10 textfile install failed",
			"dir", dir, "error", err)
	}
}

// writeW10KernelProm emits the W10-KR2 utilization gauges —
// node_agent_{pids,threads,file_nr}_utilization_ratio. Each series
// appears only when its source parsed (no fake 0s — the
// collectFileFD rule).
func (c *Collector) writeW10KernelProm(pids, threads, filefd float64,
	pidsOK, threadsOK, fdOK bool) {
	var b strings.Builder
	gauge := func(name, help string, v float64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s %s\n",
			name, help, name, name,
			strconv.FormatFloat(v, 'f', -1, 64))
	}
	if pidsOK {
		gauge("node_agent_pids_utilization_ratio",
			"Live /proc pid dirs over kernel.pid_max.", pids)
	}
	if threadsOK {
		gauge("node_agent_threads_utilization_ratio",
			"loadavg total entities over kernel.threads-max.", threads)
	}
	if fdOK {
		gauge("node_agent_file_nr_utilization_ratio",
			"file-nr allocated over maximum — fd table pressure.", filefd)
	}
	c.writeW10Prom("node-agent-kernel.prom", b.String())
}

// --- small Wave-10 helpers (uniquely named per file rules) ---

// w10RateOK reports whether the rate budget file is absent,
// unparseable, or older than d — the workerhygiene rateOK parity.
func (c *Collector) w10RateOK(name string, d time.Duration) bool {
	b, err := os.ReadFile(c.w10StatePath(name))
	if err != nil {
		return true
	}
	last, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return true
	}
	return c.cfg.nowFn().Unix()-last >= int64(d.Seconds())
}

// w10RateSpend writes the current epoch to the budget file.
func (c *Collector) w10RateSpend(name string) {
	p := c.w10StatePath(name)
	content := strconv.FormatInt(c.cfg.nowFn().Unix(), 10) + "\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		logger().Debug("hostmetrics: wave10 rate spend write failed",
			"budget", name, "error", err)
	}
}

// w10RateTrySpend is the atomic check+spend — the chronyc makestep
// budget must not double-fire across overlapping latch ticks.
func (c *Collector) w10RateTrySpend(name string, d time.Duration) bool {
	// Latch ticks are single-goroutine (Run's ticker); the file
	// check+write is short enough that a mutex buys nothing — keep
	// the workerhygiene file-budget semantics without the lock.
	if !c.w10RateOK(name, d) {
		return false
	}
	c.w10RateSpend(name)
	return true
}
