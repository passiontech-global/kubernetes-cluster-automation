// Watchdog log tailing → Kubernetes Events + problem_counter.
//
// Ported 1:1 from the removed watchdog-filelog-monitor.json: the same
// pattern→reason rules applied to the same log file. The NPD filelog
// plugin stripped the leading timestamp token (pluginConfig
// message="^\S+\s+(.*)$") and effectively anchored each pattern at
// end-of-buffer, which is why every JSON pattern ended in ".*" — a
// plain unanchored regex per complete line is the exact equivalent.
//
// Every matched line bumps problem_counter{reason} (NPD parity — one
// increment per match, aggregation doesn't undercount). The Event
// object is deduplicated: an identical reason+message inside
// EventDedupTTL aggregates into the existing Event's series
// (count++ / lastObservedTime) via merge-patch instead of creating a
// new object.
package nodereporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// logRule is one temporary filelog rule — reason → K8s Event reason +
// problem_counter label, pattern → unanchored match on the message
// part of a log line.
type logRule struct {
	reason string
	re     *regexp.Regexp
}

// logRules is the watchdog-filelog-monitor.json rules array, in order.
//
// Derivation contract: whenever an in-repo emitter writes the line a
// rule matches, the rule is BUILT from the shared latchdefs protocol
// constant (QuoteMeta / StateEnterRe / ActionEntryRe) — rewording the
// emitter is then a compile error at the emitter's own site and the
// rule follows automatically, so drift cannot strand an Event.
// Alternations matching lines nothing in this repo writes anymore
// (retired lib.sh shell modules, kernel/kubelet lines the old
// watchdog copied into the log) stay literal and are documented per
// entry — they must keep matching the retained legacy log lines.
var logRules = []logRule{
	// overlay_egress.go writes "overlay-egress unreachable"; the
	// "tinc" spelling is retired lib.sh vocabulary retained logs
	// still carry.
	{"TincEgressUnreachable", regexp.MustCompile(`(?:tinc|overlay)-egress unreachable`)},
	// overlay_egress.go writes the head from latchdefs.ActionEgress
	// ("ACTION: egress <ip> -> overlay relay table N (...)"); the
	// "tinc relay" spelling is retired lib.sh vocabulary.
	{"TincEgressFailover", regexp.MustCompile(
		regexp.QuoteMeta(latchdefs.ActionEgress) + `[0-9.]+ -> (?:tinc|overlay) relay`)},
	// hostmetrics' PSI latch writes "node-overloaded"
	// (latchdefs.LatchNodeOverloaded); "node overloaded" is retired
	// lib.sh wording.
	{nodecond.NodeOverloaded, regexp.MustCompile(`node[- ]overloaded`)},
	{"K0sworkerRestarted", regexp.MustCompile(regexp.QuoteMeta(latchdefs.ActionK0sworkerRestart))},
	{"KubeletInformerZombie", regexp.MustCompile(regexp.QuoteMeta(latchdefs.ReasonInformerZombie))},
	{"KubeletPhantomPods", regexp.MustCompile(regexp.QuoteMeta(latchdefs.ReasonPhantomPods))},
	// "ctr-task-wedged" is ctr_tasks.go's suspect keyword
	// (latchdefs.ReasonCtrTaskWedged); the other two alternations are
	// the retired shell's remediation wording.
	{"CtrTaskWedged", regexp.MustCompile(
		regexp.QuoteMeta(latchdefs.ReasonCtrTaskWedged) +
			`|ctr tasks delete|orphaned task dir`)},
	{"KonnectivityStaleId", regexp.MustCompile(
		regexp.QuoteMeta(latchdefs.ReasonKonnectivityStaleID) + `|` +
			regexp.QuoteMeta(latchdefs.ReasonKonnectivityAgentRecreate))},
	{"TincEgressRecovered", regexp.MustCompile(
		regexp.QuoteMeta(latchdefs.ActionEgress) + `[0-9.]+ -> direct underlay`)},
	{"TincEgressHeal", regexp.MustCompile(regexp.QuoteMeta(latchdefs.ActionEgressHeal))},
	{"NebulaRestarted", regexp.MustCompile(regexp.QuoteMeta(latchdefs.ActionNebulaRestart))},
	{"NebulaIsolatedEnter", latchdefs.StateEnterRe(latchdefs.LatchNebulaIsolated)},
	{"NebulaDataplaneDegraded", regexp.MustCompile(regexp.QuoteMeta(latchdefs.ReasonNebulaDataplaneDegraded))},
	{"NebulaSlowPath", regexp.MustCompile(regexp.QuoteMeta(latchdefs.ReasonNebulaDataplaneSlowpath))},
	{"NebulaSiteEdge", regexp.MustCompile(regexp.QuoteMeta(latchdefs.ReasonNebulaSiteedgeDegraded))},
	{"NebulaCertExpiring", regexp.MustCompile(regexp.QuoteMeta(latchdefs.LatchNebulaCertExpiring))},
	// WatchdogRunFailed: emitted by the retired lib.sh runner — no
	// in-repo producer.
	{"WatchdogRunFailed", regexp.MustCompile(`WATCHDOG-FAILED`)},
	// WatchdogModuleFailed: STATE-ENTER lines of the retired shell's
	// per-module failure latches ("module-failed-<id>-<name>") — the
	// prefix derives from the shared StateEnterPrefix; the
	// module-failed vocabulary has no in-repo producer.
	{"WatchdogModuleFailed", regexp.MustCompile(latchdefs.StateEnterPrefix + "module-failed-")},
	// The cilium-agent-down latch plus the "killed cilium-agent" half
	// of latchdefs.ActionCiliumAgentKill — kept at the shorter legacy
	// form, because the retired shell killed the agent without the
	// " container -" tail those lines must still match.
	{nodecond.CiliumAgentDown, regexp.MustCompile(
		regexp.QuoteMeta(latchdefs.LatchCiliumAgentDown) + `|` +
			regexp.QuoteMeta(strings.TrimPrefix(latchdefs.ActionCiliumAgentKill, latchdefs.ActionPrefix)))},
	{nodecond.KubeletRuntimeStall, regexp.MustCompile(regexp.QuoteMeta(latchdefs.LatchKubeletRuntimeStall))},
	{nodecond.DNSResolvStale, regexp.MustCompile(regexp.QuoteMeta(latchdefs.LatchDNSResolvStale))},
	{"StuckPodForceDeleted", regexp.MustCompile(regexp.QuoteMeta(latchdefs.ReasonForceDeletePod))},
	{nodecond.PodTeardownWedged, regexp.MustCompile(regexp.QuoteMeta(latchdefs.LatchPodTeardownWedged))},
	// The remediation half derives from ClockRestartUnits — the same
	// slice clock.go (and nebula_health.go's timesyncd latch line)
	// restarts from.
	{nodecond.ClockUnsynchronized, regexp.MustCompile(
		latchdefs.StateEnterRe(latchdefs.LatchClockUnsync).String() +
			`|` + latchdefs.ActionClockRestartRe().String())},
	// The nf_conntrack halves match kernel dmesg lines the retired
	// shell copied into the watchdog log — the kernel is the
	// producer, there is no in-repo wording to share.
	{nodecond.ConntrackPressure, regexp.MustCompile(
		latchdefs.StateEnterRe(latchdefs.LatchConntrackPressure).String() +
			`|nf_conntrack.*table full`)},
	// "no more IPs available" is kubelet's FailedCreatePodSandBox
	// wording — an external producer.
	{nodecond.CiliumIPAMExhausted, regexp.MustCompile(
		latchdefs.StateEnterRe(latchdefs.LatchCiliumIPAMExhausted).String() +
			`|no more IPs available`)},
	{"CorruptedImageRemoved", regexp.MustCompile(regexp.QuoteMeta(latchdefs.ActionCorruptedImageRemove))},
	{"ZombieProcessStorm", latchdefs.ActionEntryRe(latchdefs.LatchZombieStorm)},
	{"CiliumMTUExceedsOverlay", latchdefs.ActionEntryRe(latchdefs.LatchCiliumMTUDrift)},
	// cilium-wg-peer-gc: workerhygiene's cilium WireGuard peer-gc drift healer —
	// "ACTION: killed cilium-agent container - cilium_wg0 has N
	// allowed-ip peers while expected M".
	{"CiliumWireGuardPeerDrift", regexp.MustCompile(regexp.QuoteMeta(latchdefs.ActionCiliumWGKill))},
	// disk-bloat: disk-bloat runaway detector —
	// "ACTION disk-bloat: target=... bytes=... used_pct=...".
	// (nodecond constant — DiskBloatRunaway is now a condition name;
	// the reason string is unchanged.)
	{nodecond.DiskBloatRunaway, latchdefs.ActionEntryRe(latchdefs.LatchDiskBloat)},
	// journalwatch blindness latch — STATE-ENTER only (one event per
	// latch entry; the suspect:* line carrying the same detail is a
	// throttled re-reminder, matching it too would double-count).
	{nodecond.JournaldUnreadable, latchdefs.StateEnterRe(latchdefs.LatchJournalUnreadable)},
	// d-state-storm: workerhygiene's d-state-storm latch-entry line —
	// "ACTION d-state-storm: count=N runtime=M wchan=...".
	{nodecond.KernelHungTasks, latchdefs.ActionEntryRe(latchdefs.LatchDStateStorm)},
	// --- infra latch→event surface ---
	// One Event per STATE-ENTER of a latch that maps to a permanent
	// NodeCondition (conditions.go). Latches already covered by an
	// older rule (nebula-isolated → NebulaIsolatedEnter,
	// conntrack-pressure → ConntrackPressure, cilium-ipam-exhausted
	// → CiliumIPAMExhausted) are intentionally not duplicated.
	{nodecond.NebulaDegraded, latchdefs.StateEnterRe(latchdefs.LatchNebulaDegraded)},
	{nodecond.CiliumEnvoyDown, latchdefs.StateEnterRe(latchdefs.LatchCiliumEnvoyDown)},
	{nodecond.CiliumBPFMapPressure, latchdefs.StateEnterRe(latchdefs.LatchCiliumBPFMapPressure)},
	{nodecond.SpegelMirrorDegraded, latchdefs.StateEnterRe(latchdefs.LatchSpegelMirrorDegraded)},
	{nodecond.CalicoVethLeak, latchdefs.StateEnterRe(latchdefs.LatchCalicoVethLeak)},
	{nodecond.CalicoFelixDown, latchdefs.StateEnterRe(latchdefs.LatchCalicoFelixDown)},
	{nodecond.Fail2banDown, latchdefs.StateEnterRe(latchdefs.LatchFail2banDown)},
	{nodecond.KernelKeysPressure, latchdefs.StateEnterRe(latchdefs.LatchKernelKeysPressure)},
	{nodecond.ControlPlaneCertReloadStale, latchdefs.StateEnterRe(latchdefs.LatchCPCertReloadStale)},
	// Clocksource: the kernel clocksource-unstable evidence latch —
	// STATE-ENTER only (one Event per latch entry, like the other
	// infra latch→event rules).
	{nodecond.ClocksourceUnstable, latchdefs.StateEnterRe(latchdefs.LatchClocksourceUnstable)},
	// psi-memory-thrash: workerhygiene's psi-memory-thrash latch-entry line —
	// "ACTION psi-memory-thrash: avg60=... free=...".
	{"NodeMemoryPSIThrashing", latchdefs.ActionEntryRe(latchdefs.LatchPSIMemoryThrash)},
	// --- leak-pressure latch→event surface ---
	// workerhygiene's kernel-slab-leak slab-leak guard + nethealth's overlay-mtu-guard
	// DF PMTU probe — one Event per STATE-ENTER (clock-unsync is
	// already covered by the ClockUnsynchronized rule above).
	{nodecond.KernelSlabLeak, latchdefs.StateEnterRe(latchdefs.LatchKernelSlabLeak)},
	{nodecond.NebulaPMTUBlackhole, latchdefs.StateEnterRe(latchdefs.LatchNebulaPMTUBlackhole)},
	// --- latch→event surface: kernel/host deep-failure + hygiene ---
	// One Event per STATE-ENTER for the remaining registered latches.
	// containerd-corrupt and fs-readonly feed shared conditions via
	// altStateKeys in conditions.go (KubeletRuntimeStall and
	// FilesystemReadOnly respectively); the rest own their condition
	// type 1:1.
	{"ContainerdCorrupt", latchdefs.StateEnterRe(latchdefs.LatchContainerdCorrupt)},
	// FilesystemReadOnly is fed by TWO latches: the filesystem-readonly statfs
	// latch (filesystem-readonly) and the kernelfail evidence latch
	// (fs-readonly) — both registered tokens map to the one reason.
	{nodecond.FilesystemReadOnly, latchdefs.StateEnterRe(
		latchdefs.LatchFSReadonly, latchdefs.LatchFilesystemReadonly)},
	{nodecond.KernelResourceExhaustion, latchdefs.StateEnterRe(latchdefs.LatchPIDFDPressure)},
	{nodecond.ClockSkewDetected, latchdefs.StateEnterRe(latchdefs.LatchClockSkew)},
	{nodecond.KubeconfigCertExpiring, latchdefs.StateEnterRe(latchdefs.LatchKubeconfigCertExpiring)},
	{nodecond.CPUStealPressure, latchdefs.StateEnterRe(latchdefs.LatchCPUStealPressure)},
	{nodecond.CgroupDyingLeak, latchdefs.StateEnterRe(latchdefs.LatchCgroupDyingLeak)},
	{nodecond.SystemdSessionBloat, latchdefs.StateEnterRe(latchdefs.LatchSystemdSessionBloat)},
	// recent-latches latches that had conditions (conditions.go) but no
	// filelog rule — kubelet-pleg-unhealthy and disk-slow-io
	// previously entered without ever emitting an Event.
	{nodecond.KubeletPLEGUnhealthy, latchdefs.StateEnterRe(latchdefs.LatchKubeletPLEGUnhealthy)},
	{nodecond.DiskSlowIO, latchdefs.StateEnterRe(latchdefs.LatchDiskSlowIO)},
	{nodecond.KernelNetShimDegraded, latchdefs.StateEnterRe(latchdefs.LatchKernelNetShim)},
	// inode-pressure: hostmetrics' inode-pressure latch — a Warning on entry
	// (the STATE-ENTER line carries the offending mount + ratio); the
	// clean end of the episode earns an informational Event via
	// exitLogRules below.
	{nodecond.InodePressure, latchdefs.StateEnterRe(latchdefs.LatchInodePressure)},
	// hostmetrics' clock-warp detector line —
	// "ACTION clock-warp: delta=... tick=... (events=N)".
	{"NodeClockWarpDetected", latchdefs.ActionEntryRe(latchdefs.ActionClockWarp)},
	// --- W21 latch→event surface ---
	// The three latches whose producers emit the ACTION-entry line
	// once per episode (the disk-bloat NPD contract shape —
	// ActionEntryPrefix at the Enter site, gated on the latch
	// being absent): cilium-envoy-xds-reject (workerhygiene envoy
	// xDS-NACK streak), nebula-mtu-blackhole (nethealth routeguard
	// NM4 DF-probe blackhole) and page-alloc-failure (hostmetrics
	// kmsg buddy-allocator fragmentation evidence).
	{nodecond.CiliumEnvoyXDSReject, latchdefs.ActionEntryRe(latchdefs.LatchCiliumEnvoyXDSReject)},
	{nodecond.NebulaMTUBlackhole, latchdefs.ActionEntryRe(latchdefs.LatchNebulaMTUBlackhole)},
	{nodecond.KernelPageAllocFailure, latchdefs.ActionEntryRe(latchdefs.LatchPageAllocFailure)},
	// controllerhygiene's sig13 watch-cache wedge latch — one Event
	// per STATE-ENTER (the apiserver serving stale watch-cache data
	// is exactly when cluster-side heals must defer pod churn).
	{nodecond.ApiserverWatchCacheWedged, latchdefs.StateEnterRe(latchdefs.LatchAPIServerCacheWedged)},
}

// exitLogRules — STATE-EXIT lines that earn an informational (Normal)
// Event marking a latch episode's clean end. Entry events live in
// logRules; an exit is recovery, not a problem, so it must not render
// as a Warning. The counter for a matched exit still rides the shared
// problem_counter surface (reason = the episode's healthy reason).
var exitLogRules = []logRule{
	// inode-pressure: inode-pressure cleared — every monitored mount back to
	// <=90% inode usage.
	{"FilesystemInodesHealthy", latchdefs.StateExitRe(latchdefs.LatchInodePressure)},
}

// maxEventNote caps the Event note — the apiserver validates the
// message/note payload (~1KiB); watchdog lines are far shorter but a
// garbage log line must not fail the create.
const maxEventNote = 1024

const (
	// maxLogReadBytes bounds one tail read. The watchdog caps its own
	// log at ~1MB, so a file far beyond that means broken rotation or
	// a flood — the first scan jumps to the last maxLogReadBytes
	// instead of slurping the whole file into heap.
	maxLogReadBytes = 4 << 20
	// maxLogPendingBytes bounds the carried partial-line buffer — a
	// line that never terminates cannot grow the carry forever.
	maxLogPendingBytes = 64 << 10
	// maxEmittedEvents bounds the dedup map after TTL pruning — a
	// flood of distinct reason+message pairs evicts oldest-first
	// instead of growing without limit.
	maxEmittedEvents = 1024
)

// emittedEvent tracks one created Event for series aggregation.
type emittedEvent struct {
	name  string
	count int64
	at    time.Time // last emit — TTL eviction key
}

// syncLogEvents consumes new watchdog log lines, matches the ported
// rules, bumps problem_counter and emits/aggregates Events. A missing
// log file is not an error (nodes without the watchdog simply have
// nothing to report).
func (r *Reporter) syncLogEvents(ctx context.Context) error {
	lines, replayCount, err := r.readNewLogLines()
	if err != nil {
		return err
	}
	r.pruneEmitted()
	for i, line := range lines {
		r.processLogLine(ctx, line, i < replayCount)
	}
	return nil
}

// readNewLogLines returns the complete lines appended since the last
// call and how many of the LEADING lines must go through the replay
// filter (the LogLookback window in processLogLine) — replay is
// per-line because the two byte generations one read can carry have
// different claims to liveness. A trailing partial line is carried
// over to the next cycle so a line split across writes is never
// half-matched.
//
// Every line replays on the first scan after (re)start. On a
// rotation (the rename-to-.1 the watchdog store performs at
// watchdogLogMaxBytes) only the OLD-generation bytes replay — the
// unread .1 tail drained before the offset reset, plus the partial
// line it continues — while the FRESH file's lines are live events,
// not replay (a blanket replay flag would let the lookback filter
// drop a just-written line whose timestamp is unparseable or outside
// the window). A shrink with NO .1 tail is a wholesale rewrite: no
// generation boundary exists to attribute the new file's content to,
// so every line replays exactly like the pre-split behavior — old
// retained lines stay behind the lookback filter instead of
// re-incrementing problem_counter. (NPD kept the stale offset and
// silently missed post-rotation lines; rescanning is strictly
// better.)
//
// The lines appended to the old generation AFTER the last read live
// on in <log>.1 and would be lost by a bare offset reset — so on a
// shrink the unread tail is drained from .1 FIRST and prepended to
// the fresh file's bytes, preserving both order and the carried
// partial line (the .1 tail continues it).
func (r *Reporter) readNewLogLines() ([][]byte, int, error) {
	replayAll := !r.logScanned
	win, err := r.readLogWindow()
	if err != nil || win == nil {
		return nil, 0, err
	}

	pending := r.logPending
	r.logPending = nil
	buf := append(pending, win.data...)
	if len(buf) == 0 {
		return nil, 0, nil
	}
	last := bytes.LastIndexByte(buf, '\n')
	if last < 0 {
		// The whole tail is one unfinished line — keep only the last
		// maxLogPendingBytes so a never-terminated line cannot grow
		// the carry buffer without bound.
		if len(buf) > maxLogPendingBytes {
			buf = buf[len(buf)-maxLogPendingBytes:]
		}
		r.logPending = buf
		return nil, 0, nil
	}
	if rem := buf[last+1:]; len(rem) > 0 {
		if len(rem) > maxLogPendingBytes {
			rem = rem[len(rem)-maxLogPendingBytes:]
		}
		r.logPending = append([]byte(nil), rem...)
	}
	// Split in place — bytes.Split on a big chunk materialises a
	// [][]byte header per line; IndexByte iteration avoids that.
	var lines [][]byte
	for rest := buf[:last]; len(rest) > 0; {
		i := bytes.IndexByte(rest, '\n')
		if i < 0 {
			lines = append(lines, rest)
			break
		}
		lines = append(lines, rest[:i])
		rest = rest[i+1:]
	}
	// The replay prefix: everything on the first scan, everything
	// after an unattributed rewrite, and otherwise exactly the lines
	// STARTING inside the old-generation prefix (a line straddling
	// the boundary began in the old generation — its completion
	// rides the fresh bytes, but it is still old-gen content).
	switch {
	case replayAll, win.noTail:
		return lines, len(lines), nil
	default:
		// oldGenBuf is the length of the OLD-generation prefix of
		// buf: the carried partial line (it began in the old
		// generation) plus the drained .1 tail — only meaningful
		// for a rename rotation, the replay boundary the fresh
		// file's lines start behind. No rotation → no old
		// generation → nothing replays.
		oldGenBuf := 0
		if win.rotated {
			oldGenBuf = len(pending) + win.oldGenTail
		}
		replayCount := 0
		pos := 0
		for _, ln := range lines {
			if pos >= oldGenBuf {
				break
			}
			replayCount++
			pos += len(ln) + 1
		}
		return lines, replayCount, nil
	}
}

// logWindow is one read cycle's byte window plus the rotation
// metadata the replay attribution needs: data is the .1 tail
// prepended to the fresh file's bytes, oldGenTail the drained
// tail's length, rotated/noTail the shrink classification.
type logWindow struct {
	data       []byte
	oldGenTail int
	rotated    bool
	noTail     bool
}

// readLogWindow performs the stat/rotate/mid-seek/open/read half of
// a scan and returns the consumed byte window. It owns the offset
// bookkeeping — r.logOffset advances by bytes actually consumed
// from the LIVE file (not fi.Size(), so lines appended between
// Stat and Read aren't double-read next cycle, and the drained .1
// tail's length is excluded), and r.logScanned arms only after a
// successful read so a failed first pass can't disarm the lookback
// filter. nil window = the log file is absent (not an error).
func (r *Reporter) readLogWindow() (*logWindow, error) {
	fi, err := os.Stat(r.cfg.WatchdogLogFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat %s: %w", r.cfg.WatchdogLogFile, err)
	}
	var tail []byte // unread bytes of the rotated .1 generation
	win := &logWindow{}
	// A rename rotation swaps the file under the same path. Size
	// alone misses it when the fresh file grows past the old offset
	// before the next scan — the seek would then land mid-file in
	// the NEW generation and the unread .1 tail would never drain
	// (Events + problem_counter silently lost for that window).
	// Identity (dev/ino via os.SameFile) detects the generation
	// change regardless of size; the size check stays for the
	// same-inode shrink (in-place truncate/rewrite).
	generationChanged := r.logFi != nil && !os.SameFile(r.logFi, fi)
	if generationChanged || fi.Size() < r.logOffset {
		win.rotated = true
		logger().Debug("nodereporter: watchdog log rotated — draining "+
			"the .1 tail, offset reset", "file", r.cfg.WatchdogLogFile,
			"oldOffset", r.logOffset, "size", fi.Size(),
			"generationChanged", generationChanged)
		// The .1 tail continues r.logPending (the partial line the
		// old generation never terminated) — read it BEFORE clearing
		// anything. The carry survives only when the tail actually
		// carries its continuation; an absent/empty tail (in-place
		// rewrite, .1 already gone or fully consumed) means the
		// partial line can never complete — keeping it would
		// concatenate the fresh file's first line onto a dead
		// fragment.
		tail = readTailBytes(r.cfg.WatchdogLogFile+".1",
			r.logOffset, maxLogReadBytes)
		if len(tail) == 0 {
			r.logPending = nil
			win.noTail = true // wholesale rewrite — nothing is attributable
		}
		r.logOffset = 0
	}
	// First scan of an oversized file: jump to the last
	// maxLogReadBytes and drop the partial line at the cut — the cap
	// exists so a log that outgrew the ~1MB watchdog cap (broken
	// rotation, flood) is never slurped whole into RAM.
	midSeek := false
	if r.logOffset == 0 && fi.Size() > maxLogReadBytes {
		r.logOffset = fi.Size() - maxLogReadBytes
		r.logPending = nil
		midSeek = true
	}
	f, err := os.Open(r.cfg.WatchdogLogFile)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", r.cfg.WatchdogLogFile, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(r.logOffset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek %s: %w", r.cfg.WatchdogLogFile, err)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxLogReadBytes))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", r.cfg.WatchdogLogFile, err)
	}
	// Bytes consumed from the LIVE file — captured before any cut or
	// tail-prepend mangles data (the mid-file seek's discarded head
	// WAS consumed; the .1 tail was not).
	rawLen := int64(len(data))
	// A mid-file seek lands inside a line — discard everything up to
	// the first newline; the head of that line was never read.
	if midSeek {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		} else {
			data = nil
		}
	}
	if len(tail) > 0 {
		// Rotated-generation bytes precede the fresh file's — the
		// events they map onto must not be reordered behind it.
		data = append(tail, data...)
	}
	win.data = data
	win.oldGenTail = len(tail)
	// The tail was fully read — this successful pass counts as the
	// replay scan even if it yielded no complete lines yet.
	r.logScanned = true
	r.logOffset += rawLen
	// Remember the generation read — the next scan's os.SameFile
	// check compares against THIS stat.
	r.logFi = fi
	return win, nil
}

// readTailBytes drains up to max bytes of path starting at offset —
// the rotated .1 generation's unread tail. nil on any absence/error/
// empty read: the drain is strictly best-effort, a lost tail just
// degrades to the pre-tail behavior (offset reset + fresh-file read).
func readTailBytes(path string, offset, max int64) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || offset >= fi.Size() {
		return nil
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(f, max))
	if err != nil || len(data) == 0 {
		return nil
	}
	return data
}

// splitLogLine peels the leading timestamp token (filelog
// pluginConfig parity): returns the message and the parsed RFC3339
// timestamp (zero when absent/unparseable).
func splitLogLine(line []byte) (msg string, ts time.Time) {
	s := string(bytes.TrimRight(line, "\r"))
	i := bytes.IndexByte(line, ' ')
	if i < 0 {
		return s, time.Time{}
	}
	msg = string(bytes.TrimLeft(line[i+1:], " "))
	if t, err := time.Parse(time.RFC3339, s[:i]); err == nil {
		ts = t
	}
	return msg, ts
}

// processLogLine applies all rules to one line. On the first scan
// (replay) only lines inside LogLookback with a parseable timestamp
// are emitted — unparseable/older lines are skipped so a restart
// doesn't re-report ancient history.
func (r *Reporter) processLogLine(ctx context.Context, line []byte, replay bool) {
	if len(line) == 0 {
		return
	}
	msg, ts := splitLogLine(line)
	if replay && (ts.IsZero() || r.cfg.Clock.Now().Sub(ts) > r.cfg.LogLookback) {
		return
	}
	for _, rule := range logRules {
		if !rule.re.MatchString(msg) {
			continue
		}
		r.problemCounter.WithLabelValues(rule.reason).Inc()
		if err := r.emitEvent(ctx, rule.reason, msg, corev1.EventTypeWarning); err != nil {
			// Logged, not fatal — the counter already reflects the
			// match and the next identical line retries the Event.
			logger().Error("nodereporter: event emit failed",
				"reason", rule.reason, "error", err)
		}
	}
	for _, rule := range exitLogRules {
		if !rule.re.MatchString(msg) {
			continue
		}
		r.problemCounter.WithLabelValues(rule.reason).Inc()
		if err := r.emitEvent(ctx, rule.reason, msg, corev1.EventTypeNormal); err != nil {
			logger().Error("nodereporter: exit event emit failed",
				"reason", rule.reason, "error", err)
		}
	}
}

// emitEvent creates or aggregates one Event of the given type on this
// Node.
// Dedup key is reason+message: a fresh key creates a new object; a
// repeat inside EventDedupTTL series-patches the existing one
// (count++, lastObservedTime). A NotFound patch failure (event TTL'd
// away) drops the entry and recreates; any OTHER patch error keeps
// the entry and returns the error — recreating a fresh object per
// occurrence under a persistent failure (RBAC create-but-not-patch,
// apiserver degradation) would spam unbounded Events.
func (r *Reporter) emitEvent(ctx context.Context, reason, note string, eventType string) error {
	events := r.cfg.Client.EventsV1().Events(r.cfg.EventNamespace)
	now := r.cfg.Clock.Now()
	// Truncate BEFORE keying: two >1KiB notes sharing the first
	// maxEventNote bytes store an identical Note, so they must share
	// one dedup entry — keying on the untruncated note would create
	// distinct Events with identical content. The cut snaps back to
	// a rune boundary and ToValidUTF8 strips any remaining invalid
	// bytes: the apiserver stores Note as a UTF-8 string and rejects
	// invalid input, so a garbage log line must not wedge its Event
	// create permanently.
	if len(note) > maxEventNote {
		i := maxEventNote
		for i > 0 && !utf8.RuneStart(note[i]) {
			i--
		}
		note = strings.ToValidUTF8(note[:i], "")
	}
	key := reason + "\x1f" + note

	if e, ok := r.emittedEvts[key]; ok && now.Sub(e.at) <= r.cfg.EventDedupTTL {
		patch, err := json.Marshal(map[string]any{
			"series": map[string]any{
				"count":            e.count + 1,
				"lastObservedTime": metav1.NewMicroTime(now),
			},
		})
		if err == nil {
			_, err = events.Patch(ctx, e.name, types.MergePatchType,
				patch, metav1.PatchOptions{})
		}
		if err == nil {
			e.count++
			e.at = now
			return nil
		}
		if !apierrors.IsNotFound(err) {
			// Not a "the Event is gone" — RBAC, throttling, a wedged
			// apiserver. Keep the dedup entry: deleting it here would
			// fall through to a fresh Create on EVERY occurrence of
			// this reason+message for as long as the failure lasts.
			// The caller logs the error; the next identical line
			// retries the patch against the same entry.
			return fmt.Errorf("patch event %s/%s: %w",
				r.cfg.EventNamespace, e.name, err)
		}
		delete(r.emittedEvts, key) // stale entry — recreate below
	}

	// Kubelet-style <node>.<hex> name with a monotonic sequence — the
	// nanos alone could collide for two reasons fired in the same
	// cycle.
	name := fmt.Sprintf("%s.%x%x", r.cfg.NodeName, now.UnixNano(), r.evSeq.Add(1))
	ev := &eventsv1.Event{
		ObjectMeta:          metav1.ObjectMeta{Name: name, Namespace: r.cfg.EventNamespace},
		EventTime:           metav1.NewMicroTime(now),
		Reason:              reason,
		Note:                note,
		Type:                eventType,
		ReportingController: "node-host-agent",
		ReportingInstance:   r.cfg.NodeName,
		// events.k8s.io/v1 validation: action is REQUIRED and the
		// deprecated* compat fields must be UNSET (apiserver rejects
		// with "needs to be unset" on this k8s version).
		Action: reason,
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Node",
			Name:       r.cfg.NodeName,
		},
	}
	created, err := events.Create(ctx, ev, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create event %s/%s: %w", r.cfg.EventNamespace, name, err)
	}
	r.emittedEvts[key] = &emittedEvent{name: created.Name, count: 1, at: now}
	logger().Info("nodereporter: event emitted",
		"node", r.cfg.NodeName, "event", created.Name,
		"namespace", r.cfg.EventNamespace, "reason", reason)
	return nil
}

// pruneEmitted drops dedup entries past the TTL — the apiserver GCs
// Events at ~1h, so aggregation targets older than that are gone and
// the map would grow unboundedly otherwise. The map is additionally
// hard-capped: a flood of distinct reason+message pairs evicts the
// least-recently-observed entries first.
func (r *Reporter) pruneEmitted() {
	now := r.cfg.Clock.Now()
	for k, e := range r.emittedEvts {
		if now.Sub(e.at) > r.cfg.EventDedupTTL {
			delete(r.emittedEvts, k)
		}
	}
	if len(r.emittedEvts) > maxEmittedEvents {
		// Single pass: collect (key, at), sort freshest-first, drop
		// everything past the cap — no per-eviction map rescan.
		type observed struct {
			key string
			at  time.Time
		}
		es := make([]observed, 0, len(r.emittedEvts))
		for k, e := range r.emittedEvts {
			es = append(es, observed{k, e.at})
		}
		slices.SortFunc(es, func(a, b observed) int { return b.at.Compare(a.at) })
		for _, o := range es[maxEmittedEvents:] {
			delete(r.emittedEvts, o.key)
		}
	}
}
