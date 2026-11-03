// The three remaining node-problem-detector monitors, ported into
// nodereporter so the NPD DaemonSet can be retired (values.yaml
// log_monitors: kernel-monitor, docker-monitor -> dropped with
// containerd, readonly-monitor + custom kubelet-stale).
//
//   - kubelet-stale-monitor (custom_monitor_definitions in the NPD
//     helm values, journald plugin on unit k0sworker.service):
//     journald lines are fetched via `journalctl -u <unit> --since
//     @<epoch> -o json` through the host nsenter wrapper (systemd
//     package parity) with a __REALTIME_TIMESTAMP cursor so only new
//     lines are processed. The first cycle replays LogLookback (5m) —
//     the NPD "lookback" parity. Matching lines bump
//     problem_counter{reason} and emit Events; no conditions (the
//     JSON had "conditions": []).
//   - kernel-monitor (upstream kernel-monitor.json, kmsg plugin):
//     drains the host kernel ring buffer — the DaemonSet bind-mounts
//     host /dev/kmsg at /dev/kmsg (CharDevice, ro), with
//     <HostRoot>/dev/kmsg as the fallback path — via O_NONBLOCK
//     reads. When kmsg cannot be opened the monitor falls back to
//     `journalctl -k` for the process lifetime. kmsg records carry
//     µs-since-boot timestamps, so the backlog replays through
//     the same 5m lookback converted via /proc/uptime (hostPID ->
//     host uptime) — kept armed across drains until the ring is
//     drained to EAGAIN (the 4MiB per-cycle cap can slice a big
//     backlog); the journald fallback is already cursor-bounded.
//     KernelDeadlock is a PERMANENT condition: once latched it stays
//     True for the agent lifetime (NPD parity — permanent conditions
//     never clear).
//   - readonly-monitor: upstream also watched kmsg ("Remounting
//     filesystem read-only"); this port checks the actual mount
//     table instead — /proc/1/mounts (hostPID -> the HOST mount
//     table, a container procfs would only see the pod's mount ns)
//     for the watched mountpoints on ext4/xfs/btrfs — so
//     ReadonlyFilesystem clears when the fs is remounted rw, which
//     the kmsg pattern never could.
//
// The two NodeConditions (KernelDeadlock, ReadonlyFilesystem) keep
// the exact upstream type/default-reason/default-message strings and
// the same zero-churn strategic-merge patch mechanics as the 9
// watchdog conditions in conditions.go — they are kept here so the
// watchdog latch table stays untouched.
package nodereporter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// kubelet-stale-monitor.json rules — journald plugin, temporary
// only. KubeletNodeNotFound covers both the klog-escaped quoting the
// values.yaml pattern decoded to (`node \"X\" not found` — the
// informer-zombie spam signature) and the plain form.
var kubeletJournalRules = []logRule{
	{"KubeletNodeNotFound", regexp.MustCompile(`node \\?"[^"\\]+\\?" not found|not registered yet`)},
	{"KubeletObjectNotRegistered", regexp.MustCompile(`not registered|no relationship found between node`)},
}

// kernel-monitor.json temporary rules (the upstream set, trimmed to
// the reasons kept by this deployment's alert rules).
var kernelTempRules = []logRule{
	{"OOMKilling", regexp.MustCompile(`Killed process \d+ .* out of memory|Out of memory: Killed process`)},
	{"TaskHung", regexp.MustCompile(`task [\S ]+:\w+ blocked for more than \w+ seconds`)},
	{"KernelOops", regexp.MustCompile(`BUG: unable to handle kernel|kernel BUG at|Oops:`)},
	{"Ext4Error", regexp.MustCompile(`EXT4-fs error`)},
	{"Ext4Warning", regexp.MustCompile(`EXT4-fs warning`)},
}

// kernelDeadlockRe is the permanent KernelDeadlock rule — the
// hung-task watcher's "INFO: task ... blocked" output.
var kernelDeadlockRe = regexp.MustCompile(`INFO: task .* blocked for more than`)

// maxKmsgReadBytes bounds one kmsg drain per cycle — a printk flood
// is sliced across cycles instead of slurping the whole ring.
const maxKmsgReadBytes = 4 << 20

// The two NPD NodeConditions and their upstream strings
// (kernel-monitor.json + readonly-monitor.json conditions[]).
const (
	condKernelDeadlock corev1.NodeConditionType = "KernelDeadlock"
	condReadonlyFS     corev1.NodeConditionType = "ReadonlyFilesystem"

	kernelDeadlockDefaultReason = "KernelHasNoDeadlock"
	kernelDeadlockDefaultMsg    = "kernel has no deadlock"
	kernelDeadlockProblemReason = "KernelDeadlock"

	readonlyDefaultReason = "FilesystemIsNotReadOnly"
	readonlyDefaultMsg    = "Filesystem is not read-only"
	readonlyProblemReason = "FilesystemIsReadOnly"
)

// ---------------------------------------------------------------------------
// journald source (kubelet-stale monitor + kernel journalctl fallback)
// ---------------------------------------------------------------------------

// journalEntry is one `journalctl -o json` record reduced to the two
// fields the rules need.
type journalEntry struct {
	msg  string
	tsUS int64 // __REALTIME_TIMESTAMP, µs since epoch
}

// parseJournalJSON decodes line-delimited `journalctl -o json`
// output. Malformed lines (a truncated tail of a flooded journal)
// are skipped rather than failing the whole batch.
func parseJournalJSON(data string) []journalEntry {
	var out []journalEntry
	for _, line := range bytes.Split([]byte(data), []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var e struct {
			Message json.RawMessage `json:"MESSAGE"`
			TS      string          `json:"__REALTIME_TIMESTAMP"`
		}
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		ts, _ := strconv.ParseInt(e.TS, 10, 64)
		out = append(out, journalEntry{msg: journalMessage(e.Message), tsUS: ts})
	}
	return out
}

// journalMessage unwraps the MESSAGE field — journald emits a JSON
// string for text but an array of byte values for non-UTF8 payloads.
func journalMessage(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var b []byte
	if err := json.Unmarshal(raw, &b); err == nil {
		return string(b)
	}
	return ""
}

// fetchJournal runs `journalctl <args...> --since @<cursor> -o json`
// and returns entries strictly newer than *cursor. The cursor is a
// µs wall timestamp: 0 means "first cycle", which bounds the fetch
// to LogLookback. On success the cursor advances to the fetch time
// (or the newest seen entry if the host clock runs ahead) so the
// --since window never grows unboundedly; entries ≤ cursor were
// already processed. A fetch error leaves the cursor untouched —
// the same window is retried next cycle.
func (r *Reporter) fetchJournal(ctx context.Context, cursor *int64, args ...string) ([]journalEntry, error) {
	now := r.cfg.nowFn()
	sinceUS := *cursor
	if sinceUS <= 0 {
		sinceUS = now.Add(-r.cfg.LogLookback).UnixMicro()
	}
	full := append([]string(nil), args...)
	full = append(full, "--since", "@"+strconv.FormatInt(sinceUS/1e6, 10),
		"-o", "json", "--no-pager")
	out, err := r.cfg.journalFetch(ctx, full...)
	if err != nil {
		return nil, fmt.Errorf("journalctl %s: %w", strings.Join(args, " "), err)
	}
	var kept []journalEntry
	next := now.UnixMicro()
	for _, e := range parseJournalJSON(out) {
		if e.tsUS <= *cursor {
			continue // already processed on a previous cycle
		}
		kept = append(kept, e)
		if e.tsUS > next {
			next = e.tsUS
		}
	}
	*cursor = next
	return kept, nil
}

// syncKubeletJournal is the kubelet-stale-monitor port: new
// k0sworker.service journal lines → rules → problem_counter + Event.
func (r *Reporter) syncKubeletJournal(ctx context.Context) error {
	entries, err := r.fetchJournal(ctx, &r.kubeletJournalUS,
		"-u", r.cfg.KubeletJournalUnit)
	if err != nil {
		return err
	}
	for _, e := range entries {
		r.matchEventRules(ctx, kubeletJournalRules, e.msg)
	}
	return nil
}

// matchEventRules applies a temporary rule set to one line: every
// matching rule increments problem_counter and emits/aggregates an
// Event — same semantics as processLogLine for the watchdog filelog.
func (r *Reporter) matchEventRules(ctx context.Context, rules []logRule, msg string) {
	for _, rule := range rules {
		if !rule.re.MatchString(msg) {
			continue
		}
		r.problemCounter.WithLabelValues(rule.reason).Inc()
		if err := r.emitEvent(ctx, rule.reason, msg); err != nil {
			slog.Error("nodereporter: event emit failed",
				"reason", rule.reason, "error", err)
		}
	}
}

// ---------------------------------------------------------------------------
// kernel monitor (kmsg tail, journalctl -k fallback)
// ---------------------------------------------------------------------------

// kernelLine is one kernel record: the message text plus its
// µs-since-boot timestamp (-1 when unknown, e.g. journald path where
// the cursor already bounds the window).
type kernelLine struct {
	msg  string
	usec int64
}

// parseKmsgRecord splits a /dev/kmsg record "pri,seq,usec,flags;msg"
// into its message and boot-relative timestamp. Lines without the
// kmsg header pass through whole with an unknown timestamp.
func parseKmsgRecord(line []byte) kernelLine {
	s := strings.TrimRight(string(line), "\r")
	i := strings.IndexByte(s, ';')
	if i < 0 {
		return kernelLine{msg: s, usec: -1}
	}
	usec := int64(-1)
	if f := strings.Split(s[:i], ","); len(f) >= 3 {
		if v, err := strconv.ParseInt(f[2], 10, 64); err == nil {
			usec = v
		}
	}
	return kernelLine{msg: s[i+1:], usec: usec}
}

// splitPendingLines carries a trailing partial line into the next
// drain, same contract as the watchdog log tail.
func splitPendingLines(pending, data []byte) (lines [][]byte, rest []byte) {
	buf := append(pending, data...)
	last := bytes.LastIndexByte(buf, '\n')
	if last < 0 {
		if len(buf) > maxLogPendingBytes {
			buf = buf[len(buf)-maxLogPendingBytes:]
		}
		return nil, buf
	}
	if rem := buf[last+1:]; len(rem) > 0 {
		if len(rem) > maxLogPendingBytes {
			rem = rem[len(rem)-maxLogPendingBytes:]
		}
		rest = append([]byte(nil), rem...)
	}
	for b := buf[:last]; len(b) > 0; {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			lines = append(lines, b)
			break
		}
		lines = append(lines, b[:i])
		b = b[i+1:]
	}
	return lines, rest
}

// openKmsg tries the kmsg device paths in order — the DaemonSet
// mounts host /dev/kmsg at the same path; <HostRoot>/dev/kmsg covers
// layouts that mount the whole host /dev (or host root) instead.
func openKmsg(cfg *Config) *os.File {
	seen := map[string]bool{}
	for _, p := range []string{cfg.KmsgFile, filepath.Join(cfg.HostRoot, "dev/kmsg")} {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		if f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
			return f
		}
	}
	return nil
}

// readKmsgAvail drains all currently-available records from an
// O_NONBLOCK kmsg handle — each read returns one ring record and
// EAGAIN signals "caught up". The drain is capped per cycle so a
// printk flood is amortised across cycles. caughtUp reports whether
// the drain ended because the source ran dry (EAGAIN/EOF — the whole
// ring backlog consumed) rather than being cut at the byte cap; the
// caller keeps the lookback age filter armed until it sees it.
func readKmsgAvail(f *os.File) (data []byte, caughtUp bool, err error) {
	var buf bytes.Buffer
	tmp := make([]byte, 8192)
	for buf.Len() <= maxKmsgReadBytes {
		n, err := f.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, io.EOF) {
				return buf.Bytes(), true, nil
			}
			return buf.Bytes(), false, err
		}
		if n == 0 {
			return buf.Bytes(), true, nil
		}
	}
	return buf.Bytes(), false, nil
}

// kernelLines returns new kernel records and whether they must pass
// the first-scan lookback filter. kmsg path: lazily open the device
// (a reopen after a read error re-arms the lookback replay so the
// ring backlog isn't re-emitted live). The filter stays armed until
// the ring is drained to EAGAIN — the 4MiB per-drain cap can slice a
// big backlog across cycles, and backlog past the cap is still replay,
// not live history (a stale hung-task line would otherwise latch a
// PERMANENT KernelDeadlock on a fresh agent start). Journald
// fallback: permanent once kmsg cannot be opened, bounded by its own
// cursor so replay is never needed.
func (r *Reporter) kernelLines(ctx context.Context) ([]kernelLine, bool, error) {
	for {
		if r.kmsgJournalMode {
			entries, err := r.fetchJournal(ctx, &r.kernelJournalUS, "-k")
			if err != nil {
				return nil, false, err
			}
			lines := make([]kernelLine, 0, len(entries))
			for _, e := range entries {
				lines = append(lines, kernelLine{msg: e.msg, usec: -1})
			}
			return lines, false, nil
		}
		if r.kmsgSrc == nil {
			r.kmsgSrc = openKmsg(&r.cfg)
			r.kmsgScanned = false // fresh handle → backlog replays via lookback
			if r.kmsgSrc == nil {
				r.kmsgJournalMode = true
				slog.Warn("nodereporter: /dev/kmsg unreadable, kernel monitor "+
					"falls back to journalctl -k for the process lifetime",
					"kmsg", r.cfg.KmsgFile, "hostRoot", r.cfg.HostRoot)
				continue
			}
		}
		data, caughtUp, err := readKmsgAvail(r.kmsgSrc)
		if err != nil {
			r.kmsgSrc.Close()
			r.kmsgSrc = nil // reopen next cycle → lookback re-armed
			return nil, false, fmt.Errorf("read %s: %w", r.cfg.KmsgFile, err)
		}
		replay := !r.kmsgScanned
		if caughtUp {
			// Drained to EAGAIN — the ring backlog is fully consumed;
			// records from here on are live. kmsgScanned is "caught up
			// at least once on this handle" (the field name predates
			// the EAGAIN semantics).
			r.kmsgScanned = true
		}
		var raw [][]byte
		raw, r.kmsgPending = splitPendingLines(r.kmsgPending, data)
		lines := make([]kernelLine, 0, len(raw))
		for _, l := range raw {
			lines = append(lines, parseKmsgRecord(l))
		}
		return lines, replay, nil
	}
}

// hostUptimeSeconds reads the first field of /proc/uptime — under
// hostPID this is the HOST uptime, which converts kmsg µs-since-boot
// timestamps into ages for the first-scan lookback.
func hostUptimeSeconds(path string) (float64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	f := strings.Fields(string(data))
	if len(f) == 0 {
		return 0, fmt.Errorf("empty uptime %s", path)
	}
	return strconv.ParseFloat(f[0], 64)
}

// syncKernelMonitor is the kernel-monitor port: new kernel lines →
// temporary rules (counter + Event) plus the permanent KernelDeadlock
// latch.
func (r *Reporter) syncKernelMonitor(ctx context.Context) error {
	lines, replay, err := r.kernelLines(ctx)
	if err != nil {
		return err
	}
	uptime := float64(-1)
	if replay {
		if u, e := hostUptimeSeconds(r.cfg.ProcUptimeFile); e == nil {
			uptime = u
		}
	}
	for _, l := range lines {
		if replay {
			// kmsg records: age = uptime - usec. Unknown ts or an
			// unreadable uptime → drop the backlog line rather than
			// replay ancient ring history as live (filelog parity).
			if l.usec <= 0 || uptime < 0 {
				continue
			}
			if uptime-float64(l.usec)/1e6 > r.cfg.LogLookback.Seconds() {
				continue
			}
		}
		r.processKernelLine(ctx, l.msg)
	}
	return nil
}

// processKernelLine applies the temporary kernel rules plus the
// permanent KernelDeadlock latch to one kernel message.
func (r *Reporter) processKernelLine(ctx context.Context, msg string) {
	r.matchEventRules(ctx, kernelTempRules, msg)
	if kernelDeadlockRe.MatchString(msg) {
		r.problemCounter.WithLabelValues(kernelDeadlockProblemReason).Inc()
		if !r.kernelDeadlock {
			// Permanent: latch True for the agent lifetime (NPD
			// permanent-rule parity) and emit the transition Event.
			r.kernelDeadlock = true
			r.kernelDeadlockMsg = msg
			if err := r.emitEvent(ctx, kernelDeadlockProblemReason, msg); err != nil {
				slog.Error("nodereporter: event emit failed",
					"reason", kernelDeadlockProblemReason, "error", err)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// readonly monitor (/proc/1/mounts)
// ---------------------------------------------------------------------------

// mountEntry is one /proc/<pid>/mounts row reduced to what the check
// needs.
type mountEntry struct {
	fstype string
	opts   map[string]bool
}

// parseProcMounts parses /proc/1/mounts into mountpoint → entry.
// Rows for the same mountpoint (stacked binds) keep the LAST entry —
// the topmost mount wins, matching the kernel's lookup.
func parseProcMounts(data []byte) map[string]mountEntry {
	out := make(map[string]mountEntry)
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		f := strings.Fields(string(line))
		if len(f) < 4 {
			continue
		}
		opts := make(map[string]bool)
		for _, o := range strings.Split(f[3], ",") {
			opts[o] = true
		}
		out[f[1]] = mountEntry{fstype: f[2], opts: opts}
	}
	return out
}

// readonlyTargets returns the watched mountpoints currently mounted
// read-only on a watched fstype, formatted for the condition message
// ("<mp> (<fstype>)"). A target absent from the table or on another
// fstype is not reported.
func readonlyTargets(mounts map[string]mountEntry, targets, fstypes []string) []string {
	fs := make(map[string]bool, len(fstypes))
	for _, t := range fstypes {
		fs[t] = true
	}
	var ro []string
	for _, t := range targets {
		e, ok := mounts[t]
		if !ok || !fs[e.fstype] {
			continue
		}
		if e.opts["ro"] {
			ro = append(ro, fmt.Sprintf("%s (%s)", t, e.fstype))
		}
	}
	return ro
}

// syncReadonlyMounts is the readonly-monitor port: watched host
// mountpoints mounted ro → ReadonlyFilesystem=True, cleared when all
// are rw again. Emits one Event per False→True transition.
func (r *Reporter) syncReadonlyMounts(ctx context.Context) error {
	data, err := os.ReadFile(r.cfg.ProcMountsFile)
	if err != nil {
		return fmt.Errorf("read %s: %w", r.cfg.ProcMountsFile, err)
	}
	ro := readonlyTargets(parseProcMounts(data),
		r.cfg.ReadonlyTargets, r.cfg.ReadonlyFSTypes)
	was := r.readonlyFS
	r.readonlyFS = len(ro) > 0
	if r.readonlyFS {
		r.readonlyFSMsg = "read-only filesystems: " + strings.Join(ro, ", ")
		if !was {
			if err := r.emitEvent(ctx, readonlyProblemReason, r.readonlyFSMsg); err != nil {
				slog.Error("nodereporter: event emit failed",
					"reason", readonlyProblemReason, "error", err)
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// NPD conditions (KernelDeadlock + ReadonlyFilesystem) → node status
// ---------------------------------------------------------------------------

// npdCond is the evaluated state of one NPD condition this cycle.
type npdCond struct {
	typ     corev1.NodeConditionType
	status  corev1.ConditionStatus
	reason  string
	message string
	// gaugeReason is the problem_gauge reason label for the True
	// state — the NPD permanent-rule reason.
	gaugeReason string
}

// evalNPDConditions computes the wanted state of the two NPD
// conditions — same default/True reason+message contract as the
// upstream conditions[] declarations.
func (r *Reporter) evalNPDConditions() []npdCond {
	kd := npdCond{typ: condKernelDeadlock, status: corev1.ConditionFalse,
		reason: kernelDeadlockDefaultReason, message: kernelDeadlockDefaultMsg,
		gaugeReason: kernelDeadlockProblemReason}
	if r.kernelDeadlock {
		kd.status = corev1.ConditionTrue
		kd.reason = kernelDeadlockProblemReason
		kd.message = r.kernelDeadlockMsg
	}
	ro := npdCond{typ: condReadonlyFS, status: corev1.ConditionFalse,
		reason: readonlyDefaultReason, message: readonlyDefaultMsg,
		gaugeReason: readonlyProblemReason}
	if r.readonlyFS {
		ro.status = corev1.ConditionTrue
		ro.reason = readonlyProblemReason
		ro.message = r.readonlyFSMsg
	}
	return []npdCond{kd, ro}
}

// syncNPDConditions pushes the two NPD conditions to node status —
// same zero-churn strategic-merge mechanics as syncConditions for
// the watchdog conditions (conditions carry patchStrategy=merge on
// type, so this patch only touches our two entries). problem_gauge
// is local and always updates; the PATCH fires only on a
// Status/Reason diff.
func (r *Reporter) syncNPDConditions(ctx context.Context) error {
	evals := r.evalNPDConditions()
	for _, e := range evals {
		v := 0.0
		if e.status == corev1.ConditionTrue {
			v = 1
		}
		r.problemGauge.WithLabelValues(string(e.typ), e.gaugeReason).Set(v)
	}

	node, err := r.cfg.Client.CoreV1().Nodes().Get(ctx, r.cfg.NodeName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get node %s: %w", r.cfg.NodeName, err)
	}
	live := make(map[corev1.NodeConditionType]corev1.NodeCondition, len(node.Status.Conditions))
	for _, c := range node.Status.Conditions {
		live[c.Type] = c
	}

	changed := false
	for _, e := range evals {
		cur, ok := live[e.typ]
		if !ok || cur.Status != e.status || cur.Reason != e.reason {
			changed = true
			break
		}
	}
	if !changed {
		return nil
	}

	now := metav1.NewTime(r.cfg.nowFn())
	conds := make([]corev1.NodeCondition, 0, len(evals))
	for _, e := range evals {
		ltt := now
		if cur, ok := live[e.typ]; ok && cur.Status == e.status {
			ltt = cur.LastTransitionTime // reason-only change keeps LTT
		}
		conds = append(conds, corev1.NodeCondition{
			Type:               e.typ,
			Status:             e.status,
			Reason:             e.reason,
			Message:            e.message,
			LastHeartbeatTime:  now,
			LastTransitionTime: ltt,
		})
	}
	payload, err := json.Marshal(map[string]any{
		"status": map[string]any{"conditions": conds},
	})
	if err != nil {
		return fmt.Errorf("marshal status patch: %w", err)
	}
	if _, err := r.cfg.Client.CoreV1().Nodes().Patch(ctx, r.cfg.NodeName,
		types.StrategicMergePatchType, payload, metav1.PatchOptions{}, "status"); err != nil {
		return fmt.Errorf("patch node %s status: %w", r.cfg.NodeName, err)
	}
	return nil
}
