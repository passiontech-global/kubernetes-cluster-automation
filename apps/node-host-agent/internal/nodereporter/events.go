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
	"log/slog"
	"os"
	"regexp"
	"time"

	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// logRule is one temporary filelog rule — reason → K8s Event reason +
// problem_counter label, pattern → unanchored match on the message
// part of a log line.
type logRule struct {
	reason string
	re     *regexp.Regexp
}

// logRules is the watchdog-filelog-monitor.json rules array, in order.
var logRules = []logRule{
	{"TincEgressUnreachable", regexp.MustCompile(`(?:tinc|overlay)-egress unreachable`)},
	{"TincEgressFailover", regexp.MustCompile(`ACTION: egress [0-9.]+ -> (?:tinc|overlay) relay`)},
	{"NodeOverloaded", regexp.MustCompile(`node[- ]overloaded`)},
	{"K0sworkerRestarted", regexp.MustCompile(`ACTION: restarting k0sworker`)},
	{"KubeletInformerZombie", regexp.MustCompile(`informer-zombie`)},
	{"KubeletPhantomPods", regexp.MustCompile(`phantom-pods`)},
	{"CtrTaskWedged", regexp.MustCompile(`ctr-task-wedged|ctr tasks delete|orphaned task dir`)},
	{"KonnectivityStaleId", regexp.MustCompile(`konnectivity stale identifier|recreating konnectivity-agent`)},
	{"TincEgressRecovered", regexp.MustCompile(`ACTION: egress [0-9.]+ -> direct underlay`)},
	{"TincEgressHeal", regexp.MustCompile(`ACTION: heal egress`)},
	{"NebulaRestarted", regexp.MustCompile(`ACTION: restarting nebula@`)},
	{"NebulaIsolatedEnter", regexp.MustCompile(`STATE-ENTER: nebula-isolated`)},
	{"NebulaDataplaneDegraded", regexp.MustCompile(`nebula-dataplane-degraded`)},
	{"NebulaSlowPath", regexp.MustCompile(`nebula-dataplane-slowpath`)},
	{"NebulaSiteEdge", regexp.MustCompile(`nebula-siteedge-degraded`)},
	{"NebulaCertExpiring", regexp.MustCompile(`nebula-cert-expiring`)},
	{"WatchdogRunFailed", regexp.MustCompile(`WATCHDOG-FAILED`)},
	{"WatchdogModuleFailed", regexp.MustCompile(`STATE-ENTER: module-failed-`)},
	{"CiliumAgentDown", regexp.MustCompile(`cilium-agent-down|killed cilium-agent`)},
	{"KubeletRuntimeStall", regexp.MustCompile(`kubelet-runtime-stall`)},
	{"DnsResolvStale", regexp.MustCompile(`dns-resolv-stale`)},
	{"StuckPodForceDeleted", regexp.MustCompile(`force-delete pod `)},
	{"PodTeardownWedged", regexp.MustCompile(`pod-teardown-wedged`)},
}

// maxEventNote caps the Event note — the apiserver validates the
// message/note payload (~1KiB); watchdog lines are far shorter but a
// garbage log line must not fail the create.
const maxEventNote = 1024

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
	lines, replay, err := r.readNewLogLines()
	if err != nil {
		return err
	}
	r.pruneEmitted()
	for _, line := range lines {
		r.processLogLine(ctx, line, replay)
	}
	return nil
}

// readNewLogLines returns the complete lines appended since the last
// call, and whether they must go through the replay filter (the
// LogLookback window in processLogLine). A trailing partial line is
// carried over to the next cycle so a line split across writes is
// never half-matched.
//
// replay is true for the first scan after (re)start and again after
// a file-shrink rotation: the watchdog caps the log at ~1MB by
// rewriting it, the offset resets to 0 and the retained tail is
// re-scanned — routing that rescan through the lookback filter keeps
// old retained lines from re-incrementing problem_counter and
// re-emitting Events as if they were live. (NPD kept the stale
// offset and silently missed post-rotation lines; rescanning is
// strictly better.)
func (r *Reporter) readNewLogLines() ([][]byte, bool, error) {
	replay := !r.logScanned
	fi, err := os.Stat(r.cfg.WatchdogLogFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, replay, nil
		}
		return nil, replay, fmt.Errorf("stat %s: %w", r.cfg.WatchdogLogFile, err)
	}
	if fi.Size() < r.logOffset {
		r.logOffset = 0
		r.logPending = nil
		replay = true // retained-tail rescan → lookback filter
	}
	f, err := os.Open(r.cfg.WatchdogLogFile)
	if err != nil {
		return nil, replay, fmt.Errorf("open %s: %w", r.cfg.WatchdogLogFile, err)
	}
	defer f.Close()
	if _, err := f.Seek(r.logOffset, io.SeekStart); err != nil {
		return nil, replay, fmt.Errorf("seek %s: %w", r.cfg.WatchdogLogFile, err)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, replay, fmt.Errorf("read %s: %w", r.cfg.WatchdogLogFile, err)
	}
	// The tail was fully read — this successful pass counts as the
	// replay scan even if it yielded no complete lines yet. Arming
	// the flag any earlier (on open) would let a failed first read
	// disarm the lookback filter and dump the entire history next
	// cycle.
	r.logScanned = true
	// Offset tracks bytes actually consumed — not fi.Size(), so lines
	// appended between Stat and Read aren't double-read next cycle.
	r.logOffset += int64(len(data))

	buf := append(r.logPending, data...)
	r.logPending = nil
	if len(buf) == 0 {
		return nil, replay, nil
	}
	last := bytes.LastIndexByte(buf, '\n')
	if last < 0 {
		r.logPending = buf // whole tail is one unfinished line
		return nil, replay, nil
	}
	if rem := buf[last+1:]; len(rem) > 0 {
		r.logPending = append([]byte(nil), rem...)
	}
	return bytes.Split(buf[:last], []byte("\n")), replay, nil
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
	if replay && (ts.IsZero() || r.cfg.nowFn().Sub(ts) > r.cfg.LogLookback) {
		return
	}
	for _, rule := range logRules {
		if !rule.re.MatchString(msg) {
			continue
		}
		r.problemCounter.WithLabelValues(rule.reason).Inc()
		if err := r.emitEvent(ctx, rule.reason, msg); err != nil {
			// Logged, not fatal — the counter already reflects the
			// match and the next identical line retries the Event.
			slog.Error("nodereporter: event emit failed",
				"reason", rule.reason, "error", err)
		}
	}
}

// emitEvent creates or aggregates one Warning Event on this Node.
// Dedup key is reason+message: a fresh key creates a new object; a
// repeat inside EventDedupTTL series-patches the existing one
// (count++, lastObservedTime). A patch failure (event TTL'd away)
// drops the entry and recreates.
func (r *Reporter) emitEvent(ctx context.Context, reason, note string) error {
	events := r.cfg.Client.EventsV1().Events(r.cfg.EventNamespace)
	now := r.cfg.nowFn()
	// Truncate BEFORE keying: two >1KiB notes sharing the first
	// maxEventNote bytes store an identical Note, so they must share
	// one dedup entry — keying on the untruncated note would create
	// distinct Events with identical content.
	if len(note) > maxEventNote {
		note = note[:maxEventNote]
	}
	key := reason + "\x1f" + note

	if e, ok := r.emittedEvts[key]; ok && now.Sub(e.at) <= r.cfg.EventDedupTTL {
		patch, err := json.Marshal(map[string]any{
			"series": map[string]any{
				"count":            e.count + 1,
				"lastObservedTime": metav1.NewMicroTime(now),
			},
			"deprecatedCount":         e.count + 1,
			"deprecatedLastTimestamp": metav1.NewTime(now),
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
		Type:                corev1.EventTypeWarning,
		ReportingController: "node-host-agent",
		ReportingInstance:   r.cfg.NodeName,
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Node",
			Name:       r.cfg.NodeName,
		},
		// Deprecated fields keep `kubectl get events` SOURCE/LAST SEEN/
		// COUNT columns populated on older kubectl versions.
		DeprecatedSource:         corev1.EventSource{Component: "node-host-agent", Host: r.cfg.NodeName},
		DeprecatedFirstTimestamp: metav1.NewTime(now),
		DeprecatedLastTimestamp:  metav1.NewTime(now),
		DeprecatedCount:          1,
	}
	created, err := events.Create(ctx, ev, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("create event %s/%s: %w", r.cfg.EventNamespace, name, err)
	}
	r.emittedEvts[key] = &emittedEvent{name: created.Name, count: 1, at: now}
	return nil
}

// pruneEmitted drops dedup entries past the TTL — the apiserver GCs
// Events at ~1h, so aggregation targets older than that are gone and
// the map would grow unboundedly otherwise.
func (r *Reporter) pruneEmitted() {
	now := r.cfg.nowFn()
	for k, e := range r.emittedEvts {
		if now.Sub(e.at) > r.cfg.EventDedupTTL {
			delete(r.emittedEvts, k)
		}
	}
}
