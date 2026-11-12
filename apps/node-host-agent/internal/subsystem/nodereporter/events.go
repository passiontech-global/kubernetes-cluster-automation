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
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// logRule is one temporary filelog rule — reason → K8s Event reason +
// problem_counter label, pattern → unanchored match on the message
// part of a log line.
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
//
// The log offset commits ONLY when every Event write in the batch
// succeeded: readNewLogLines advances r.logOffset while reading, so
// a failed emit would otherwise lose those lines permanently (the
// next scan resumes past them). On any emit failure the pre-read
// offset/pending/scanned state is restored and the whole window
// replays next cycle — emitEvent's reason+message dedup absorbs the
// re-emission, and problem_counter recounts the replayed matches
// (a counter of observed problems, not delivered events).
func (r *Reporter) syncLogEvents(ctx context.Context) error {
	savedOffset, savedPending := r.logOffset, r.logPending
	savedScanned, savedFi := r.logScanned, r.logFi
	lines, replayCount, err := r.readNewLogLines()
	if err != nil {
		return err
	}
	r.pruneEmitted()
	allEmitted := true
	for i, line := range lines {
		if !r.processLogLine(ctx, line, i < replayCount) {
			allEmitted = false
		}
	}
	if !allEmitted {
		r.logOffset, r.logPending = savedOffset, savedPending
		r.logScanned, r.logFi = savedScanned, savedFi
	}
	return nil
}

// processLogLine applies all rules to one line and reports whether
// every matched Event write succeeded — false tells syncLogEvents to
// roll the log offset back so the line replays next cycle. On the
// first scan (replay) only lines inside LogLookback with a parseable
// timestamp are emitted — unparseable/older lines are skipped so a
// restart doesn't re-report ancient history.
func (r *Reporter) processLogLine(ctx context.Context, line []byte, replay bool) bool {
	if len(line) == 0 {
		return true
	}
	msg, ts := splitLogLine(line)
	if replay && (ts.IsZero() || r.cfg.Clock.Now().Sub(ts) > r.cfg.LogLookback) {
		return true
	}
	ok := true
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
			ok = false
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
			ok = false
		}
	}
	return ok
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
