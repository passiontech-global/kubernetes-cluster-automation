// journal.go — the journald-plugin monitor port
// (kubelet-stale-monitor.json custom_monitor_definitions in the
// NPD helm values, journald plugin on unit k0sworker.service):
// journald lines are fetched via `journalctl -o json` through the
// host nsenter wrapper (systemd package parity) with a
// __REALTIME_TIMESTAMP cursor so only new lines are processed —
// the JSON-line decode and since/after-cursor fetch live in
// platform/journalwatch, and both journald consumers share ONE
// tail through its Multiplexer (the kernel monitor's journalctl -k
// fallback is the second subscriber — kernel.go). The first cycle
// replays LogLookback (5m) — the NPD "lookback" parity. Matching
// lines bump problem_counter{reason} and emit Events; no
// conditions (the JSON had "conditions": []).
package npd

import (
	"context"
	"regexp"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/journalwatch"
)

// Subscriber ids on the shared journalwatch.Multiplexer — one per
// journald consumer so each keeps its own pending queue off the
// single shared __CURSOR.
const (
	journalSubKubelet = "kubelet-journal"
	journalSubKernel  = "kernel-journal"
)

// rule is one temporary monitor rule — reason → K8s Event reason +
// problem_counter label, pattern → unanchored match on the message.
// Same shape as the parent's filelog logRule.
type rule struct {
	reason string
	re     *regexp.Regexp
}

// kubelet-stale-monitor.json rules — journald plugin, temporary
// only. KubeletNodeNotFound covers both the klog-escaped quoting the
// values.yaml pattern decoded to (`node \"X\" not found` — the
// informer-zombie spam signature) and the plain form.
var kubeletJournalRules = []rule{
	{"KubeletNodeNotFound", regexp.MustCompile(`node \\?"[^"\\]+\\?" not found|not registered yet`)},
	{"KubeletObjectNotRegistered", regexp.MustCompile(`not registered|no relationship found between node`)},
}

// pollJournal drains one mux subscriber's pending queue, fetching
// the shared journal window first when the last fetch is older
// than PollEvery. Lookback is re-read per poll so a post-New cfg
// re-point still lands (the Deps late-binding contract).
func (m *Monitor) pollJournal(ctx context.Context, sub string) ([]journalwatch.Entry, error) {
	m.journal.Lookback = m.cfg().LogLookback
	return m.journal.Poll(ctx, sub)
}

// SyncKubeletJournal is the kubelet-stale-monitor port: new
// k0sworker.service journal lines → rules → problem_counter +
// Event. The unit filter moved client-side onto the mux match —
// journalctl -u used to do it server-side, but the shared tail
// reads the whole journal once for every subscriber.
func (m *Monitor) SyncKubeletJournal(ctx context.Context, s Sink) error {
	unit := m.cfg().KubeletJournalUnit
	// Re-subscribing replaces the predicate while KEEPING the
	// pending queue — a cfg re-point lands without losing entries
	// already fetched for this consumer.
	if err := m.journal.Subscribe(journalSubKubelet,
		func(e journalwatch.Entry) bool { return e.Unit == unit }); err != nil {
		return err
	}
	entries, err := m.pollJournal(ctx, journalSubKubelet)
	if err != nil {
		return err
	}
	var failed []journalwatch.Entry
	for _, e := range entries {
		if !m.matchEventRules(ctx, s, kubeletJournalRules, e.Msg) {
			failed = append(failed, e)
		}
	}
	// The shared cursor already advanced at fetch time — entries
	// whose Event emit failed go back on the subscriber's pending
	// queue so the next Poll retries them (the filelog offset
	// rollback's journal-side equivalent).
	if err := m.journal.Requeue(journalSubKubelet, failed); err != nil {
		logger().Error("nodereporter: journal requeue failed",
			"subscriber", journalSubKubelet, "error", err)
	}
	return nil
}

// matchEventRules applies a temporary rule set to one line: every
// matching rule increments problem_counter and emits/aggregates an
// Event — same semantics as the parent's filelog processLogLine.
// Returns false when any matched Event write failed — the caller
// requeues the entry so the emit is retried (the counter recounts
// the replay, the same trade the filelog offset rollback makes).
func (m *Monitor) matchEventRules(ctx context.Context, s Sink, rules []rule, msg string) bool {
	ok := true
	for _, r := range rules {
		if !r.re.MatchString(msg) {
			continue
		}
		s.BumpCounter(r.reason)
		if err := s.EmitEvent(ctx, r.reason, msg); err != nil {
			logger().Error("nodereporter: event emit failed",
				"reason", r.reason, "error", err)
			ok = false
		}
	}
	return ok
}
