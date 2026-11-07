// journal.go — the journald-plugin monitor port
// (kubelet-stale-monitor.json custom_monitor_definitions in the
// NPD helm values, journald plugin on unit k0sworker.service):
// journald lines are fetched via `journalctl -u <unit> --since
// @<epoch> -o json` through the host nsenter wrapper (systemd
// package parity) with a __REALTIME_TIMESTAMP cursor so only new
// lines are processed — the JSON-line decode and since-cursor fetch
// live in platform/journalwatch. The first cycle replays
// LogLookback (5m) — the NPD "lookback" parity. Matching lines bump
// problem_counter{reason} and emit Events; no conditions (the JSON
// had "conditions": []). The kernel monitor's `journalctl -k`
// fallback shares the same fetch (kernel.go).
package npd

import (
	"context"
	"regexp"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/journalwatch"
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

// fetchJournal runs `journalctl <args...> --since @<cursor> -o
// json` (journalwatch.Fetch) and returns entries strictly newer
// than *cursor. The cursor is a µs wall timestamp: 0 means "first
// cycle", which bounds the fetch to LogLookback. On success the
// cursor advances to the fetch time (or the newest seen entry if
// the host clock runs ahead) so the --since window never grows
// unboundedly; entries ≤ cursor were already processed. A fetch
// error leaves the cursor untouched — the same window is retried
// next cycle.
func (m *Monitor) fetchJournal(ctx context.Context, cursor *int64, args ...string) ([]journalwatch.Entry, error) {
	return journalwatch.Fetch(ctx, m.deps.JournalFetch, m.deps.Now(),
		m.cfg().LogLookback, cursor, args...)
}

// SyncKubeletJournal is the kubelet-stale-monitor port: new
// k0sworker.service journal lines → rules → problem_counter + Event.
func (m *Monitor) SyncKubeletJournal(ctx context.Context, s Sink) error {
	entries, err := m.fetchJournal(ctx, &m.kubeletJournalUS,
		"-u", m.cfg().KubeletJournalUnit)
	if err != nil {
		return err
	}
	for _, e := range entries {
		m.matchEventRules(ctx, s, kubeletJournalRules, e.Msg)
	}
	return nil
}

// matchEventRules applies a temporary rule set to one line: every
// matching rule increments problem_counter and emits/aggregates an
// Event — same semantics as the parent's filelog processLogLine.
func (m *Monitor) matchEventRules(ctx context.Context, s Sink, rules []rule, msg string) {
	for _, r := range rules {
		if !r.re.MatchString(msg) {
			continue
		}
		s.BumpCounter(r.reason)
		if err := s.EmitEvent(ctx, r.reason, msg); err != nil {
			logger().Error("nodereporter: event emit failed",
				"reason", r.reason, "error", err)
		}
	}
}
