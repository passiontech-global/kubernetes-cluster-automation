// npd_journal.go — the journald-plugin monitor port
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
// fallback shares the same fetch (npd_kernel.go).
package nodereporter

import (
	"context"
	"regexp"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/journalwatch"
)

// kubelet-stale-monitor.json rules — journald plugin, temporary
// only. KubeletNodeNotFound covers both the klog-escaped quoting the
// values.yaml pattern decoded to (`node \"X\" not found` — the
// informer-zombie spam signature) and the plain form.
var kubeletJournalRules = []logRule{
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
func (r *Reporter) fetchJournal(ctx context.Context, cursor *int64, args ...string) ([]journalwatch.Entry, error) {
	return journalwatch.Fetch(ctx, r.cfg.journalFetch, r.cfg.Clock.Now(),
		r.cfg.LogLookback, cursor, args...)
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
		r.matchEventRules(ctx, kubeletJournalRules, e.Msg)
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
			logger().Error("nodereporter: event emit failed",
				"reason", rule.reason, "error", err)
		}
	}
}
