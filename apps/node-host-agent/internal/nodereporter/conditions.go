// Condition evaluation + node status patching.
//
// The mapping table is a 1:1 port of the removed NPD
// watchdog-state-monitor.json (custom plugin): Type, default
// Reason/Message, permanent-rule problem Reason and the state-<key>
// latch file the check script probed. WatchdogStale is the special
// one — check-watchdog-fresh.sh gated on the `installed` marker and
// compared `last-run` age to 1200s.
package nodereporter

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// conditionDef is one permanent NodeCondition — 1:1 with a
// conditions[] + permanent rules[] pair of the removed
// watchdog-state-monitor.json.
type conditionDef struct {
	typ            corev1.NodeConditionType
	defaultReason  string
	defaultMessage string
	problemReason  string
	stateKey       string // latch file state-<stateKey>; "" = special probe
	// altStateKey is an optional second latch that trips the same
	// condition — the T15 kubelet watchdog's state-kubelet-healthz-down
	// (restart budget exhausted) must fire KubeletRuntimeStall so the
	// existing NHC k0sworker-remediate-exhausted rule keeps working.
	altStateKey string
}

// conditionDefs is the 9-condition table ported from the NPD JSON —
// order preserved so rendered status.conditions stays stable.
var conditionDefs = []conditionDef{
	{
		typ:            "NodeOverloaded",
		defaultReason:  "NodeLoadNormal",
		defaultMessage: "node not overloaded (load15 <= 4xCPU)",
		problemReason:  "NodeOverloadedDetected",
		stateKey:       "node-overloaded",
	},
	{
		typ:            "WatchdogStale",
		defaultReason:  "WatchdogFresh",
		defaultMessage: "node-watchdog ran recently (last-run < 20 min)",
		problemReason:  "WatchdogStaleDetected",
		// no stateKey — evaluated by watchdogStale() from installed/last-run
	},
	{
		typ:            "CiliumAgentDown",
		defaultReason:  "CiliumAgentUp",
		defaultMessage: "cilium-agent healthz OK",
		problemReason:  "CiliumAgentDownDetected",
		stateKey:       "cilium-agent-down",
	},
	{
		typ:            "CiliumInitStuck",
		defaultReason:  "CiliumEndpointsReady",
		defaultMessage: "no cilium endpoint stuck in init (informer healthy)",
		problemReason:  "CiliumInitStuckDetected",
		stateKey:       "cilium-init-stuck",
	},
	{
		typ:            "KubeletRuntimeStall",
		defaultReason:  "KubeletRuntimeOk",
		defaultMessage: "no phantom-pods wedge (ctr alive, tasks > 0)",
		problemReason:  "KubeletRuntimeStallDetected",
		stateKey:       "kubelet-runtime-stall",
		altStateKey:    "kubelet-healthz-down",
	},
	{
		typ:            "DnsFallbackActive",
		defaultReason:  "DnsDirectOk",
		defaultMessage: "DNS via resolv.conf healthy, no /etc/hosts pin",
		problemReason:  "DnsFallbackEngaged",
		stateKey:       "dns-fallback",
	},
	{
		typ:            "DnsResolvStale",
		defaultReason:  "DnsResolvFresh",
		defaultMessage: "DNS pods (nld/coredns) resolv.conf matches host",
		problemReason:  "DnsResolvStaleDetected",
		stateKey:       "dns-resolv-stale",
	},
	{
		typ:            "PodTeardownWedged",
		defaultReason:  "PodTeardownOk",
		defaultMessage: "no long-Terminating pod with leftover task",
		problemReason:  "PodTeardownWedgedDetected",
		stateKey:       "pod-teardown-wedged",
	},
	{
		typ:            "KubeletWatchWedge",
		defaultReason:  "KubeletWatchOk",
		defaultMessage: "kubelet receives pod assignment normally (no unseen pod)",
		problemReason:  "KubeletWatchWedgeDetected",
		stateKey:       "kubelet-watch-wedge",
	},
}

// condEval is the evaluated state of one condition this cycle.
type condEval struct {
	def     conditionDef
	status  corev1.ConditionStatus
	reason  string
	message string
}

// syncConditions evaluates the 9 conditions, updates problem_gauge,
// then patches the node status iff any Status/Reason differs from the
// live object. A GET failure skips the patch only — gauges are purely
// local and always update.
func (r *Reporter) syncConditions(ctx context.Context) error {
	evals := r.evalConditions()
	for _, e := range evals {
		v := 0.0
		if e.status == corev1.ConditionTrue {
			v = 1
		}
		r.problemGauge.WithLabelValues(string(e.def.typ), e.def.problemReason).Set(v)
	}

	node, err := r.cfg.Client.CoreV1().Nodes().Get(ctx, r.cfg.NodeName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get node %s: %w", r.cfg.NodeName, err)
	}
	live := make(map[corev1.NodeConditionType]corev1.NodeCondition, len(node.Status.Conditions))
	for _, c := range node.Status.Conditions {
		live[c.Type] = c
	}

	// Zero-churn gate: PATCH only when a Status or Reason differs —
	// message-only drift (e.g. the WatchdogStale age counter ticking)
	// does not churn the API.
	changed := false
	var changedList []string
	for _, e := range evals {
		cur, ok := live[e.def.typ]
		if !ok || cur.Status != e.status || cur.Reason != e.reason {
			changed = true
			changedList = append(changedList, fmt.Sprintf(
				"%s=%s(%s)", e.def.typ, e.status, e.reason))
		}
	}
	if !changed {
		return nil
	}

	// conditions carry patchStrategy=merge patchMergeKey=type — a
	// strategic merge patch updates only our 9 entries and leaves
	// kubelet-owned conditions (Ready, *Pressure, ...) untouched.
	now := metav1.NewTime(r.cfg.nowFn())
	conds := make([]corev1.NodeCondition, 0, len(evals))
	for _, e := range evals {
		ltt := now
		// Transition time moves only on a status flip; a reason-only
		// change keeps the original transition timestamp (the NPD and
		// kubelet convention).
		if cur, ok := live[e.def.typ]; ok && cur.Status == e.status {
			ltt = cur.LastTransitionTime
		}
		conds = append(conds, corev1.NodeCondition{
			Type:               e.def.typ,
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
	slog.Info("nodereporter: node conditions updated",
		"node", r.cfg.NodeName, "changed", changedList)
	return nil
}

// evalConditions reads the latch files once and computes the wanted
// state of all 9 conditions.
func (r *Reporter) evalConditions() []condEval {
	out := make([]condEval, 0, len(conditionDefs))
	for _, d := range conditionDefs {
		res := condEval{def: d, status: corev1.ConditionFalse,
			reason: d.defaultReason, message: d.defaultMessage}
		if d.stateKey == "" {
			if stale, age := r.watchdogStale(); stale {
				res.status = corev1.ConditionTrue
				res.reason = d.problemReason
				// Ported from check-watchdog-fresh.sh's echo — NHC/SNR
				// and runbooks historically matched on that string.
				res.message = fmt.Sprintf(
					"node-watchdog missed heartbeat %ds (timer dead or run failed)", age)
			}
		} else if key, since, ok := r.firstLatch(d.stateKey, d.altStateKey); ok {
			res.status = corev1.ConditionTrue
			res.reason = d.problemReason
			// check-watchdog-state.sh echo verbatim.
			res.message = fmt.Sprintf("watchdog state %s active since %s", key, since)
		}
		out = append(out, res)
	}
	return out
}

// firstLatch probes the given latch keys in order and reports the
// first present one's key + content — dual-latch conditions name
// their fallback key in altStateKey (primary wins on the message).
func (r *Reporter) firstLatch(keys ...string) (key, since string, ok bool) {
	for _, k := range keys {
		if k == "" {
			continue
		}
		if s, found := r.stateFileSince(k); found {
			return k, s, true
		}
	}
	return "", "", false
}

// stateFileSince reports whether state-<key> exists, and its content
// (the epoch state_enter wrote; "unknown" when empty/unreadable —
// check-watchdog-state.sh's `|| echo unknown` fallback).
func (r *Reporter) stateFileSince(key string) (string, bool) {
	p := filepath.Join(r.cfg.WatchdogStateDir, "state-"+key)
	data, err := os.ReadFile(p)
	if err != nil {
		return "", false
	}
	if s := strings.TrimSpace(string(data)); s != "" {
		return s, true
	}
	return "unknown", true
}

// writeHeartbeat is the writer half of the installed/last-run
// contract watchdogStale() reads. The shell watchdog's prom_emit
// trap owned it; on agent-managed nodes nothing else writes last-run,
// so the reporter self-heartbeats once per cycle — otherwise its own
// staleness probe latches True ~20m after the last shell heartbeat
// and never clears.
//
// `installed` is created only when absent (ansible force:false
// parity — presence activates the probe's gate, content is the
// baseline epoch used when last-run doesn't exist yet); `last-run`
// is rewritten every cycle, atomically via tmp+rename so a reader
// never observes a truncated epoch.
func (r *Reporter) writeHeartbeat() error {
	if err := os.MkdirAll(r.cfg.WatchdogStateDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", r.cfg.WatchdogStateDir, err)
	}
	now := r.cfg.nowFn().Unix()
	installed := filepath.Join(r.cfg.WatchdogStateDir, "installed")
	if _, err := os.Stat(installed); os.IsNotExist(err) {
		if err := writeEpochFile(installed, now); err != nil {
			return fmt.Errorf("write %s: %w", installed, err)
		}
	}
	lastRun := filepath.Join(r.cfg.WatchdogStateDir, "last-run")
	if err := writeEpochFile(lastRun, now); err != nil {
		return fmt.Errorf("write %s: %w", lastRun, err)
	}
	return nil
}

// writeEpochFile writes "<epoch>\n" (date +%s parity) via a same-dir
// tmp file + rename — atomic on POSIX.
func writeEpochFile(path string, epoch int64) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(epoch, 10)+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// watchdogStale is check-watchdog-fresh.sh ported: no `installed`
// marker → not stale (node without the watchdog must never
// false-positive). Baseline timestamp is last-run's content, falling
// back to installed's, then 0; non-numeric content parses to 0 —
// same as the shell's arithmetic treating garbage as 0. age >
// threshold → stale.
func (r *Reporter) watchdogStale() (bool, int64) {
	installedPath := filepath.Join(r.cfg.WatchdogStateDir, "installed")
	if _, err := os.Stat(installedPath); err != nil {
		return false, 0
	}
	ts := int64(0)
	if data, err := os.ReadFile(filepath.Join(r.cfg.WatchdogStateDir, "last-run")); err == nil {
		ts = parseEpoch(data)
	} else if data, err := os.ReadFile(installedPath); err == nil {
		ts = parseEpoch(data)
	}
	age := r.cfg.nowFn().Unix() - ts
	if age < 0 {
		age = 0 // clock skew / future timestamp → fresh
	}
	return age > int64(r.cfg.StaleThreshold.Seconds()), age
}

// parseEpoch parses a watchdog epoch file; garbage → 0 (shell parity:
// non-numeric content collapses to 0 inside $((...))).
func parseEpoch(b []byte) int64 {
	v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}
