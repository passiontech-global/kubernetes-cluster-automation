// Condition evaluation + node status patching.
//
// The latch→condition mapping lives in latchdefs.CondDefs (the SSOT
// ported 1:1 from the removed NPD watchdog-state-monitor.json:
// Type, default Reason/Message, permanent-rule problem Reason and
// the state-<key> latch file the check script probed); this file
// only fixes the rendered order (conditionOrder) and projects the
// defs. WatchdogStale is the special one — check-watchdog-fresh.sh
// gated on the `installed` marker and compared `last-run` age to
// 1200s — so it stays a local def with no latch.
package nodereporter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
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
	// altStateKeys are optional extra latches that trip the same
	// condition — the T15 kubelet watchdog's state-kubelet-healthz-down
	// (restart budget exhausted) and the A4 probes'
	// state-kubelet-syncloop-down / state-containerd-sock-down must
	// all fire KubeletRuntimeStall so the existing NHC
	// k0sworker-remediate-exhausted rule keeps working (BUG-H4).
	altStateKeys []string
}

// conditionOrder is the rendered node.status.conditions order for the
// latch-backed watchdog conditions — the historical NPD
// watchdog-state-monitor.json order with agent-added surfaces
// appended at the tail. The "" entry is WatchdogStale, the one
// condition whose evidence is a heartbeat-freshness probe rather
// than a state-* latch (see staleConditionDef). Order is
// load-bearing: node_status.conditions is an ordered list and
// consumers/tests compare index-stable output.
var conditionOrder = []string{
	latchdefs.LatchNodeOverloaded,
	"",
	latchdefs.LatchCiliumAgentDown,
	latchdefs.LatchCiliumInitStuck,
	latchdefs.LatchKubeletRuntimeStall,
	latchdefs.LatchDNSFallback,
	latchdefs.LatchDNSResolvStale,
	latchdefs.LatchPodTeardownWedged,
	latchdefs.LatchKubeletWatchWedge,
	latchdefs.LatchJournalUnreadable,
	latchdefs.LatchFilesystemReadonly,
	latchdefs.LatchDStateStorm,
	latchdefs.LatchNebulaIsolated,
	latchdefs.LatchNebulaDegraded,
	latchdefs.LatchCiliumEnvoyDown,
	latchdefs.LatchCiliumIPAMExhausted,
	latchdefs.LatchCiliumBPFMapPressure,
	latchdefs.LatchSpegelMirrorDegraded,
	latchdefs.LatchCalicoVethLeak,
	latchdefs.LatchCalicoFelixDown,
	latchdefs.LatchFail2banDown,
	latchdefs.LatchConntrackPressure,
	latchdefs.LatchKernelKeysPressure,
	latchdefs.LatchCPCertReloadStale,
	latchdefs.LatchPSIMemoryThrash,
	latchdefs.LatchClockUnsync,
	latchdefs.LatchKernelSlabLeak,
	latchdefs.LatchNebulaPMTUBlackhole,
	latchdefs.LatchPIDFDPressure,
	latchdefs.LatchClockSkew,
	latchdefs.LatchKubeconfigCertExpiring,
	latchdefs.LatchCPUStealPressure,
	latchdefs.LatchCgroupDyingLeak,
	latchdefs.LatchSystemdSessionBloat,
	latchdefs.LatchKubeletPLEGUnhealthy,
	latchdefs.LatchDiskSlowIO,
	latchdefs.LatchKernelNetShim,
	latchdefs.LatchClocksourceUnstable,
	latchdefs.LatchCiliumMTUDrift,
	latchdefs.LatchCiliumWGPeerWipe,
	latchdefs.LatchInodePressure,
	latchdefs.LatchKonnectivityIPMismatch,
	latchdefs.LatchCiliumEnvoyXDSReject,
	latchdefs.LatchDiskBloat,
	latchdefs.LatchNebulaMTUBlackhole,
	latchdefs.LatchNebulaSlowpath,
	latchdefs.LatchNebulaSiteedge,
	latchdefs.LatchPageAllocFailure,
	latchdefs.LatchAPIServerCacheWedged,
}

// staleConditionDef is WatchdogStale's def — the one condition whose
// evidence is a freshness probe over the watchdog heartbeat files,
// not a state-* latch, so it has no latchdefs entry by design.
var staleConditionDef = conditionDef{
	typ:            nodecond.WatchdogStale,
	defaultReason:  "WatchdogFresh",
	defaultMessage: "node-watchdog ran recently (last-run < 20 min)",
	problemReason:  "WatchdogStaleDetected",
}

// conditionDefs is the projected latch→condition table: latchdefs.
// CondDefs carries the per-latch metadata (type, reason/message,
// problem reason, alt latches) and conditionOrder fixes the render
// order. Latches without a CondDefs entry have no condition surface
// by design.
var conditionDefs = buildConditionDefs()

// buildConditionDefs projects latchdefs.CondDefs onto conditionOrder.
func buildConditionDefs() []conditionDef {
	defs := make([]conditionDef, 0, len(conditionOrder))
	for _, latch := range conditionOrder {
		if latch == "" {
			defs = append(defs, staleConditionDef)
			continue
		}
		cd, ok := latchdefs.CondDefs[latch]
		if !ok {
			continue
		}
		defs = append(defs, conditionDef{
			typ:            corev1.NodeConditionType(cd.Type),
			defaultReason:  cd.DefaultReason,
			defaultMessage: cd.DefaultMessage,
			problemReason:  cd.ProblemReason,
			stateKey:       latch,
			altStateKeys:   cd.Alts,
		})
	}
	return defs
}

// condEval is the evaluated state of one condition this cycle.
type condEval struct {
	def     conditionDef
	status  corev1.ConditionStatus
	reason  string
	message string
}

// wantedCond flattens one evaluated condition — a watchdog latch
// condition or an NPD monitor condition — to the fields the
// diff/patch pass needs.
type wantedCond struct {
	typ         corev1.NodeConditionType
	status      corev1.ConditionStatus
	reason      string
	message     string
	gaugeReason string // problem_gauge reason label
}

// syncConditions evaluates BOTH the watchdog latch conditions and
// the two NPD monitor conditions, updates problem_gauge for all of
// them, then merges every diff into ONE status patch — one Node
// GET + at most one PATCH per cycle (the two evaluators used to
// fetch and patch separately, doubling apiserver traffic). A GET
// failure skips the patch only — gauges are purely local and
// always update.
func (r *Reporter) syncConditions(ctx context.Context) error {
	var all []wantedCond
	for _, e := range r.evalConditions() {
		all = append(all, wantedCond{e.def.typ, e.status, e.reason,
			e.message, e.def.problemReason})
	}
	for _, e := range r.monitors.EvalConditions() {
		all = append(all, wantedCond{
			typ: e.Type, status: e.Status, reason: e.Reason,
			message: e.Message, gaugeReason: e.GaugeReason})
	}
	for _, w := range all {
		v := 0.0
		if w.status == corev1.ConditionTrue {
			v = 1
		}
		r.problemGauge.WithLabelValues(string(w.typ), w.gaugeReason).Set(v)
	}

	node, err := r.cfg.Client.CoreV1().Nodes().Get(ctx, r.cfg.NodeName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get node %s: %w", r.cfg.NodeName, err)
	}
	live := make(map[corev1.NodeConditionType]corev1.NodeCondition, len(node.Status.Conditions))
	for _, c := range node.Status.Conditions {
		live[c.Type] = c
	}
	now := metav1.NewTime(r.cfg.Clock.Now())

	// Zero-churn gate: PATCH only when a Status or Reason differs —
	// message-only drift (e.g. the WatchdogStale age counter ticking)
	// does not churn the API.
	changed := false
	var changedList []string
	// heartbeatDue is the gate's other trigger: lastHeartbeatTime is
	// the reporter-liveness stamp cluster-side checks trust
	// (node-hang-precordon refuses a condition whose heartbeat
	// froze — a dead reporter's True value may be a zombie). A
	// steady condition set still re-patches once per
	// HeartbeatInterval so "heartbeat fresh" keeps meaning
	// "reporter alive"; anything that writes our conditions without
	// a stamp is refreshed on the next cycle.
	heartbeatDue := false
	for _, w := range all {
		cur, ok := live[w.typ]
		if !ok || cur.Status != w.status || cur.Reason != w.reason {
			changed = true
			changedList = append(changedList, fmt.Sprintf(
				"%s=%s(%s)", w.typ, w.status, w.reason))
			continue
		}
		if now.Sub(cur.LastHeartbeatTime.Time) >= r.cfg.HeartbeatInterval {
			heartbeatDue = true
		}
	}
	if !changed && !heartbeatDue {
		return nil
	}

	// conditions carry patchStrategy=merge patchMergeKey=type — a
	// strategic merge patch updates only our entries and leaves
	// kubelet-owned conditions (Ready, *Pressure, ...) untouched.
	conds := make([]corev1.NodeCondition, 0, len(all))
	for _, w := range all {
		ltt := now
		// Transition time moves only on a status flip; a reason-only
		// change keeps the original transition timestamp (the NPD and
		// kubelet convention).
		if cur, ok := live[w.typ]; ok && cur.Status == w.status {
			ltt = cur.LastTransitionTime
		}
		conds = append(conds, corev1.NodeCondition{
			Type:               w.typ,
			Status:             w.status,
			Reason:             w.reason,
			Message:            w.message,
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
	if len(changedList) > 0 {
		logger().Info("nodereporter: node conditions updated",
			"node", r.cfg.NodeName, "changed", changedList)
	} else {
		// Routine heartbeat refresh — Debug, or the periodic
		// re-patch would read as real churn in the logs.
		logger().Debug("nodereporter: node condition heartbeats refreshed",
			"node", r.cfg.NodeName)
	}
	return nil
}

// evalConditions reads the latch files once and computes the wanted
// state of all watchdog conditions.
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
		} else if key, since, ok := r.firstLatch(d.stateKey, d.altStateKeys); ok {
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
// first present one's key + content — multi-latch conditions name
// their fallback keys in altStateKeys (primary wins on the message).
func (r *Reporter) firstLatch(primary string, alts []string) (key, since string, ok bool) {
	for _, k := range append([]string{primary}, alts...) {
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
	data, err := os.ReadFile(r.state.Path(key))
	if err != nil {
		return "", false
	}
	if s := strings.TrimSpace(string(data)); s != "" {
		return s, true
	}
	return "unknown", true
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
	age := r.cfg.Clock.Now().Unix() - ts
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
