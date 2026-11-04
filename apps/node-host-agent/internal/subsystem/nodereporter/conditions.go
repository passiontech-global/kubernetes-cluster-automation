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
	// altStateKeys are optional extra latches that trip the same
	// condition — the T15 kubelet watchdog's state-kubelet-healthz-down
	// (restart budget exhausted) and the A4 probes'
	// state-kubelet-syncloop-down / state-containerd-sock-down must
	// all fire KubeletRuntimeStall so the existing NHC
	// k0sworker-remediate-exhausted rule keeps working (BUG-H4).
	altStateKeys []string
}

// conditionDefs is the watchdog-condition table ported from the NPD
// JSON — order preserved so rendered status.conditions stays stable —
// plus agent-added entries at the tail (JournaldUnreadable).
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
		// BUG-H4: the PLEG/syncloop freeze and the hung containerd
		// socket are runtime stalls too — every latch must light
		// the condition.
		altStateKeys: []string{
			"kubelet-healthz-down",
			"kubelet-syncloop-down",
			"containerd-sock-down",
		},
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
	{
		// Agent-added (not in the NPD JSON): the journalwatch
		// tracker's blindness latch — journald installed but every
		// journal read produces nothing, so all journal-grep checks
		// and this reporter's own journal monitors are blind.
		typ:            "JournaldUnreadable",
		defaultReason:  "JournaldReadable",
		defaultMessage: "journald journal reads return entries",
		problemReason:  "JournaldUnreadableDetected",
		stateKey:       "journal-unreadable",
	},
	{
		// Agent-added (W5.3): hostmetrics' statfs probes found a
		// mount reporting ST_RDONLY — the fs remounted read-only
		// (kernel error path) and every write on it silently fails.
		typ:            "FilesystemReadOnly",
		defaultReason:  "FilesystemReadWrite",
		defaultMessage: "all probed filesystems are read-write",
		problemReason:  "FilesystemReadOnlyDetected",
		stateKey:       "filesystem-readonly",
	},
	{
		// Agent-added (W7-H1): workerhygiene's D-state storm
		// detector — >=5 tasks (or >=2 runtime-critical) stuck in
		// uninterruptible sleep means a hung kernel IO path no
		// service restart can clear; NHC→SNR owns the remedy.
		typ:            "KernelHungTasks",
		defaultReason:  "KernelTasksRunOk",
		defaultMessage: "no D-state task storm (uninterruptible sleep below threshold)",
		problemReason:  "KernelHungTasksDetected",
		stateKey:       "d-state-storm",
	},
	// --- Wave-8 latch→condition surface ---
	// Agent-added conditions for the latches the hygiene subsystems
	// already wrote (or Wave-8 adds): every state-<key> below maps
	// 1:1 to a permanent NodeCondition so the NHC→SNR chain and the
	// problem_gauge series cover the full latch set.
	{
		typ:            "NebulaIsolated",
		defaultReason:  "NebulaMeshHealthy",
		defaultMessage: "all nebula peers handshake normally",
		problemReason:  "NebulaIsolatedDetected",
		stateKey:       "nebula-isolated",
	},
	{
		typ:            "NebulaDegraded",
		defaultReason:  "NebulaDataplaneOk",
		defaultMessage: "nebula dataplane healthy (no relay/latency degradation)",
		problemReason:  "NebulaDegradedDetected",
		stateKey:       "nebula-degraded",
	},
	{
		typ:            "CiliumEnvoyDown",
		defaultReason:  "CiliumEnvoyReady",
		defaultMessage: "cilium-envoy admin /ready OK",
		problemReason:  "CiliumEnvoyDownDetected",
		stateKey:       "cilium-envoy-down",
	},
	{
		typ:            "CiliumIPAMExhausted",
		defaultReason:  "CiliumIPAMOk",
		defaultMessage: "cilium IPAM pool has headroom (no address leak)",
		problemReason:  "CiliumIPAMExhaustedDetected",
		stateKey:       "cilium-ipam-exhausted",
	},
	{
		typ:            "CiliumBPFMapPressure",
		defaultReason:  "CiliumBPFMapsOk",
		defaultMessage: "critical cilium BPF maps below 90% capacity",
		problemReason:  "CiliumBPFMapPressureDetected",
		stateKey:       "cilium-bpf-map-pressure",
	},
	{
		typ:            "SpegelMirrorDegraded",
		defaultReason:  "SpegelMirrorReady",
		defaultMessage: "spegel P2P mirror pod Ready",
		problemReason:  "SpegelMirrorDegradedDetected",
		stateKey:       "spegel-mirror-degraded",
	},
	{
		typ:            "CalicoVethLeak",
		defaultReason:  "CalicoVethCountOk",
		defaultMessage: "cali* veth count matches pod count (no CNI DEL leak)",
		problemReason:  "CalicoVethLeakDetected",
		stateKey:       "calico-veth-leak",
	},
	{
		typ:            "CalicoFelixDown",
		defaultReason:  "CalicoFelixReady",
		defaultMessage: "calico felix :9099 readiness OK",
		problemReason:  "CalicoFelixDownDetected",
		stateKey:       "calico-felix-down",
	},
	{
		typ:            "Fail2banDown",
		defaultReason:  "Fail2banActive",
		defaultMessage: "fail2ban service installed and active",
		problemReason:  "Fail2banDownDetected",
		stateKey:       "fail2ban-down",
	},
	{
		typ:            "ConntrackPressure",
		defaultReason:  "ConntrackNormal",
		defaultMessage: "nf_conntrack table below pressure threshold",
		problemReason:  "ConntrackPressureDetected",
		stateKey:       "conntrack-pressure",
	},
	{
		typ:            "KernelKeysPressure",
		defaultReason:  "KernelKeysNormal",
		defaultMessage: "kernel keyring quota below pressure threshold",
		problemReason:  "KernelKeysPressureDetected",
		stateKey:       "kernel-keys-pressure",
	},
	{
		typ:            "ControlPlaneCertReloadStale",
		defaultReason:  "ControlPlaneCertReloadFresh",
		defaultMessage: "control-plane cert reload markers fresh",
		problemReason:  "ControlPlaneCertReloadStaleDetected",
		stateKey:       "cp-cert-reload-stale",
	},
	{
		typ:            "MemoryPSIThrashing",
		defaultReason:  "MemoryPSINormal",
		defaultMessage: "memory PSI full avg60 <= 25% or free memory >= 8%",
		problemReason:  "MemoryPSIThrashingDetected",
		stateKey:       "psi-memory-thrash",
	},
}

// condEval is the evaluated state of one condition this cycle.
type condEval struct {
	def     conditionDef
	status  corev1.ConditionStatus
	reason  string
	message string
}

// syncConditions evaluates the conditions, updates problem_gauge,
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
	logger().Info("nodereporter: node conditions updated",
		"node", r.cfg.NodeName, "changed", changedList)
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

// initHeartbeatFiles seeds the installed/last-run pair ONCE — only
// for files that don't already exist (BUG-H1). The shell watchdog's
// prom_emit trap owned the periodic last-run refresh; on agent
// nodes the hygiene Cycle()s (workerhygiene/controllerhygiene/
// nethealth) own it now. The reporter still needs the pair on a
// fresh state dir — a missing `installed` disables the staleness
// gate entirely and a missing `last-run` reads as epoch 0 — so it
// initializes them at startup for new envs and unit tests where no
// hygiene subsystem has run yet.
//
// `installed` is created only when absent (ansible force:false
// parity — presence activates the probe's gate, content is the
// baseline epoch used when last-run doesn't exist yet); `last-run`
// is likewise created only when absent, atomically via tmp+rename
// so a reader never observes a truncated epoch.
func (r *Reporter) initHeartbeatFiles() error {
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
	if _, err := os.Stat(lastRun); os.IsNotExist(err) {
		if err := writeEpochFile(lastRun, now); err != nil {
			return fmt.Errorf("write %s: %w", lastRun, err)
		}
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
