// npd_readonly.go — the readonly-monitor port plus the two NPD
// NodeConditions (KernelDeadlock, ReadonlyFilesystem) the monitors
// feed. Upstream also watched kmsg ("Remounting filesystem
// read-only"); this port checks the actual mount table instead —
// /proc/1/mounts (hostPID -> the HOST mount table, a container
// procfs would only see the pod's mount ns) for the watched
// mountpoints on ext4/xfs/btrfs — so ReadonlyFilesystem clears when
// the fs is remounted rw, which the kmsg pattern never could.
//
// The two NodeConditions keep the exact upstream
// type/default-reason/default-message strings and the same
// zero-churn strategic-merge patch mechanics as the 9 watchdog
// conditions in conditions.go — they are kept here so the watchdog
// latch table stays untouched.
package nodereporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// The ReadonlyFilesystem NodeCondition and its upstream strings
// (readonly-monitor.json conditions[]).
const (
	condReadonlyFS corev1.NodeConditionType = "ReadonlyFilesystem"

	readonlyDefaultReason = "FilesystemIsNotReadOnly"
	readonlyDefaultMsg    = "Filesystem is not read-only"
	readonlyProblemReason = "FilesystemIsReadOnly"
)

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
				logger().Error("nodereporter: event emit failed",
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
	var changedList []string
	for _, e := range evals {
		cur, ok := live[e.typ]
		if !ok || cur.Status != e.status || cur.Reason != e.reason {
			changed = true
			changedList = append(changedList, fmt.Sprintf(
				"%s=%s(%s)", e.typ, e.status, e.reason))
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
	logger().Info("nodereporter: npd node conditions updated",
		"node", r.cfg.NodeName, "changed", changedList)
	return nil
}
