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
	"fmt"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
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
// upstream conditions[] declarations. The Node GET + merged status
// PATCH lives in conditions.go's syncConditions, which evaluates
// this set alongside the watchdog latch conditions and ships both
// in ONE apiserver round-trip per cycle (each evaluator used to
// fetch and patch separately).
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
