// readonly.go — the readonly-monitor port plus the
// ReadonlyFilesystem condition strings it feeds. Upstream also
// watched kmsg ("Remounting filesystem read-only"); this port
// checks the actual mount table instead — /proc/1/mounts (hostPID
// -> the HOST mount table, a container procfs would only see the
// pod's mount ns) for the watched mountpoints on ext4/xfs/btrfs —
// so ReadonlyFilesystem clears when the fs is remounted rw, which
// the kmsg pattern never could. The evaluated condition itself
// ships through monitor.go's EvalConditions — the parent's
// syncConditions merges it into the one status patch per cycle.
package npd

import (
	"context"
	"fmt"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// The ReadonlyFilesystem NodeCondition and its upstream strings
// (readonly-monitor.json conditions[]).
const (
	condReadonlyFS corev1.NodeConditionType = nodecond.ReadonlyFilesystem

	readonlyDefaultReason = "FilesystemIsNotReadOnly"
	readonlyDefaultMsg    = "Filesystem is not read-only"
	readonlyProblemReason = "FilesystemIsReadOnly"
)

// readonlyTargets returns the watched mountpoints currently mounted
// read-only on a watched fstype, formatted for the condition message
// ("<mp> (<fstype>)"). A target absent from the table or on another
// fstype is not reported. mounts is mountpoint → topmost Mount —
// procfs.LastByMountPoint's reduction (stacked binds keep the LAST
// entry, matching the kernel's lookup).
func readonlyTargets(mounts map[string]procfs.Mount, targets, fstypes []string) []string {
	fs := make(map[string]bool, len(fstypes))
	for _, t := range fstypes {
		fs[t] = true
	}
	var ro []string
	for _, t := range targets {
		e, ok := mounts[t]
		if !ok || !fs[e.FSType] {
			continue
		}
		if e.HasOpt("ro") {
			ro = append(ro, fmt.Sprintf("%s (%s)", t, e.FSType))
		}
	}
	return ro
}

// SyncReadonlyMounts is the readonly-monitor port: watched host
// mountpoints mounted ro → ReadonlyFilesystem=True, cleared when all
// are rw again. Emits one Event per False→True transition.
func (m *Monitor) SyncReadonlyMounts(ctx context.Context, s Sink) error {
	cfg := m.cfg()
	data, err := os.ReadFile(cfg.ProcMountsFile)
	if err != nil {
		return fmt.Errorf("read %s: %w", cfg.ProcMountsFile, err)
	}
	ro := readonlyTargets(procfs.LastByMountPoint(procfs.ParseMounts(data)),
		cfg.ReadonlyTargets, cfg.ReadonlyFSTypes)
	was := m.readonlyFS
	m.readonlyFS = len(ro) > 0
	if m.readonlyFS {
		m.readonlyFSMsg = "read-only filesystems: " + strings.Join(ro, ", ")
		if !was {
			if err := s.EmitEvent(ctx, readonlyProblemReason, m.readonlyFSMsg); err != nil {
				logger().Error("nodereporter: event emit failed",
					"reason", readonlyProblemReason, "error", err)
			}
		}
	}
	return nil
}
