// fsreadonly.go — fs-readonly updateFSReadonlyEvidence: ro ext4/xfs/btrfs
// mounts under the PVC provisioner roots parsed out of
// /proc/<pid>/mounts → state-fs-readonly (FilesystemReadOnly) ahead
// of statfs. The kernelfail contract overview lives in kernelfail.go.
package kernelfail

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
)

// fsErrorLatchTTL bounds state-fs-readonly's kernel-error
// evidence: a marker older than this no longer holds the latch
// (a single ext4 error from a transient USB reset must not
// latch FilesystemReadOnly forever).
const fsErrorLatchTTL = 30 * time.Minute

// --- fs-readonly: read-only mounts under PVC dirs ---

// pvcMountFSTypes are the journaled filesystems a PVC backing mount
// realistically uses — the plan's ext4/xfs plus btrfs (same failure
// class, same ro-remount signature).
var pvcMountFSTypes = map[string]bool{
	"ext4": true, "xfs": true, "btrfs": true,
}

// k8sROBindExcludeRe filters the EXPECTED read-only binds Kubernetes
// creates under pod volume dirs — configmap/secret/projected/
// downwardapi/serviceaccount mounts are ro by design and must never
// count as filesystem faults.
var k8sROBindExcludeRe = regexp.MustCompile(
	`kubernetes\.io~(configmap|secret|projected|downwardapi)|` +
		`kubernetes\.io/serviceaccount`)

// pvcMountRoots returns the host-side roots whose submounts are PVC
// backing volumes — OpenEBS LocalPV, local-path-provisioner, and the
// kubelet pods dir (hostPath + PVC bind mounts alike). The mount
// table reports HOST paths, so these are literal host paths —
// OpenEBSLocalDir already follows that convention.
func (r *Runner) pvcMountRoots() []string {
	return []string{
		r.deps.OpenEBSLocalDir,
		"/opt/local-path-provisioner",
		"/var/lib/k0s/kubelet/pods",
	}
}

// roPVCMounts returns "mp (fstype)" for every ro ext4/xfs/btrfs
// mount under a PVC root that isn't an expected Kubernetes ro bind.
func (r *Runner) roPVCMounts() []string {
	// /proc/1/mounts is the host mount table under hostPID (the
	// DaemonSet contract); ProcRoot/mounts covers odd layouts.
	var data []byte
	var err error
	for _, p := range []string{
		filepath.Join(r.deps.ProcRoot, "1", "mounts"),
		filepath.Join(r.deps.ProcRoot, "mounts"),
	} {
		if data, err = os.ReadFile(p); err == nil {
			break
		}
	}
	if err != nil {
		return nil
	}
	roots := r.pvcMountRoots()
	var out []string
	for _, m := range procfs.ParseMounts(data) {
		if !m.HasOpt("ro") || !pvcMountFSTypes[m.FSType] {
			continue
		}
		under := false
		for _, root := range roots {
			if root == "" {
				continue
			}
			if m.MountPoint == root || strings.HasPrefix(m.MountPoint, root+"/") {
				under = true
				break
			}
		}
		if !under {
			continue
		}
		if k8sROBindExcludeRe.MatchString(m.MountPoint) ||
			k8sROBindExcludeRe.MatchString(m.Source) {
			continue
		}
		out = append(out, m.MountPoint+" ("+m.FSType+")")
	}
	return out
}

// updateFSReadonlyEvidence drives state-fs-readonly — the kernelfail
// evidence latch feeding FilesystemReadOnly. Two evidence sources,
// either sufficient:
//
//   - a kmsg-fs-error marker younger than fsErrorLatchTTL (kernel
//     saw a filesystem/block error — the fs may already be remounted
//     ro or heading there), and
//   - an ro ext4/xfs/btrfs mount under a PVC root in the host mount
//     table (fs-readonly — catches the remount statfs hasn't probed).
//
// The latch clears only when BOTH evidences are absent; an
// unreadable mounts file contributes nothing (fail-safe, not
// fail-latch).
func (r *Runner) updateFSReadonlyEvidence() {
	p := r.deps.Store.Path(latchdefs.LatchFSReadonly)
	_, lerr := os.Stat(p)
	evidence := ""
	if b, err := os.ReadFile(r.statePath(kmsgFsErrorFile)); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if epoch, perr := strconv.ParseInt(f[0], 10, 64); perr == nil {
				age := r.deps.Clock.Now().Unix() - epoch
				if age >= 0 && age < int64(fsErrorLatchTTL.Seconds()) {
					evidence = "kernel-fs-error"
				} else {
					_ = os.Remove(r.statePath(kmsgFsErrorFile))
				}
			}
		}
	}
	if ros := r.roPVCMounts(); len(ros) > 0 {
		if evidence != "" {
			evidence += " + "
		}
		evidence += "ro-mount: " + strings.Join(ros, ", ")
	}
	switch {
	case evidence != "" && lerr != nil:
		r.ensureStateLatch(p, latchdefs.LatchFilePrefix+latchdefs.LatchFSReadonly, evidence)
	case evidence == "" && lerr == nil:
		// STATE-EXIT: the file is the contract half; the log line
		// is what nodereporter's filelog tails for the transition.
		r.deps.Store.Exit(latchdefs.LatchFSReadonly, nil)
	}
}
