// fsreadonly.go — W10-ST1 updateFSReadonlyEvidence: ro ext4/xfs/btrfs
// mounts under the PVC provisioner roots parsed out of
// /proc/<pid>/mounts → state-fs-readonly (FilesystemReadOnly) ahead
// of statfs. The Wave-10 contract overview lives in kernel_failure_latches.go.
package hostmetrics

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
)

// fsErrorLatchTTL bounds state-fs-readonly's kernel-error
// evidence: a marker older than this no longer holds the latch
// (a single ext4 error from a transient USB reset must not
// latch FilesystemReadOnly forever).
const fsErrorLatchTTL = 30 * time.Minute

// --- W10-ST1: read-only mounts under PVC dirs ---

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

// procMount is one parsed /proc/*/mounts line.
type procMount struct {
	mp     string
	fstype string
	src    string
	ro     bool
}

// parseProcMounts parses mount-table content —
// "src mp fstype opts dump pass" per line, octal escapes ignored
// (mountpoints with spaces are rare under the PVC roots and a
// missed escape only narrows matching, never widens it).
func parseProcMounts(data []byte) []procMount {
	var out []procMount
	for _, ln := range strings.Split(string(data), "\n") {
		f := strings.Fields(ln)
		if len(f) < 4 {
			continue
		}
		opts := strings.Split(f[3], ",")
		m := procMount{src: f[0], mp: f[1], fstype: f[2]}
		for _, o := range opts {
			if o == "ro" {
				m.ro = true
			}
		}
		out = append(out, m)
	}
	return out
}

// pvcMountRoots returns the host-side roots whose submounts are PVC
// backing volumes — OpenEBS LocalPV, local-path-provisioner, and the
// kubelet pods dir (hostPath + PVC bind mounts alike). The mount
// table reports HOST paths, so these are literal host paths —
// OpenEBSLocalDir already follows that convention.
func (l *Latches) pvcMountRoots() []string {
	return []string{
		l.c.cfg.OpenEBSLocalDir,
		"/opt/local-path-provisioner",
		"/var/lib/k0s/kubelet/pods",
	}
}

// roPVCMounts returns "mp (fstype)" for every ro ext4/xfs/btrfs
// mount under a PVC root that isn't an expected Kubernetes ro bind.
func (l *Latches) roPVCMounts() []string {
	// /proc/1/mounts is the host mount table under hostPID (the
	// DaemonSet contract); ProcRoot/mounts covers odd layouts.
	var data []byte
	var err error
	for _, p := range []string{
		filepath.Join(l.c.cfg.ProcRoot, "1", "mounts"),
		filepath.Join(l.c.cfg.ProcRoot, "mounts"),
	} {
		if data, err = os.ReadFile(p); err == nil {
			break
		}
	}
	if err != nil {
		return nil
	}
	roots := l.pvcMountRoots()
	var out []string
	for _, m := range parseProcMounts(data) {
		if !m.ro || !pvcMountFSTypes[m.fstype] {
			continue
		}
		under := false
		for _, r := range roots {
			if r == "" {
				continue
			}
			if m.mp == r || strings.HasPrefix(m.mp, r+"/") {
				under = true
				break
			}
		}
		if !under {
			continue
		}
		if k8sROBindExcludeRe.MatchString(m.mp) ||
			k8sROBindExcludeRe.MatchString(m.src) {
			continue
		}
		out = append(out, m.mp+" ("+m.fstype+")")
	}
	return out
}

// updateFSReadonlyEvidence drives state-fs-readonly — the Wave-10
// evidence latch feeding FilesystemReadOnly. Two evidence sources,
// either sufficient:
//
//   - a kmsg-fs-error marker younger than fsErrorLatchTTL (kernel
//     saw a filesystem/block error — the fs may already be remounted
//     ro or heading there), and
//   - an ro ext4/xfs/btrfs mount under a PVC root in the host mount
//     table (W10-ST1 — catches the remount statfs hasn't probed).
//
// The latch clears only when BOTH evidences are absent; an
// unreadable mounts file contributes nothing (fail-safe, not
// fail-latch).
func (l *Latches) updateFSReadonlyEvidence() {
	p := l.c.state.Path(hoststate.LatchFSReadonly)
	_, lerr := os.Stat(p)
	evidence := ""
	if b, err := os.ReadFile(l.statePath(kmsgFsErrorFile)); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if epoch, perr := strconv.ParseInt(f[0], 10, 64); perr == nil {
				age := l.c.cfg.nowFn().Unix() - epoch
				if age >= 0 && age < int64(fsErrorLatchTTL.Seconds()) {
					evidence = "kernel-fs-error"
				} else {
					_ = os.Remove(l.statePath(kmsgFsErrorFile))
				}
			}
		}
	}
	if ros := l.roPVCMounts(); len(ros) > 0 {
		if evidence != "" {
			evidence += " + "
		}
		evidence += "ro-mount: " + strings.Join(ros, ", ")
	}
	switch {
	case evidence != "" && lerr != nil:
		l.ensureStateLatch(p, hoststate.LatchFilePrefix+hoststate.LatchFSReadonly, evidence)
	case evidence == "" && lerr == nil:
		// STATE-EXIT: the file is the contract half; the log line
		// is what nodereporter's filelog tails for the transition.
		l.c.state.Exit(hoststate.LatchFSReadonly, nil)
	}
}
