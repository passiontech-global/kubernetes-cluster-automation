// localpv_quota.go — the localpv-quota LocalPV hard-quota
// enforcer side-guard that rides the DiskBloatCheck cycle slot
// (pvc-* over 1.5x capacity under disk pressure → deprioritize
// the owning pod's tasks).
package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// --- localpv-quota: LocalPV hard-quota enforcer ---
//
// A pod writing past 1.5x its PV's capacity on an OpenEBS localpv
// hostpath under disk pressure (>80% used) starves every other
// volume on the node — the provisioner has no quota of its own.
// The enforcer measures each pvc-* dir under the provisioner
// roots, resolves the owning pod through the pod LIST's
// volume->PVC->PV chain, and deprioritizes that pod's processes
// (renice +19 + ionice idle + cgroup io.weight=1 when the v2
// interface exists). Throttled pods land in the
// localPVThrottled ledger — one throttle per agent lifetime; the
// deprioritization is sticky until the pod restarts anyway.

// localPVScanRoots returns the roots the quota scan walks —
// LocalPVQuotaDir when configured, else the ST2 provisioner roots.
func (c *DiskBloatCheck) localPVScanRoots() []string {
	if c.d.Cfg.Disk.LocalPVQuotaDir != "" {
		return []string{c.d.Cfg.Disk.LocalPVQuotaDir}
	}
	return c.d.Cfg.Disk.OrphanHostPathDirs
}

// localPVQuota runs one localpv-quota round: over-quota pvc-* dirs under
// disk pressure get their owning pod's tasks deprioritized and a
// LocalPVQuotaExceeded event emitted.
func (c *DiskBloatCheck) localPVQuota(ctx context.Context, e *wdeps.CycleEnv) {
	if !e.APIOK || c.d.Cfg.Client == nil {
		return // PV/PVC resolution needs the apiserver
	}
	if c.localPVThrottled == nil {
		c.localPVThrottled = map[string]bool{}
	}
	pvs, err := c.d.Cfg.Client.CoreV1().PersistentVolumes().
		List(ctx, metav1.ListOptions{})
	if err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: localpv-quota PV list failed: %v — quota scan inconclusive", err))
		return
	}
	pvCap := map[string]int64{}
	for _, pv := range pvs.Items {
		if q, ok := pv.Spec.Capacity[corev1.ResourceStorage]; ok {
			pvCap[pv.Name] = q.Value()
		}
	}
	// claim->pod map: pod.Spec.Volumes[].PersistentVolumeClaim —
	// resolve each claim to its PV name via a cluster-wide PVC list.
	pvcs, err := c.d.Cfg.Client.CoreV1().PersistentVolumeClaims("").
		List(ctx, metav1.ListOptions{})
	if err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: localpv-quota PVC list failed: %v — quota scan inconclusive", err))
		return
	}
	claimPV := map[string]string{} // "<ns>/<claim>" -> volumeName
	for _, pvc := range pvcs.Items {
		claimPV[pvc.Namespace+"/"+pvc.Name] = pvc.Spec.VolumeName
	}
	podByPV := map[string]*corev1.Pod{}
	for i := range e.Pods {
		for _, v := range e.Pods[i].Spec.Volumes {
			if v.PersistentVolumeClaim == nil {
				continue
			}
			if pv := claimPV[e.Pods[i].Namespace+"/"+
				v.PersistentVolumeClaim.ClaimName]; pv != "" {
				podByPV[pv] = &e.Pods[i]
			}
		}
	}
	for _, root := range c.localPVScanRoots() {
		ents, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, ent := range ents {
			if !ent.IsDir() || !strings.HasPrefix(ent.Name(), "pvc-") {
				continue
			}
			dir := filepath.Join(root, ent.Name())
			cap, ok := pvCap[ent.Name()]
			if !ok || cap <= 0 || c.localPVThrottled[dir] {
				continue
			}
			size, _ := c.d.WalkBytes(dir)
			if size <= int64(float64(cap)*c.d.Cfg.Disk.LocalPVQuotaRatio) {
				continue
			}
			// The quota only bites under real disk pressure —
			// over-request-but-plenty-free is a sizing problem,
			// not a node emergency.
			if !c.d.DiskUsageAboveWatermark(root) {
				continue
			}
			pod := podByPV[ent.Name()]
			if pod == nil {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: localpv-quota %s %dB > %.0fx PV cap (%dB) but no owning pod on this node",
					dir, size, c.d.Cfg.Disk.LocalPVQuotaRatio, cap))
				continue
			}
			c.throttlePVTasks(ctx, e, pod, dir, size, cap)
		}
	}
}

// throttlePVTasks deprioritizes every live task pid of the pod:
// renice +19 + ionice idle via the shared seams, plus cgroup v2
// io.weight=1 on the pod slice when the interface exists. The
// io.max variant is deliberately NOT written — an absolute byte
// rate has no safe value without device knowledge; io.weight
// achieves the same relative starvation (documented deviation).
func (c *DiskBloatCheck) throttlePVTasks(ctx context.Context,
	e *wdeps.CycleEnv, pod *corev1.Pod, dir string, size, cap int64) {

	uid := string(pod.UID)
	tasks, _ := e.TasksOnce()
	throttled := 0
	for _, t := range tasks[uid] {
		if !t.Live || t.PID <= 0 {
			continue
		}
		if err := c.d.Cfg.Seams.Host.ReniceFn(t.PID); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: localpv-quota renice +19 pid=%d failed: %v", t.PID, err))
		}
		if err := c.d.Cfg.Seams.Host.IoniceIdleFn(t.PID); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: localpv-quota ionice -c3 pid=%d failed: %v", t.PID, err))
		}
		throttled++
	}
	// cgroup v2 io.weight drop — best-effort: write `1` (lowest
	// weight) on the pod slice's io.weight if the file exists.
	kubepods := filepath.Join(c.d.Cfg.Runtime.CgroupRoot, "kubepods.slice")
	for _, podDir := range podSliceDirs(kubepods) {
		if podUIDFromSlice(podDir) != uid {
			continue
		}
		wf := filepath.Join(podDir, "io.weight")
		if _, err := os.Stat(wf); err == nil {
			if werr := os.WriteFile(wf, []byte("1"), 0o644); werr != nil {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: localpv-quota io.weight write %s failed: %v", wf, werr))
			}
		}
		for _, scope := range containerScopeDirs(podDir) {
			wf := filepath.Join(scope, "io.weight")
			if _, err := os.Stat(wf); err == nil {
				_ = os.WriteFile(wf, []byte("1"), 0o644)
			}
		}
	}
	c.localPVThrottled[dir] = true
	c.d.LocalPVQuotaThrottled++
	c.emitPVQuotaEvent(ctx, pod, dir, size, cap, throttled)
	c.d.Actions.WithLabelValues(wdeps.CheckDiskBloat, "localpv_throttle").Inc()
}

// emitPVQuotaEvent creates the LocalPVQuotaExceeded Warning event
// on the throttled pod.
func (c *DiskBloatCheck) emitPVQuotaEvent(ctx context.Context,
	pod *corev1.Pod, dir string, size, cap int64, throttled int) {
	now := c.d.Cfg.Seams.Host.Clock.Now()
	if err := c.d.EmitCheckEvent(ctx, wdeps.CheckEvent{
		Name:      fmt.Sprintf("%s.%x", pod.Name, now.UnixNano()),
		Namespace: pod.Namespace,
		Reason:    "LocalPVQuotaExceeded",
		Note: fmt.Sprintf(
			"localpv dir %s holds %d bytes > %.0fx PV capacity %d bytes under disk pressure — %d tasks deprioritized (ionice idle + renice +19 + io.weight)",
			dir, size, c.d.Cfg.Disk.LocalPVQuotaRatio, cap, throttled),
		When: now,
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Pod",
			Namespace:  pod.Namespace,
			Name:       pod.Name,
			UID:        pod.UID,
		},
		Owner: pod.Namespace + "/" + pod.Name,
	}); err != nil {
		return
	}
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: LocalPVQuotaExceeded — pod %s/%s dir=%s %dB > %.0fx cap %dB, %d tasks deprioritized",
		pod.Namespace, pod.Name, dir, size,
		c.d.Cfg.Disk.LocalPVQuotaRatio, cap, throttled))
}
