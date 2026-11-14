// writable_layer.go — disk side-guard promoted out of DiskBloatCheck into
// its own wdeps.Check (wdeps.CheckWritableLayer): per-guard WD_SIG kill
// switch, cycles{check,result} series and action labels. The
// guard body is unchanged — it always ran on the shared *wdeps.Deps.
package runtime

import (
	"context"
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

type WritableLayerCheck struct{ d *wdeps.Deps }

// NewWritableLayer builds the wlayer disk guard check.
func NewWritableLayer(d *wdeps.Deps) *WritableLayerCheck { return &WritableLayerCheck{d: d} }

// Name returns the check label / WD_SIG key.
func (c *WritableLayerCheck) Name() string { return wdeps.CheckWritableLayer }

// Run executes one wlayer round under its own gate.
func (c *WritableLayerCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckWritableLayer) {
		return
	}
	c.writableLayerScan(ctx, e)
	c.d.CycleResult(wdeps.CheckWritableLayer, "ok")
}

func (c *WritableLayerCheck) writableLayerScan(ctx context.Context, e *wdeps.CycleEnv) {
	if !e.APIOK || c.d.Cfg.Client == nil {
		return // pod attribution needs the apiserver
	}
	if !c.d.State.RateTrySpend("last-wlayer-scan",
		c.d.Cfg.Disk.BloatScanInterval) {
		return
	}
	threshold := c.d.Cfg.Disk.WLayerBloatThresholdBytes
	podByUID := e.PodByUID()
	// (a) overlayfs snapshot upperdirs — snapshot dir names are
	// numeric on containerd; snapshotMountIDs binds each to its
	// task id through the live rootfs mount's upperdir=, and
	// taskDirPodUID resolves that to the pod uid annotation.
	mountIDs := snapshotMountIDs(c.d)
	for _, snap := range readDirNames(c.d.Cfg.Disk.WLayerSnapshotsDir) {
		fsDir := filepath.Join(snap, "fs")
		size, _ := walkBytes(c.d, e, fsDir)
		if size <= threshold {
			continue
		}
		var pod *corev1.Pod
		if uid := snapshotPodUID(c.d, filepath.Base(snap), mountIDs); uid != "" {
			pod = podByUID[uid]
		}
		if podDeclaresEphemeralStorage(pod) {
			continue
		}
		c.emitWLayerBloatEvent(ctx, pod, fsDir, size)
	}
	// (b) kubelet pod emptyDir volumes of pods without the limit —
	// the write surface the snapshot key can't see. Restricted to
	// volumes/kubernetes.io~empty-dir: configmap/secret/projected
	// volumes are kubelet-materialized (read-only), and a
	// medium=Memory emptyDir is tmpfs-backed — it fills RAM, never
	// the data disk (scanBloat's emptyDir walk applies the same
	// statfs gate).
	for _, uidDir := range readDirNames(c.d.Cfg.PodsDir) {
		pod := podByUID[filepath.Base(uidDir)]
		if podDeclaresEphemeralStorage(pod) {
			continue
		}
		for _, vol := range readDirNames(filepath.Join(
			uidDir, "volumes", "kubernetes.io~empty-dir")) {
			var vst unix.Statfs_t
			if err := c.d.Cfg.Seams.Host.StatfsFn(vol, &vst); err == nil &&
				vst.Type == int64(unix.TMPFS_MAGIC) {
				continue // medium=Memory emptyDir — can't fill the disk
			}
			size, _ := walkBytes(c.d, e, vol)
			if size <= threshold {
				continue
			}
			c.emitWLayerBloatEvent(ctx, pod, vol, size)
		}
	}
}

// emitWLayerBloatEvent raises the ContainerWritableLayerBloat
// Warning event — pod-scoped when the writable layer resolves back
// to a pod on this node, else node-scoped in the event namespace.
func (c *WritableLayerCheck) emitWLayerBloatEvent(ctx context.Context,
	pod *corev1.Pod, dir string, size int64) {
	note := fmt.Sprintf(
		"writable layer %s holds %d bytes > threshold %d and the container declares no limits.ephemeral-storage — DiskPressure risk",
		dir, size, c.d.Cfg.Disk.WLayerBloatThresholdBytes)
	var owner string
	var err error
	if pod != nil {
		owner = "pod " + pod.Namespace + "/" + pod.Name
		err = c.d.EmitPodEvent(ctx, pod, "wlayer", "ContainerWritableLayerBloat", note)
	} else {
		now := c.d.Cfg.Seams.Host.Clock.Now()
		owner = "node " + c.d.Cfg.NodeName
		err = c.d.EmitCheckEvent(ctx, wdeps.CheckEvent{
			Name:      fmt.Sprintf("%s.wlayer.%x", c.d.Cfg.NodeName, now.UnixNano()),
			Namespace: c.d.Cfg.Host.EventNamespace,
			Reason:    "ContainerWritableLayerBloat",
			Note:      note,
			When:      now,
			Regarding: corev1.ObjectReference{
				APIVersion: "v1",
				Kind:       "Node",
				Name:       c.d.Cfg.NodeName,
			},
			Owner: owner,
		})
	}
	if err != nil {
		return
	}
	c.d.State.AppendLog(fmt.Sprintf(
		"ACTION: ContainerWritableLayerBloat — %s dir=%s bytes=%d threshold=%d",
		owner, dir, size, c.d.Cfg.Disk.WLayerBloatThresholdBytes))
	c.d.Actions.WithLabelValues(wdeps.CheckWritableLayer, "wlayer_detect").Inc()
}
