// gpu_guard.go — GPUGuardCheck (wdeps.CheckGPUGuard, P2.12): compares the
// node's nvidia.com/gpu allocatable against sysfs 0x10de census and device-plugin
// pod health, bouncing wedged plugins. Split out of csi_gpu_reg.go.
package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

const gpuPCIZeroRescanTTL = 10 * time.Minute

// GPUGuardCheck is the P2.12 plugin half: it compares the node's
// nvidia.com/gpu allocatable against the device-plugin pod's
// health and bounces a wedged plugin. The hardware/sysfs evidence
// is kernelfail's job (gpu_pcie.go → GPUHardwareError); this
// check owns only the Kubernetes registration surface.
type GPUGuardCheck struct {
	d              *wdeps.Deps
	desyncSince    time.Time
	zeroPCIDir     string
	zeroPCIModTime time.Time
	zeroPCIAt      time.Time
}

// NewGPUGuard builds the check.
func NewGPUGuard(d *wdeps.Deps) *GPUGuardCheck {
	return &GPUGuardCheck{d: d}
}

// Name returns the check label / WD_SIG key.
func (c *GPUGuardCheck) Name() string { return wdeps.CheckGPUGuard }

// devicePluginPods returns the node's GPU device-plugin pods —
// DaemonSet pods whose name or image carries nvidia-device-plugin.
func (c *GPUGuardCheck) devicePluginPods(e *wdeps.CycleEnv) []*corev1.Pod {
	var out []*corev1.Pod
	for i := range e.Pods {
		p := &e.Pods[i]
		// DaemonSet-owned only — a bare name match could hit a
		// Deployment pod (e.g. a *-csi-controller) and bounce a
		// cluster-side controller by mistake.
		if !isDaemonSetPod(p) {
			continue
		}
		lname := strings.ToLower(p.Name)
		match := strings.Contains(lname, "nvidia-device-plugin")
		if !match {
			for _, img := range p.Spec.Containers {
				if strings.Contains(strings.ToLower(img.Image),
					"nvidia-device-plugin") {
					match = true
					break
				}
			}
		}
		if match {
			out = append(out, p)
		}
	}
	return out
}

type gpuNodeCapacity struct {
	allocatable int64
	capacity    int64
	migAlloc    int64
	migCapacity int64
	isMIG       bool
}

func (c *GPUGuardCheck) nodeGPUCapacity(ctx context.Context) (gpuNodeCapacity, bool) {
	if c.d.Cfg.Client == nil {
		return gpuNodeCapacity{}, false
	}
	n, err := c.d.Cfg.Client.CoreV1().Nodes().
		Get(ctx, c.d.Cfg.NodeName,
			metav1.GetOptions{ResourceVersion: "0"})
	if err != nil {
		return gpuNodeCapacity{}, false
	}
	var out gpuNodeCapacity
	if q, has := n.Status.Allocatable["nvidia.com/gpu"]; has {
		out.allocatable = q.Value()
	}
	if q, has := n.Status.Capacity["nvidia.com/gpu"]; has {
		out.capacity = q.Value()
	}
	for resName, q := range n.Status.Capacity {
		if strings.HasPrefix(string(resName), "nvidia.com/mig-") && q.Value() > 0 {
			out.isMIG = true
			out.migCapacity += q.Value()
		}
	}
	for resName, q := range n.Status.Allocatable {
		if strings.HasPrefix(string(resName), "nvidia.com/mig-") && q.Value() > 0 {
			out.isMIG = true
			out.migAlloc += q.Value()
		}
	}
	return out, true
}

// liveGPUs runs the same sysfs-only 0x10de census kernelfail's
// gpu_pcie.go owns — one ReadDir + vendor/class reads, no exec.
// The PCI devices dir derives from SysClassNet (<sysfs>/class/net
// → <sysfs>/bus/pci/devices) so the pod's /host/sys mount and a
// standalone /sys both resolve without a second path knob.
// ok=false when sysfs is unreadable — inconclusive, never "zero
// GPUs" (a missing mount must not fabricate a desync verdict).
// On 0-GPU CPU-only nodes (allowZeroCache=true), caches the 0 result
// for gpuPCIZeroRescanTTL as long as pciDir mtime is unchanged.
func (c *GPUGuardCheck) liveGPUs(allowZeroCache bool) (int, bool) {
	pciDir := filepath.Join(c.d.Cfg.SysClassNet,
		"..", "..", "bus", "pci", "devices")
	now := c.d.Cfg.Seams.Host.Clock.Now()
	if allowZeroCache && c.zeroPCIDir == pciDir && !c.zeroPCIAt.IsZero() {
		if age := now.Sub(c.zeroPCIAt); age >= 0 && age < gpuPCIZeroRescanTTL {
			if st, err := os.Stat(pciDir); err == nil && st.ModTime().Equal(c.zeroPCIModTime) {
				return 0, true
			}
		}
	}
	ents, err := os.ReadDir(pciDir)
	if err != nil {
		c.zeroPCIAt = time.Time{}
		return 0, false
	}
	live := 0
	for _, e := range ents {
		// /sys/bus/pci/devices/* entries are SYMLINKS into
		// /sys/devices — DirEntry.IsDir() lstats and reports
		// false for them, which would count zero GPUs on every
		// real host. Accept symlinks; the vendor/class reads
		// below follow them.
		if !e.IsDir() && e.Type()&os.ModeSymlink == 0 {
			continue
		}
		dir := filepath.Join(pciDir, e.Name())
		vendor, err := os.ReadFile(filepath.Join(dir, "vendor"))
		if err != nil {
			if !os.IsNotExist(err) {
				c.zeroPCIAt = time.Time{}
				return 0, false
			}
			continue
		}
		if strings.TrimSpace(string(vendor)) != "0x10de" {
			continue
		}
		class, err := os.ReadFile(filepath.Join(dir, "class"))
		if err != nil {
			if !os.IsNotExist(err) {
				c.zeroPCIAt = time.Time{}
				return 0, false
			}
			continue
		}
		cls := strings.TrimSpace(string(class))
		// Plan's display-class filter: 0x0300xx VGA / 0x0302xx 3D —
		// audio and USB-C functions share the vendor ID but are
		// not GPU evidence.
		if strings.HasPrefix(cls, "0x0300") ||
			strings.HasPrefix(cls, "0x0302") {
			live++
		}
	}
	if live == 0 {
		if st, serr := os.Stat(pciDir); serr == nil {
			c.zeroPCIDir = pciDir
			c.zeroPCIModTime = st.ModTime()
			c.zeroPCIAt = now
		}
	} else {
		c.zeroPCIAt = time.Time{}
	}
	return live, true
}

// Run executes one GPU device-plugin round.
func (c *GPUGuardCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckGPUGuard) {
		return
	}
	if c.d.Cfg.Wave2.GPUGuardMode == envx.ModeOff {
		c.d.CycleResult(wdeps.CheckGPUGuard, "ok")
		return
	}
	if e == nil || !e.APIOK {
		c.d.CycleResult(wdeps.CheckGPUGuard, "abort")
		return
	}
	pods := c.devicePluginPods(e)
	live, liveOK := c.liveGPUs(len(pods) == 0)
	if !liveOK && len(pods) == 0 {
		// Sysfs unreadable AND no plugin pods — nothing to compare
		// against; inconclusive rather than a fabricated desync.
		c.d.CycleResult(wdeps.CheckGPUGuard, "inconclusive")
		return
	}
	if liveOK && live == 0 && len(pods) == 0 {
		// Zero-GPU node with no plugin pod — the CPU-only dormancy
		// the MODE=auto contract promises; no API call needed.
		c.desyncSince = time.Time{}
		c.d.CycleResult(wdeps.CheckGPUGuard, "ok")
		return
	}
	capInfo, ok := c.nodeGPUCapacity(ctx)
	if !ok {
		c.d.CycleResult(wdeps.CheckGPUGuard, "inconclusive")
		return
	}
	alloc, capacity := capInfo.allocatable, capInfo.capacity
	if capInfo.isMIG {
		alloc, capacity = capInfo.migAlloc, capInfo.migCapacity
	}
	desynced := false
	if capInfo.isMIG {
		if alloc == 0 || (capacity > 0 && alloc < capacity) {
			desynced = true
		}
	} else if liveOK && live > 0 &&
		(alloc == 0 || (capacity > 0 && alloc < capacity) || alloc < int64(live)) {
		desynced = true
	}
	if !desynced && alloc > 0 {
		unready := len(pods) > 0
		for _, p := range pods {
			if p.DeletionTimestamp == nil && wdeps.PodReady(p) {
				unready = false
				break
			}
		}
		desynced = unready
	}
	if !desynced {
		if !liveOK {
			c.d.CycleResult(wdeps.CheckGPUGuard, "abort")
			return
		}
		c.desyncSince = time.Time{}
		c.d.CycleResult(wdeps.CheckGPUGuard, "ok")
		return
	}
	if c.desyncSince.IsZero() {
		c.desyncSince = c.d.Cfg.Seams.Host.Clock.Now()
	}
	desyncFor := c.d.Cfg.Seams.Host.Clock.Now().Sub(c.desyncSince)
	if desyncFor < time.Duration(c.d.Cfg.Wave2.GPUGuardDesyncMin)*time.Minute {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: gpu-pcie-guard live=%d allocatable=%d capacity=%d pluginPods=%d (%.0fm of %dm)",
			live, alloc, capacity, len(pods), desyncFor.Minutes(),
			c.d.Cfg.Wave2.GPUGuardDesyncMin))
		c.d.CycleResult(wdeps.CheckGPUGuard, "ok")
		return
	}
	// Past the window: bounce the plugin pods (hold + cooldown gated).
	// GPUHealEnabled gates the REMEDY only — detection keeps running.
	cooldown := time.Duration(c.d.Cfg.Wave2.GPUGuardBounceCooldownMin) * time.Minute
	// Same no-op guard as the CSI bounce: filter already-Terminating
	// plugin pods BEFORE spending the cooldown or stamping
	// LocalRemediation. A set of pods that is on its way out has
	// nothing to bounce and must not burn the restart budget.
	var livePods []*corev1.Pod
	for _, p := range pods {
		if p.DeletionTimestamp == nil {
			livePods = append(livePods, p)
		}
	}
	if c.d.Cfg.Wave2.GPUHealEnabled && len(livePods) > 0 && e != nil && e.APIOK &&
		!c.d.HoldLocalAction(ctx) &&
		c.d.State.RateTrySpend("last-gpu-plugin-bounce", cooldown) {
		c.d.StampLocalRemediation(ctx)
		for _, p := range livePods {
			c.d.State.AppendLog(fmt.Sprintf(
				"ACTION gpu-plugin-bounce: deleting device-plugin pod %s/%s (live=%d allocatable=%d, desync %.0fm)",
				p.Namespace, p.Name, live, alloc, desyncFor.Minutes()))
			if err := c.d.DeletePodGraceful(ctx, p); err != nil {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: gpu-pcie-guard bounce %s/%s failed: %v",
					p.Namespace, p.Name, err))
				continue
			}
			c.d.Actions.WithLabelValues(wdeps.CheckGPUGuard, "pod_delete").Inc()
		}
		c.emitGPUDesevent(ctx, live, alloc, capacity, len(pods))
	}
	c.d.CycleResult(wdeps.CheckGPUGuard, "ok")
}

// emitGPUDesevent emits the node Warning event for a persistent
// GPU registration desync — either shape (hardware-vs-allocatable
// or allocatable-vs-plugin-health) carries the same reason.
func (c *GPUGuardCheck) emitGPUDesevent(ctx context.Context, live int,
	alloc, capacity int64, pods int) {
	now := c.d.Cfg.Seams.Host.Clock.Now()
	_ = c.d.EmitCheckEvent(ctx, wdeps.CheckEvent{
		Name:      fmt.Sprintf("%s.gpu-desync.%x", c.d.Cfg.NodeName, now.UnixNano()),
		Namespace: c.d.Cfg.Host.EventNamespace,
		Reason:    "GPUDevicePluginDesync",
		Note: fmt.Sprintf(
			"node-host-agent: GPU registration desync — sysfs live=%d, node allocatable=%d capacity=%d, device-plugin pods=%d",
			live, alloc, capacity, pods),
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Node",
			Name:       c.d.Cfg.NodeName,
		},
	})
}
