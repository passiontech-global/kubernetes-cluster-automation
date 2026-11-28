// csi_gpu_reg.go — the CSI registration guard (wdeps.CheckCSIGuard,
// P1.6) and the GPU device-plugin guard (wdeps.CheckGPUGuard, the
// Kubernetes-plugin half of P2.12).
//
// CSI guard: kubelet's CSI node-driver-registrar keeps a unix
// socket per driver at <kubelet>/plugins_registry/<driver>-reg.sock
// AND publishes the driver list on the node's CSINode object. The
// two can desync three ways, all healed here:
//
//   - orphan socket: a -reg.sock whose driver is absent from
//     CSINode.spec.drivers (driver unregistered but socket leaked —
//     kubelet's CSI plugin watcher then keeps trying to dial a dead
//     registrar). Removed after CSIGuardECONNRefusedCycle cycles of
//     ECONNREFUSED on the probe dial.
//   - missing socket: CSINode lists a driver with no -reg.sock and
//     no live plugin pod — the registration object outlived the
//     plugin. The node-plugin pod is bounced (delete, DaemonSet
//     recreates it) after CSIGuardMissingMin minutes of desync,
//     cooldown-gated by last-csi-reg-bounce.
//   - wedge latch: a desync that survives both remedies enters
//     state-csi-registration-wedged → NodeCondition
//     CSIRegistrationWedged.
//
// Zero-cost when no CSI exists: no -reg.sock entries, no CSINode
// drivers, no csi plugin pods → immediate ok, no API calls beyond
// the cheap local dir read (the CSINode GET only runs when local
// evidence exists).
//
// GPU plugin guard: the hardware half (sysfs 0x10de census) lives
// in hostmetrics/kernelfail/gpu_pcie.go feeding GPUHardwareError;
// this half watches the Kubernetes side — a node whose
// allocatable nvidia.com/gpu disagrees with the device-plugin
// pod's health for >= GPUGuardDesyncMin gets the plugin pod
// bounced (cooldown-gated), and a persistent desync emits a
// GPUDevicePluginDesync event. It never touches the
// gpu-hardware-error latch — that owner is hostmetrics.
package runtime

import (
	"context"
	json "encoding/json/v2"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// pluginsRegistryDir resolves the kubelet plugins_registry path —
// sibling of the pods dir (both live directly under the kubelet
// data dir), host-mounted like every other wdeps path.
func pluginsRegistryDir(d *wdeps.Deps) string {
	return filepath.Join(filepath.Dir(d.Cfg.PodsDir), "plugins_registry")
}

// regSockets returns driver name → socket path for every
// *-reg.sock entry in plugins_registry. ok=false when the dir is
// unreadable — inconclusive, never a "no CSI" verdict (a missing
// mount must not read as zero drivers and mass-delete).
func regSockets(d *wdeps.Deps) (map[string]string, bool) {
	ents, err := os.ReadDir(pluginsRegistryDir(d))
	if err != nil {
		return nil, false
	}
	out := map[string]string{}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "-reg.sock") {
			continue
		}
		out[strings.TrimSuffix(e.Name(), "-reg.sock")] =
			filepath.Join(pluginsRegistryDir(d), e.Name())
	}
	return out, true
}

// csiNodeDrivers fetches this node's CSINode driver names, falling back to
// Node.Annotations["csi.volume.kubernetes.io/nodeid"] if CSINodes().Get returns
// 403 Forbidden.
func (c *CSIGuardCheck) csiNodeDrivers(ctx context.Context) (map[string]bool, bool) {
	if c.d.Cfg.Client == nil {
		return nil, false
	}
	n, err := c.d.Cfg.Client.StorageV1().CSINodes().
		Get(ctx, c.d.Cfg.NodeName,
			metav1.GetOptions{ResourceVersion: "0"})
	if err == nil {
		out := map[string]bool{}
		for _, drv := range n.Spec.Drivers {
			out[drv.Name] = true
		}
		return out, true
	}
	if !apierrors.IsForbidden(err) {
		return nil, false
	}
	node, nerr := c.d.Cfg.Client.CoreV1().Nodes().
		Get(ctx, c.d.Cfg.NodeName, metav1.GetOptions{ResourceVersion: "0"})
	if nerr != nil {
		return nil, false
	}
	raw := node.Annotations["csi.volume.kubernetes.io/nodeid"]
	out := map[string]bool{}
	if strings.TrimSpace(raw) == "" {
		return out, true
	}
	var parsed map[string]string
	if jerr := json.Unmarshal([]byte(raw), &parsed); jerr != nil {
		return nil, false
	}
	for drv := range parsed {
		out[drv] = true
	}
	return out, true
}

func podMatchesCSIDriver(p *corev1.Pod, drv string) bool {
	if p == nil || drv == "" {
		return false
	}
	ldrv := strings.ToLower(drv)
	if strings.Contains(strings.ToLower(p.Name), ldrv) {
		return true
	}
	// Match against prefix tokens such as "cephfs" / "rook-ceph" / "nfs" / "openebs"
	// only when volume mounts / args / env reference the driver or its socket/plugin dir.
	for i := range p.Spec.Volumes {
		if hp := p.Spec.Volumes[i].HostPath; hp != nil {
			if strings.Contains(strings.ToLower(hp.Path), ldrv) {
				return true
			}
		}
	}
	for i := range p.Spec.Containers {
		ct := &p.Spec.Containers[i]
		for _, a := range ct.Command {
			if strings.Contains(strings.ToLower(a), ldrv) {
				return true
			}
		}
		for _, a := range ct.Args {
			if strings.Contains(strings.ToLower(a), ldrv) {
				return true
			}
		}
		for _, ev := range ct.Env {
			if strings.Contains(strings.ToLower(ev.Value), ldrv) {
				return true
			}
		}
	}
	return false
}

// isDaemonSetPod reports whether the pod is owned by a DaemonSet —
// the node-plugin shape every CSI/GPU registrar runs as. The owner
// check is what keeps *-csi-controller Deployments (cluster-side,
// not node plugins) out of the bounce set.
func isDaemonSetPod(p *corev1.Pod) bool {
	for _, ref := range p.OwnerReferences {
		if ref.Kind == "DaemonSet" {
			return true
		}
	}
	return false
}

// csiPluginPods returns this node's CSI node-driver pods: DaemonSet-
// owned pods that look like a CSI plugin — "csi" in the name or any
// container image (rook-ceph, longhorn, openEBS and friends live in
// their own namespaces, so a kube-system hardcode misses them).
func (c *CSIGuardCheck) csiPluginPods(e *wdeps.CycleEnv) []*corev1.Pod {
	var out []*corev1.Pod
	for i := range e.Pods {
		p := &e.Pods[i]
		if !isDaemonSetPod(p) {
			continue
		}
		lname := strings.ToLower(p.Name)
		csiish := strings.Contains(lname, "csi") ||
			strings.Contains(lname, "cephfs") ||
			strings.Contains(lname, "rook-ceph")
		if !csiish {
			for _, img := range p.Spec.Containers {
				if strings.Contains(strings.ToLower(img.Image), "csi") {
					csiish = true
					break
				}
			}
		}
		if csiish {
			out = append(out, p)
		}
	}
	return out
}

// csiGuardWedgeGrace bounds how long a past-window desync may keep
// retrying a bounce before the wedge latch is forced. Without it a
// plugin pod stuck Terminating (or a delete that keeps failing) leaves
// bouncedThisWindow=false forever, so CSIRegistrationWedged can never
// arm — exactly the wedge the latch exists to report. The clock seam
// drives the grace so tests advance it without real time.
const csiGuardWedgeGrace = 15 * time.Minute

// CSIGuardCheck is the P1.6 healer as a Check; it owns the
// per-driver ECONNREFUSED streaks and the desync marker.
type CSIGuardCheck struct {
	d                 *wdeps.Deps
	fails             int
	refused           map[string]int // driver → consecutive ECONNREFUSED cycles
	desyncSince       time.Time      // first-seen of the current desync window
	bouncedThisWindow bool
}

// NewCSIGuard builds the check.
func NewCSIGuard(d *wdeps.Deps) *CSIGuardCheck {
	return &CSIGuardCheck{d: d, refused: map[string]int{}}
}

// Name returns the check label / WD_SIG key.
func (c *CSIGuardCheck) Name() string { return wdeps.CheckCSIGuard }

// socketRefused probes the registration socket with a bounded
// unix dial — ECONNREFUSED means the file is a stale leftover
// (nobody listening); a successful dial or timeout means a live
// or wedged registrar (not ours to remove).
func (c *CSIGuardCheck) socketRefused(path string) bool {
	probe := time.Duration(c.d.Cfg.Wave2.CSIGuardProbeSec) * time.Second
	if probe <= 0 {
		probe = 2 * time.Second
	}
	conn, err := net.DialTimeout("unix", path, probe)
	if err == nil {
		_ = conn.Close()
		return false
	}
	return strings.Contains(err.Error(), "connection refused")
}

// Run executes one CSI-registration round.
func (c *CSIGuardCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckCSIGuard) {
		return
	}
	mode := c.d.Cfg.Wave2.CSIGuardMode
	if mode == envx.ModeOff {
		c.d.CycleResult(wdeps.CheckCSIGuard, "ok")
		return
	}
	if e == nil || !e.APIOK {
		c.d.CycleResult(wdeps.CheckCSIGuard, "abort")
		return
	}
	socks, ok := regSockets(c.d)
	if !ok {
		c.d.CycleResult(wdeps.CheckCSIGuard, "inconclusive")
		return
	}
	// Local pre-filter: only fetch CSINode when local evidence
	// exists — no sockets AND no CSI pods is the zero-CSI node.
	pods := c.csiPluginPods(e)
	if len(socks) == 0 && len(pods) == 0 {
		clear(c.refused)
		c.d.State.Exit(latchdefs.LatchCSIRegistrationWedged, nil)
		c.d.CycleResult(wdeps.CheckCSIGuard, "ok")
		return
	}
	// ModeAuto additionally requires at least one CSI signal; the
	// pods/sockets above already prove one exists, so auto and on
	// share the path.
	drivers, dok := c.csiNodeDrivers(ctx)
	if !dok {
		c.d.CycleResult(wdeps.CheckCSIGuard, "inconclusive")
		return
	}
	for drv := range c.refused {
		if _, hasSock := socks[drv]; !hasSock || drivers[drv] {
			delete(c.refused, drv)
		}
	}

	// Orphan sockets: present on disk, absent from CSINode.
	// CSIHealEnabled gates the REMEDY only — detection and the
	// wedge latch keep running with heals off (detect-only mode).
	heal := c.d.Cfg.Wave2.CSIHealEnabled
	for drv, path := range socks {
		if drivers[drv] {
			continue
		}
		if c.socketRefused(path) {
			c.refused[drv]++
		} else {
			c.refused[drv] = 0
		}
		if heal && c.refused[drv] >= c.d.Cfg.Wave2.CSIGuardECONNRefusedCycle {
			if c.d.HoldLocalAction(ctx) {
				c.d.State.AppendLog(fmt.Sprintf(
					"cleanup: csi-registration-guard orphan -reg.sock %s remove held - cluster maintenance in progress",
					path))
				continue
			}
			if err := os.Remove(path); err != nil {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: csi-registration-guard orphan -reg.sock %s remove failed: %v",
					path, err))
			} else {
				c.d.State.AppendLog(fmt.Sprintf(
					"ACTION csi-reg-bounce: removed orphan registration socket %s (driver %s absent from CSINode)",
					path, drv))
				c.d.Actions.WithLabelValues(wdeps.CheckCSIGuard, "reg_sock_rm").Inc()
				delete(c.refused, drv)
			}
		}
	}
	// Missing registrations: only count CSINode drivers with an active
	// DaemonSet plugin pod on this node (stale CSINode entries from
	// uninstalled drivers must not latch CSIRegistrationWedged forever).
	var missing []string
	var targetPods []*corev1.Pod
	seenPod := map[string]bool{}
	for drv := range drivers {
		if _, hasSock := socks[drv]; hasSock {
			continue
		}
		var matched []*corev1.Pod
		for _, p := range pods {
			if podMatchesCSIDriver(p, drv) {
				matched = append(matched, p)
			}
		}
		if len(matched) == 0 {
			continue // driver uninstalled on this node — stale CSINode entry only
		}
		missing = append(missing, drv)
		for _, p := range matched {
			pk := p.Namespace + "/" + p.Name
			if !seenPod[pk] {
				seenPod[pk] = true
				targetPods = append(targetPods, p)
			}
		}
	}
	if len(missing) > 0 {
		if c.desyncSince.IsZero() {
			c.desyncSince = c.d.Cfg.Seams.Host.Clock.Now()
		}
	} else {
		c.desyncSince = time.Time{}
		c.bouncedThisWindow = false
	}
	desyncFor := c.d.Cfg.Seams.Host.Clock.Now().Sub(c.desyncSince)
	window := time.Duration(c.d.Cfg.Wave2.CSIGuardMissingMin) * time.Minute
	pastWindow := len(missing) > 0 && desyncFor >= window
	bouncedBefore := c.bouncedThisWindow
	if heal && pastWindow {
		if c.bounceStaleCSIPods(ctx, e, targetPods, missing) {
			c.bouncedThisWindow = true
		}
	}
	// A desync older than the wait window PLUS the grace latches even
	// when no bounce ever landed: a pod stuck Terminating (or a failing
	// delete) must not pin bouncedThisWindow=false forever.
	pastGrace := pastWindow && desyncFor >= window+csiGuardWedgeGrace
	// When healing is active, wait until at least one prior bounce failed to
	// recover before latching CSIRegistrationWedged — or until the grace
	// window proves bounces cannot clear the wedge.
	if pastWindow && (!heal || bouncedBefore || pastGrace) {
		joined := strings.Join(missing, ",")
		if c.d.StreakPending(&c.fails,
			"suspect: csi-registration-guard drivers missing registration: "+joined) {
			c.d.CycleResult(wdeps.CheckCSIGuard, "ok")
			return
		}
		c.d.State.Enter(latchdefs.LatchCSIRegistrationWedged,
			"missing="+joined)
		c.d.CycleResult(wdeps.CheckCSIGuard, "ok")
		return
	}
	if len(missing) == 0 {
		c.fails = 0
		c.d.State.Exit(latchdefs.LatchCSIRegistrationWedged, nil)
	}
	c.d.CycleResult(wdeps.CheckCSIGuard, "ok")
}

// bounceStaleCSIPods deletes ONLY the CSI node-plugin pods belonging to
// drivers in missing. Returns true if at least one pod delete landed.
func (c *CSIGuardCheck) bounceStaleCSIPods(ctx context.Context,
	e *wdeps.CycleEnv, pods []*corev1.Pod, missing []string) bool {
	if e == nil || !e.APIOK || len(pods) == 0 {
		return false
	}
	// A pod already Terminating is on its way out — there is nothing
	// to bounce. Filter FIRST: an all-terminating target set must not
	// burn the 30-minute cooldown or stamp LocalRemediation for a
	// no-op cycle (the budget is spent atomically before the action).
	var live []*corev1.Pod
	for _, p := range pods {
		if p.DeletionTimestamp == nil {
			live = append(live, p)
		}
	}
	if len(live) == 0 {
		return false
	}
	if c.d.HoldLocalAction(ctx) {
		c.d.State.AppendLog(
			"cleanup: csi-registration-guard bounce held - cluster maintenance in progress")
		return false
	}
	cooldown := time.Duration(c.d.Cfg.Wave2.CSIGuardBounceCooldownMin) * time.Minute
	if !c.d.State.RateTrySpend("last-csi-reg-bounce", cooldown) {
		return false
	}
	c.d.StampLocalRemediation(ctx)
	bounced := false
	for _, p := range live {
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION csi-reg-bounce: deleting stale CSI plugin pod %s/%s (drivers missing registration: %s)",
			p.Namespace, p.Name, strings.Join(missing, ",")))
		if err := c.d.DeletePodGraceful(ctx, p); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: csi-registration-guard bounce %s/%s failed: %v",
				p.Namespace, p.Name, err))
			continue
		}
		bounced = true
		c.d.Actions.WithLabelValues(wdeps.CheckCSIGuard, "pod_delete").Inc()
	}
	return bounced
}
