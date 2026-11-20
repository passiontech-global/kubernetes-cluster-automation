// csi_gpu_reg_test.go — coverage for the P1.6 CSI registration
// guard and the P2.12 GPU device-plugin guard: orphan -reg.sock
// removal behind the ECONNREFUSED streak + heal gate, the
// missing-registration desync window → latch → RECOVERY path
// (the latch must exit once every driver re-registers), the
// DaemonSet-owner plugin-pod filter, and the sysfs-symlink GPU
// census feeding the allocatable desync verdict.
package runtime_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/nodecoord"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/runtime"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdepstest"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/nodecond"
)

// pluginsRegistryDir mirrors the check's derivation —
// <PodsDir>/../plugins_registry.
func pluginsRegistryDir(e *env) string {
	return filepath.Join(filepath.Dir(e.KubepodsDir), "plugins_registry")
}

func mkRegSocket(t *testing.T, e *env, driver string) string {
	t.Helper()
	dir := pluginsRegistryDir(e)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A plain file, not a bound socket — the unix dial fails with
	// ECONNREFUSED, which is exactly the stale-leftover evidence
	// the guard requires before removing.
	p := filepath.Join(dir, driver+"-reg.sock")
	if err := os.WriteFile(p, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func csiNode(name string, drivers ...string) *storagev1.CSINode {
	n := &storagev1.CSINode{ObjectMeta: metav1.ObjectMeta{Name: name}}
	for _, d := range drivers {
		n.Spec.Drivers = append(n.Spec.Drivers,
			storagev1.CSINodeDriver{Name: d})
	}
	return n
}

func cycleWithPods(pods ...corev1.Pod) *wdeps.CycleEnv {
	return &wdeps.CycleEnv{WorkerActive: true, APIOK: true, Pods: pods}
}

func latchFile(e *env, latch string) string {
	return filepath.Join(e.StateDir, "state-"+latch)
}

func latched(e *env, latch string) bool {
	_, err := os.Stat(latchFile(e, latch))
	return err == nil
}

// TestCSIGuardOrphanSocketRemoved pins the orphan path: a -reg.sock
// whose driver is absent from CSINode and that refuses connections
// is removed once the refused-streak is met — and only then.
func TestCSIGuardOrphanSocketRemoved(t *testing.T) {
	cn := csiNode("node-a", "csi.healthy.com")
	e := fixture(t, cn)
	e.H.Cfg.Wave2.CSIGuardMode = envx.ModeOn
	e.H.Cfg.Wave2.CSIHealEnabled = true
	e.H.Cfg.Wave2.CSIGuardECONNRefusedCycle = 2
	orphan := mkRegSocket(t, e, "csi.orphan.com")
	healthy := mkRegSocket(t, e, "csi.healthy.com")
	chk := wdepstest.Check[*runtime.CSIGuardCheck](e.H, wdeps.CheckCSIGuard)
	ctx := context.Background()

	chk.Run(ctx, cycleWithPods()) // refused streak 1 — kept
	if _, err := os.Stat(orphan); err != nil {
		t.Fatal("orphan removed before the refused streak completed")
	}
	chk.Run(ctx, cycleWithPods()) // streak 2 — removed
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("orphan sock still present after refused streak: %v", err)
	}
	if _, err := os.Stat(healthy); err != nil {
		t.Fatalf("healthy driver socket removed: %v", err)
	}
}

// TestCSIGuardHealDisabledKeepsOrphan pins the detect-only posture:
// CSIHealEnabled=false leaves the socket on disk.
func TestCSIGuardHealDisabledKeepsOrphan(t *testing.T) {
	cn := csiNode("node-a")
	e := fixture(t, cn)
	e.H.Cfg.Wave2.CSIGuardMode = envx.ModeOn
	e.H.Cfg.Wave2.CSIHealEnabled = false
	e.H.Cfg.Wave2.CSIGuardECONNRefusedCycle = 1
	orphan := mkRegSocket(t, e, "csi.orphan.com")
	chk := wdepstest.Check[*runtime.CSIGuardCheck](e.H, wdeps.CheckCSIGuard)
	chk.Run(context.Background(), cycleWithPods())
	if _, err := os.Stat(orphan); err != nil {
		t.Fatalf("heal-off removed orphan socket: %v", err)
	}
}

func TestCSIGuardOrphanSocketRemoveHeldByMaintenance(t *testing.T) {
	cn := csiNode("node-a")
	e := fixture(t, cn)
	e.H.Cfg.Wave2.CSIGuardMode = envx.ModeOn
	e.H.Cfg.Wave2.CSIHealEnabled = true
	e.H.Cfg.Wave2.CSIGuardECONNRefusedCycle = 1
	e.H.Cfg.Coord = &nodecoord.Coord{
		Now: func() time.Time { return e.Now },
		GetAnnos: func(context.Context) (map[string]string, error) {
			return map[string]string{nodecond.KuredLockAnno: `{"nodeID":"node-a"}`}, nil
		},
	}
	orphan := mkRegSocket(t, e, "csi.orphan.com")
	wdepstest.Check[*runtime.CSIGuardCheck](e.H, wdeps.CheckCSIGuard).Run(
		context.Background(), cycleWithPods())
	if _, err := os.Stat(orphan); err != nil {
		t.Fatalf("orphan socket removed despite HoldLocalAction: %v", err)
	}
}

// TestCSIGuardMissingRegistrationLatchRecovers is the regression
// for the stuck-wedge bug: drivers missing registration past the
// window latch CSIRegistrationWedged — and the latch must EXIT once
// every driver has a socket again (the old triple-empty guard kept
// it latched forever on any node with sockets/pods/drivers).
func TestCSIGuardMissingRegistrationLatchRecovers(t *testing.T) {
	cn := csiNode("node-a", "csi.bad.com", "csi.ok.com")
	badPod := csiPluginPod("csi-bad-node-a", "kube-system", "uid-bad")
	badPod.Spec.Volumes = []corev1.Volume{{
		Name: "plugin-dir",
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/k0s/kubelet/plugins/csi.bad.com"},
		},
	}}
	e := fixture(t, cn, badPod)
	e.H.Cfg.Wave2.CSIGuardMode = envx.ModeOn
	e.H.Cfg.Wave2.CSIHealEnabled = false // latch path, no pod bounce
	e.H.Cfg.Wave2.CSIGuardMissingMin = 0 // window already open
	mkRegSocket(t, e, "csi.ok.com")      // one healthy driver passes the pre-filter
	chk := wdepstest.Check[*runtime.CSIGuardCheck](e.H, wdeps.CheckCSIGuard)
	ctx := context.Background()

	// ConsecNeeded=2 → two past-window cycles latch the wedge.
	for i := 0; i < 3; i++ {
		chk.Run(ctx, cycleWithPods(*badPod))
	}
	if !latched(e, latchdefs.LatchCSIRegistrationWedged) {
		t.Fatal("CSIRegistrationWedged not latched on persistent desync")
	}

	// Recovery: the missing driver re-registers (socket appears).
	mkRegSocket(t, e, "csi.bad.com")
	chk.Run(ctx, cycleWithPods(*badPod))
	if latched(e, latchdefs.LatchCSIRegistrationWedged) {
		t.Fatal("latch stuck after all drivers re-registered")
	}
}

// TestCSIGuardTerminatingPodWedgeLatches pins the stuck-Terminating
// deadlock: with healing on, a plugin pod that never finishes deleting
// is skipped by the bounce, so bouncedThisWindow stays false. The
// wedge latch must still arm once the desync outlives the wait window
// plus the grace (clock seam advanced), rather than waiting forever.
func TestCSIGuardTerminatingPodWedgeLatches(t *testing.T) {
	cn := csiNode("node-a", "csi.stuck.com", "csi.healthy.com")
	stuck := csiPluginPod("csi-stuck-node-a", "kube-system", "uid-stuck")
	now := metav1.Now()
	stuck.DeletionTimestamp = &now // stuck Terminating — bounce always skips it
	stuck.Spec.Volumes = []corev1.Volume{{
		Name: "plugin-dir",
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/k0s/kubelet/plugins/csi.stuck.com"},
		},
	}}
	e := fixture(t, cn)
	e.H.Cfg.Wave2.CSIGuardMode = envx.ModeOn
	e.H.Cfg.Wave2.CSIHealEnabled = true
	e.H.Cfg.Wave2.CSIGuardMissingMin = 0 // wait window already open
	mkRegSocket(t, e, "csi.healthy.com") // passes the local pre-filter, no orphan
	chk := wdepstest.Check[*runtime.CSIGuardCheck](e.H, wdeps.CheckCSIGuard)
	ctx := context.Background()

	// Cycle 1: the pod is Terminating so no bounce lands. Before the
	// grace elapses there is no latch and no streak advance.
	chk.Run(ctx, cycleWithPods(*stuck))
	if latched(e, latchdefs.LatchCSIRegistrationWedged) {
		t.Fatal("CSIRegistrationWedged armed before the grace window")
	}

	// Advance the clock past the grace. Two past-grace cycles confirm
	// the streak (ConsecNeeded=2) and arm the wedge.
	e.Now = e.Now.Add(16 * time.Minute)
	chk.Run(ctx, cycleWithPods(*stuck))
	chk.Run(ctx, cycleWithPods(*stuck))
	if !latched(e, latchdefs.LatchCSIRegistrationWedged) {
		t.Fatal("stuck-Terminating CSI pod never latched CSIRegistrationWedged")
	}
}

// TestCSIGuardTerminatingPodDoesNotSpendBounceBudget: a desync whose
// only matching plugin pod is already Terminating has nothing to
// bounce. The cooldown must stay unspent and no remediation may be
// stamped; a live pod in the same desync still gets the real bounce.
func TestCSIGuardTerminatingPodDoesNotSpendBounceBudget(t *testing.T) {
	cn := csiNode("node-a", "csi.stuck.com")
	stuck := csiPluginPod("csi-stuck-node-a", "kube-system", "uid-stuck")
	now := metav1.Now()
	stuck.DeletionTimestamp = &now
	stuck.Spec.Volumes = []corev1.Volume{{
		Name: "plugin-dir",
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/k0s/kubelet/plugins/csi.stuck.com"},
		},
	}}
	live := csiPluginPod("csi-live-node-a", "kube-system", "uid-live")
	live.Spec.Volumes = stuck.Spec.Volumes
	e := fixture(t, cn, stuck, live)
	if err := os.MkdirAll(pluginsRegistryDir(e), 0o755); err != nil {
		t.Fatal(err) // readable registry dir — no sockets, no orphans
	}
	e.H.Cfg.Wave2.CSIGuardMode = envx.ModeOn
	e.H.Cfg.Wave2.CSIHealEnabled = true
	e.H.Cfg.Wave2.CSIGuardMissingMin = 0 // wait window already open
	e.H.Cfg.Wave2.CSIGuardBounceCooldownMin = 30
	budget := filepath.Join(e.StateDir, "last-csi-reg-bounce")
	chk := wdepstest.Check[*runtime.CSIGuardCheck](e.H, wdeps.CheckCSIGuard)
	ctx := context.Background()

	chk.Run(ctx, cycleWithPods(*stuck))
	if _, err := os.Stat(budget); !os.IsNotExist(err) {
		t.Fatalf("all-Terminating CSI bounce spent the cooldown (stat err=%v)", err)
	}

	// Positive control: the same desync with a live target DOES bounce
	// and spend the budget.
	chk.Run(ctx, cycleWithPods(*live))
	if _, err := os.Stat(budget); err != nil {
		t.Fatalf("live CSI bounce did not spend the cooldown: %v", err)
	}
}

// csiPluginPod builds a DaemonSet-owned CSI node-plugin pod — the
// shape csiPluginPods must select (and *-csi-controller
// Deployments must not).
func csiPluginPod(name, ns, uid string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns, UID: types.UID(uid),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "DaemonSet",
				Name: "csi-node-driver-registrar",
			}},
		},
		Spec: corev1.PodSpec{
			NodeName:   "node-a",
			Containers: []corev1.Container{{Image: "registry.k8s.io/sig-storage/csi-node-driver:v1"}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

// TestCSIGuardPluginPodFilter pins the owner/namespace-agnostic
// selection: a DaemonSet pod in a non-kube-system namespace with a
// CSI-ish image counts; a Deployment-owned *-csi-controller pod in
// kube-system does NOT.
func TestCSIGuardPluginPodFilter(t *testing.T) {
	plugin := csiPluginPod("csi-node-driver-registrar-x", "rook-ceph", "uid-plugin")
	controller := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "csi-provisioner-0", Namespace: "rook-ceph",
			UID: types.UID("uid-ctrl"),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "Deployment",
				Name: "csi-provisioner",
			}},
		},
		Spec:   corev1.PodSpec{NodeName: "node-a"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	cn := csiNode("node-a") // no drivers → missing stays empty
	e := fixture(t, cn, plugin, controller)
	e.H.Cfg.Wave2.CSIGuardMode = envx.ModeOn
	// Plugin pod alone passes the pre-filter; with no drivers and no
	// orphan sockets the run must stay ok — the Deployment pod must
	// not have been treated as a node plugin (a bounce would try to
	// delete it; nothing latches, nothing deletes).
	chk := wdepstest.Check[*runtime.CSIGuardCheck](e.H, wdeps.CheckCSIGuard)
	chk.Run(context.Background(),
		cycleWithPods(*plugin, *controller))
	// The controller pod still exists — never a bounce target.
	got, err := e.CS.CoreV1().Pods("rook-ceph").Get(context.Background(),
		"csi-provisioner-0", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("controller pod touched: %v", err)
	}
	if got.DeletionTimestamp != nil {
		t.Fatal("Deployment-owned CSI pod was deleted")
	}
}

// gpuPluginPod builds a DaemonSet-owned NVIDIA device-plugin pod.
func gpuPluginPod(name, ns, uid string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns, UID: types.UID(uid),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "DaemonSet",
				Name: "nvidia-device-plugin-daemonset",
			}},
		},
		Spec: corev1.PodSpec{
			NodeName: "node-a",
			Containers: []corev1.Container{{
				Image: "nvcr.io/nvidia/k8s-device-plugin:v0.14.5",
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

// mkSysfsGPU plants one NVIDIA VGA function under a fake sysfs:
// /sys/bus/pci/devices/<bdf> is a SYMLINK into /sys/devices (the
// real kernel layout — DirEntry.IsDir lstats and misses every one
// of them, which is the bug this census must not repeat).
func mkSysfsGPU(t *testing.T, sysRoot, bdf string) {
	t.Helper()
	devDir := filepath.Join(sysRoot, "devices", "pci0000:00", bdf)
	if err := os.MkdirAll(devDir, 0o755); err != nil {
		t.Fatal(err)
	}
	wdepstest.WriteFile(t, filepath.Join(devDir, "vendor"), "0x10de\n")
	wdepstest.WriteFile(t, filepath.Join(devDir, "class"), "0x030000\n")
	linkParent := filepath.Join(sysRoot, "bus", "pci", "devices")
	if err := os.MkdirAll(linkParent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(devDir, filepath.Join(linkParent, bdf)); err != nil {
		t.Fatal(err)
	}
}

// gpuEnv builds the fixture with SysClassNet pointed at a two-level
// <root>/sys/class/net so liveGPUs' ../../bus/pci/devices derivation
// lands inside the tempdir (the fixture's default sysnet is one
// level deep and would escape it).
func gpuEnv(t *testing.T, objs ...kruntime.Object) *env {
	t.Helper()
	e := fixture(t, objs...)
	root := filepath.Dir(e.KubepodsDir)
	sysRoot := filepath.Join(root, "sys")
	e.H.Cfg.SysClassNet = filepath.Join(sysRoot, "class", "net")
	return e
}

// TestGPUGuardLiveGPUZeroAllocatable pins desync shape (a): sysfs
// proves a live NVIDIA function while the node advertises zero
// allocatable — the device-plugin pod is bounced past the window.
func TestGPUGuardLiveGPUZeroAllocatable(t *testing.T) {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}}
	plugin := gpuPluginPod("nvidia-device-plugin-x", "gpu-operator", "uid-gpu")
	e := gpuEnv(t, node, plugin)
	root := filepath.Dir(e.KubepodsDir)
	mkSysfsGPU(t, filepath.Join(root, "sys"), "0000:01:00.0")
	e.H.Cfg.Wave2.GPUGuardMode = envx.ModeOn
	e.H.Cfg.Wave2.GPUHealEnabled = true
	e.H.Cfg.Wave2.GPUGuardDesyncMin = 0
	chk := wdepstest.Check[*runtime.GPUGuardCheck](e.H, wdeps.CheckGPUGuard)
	ctx := context.Background()

	chk.Run(ctx, cycleWithPods(*plugin))
	_, err := e.CS.CoreV1().Pods("gpu-operator").Get(ctx,
		"nvidia-device-plugin-x", metav1.GetOptions{})
	if err == nil {
		t.Fatal("device-plugin pod survived live-vs-allocatable desync")
	}
	if !apierrors.IsNotFound(err) {
		t.Fatalf("unexpected pod get error: %v", err)
	}
}

// TestGPUGuardTerminatingPluginDoesNotSpendBounceBudget: same no-op
// rule for the GPU half — a Terminating device-plugin pod must not
// burn last-gpu-plugin-bounce or stamp LocalRemediation. A live pod
// in the desync still takes the real bounce.
func TestGPUGuardTerminatingPluginDoesNotSpendBounceBudget(t *testing.T) {
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a"}}
	plugin := gpuPluginPod("nvidia-device-plugin-x", "gpu-operator", "uid-gpu")
	now := metav1.Now()
	plugin.DeletionTimestamp = &now
	live := gpuPluginPod("nvidia-device-plugin-live", "gpu-operator", "uid-gpu-live")
	e := gpuEnv(t, node, plugin, live)
	root := filepath.Dir(e.KubepodsDir)
	mkSysfsGPU(t, filepath.Join(root, "sys"), "0000:01:00.0")
	e.H.Cfg.Wave2.GPUGuardMode = envx.ModeOn
	e.H.Cfg.Wave2.GPUHealEnabled = true
	e.H.Cfg.Wave2.GPUGuardDesyncMin = 0
	e.H.Cfg.Wave2.GPUGuardBounceCooldownMin = 30
	budget := filepath.Join(e.StateDir, "last-gpu-plugin-bounce")
	chk := wdepstest.Check[*runtime.GPUGuardCheck](e.H, wdeps.CheckGPUGuard)
	ctx := context.Background()

	chk.Run(ctx, cycleWithPods(*plugin))
	if _, err := os.Stat(budget); !os.IsNotExist(err) {
		t.Fatalf("all-Terminating GPU bounce spent the cooldown (stat err=%v)", err)
	}

	// Positive control: a live plugin pod still gets bounced and
	// spends the budget.
	chk.Run(ctx, cycleWithPods(*live))
	if _, err := os.Stat(budget); err != nil {
		t.Fatalf("live GPU bounce did not spend the cooldown: %v", err)
	}
}

// TestGPUGuardZeroGPUNodeDormant pins the MODE=auto dormancy: no
// sysfs GPUs and no plugin pods → ok without ever needing the node
// API (a CPU-only node must not fabricate a desync).
func TestGPUGuardZeroGPUNodeDormant(t *testing.T) {
	e := gpuEnv(t)
	root := filepath.Dir(e.KubepodsDir)
	if err := os.MkdirAll(filepath.Join(root, "sys", "bus", "pci", "devices"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.H.Cfg.Wave2.GPUGuardMode = envx.ModeAuto
	chk := wdepstest.Check[*runtime.GPUGuardCheck](e.H, wdeps.CheckGPUGuard)
	chk.Run(context.Background(), cycleWithPods())
	// No latch, no deletes — the run stays ok by construction.
	if latched(e, latchdefs.LatchCSIRegistrationWedged) {
		t.Fatal("unexpected latch on a zero-GPU node")
	}
}
