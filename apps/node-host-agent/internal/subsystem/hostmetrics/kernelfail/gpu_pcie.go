// gpu_pcie.go — the L1 half of P2.12 (GPU PCIe/device-plugin
// desync): a sysfs-only NVIDIA census that feeds the existing
// GPUHardwareError latch — NO nvidia-smi, NO driver ioctls, just
// /sys/bus/pci/devices reads under the host proc root.
//
// Two evidence classes, both re-armed every tick while the
// condition holds (they ride hardware.go's acute-evidence map, so
// the latch releases on its own hwAcuteEvidenceTTL after the node
// heals — a driver reload that takes minutes must not flap the
// condition):
//
//   - "gpu:pcie-unbound" — a display-class NVIDIA function
//     (class 0x03xxxx — VGA/3D/display, NOT the audio or USB-C
//     functions that legitimately sit driverless) whose device
//     dir has no driver symlink: the kernel sees the card but no
//     driver bound it — nvidia driver crash, failed reload, or a
//     device the driver refused.
//   - "gpu:pcie-loss" — the display-class NVIDIA device count
//     dropped below the recorded baseline: hardware disappeared
//     (PCIe surprise removal, dead slot, firmware-level loss).
//     The baseline persists in the watchdog state dir so an agent
//     restart can't forget a GPU that died while it was down; a
//     HIGHER count re-baselines upward (hot-add is not loss).
//
// Zero-cost on CPU-only nodes: one ReadDir + per-device vendor
// read under <HostRoot>/sys — no exec, no nvidia-smi fork.
//
// GPUGuardMode gates the whole census (off = dormant); auto and
// on share the path — auto IS the sysfs-only cheap scan, there is
// no heavier probe to defer to. GPUExpectedCount is the operator-
// declared GPU total (0 = learn-from-hardware): the loss verdict
// fires when live < max(GPUExpectedCount, learnedBaseline).
package kernelfail

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

const (
	// gpuPCIVendor is the PCI vendor ID every NVIDIA function
	// carries (0x10de).
	gpuPCIVendor = "0x10de"
	// gpuPCIClass prefixes the PCI class codes of real GPU
	// functions the plan counts: 0x0300xx VGA and 0x0302xx 3D
	// controller (the class file renders "0x030000"/"0x030200").
	// The NVIDIA audio (0x0403) and USB-C (0x0c03/0x0c80)
	// functions share the vendor ID but are not GPU loss evidence.
	gpuPCIClassVGA = "0x0300"
	gpuPCIClass3D  = "0x0302"
	// gpuPCIBaselineName is the watchdog-state file holding the
	// max-seen display-class NVIDIA device count.
	gpuPCIBaselineName = "gpu-pcie-baseline"
	// gpuPCIPromName is the textfile drop carrying the live /
	// expected device gauges.
	gpuPCIPromName = "node-agent-gpu-pcie.prom"
)

// gpuPCIDevice is one display-class NVIDIA PCI function.
type gpuPCIDevice struct {
	name    string // PCI slot name (0000:01:00.0)
	devPath string // <sys>/bus/pci/devices/<name>
}

// scanGPUPCIDevices lists display-class NVIDIA PCI functions under
// <HostRoot>/sys/bus/pci/devices — HostRoot-joined like the EDAC
// and sys/class/net globs (pod mode reads /host/sys/..., standalone
// "/" reads /sys/...). /proc/sys is the sysctl tree, NOT sysfs —
// joining under ProcRoot would look for a path that never exists.
// ok=false when the sysfs tree is unreadable — inconclusive,
// never evidence (a missing /sys in a container without host
// sysfs must not fabricate GPU loss).
func (r *Runner) scanGPUPCIDevices() ([]gpuPCIDevice, bool) {
	hostRoot := r.deps.HostRoot
	if hostRoot == "" {
		hostRoot = "/"
	}
	devDir := filepath.Join(hostRoot, "sys", "bus", "pci", "devices")
	ents, err := os.ReadDir(devDir)
	if err != nil {
		return nil, false
	}
	var out []gpuPCIDevice
	for _, e := range ents {
		// /sys/bus/pci/devices/* entries are SYMLINKS into
		// /sys/devices — DirEntry.IsDir() lstats and reports
		// false for them, which would count zero GPUs on every
		// real host. Accept symlinks; the vendor/class reads
		// below follow them.
		if !e.IsDir() && e.Type()&os.ModeSymlink == 0 {
			continue
		}
		dir := filepath.Join(devDir, e.Name())
		vendor, err := os.ReadFile(filepath.Join(dir, "vendor"))
		if err != nil || strings.TrimSpace(string(vendor)) != gpuPCIVendor {
			continue
		}
		class, err := os.ReadFile(filepath.Join(dir, "class"))
		if err != nil {
			continue
		}
		cls := strings.TrimSpace(string(class))
		if !strings.HasPrefix(cls, gpuPCIClassVGA) &&
			!strings.HasPrefix(cls, gpuPCIClass3D) {
			continue
		}
		out = append(out, gpuPCIDevice{name: e.Name(), devPath: dir})
	}
	return out, true
}

// gpuPCIDriverBound reports whether the device has a driver bound —
// the kernel exposes it as the "driver" symlink inside the device
// dir. A dangling/missing symlink means unbound.
func gpuPCIDriverBound(dev gpuPCIDevice) bool {
	_, err := os.Readlink(filepath.Join(dev.devPath, "driver"))
	return err == nil
}

// gpuPCIBaseline reads the persisted display-class NVIDIA count —
// 0 with ok=false when no baseline exists yet (first scan seeds it
// without alarming).
func (r *Runner) gpuPCIBaselinePath() string {
	if r.deps.Store == nil || r.deps.Store.Dir == "" {
		return ""
	}
	return filepath.Join(r.deps.Store.Dir, gpuPCIBaselineName)
}

func (r *Runner) gpuPCIBaseline() (int, bool) {
	p := r.gpuPCIBaselinePath()
	if p == "" {
		return 0, false
	}
	// Clean up legacy state-gpu-pcie-baseline left by earlier builds if present.
	if legacy := r.deps.Store.Path(gpuPCIBaselineName); legacy != "" && legacy != p {
		_ = os.Remove(legacy)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// writeGPUPCIbaseline persists the display-class NVIDIA count atomically
// without the state- prefix so collectWatchdog never surfaces it as a latch.
func (r *Runner) writeGPUPCIbaseline(n int) {
	p := r.gpuPCIBaselinePath()
	if p == "" {
		return
	}
	_ = fsx.WriteFileAtomicNoSync(p, strconv.Itoa(n)+"\n")
}

// updateGPUPCIe runs the sysfs census once per latch tick and feeds
// the GPU-prefixed acute evidence classes — must run BEFORE
// updateHardwareHealth so the fresh stamps are in the acute map when
// the latch writer partitions them. GPUGuardMode=off makes the
// whole check dormant; auto/on run the same cheap sysfs scan (auto
// IS the zero-cost path — there is no heavier probe to defer to).
// Every successful scan also refreshes the live/expected textfile
// gauges.
func (r *Runner) updateGPUPCIe() {
	if r.deps.GPUGuardMode == envx.ModeOff {
		return
	}
	devs, ok := r.scanGPUPCIDevices()
	if !ok {
		return // inconclusive — contribute nothing
	}
	live := len(devs)

	// Unbound display functions — driver crash / refused bind.
	var unbound []string
	for _, d := range devs {
		if !gpuPCIDriverBound(d) {
			unbound = append(unbound, d.name)
		}
	}
	if len(unbound) > 0 {
		r.hwNoteAcute("gpu:pcie-unbound",
			"NVIDIA PCIe function(s) present with no driver bound: "+
				strings.Join(unbound, ","))
	}

	// Device-count baseline — max-seen ever, persisted so an agent
	// restart can't forget a GPU that died while it was down; a
	// HIGHER count re-baselines upward (hot-add is not loss).
	baseline, hasBaseline := r.gpuPCIBaseline()
	switch {
	case !hasBaseline:
		r.writeGPUPCIbaseline(live)
		baseline = live
	case live > baseline:
		r.writeGPUPCIbaseline(live)
		baseline = live
	}

	// Loss verdict: live below max(GPUExpectedCount, baseline) —
	// the operator-declared count wins over the learned one so a
	// node imaged with fewer GPUs than spec still alarms.
	expected := baseline
	if r.deps.GPUExpectedCount > expected {
		expected = r.deps.GPUExpectedCount
	}
	if live < expected {
		r.hwNoteAcute("gpu:pcie-loss",
			fmt.Sprintf("NVIDIA display-class PCIe devices below "+
				"expected: live=%d expected=%d (baseline=%d, configured=%d)",
				live, expected, baseline, r.deps.GPUExpectedCount))
	}
	r.writeGPUPCIProm(live, expected)
}

// writeGPUPCIProm renders node_agent_gpu_pcie_devices_live /
// node_agent_gpu_pcie_devices_expected into the node-exporter
// textfile dir — the scrape-side view of the same census the latch
// consumes (writeStealEntropyProm's rules: only on a successful
// scan, WriteLogged so a bad mount can't spam the watchdog tail).
func (r *Runner) writeGPUPCIProm(live, expected int) {
	var b promfile.Builder
	b.Gauge("node_agent_gpu_pcie_devices_live",
		"Display-class NVIDIA PCI functions with a live sysfs entry (vendor 0x10de, class 0x0300/0x0302).",
		float64(live))
	b.Gauge("node_agent_gpu_pcie_devices_expected",
		"Expected display-class NVIDIA PCI functions — max(learned max-seen baseline, NODE_HOST_AGENT_GPU_EXPECTED_COUNT).",
		float64(expected))
	dir := r.textfileDir()
	_ = promfile.WriteLogged(dir, gpuPCIPromName,
		[]byte(b.String()), func(dir, _ string, err error) {
			logger().Warn("hostmetrics: gpu-pcie textfile install failed",
				"dir", dir, "error", err)
		})
}
