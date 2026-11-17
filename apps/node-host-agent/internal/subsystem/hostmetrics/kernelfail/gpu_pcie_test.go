// gpu_pcie_test.go — the P2.12 sysfs census: HostRoot-joined PCI
// device scan (the /proc/sys-vs-/sys bug this file's first
// revision shipped), the 0x0300/0x0302 class filter, the
// GPUGuardMode dormancy, the max(GPUExpectedCount, baseline)
// loss verdict and the live/expected textfile gauges.
package kernelfail

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/testutil"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/envx"
)

// seedGPUPCI writes one PCI device the way the kernel lays it out:
// the real device dir lives under sys/devices/... and
// sys/bus/pci/devices/<slot> is a SYMLINK to it — DirEntry.IsDir()
// lstats and reports false for the link, so a fixture that mkdirs
// straight into devices/ would hide the production miss this
// layout exists to pin.
func seedGPUPCI(t *testing.T, hostRoot, slot, vendor, class string,
	bound bool) {
	t.Helper()
	real := filepath.Join(hostRoot, "sys", "devices", "pci0000:00",
		slot)
	link := filepath.Join(hostRoot, "sys", "bus", "pci", "devices", slot)
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	testutil.WriteFile(t, filepath.Join(real, "vendor"), vendor+"\n")
	testutil.WriteFile(t, filepath.Join(real, "class"), class+"\n")
	if bound {
		if err := os.Symlink("../../../bus/pci/drivers/nvidia",
			real+"/driver"); err != nil {
			t.Fatal(err)
		}
	}
	rel, err := filepath.Rel(filepath.Dir(link), real)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(rel, link); err != nil {
		t.Fatal(err)
	}
}

func gpuAcute(f *fixture, class string) (hwAcute, bool) {
	a, ok := f.r.hw.acute[class]
	return a, ok
}

func TestGPUPCIeScanHostRootNotProcRoot(t *testing.T) {
	f := kfixture(t)
	// The census must read <HostRoot>/sys — NOT <ProcRoot>/sys
	// (/proc/sys is the sysctl tree; /proc/sys/bus/pci/devices
	// never exists). Seed ONLY under hostroot.
	seedGPUPCI(t, f.deps.HostRoot, "0000:01:00.0", "0x10de", "0x030000", true)
	seedGPUPCI(t, f.deps.HostRoot, "0000:02:00.0", "0x10de", "0x030200", true)
	// Non-GPU decoys: wrong vendor, NVIDIA audio class, unbound
	// display function.
	seedGPUPCI(t, f.deps.HostRoot, "0000:03:00.0", "0x8086", "0x030000", true)
	seedGPUPCI(t, f.deps.HostRoot, "0000:04:00.0", "0x10de", "0x040300", true)
	seedGPUPCI(t, f.deps.HostRoot, "0000:05:00.0", "0x10de", "0x030000", false)

	devs, ok := f.r.scanGPUPCIDevices()
	if !ok {
		t.Fatal("scan inconclusive with seeded sysfs")
	}
	if len(devs) != 3 {
		t.Fatalf("scan found %d devices, want 3 (2 bound + 1 unbound GPU)", len(devs))
	}
}

func TestGPUPCIeModeOffDormant(t *testing.T) {
	f := kfixture(t)
	f.r.deps.GPUGuardMode = envx.ModeOff
	seedGPUPCI(t, f.deps.HostRoot, "0000:01:00.0", "0x10de", "0x030000", false)
	f.r.updateGPUPCIe()
	if _, ok := gpuAcute(f, "gpu:pcie-unbound"); ok {
		t.Fatal("ModeOff still produced unbound evidence")
	}
	if _, ok := gpuAcute(f, "gpu:pcie-loss"); ok {
		t.Fatal("ModeOff still produced loss evidence")
	}
}

func TestGPUPCIeBaselineLearnThenLoss(t *testing.T) {
	f := kfixture(t)
	seedGPUPCI(t, f.deps.HostRoot, "0000:01:00.0", "0x10de", "0x030000", true)
	seedGPUPCI(t, f.deps.HostRoot, "0000:02:00.0", "0x10de", "0x030200", true)

	// First scan seeds the baseline at 2 — no loss verdict yet.
	f.r.updateGPUPCIe()
	if _, ok := gpuAcute(f, "gpu:pcie-loss"); ok {
		t.Fatal("first scan fired pcie-loss before a baseline existed")
	}

	// Drop one device dir → live 1 < baseline 2 → loss evidence.
	if err := os.RemoveAll(filepath.Join(f.deps.HostRoot,
		"sys", "bus", "pci", "devices", "0000:02:00.0")); err != nil {
		t.Fatal(err)
	}
	f.r.hw.acute = map[string]hwAcute{} // fresh tick — evidence re-arms per scan
	f.r.updateGPUPCIe()
	if _, ok := gpuAcute(f, "gpu:pcie-loss"); !ok {
		t.Fatal("dropped GPU produced no pcie-loss evidence")
	}
}

func TestGPUPCIeExpectedCountOverridesBaseline(t *testing.T) {
	f := kfixture(t)
	f.r.deps.GPUExpectedCount = 4
	// Operator declares 4 GPUs; hardware baseline learns 2 — the
	// configured count must win: live 2 < max(4, 2).
	seedGPUPCI(t, f.deps.HostRoot, "0000:01:00.0", "0x10de", "0x030000", true)
	seedGPUPCI(t, f.deps.HostRoot, "0000:02:00.0", "0x10de", "0x030200", true)
	f.r.updateGPUPCIe()
	if _, ok := gpuAcute(f, "gpu:pcie-loss"); !ok {
		t.Fatal("GPUExpectedCount=4 with live=2 produced no pcie-loss")
	}
}

func TestGPUPCIeZeroGPUNoFalseLoss(t *testing.T) {
	f := kfixture(t)
	// CPU-only node: empty devices dir, expected 0 → live 0 is NOT
	// below expected 0 — the auto-mode dormancy contract.
	devDir := filepath.Join(f.deps.HostRoot, "sys", "bus", "pci", "devices")
	if err := os.MkdirAll(devDir, 0o755); err != nil {
		t.Fatal(err)
	}
	seedGPUPCI(t, f.deps.HostRoot, "0000:01:00.0", "0x8086", "0x020000", true)
	f.r.updateGPUPCIe()
	if _, ok := gpuAcute(f, "gpu:pcie-loss"); ok {
		t.Fatal("CPU-only node fired pcie-loss")
	}
	if _, ok := gpuAcute(f, "gpu:pcie-unbound"); ok {
		t.Fatal("CPU-only node fired pcie-unbound")
	}
}

func TestGPUPCIPromGauges(t *testing.T) {
	f := kfixture(t)
	tfDir := t.TempDir()
	f.r.deps.TextfileDir = tfDir
	seedGPUPCI(t, f.deps.HostRoot, "0000:01:00.0", "0x10de", "0x030000", true)
	f.r.updateGPUPCIe()
	data, err := os.ReadFile(filepath.Join(tfDir, gpuPCIPromName))
	if err != nil {
		t.Fatalf("gpu-pcie prom not written: %v", err)
	}
	body := string(data)
	if !strings.Contains(body, "node_agent_gpu_pcie_devices_live 1") {
		t.Fatalf("live gauge missing/wrong:\n%s", body)
	}
	if !strings.Contains(body, "node_agent_gpu_pcie_devices_expected 1") {
		t.Fatalf("expected gauge missing/wrong:\n%s", body)
	}
}
