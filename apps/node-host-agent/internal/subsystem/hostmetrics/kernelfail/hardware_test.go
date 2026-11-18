// hardware_test.go — hardware-health coverage: the meminfo
// HardwareCorrupted field, the EDAC ue/ce sysfs scan (and its
// absent-EDAC fail-safe), the kmsg acute signatures (MCE, PCIe AER,
// NVMe reset streak, NVIDIA Xid) and the evidence TTL decay.
package kernelfail

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
)

// hwLatchSet reports whether state-<latch> exists.
func hwLatchSet(r *Runner, latch string) bool {
	_, err := os.Stat(r.deps.Store.Path(latch))
	return err == nil
}

// seedHardwareFixture writes a minimal /proc/meminfo under the
// fixture ProcRoot and returns its path.
func seedHardwareFixture(t *testing.T, f *fixture) string {
	t.Helper()
	meminfo := filepath.Join(f.deps.ProcRoot, "meminfo")
	writePrefailFile(t, meminfo, "MemTotal:       16384000 kB\n"+
		"HardwareCorrupted:        0 kB\n")
	return meminfo
}

// writeEDAC drops ue_count/ce_count files under a fake mc dir inside
// the fixture HostRoot tree (the EDACGlob New() defaulted to
// <hostroot>/sys/devices/system/edac/mc/mc*).
func writeEDAC(t *testing.T, f *fixture, mc, ue, ce string) {
	t.Helper()
	dir := filepath.Join(f.deps.HostRoot, "sys", "devices", "system", "edac", "mc", mc)
	writePrefailFile(t, filepath.Join(dir, "ue_count"), ue+"\n")
	writePrefailFile(t, filepath.Join(dir, "ce_count"), ce+"\n")
}

func readHardwareProm(t *testing.T, r *Runner) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(r.textfileDir(), hardwarePromName))
	if err != nil {
		return ""
	}
	return string(data)
}

func TestHardwareCorruptedMeminfoLatches(t *testing.T) {
	f := kfixture(t)
	seedHardwareFixture(t, f)
	writePrefailFile(t, filepath.Join(f.deps.ProcRoot, "meminfo"),
		"MemTotal:       16384000 kB\nHardwareCorrupted:       12 kB\n")
	f.r.updateHardwareHealth()
	if !hwLatchSet(f.r, latchdefs.LatchHardwareCorrupted) {
		t.Fatal("state-hardware-corrupted not latched on HardwareCorrupted=12 kB")
	}
	if hwLatchSet(f.r, latchdefs.LatchGPUHardwareError) {
		t.Fatal("gpu latch armed on a memory-only signature")
	}
	prom := readHardwareProm(t, f.r)
	if !strings.Contains(prom,
		"node_agent_memory_hardware_corrupted_bytes 12288") {
		t.Fatalf("corrupted-bytes gauge missing:\n%s", prom)
	}
	// Clean the field — the latch must Exit.
	writePrefailFile(t, filepath.Join(f.deps.ProcRoot, "meminfo"),
		"MemTotal:       16384000 kB\nHardwareCorrupted:        0 kB\n")
	f.r.updateHardwareHealth()
	if hwLatchSet(f.r, latchdefs.LatchHardwareCorrupted) {
		t.Fatal("latch held on HardwareCorrupted=0")
	}
}

func TestHardwareEDACUELatchesAndProm(t *testing.T) {
	f := kfixture(t)
	seedHardwareFixture(t, f)
	writeEDAC(t, f, "mc0", "2", "40")
	writeEDAC(t, f, "mc1", "0", "7")
	f.r.updateHardwareHealth()
	if !hwLatchSet(f.r, latchdefs.LatchHardwareCorrupted) {
		t.Fatal("state-hardware-corrupted not latched on edac ue_count=2")
	}
	logData, err := os.ReadFile(f.log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logData), "edac ue_count=2 ce_count=47") {
		t.Fatalf("STATE-ENTER evidence missing totals:\n%s", logData)
	}
	prom := readHardwareProm(t, f.r)
	for _, want := range []string{
		`node_agent_edac_uncorrectable_errors{mc="mc0"} 2`,
		`node_agent_edac_correctable_errors{mc="mc0"} 40`,
		`node_agent_edac_uncorrectable_errors{mc="mc1"} 0`,
		`node_agent_edac_correctable_errors{mc="mc1"} 7`,
	} {
		if !strings.Contains(prom, want) {
			t.Fatalf("textfile missing %q:\n%s", want, prom)
		}
	}
}

func TestHardwareNoEDACFailSafe(t *testing.T) {
	f := kfixture(t)
	seedHardwareFixture(t, f) // meminfo clean, no edac dirs at all
	f.r.updateHardwareHealth()
	if hwLatchSet(f.r, latchdefs.LatchHardwareCorrupted) {
		t.Fatal("latch armed with no EDAC and clean meminfo (VM fail-safe)")
	}
	// CE-only controllers trend but never latch.
	writeEDAC(t, f, "mc0", "0", "999")
	f.r.updateHardwareHealth()
	if hwLatchSet(f.r, latchdefs.LatchHardwareCorrupted) {
		t.Fatal("ce_count-only armed the corruption latch")
	}
	if prom := readHardwareProm(t, f.r); !strings.Contains(prom,
		`node_agent_edac_correctable_errors{mc="mc0"} 999`) {
		t.Fatalf("ce gauge missing:\n%s", prom)
	}
}

// TestHardwarePartialEDACCounterSkipped is the partial-read regression:
// a controller that serves only ONE of its two counters is mid-
// reset, not healthy. It must contribute NOTHING — including no
// fabricated ue=0/ce=0 gauge that would reassure the scrape and
// hide a genuine uncorrectable-error signal.
func TestHardwarePartialEDACCounterSkipped(t *testing.T) {
	f := kfixture(t)
	seedHardwareFixture(t, f)
	base := filepath.Join(f.deps.HostRoot, "sys", "devices", "system", "edac", "mc")
	// ue_count readable (nonzero!) but ce_count missing.
	writePrefailFile(t, filepath.Join(base, "mc-no-ce", "ue_count"), "9\n")
	// ce_count readable but ue_count missing.
	writePrefailFile(t, filepath.Join(base, "mc-no-ue", "ce_count"), "77\n")
	f.r.updateHardwareHealth()
	if hwLatchSet(f.r, latchdefs.LatchHardwareCorrupted) {
		t.Fatal("partially-readable EDAC controller armed the hardware latch")
	}
	prom := readHardwareProm(t, f.r)
	for _, mc := range []string{"mc-no-ce", "mc-no-ue"} {
		if strings.Contains(prom, mc) {
			t.Fatalf("partial-read controller %s emitted a fabricated gauge:\n%s", mc, prom)
		}
	}
}

func TestHardwareKmsgCorrectedMCEDoesNotLatch(t *testing.T) {
	f := kfixture(t)
	seedHardwareFixture(t, f)
	kmsgFixture(t, f.deps,
		"mce: [Hardware Error]: CPU 0: Machine Check Exception: Bank 5, status 0xb20000000001000",
		"mce: [Hardware Error]: Corrected error — must not latch")
	f.r.checkKernelDmesg(context.Background())
	f.r.updateHardwareHealth()
	if hwLatchSet(f.r, latchdefs.LatchHardwareCorrupted) {
		t.Fatal("corrected/bank-status MCE armed the corruption latch")
	}
}

func TestHardwareKmsgUncorrectedMCELatches(t *testing.T) {
	f := kfixture(t)
	seedHardwareFixture(t, f)
	kmsgFixture(t, f.deps,
		"mce: [Hardware Error]: CPU 0: Machine Check Exception: Uncorrected, context 0")
	f.r.checkKernelDmesg(context.Background())
	f.r.updateHardwareHealth()
	if !hwLatchSet(f.r, latchdefs.LatchHardwareCorrupted) {
		t.Fatal("uncorrected MCE did not arm state-hardware-corrupted")
	}
}

func TestHardwareNVMeResetStreak(t *testing.T) {
	f := kfixture(t)
	seedHardwareFixture(t, f)
	// Two resets — below the streak.
	for i := 0; i < 2; i++ {
		f.r.notePCIeNVMeReset("nvme nvme0: I/O 42 QID 5 timeout, resetting controller")
	}
	f.r.updateHardwareHealth()
	if hwLatchSet(f.r, latchdefs.LatchHardwareCorrupted) {
		t.Fatal("two resets armed the latch (streak is 3)")
	}
	f.r.notePCIeNVMeReset("nvme nvme0: I/O 57 QID 9 timeout, resetting controller")
	f.r.updateHardwareHealth()
	if !hwLatchSet(f.r, latchdefs.LatchHardwareCorrupted) {
		t.Fatal("three resets in 10m did not arm state-hardware-corrupted")
	}
}

func TestHardwareAcuteEvidenceDecays(t *testing.T) {
	f := kfixture(t)
	seedHardwareFixture(t, f)
	now := time.Now()
	f.deps.Clock.Set(func() time.Time { return now })
	f.r.noteHardwareCorrupt("mce: [Hardware Error]: Uncorrected")
	f.r.updateHardwareHealth()
	if !hwLatchSet(f.r, latchdefs.LatchHardwareCorrupted) {
		t.Fatal("acute MCE did not arm the latch")
	}
	// Past the TTL with no durable counters the latch must clear.
	now = now.Add(hwAcuteEvidenceTTL + time.Minute)
	f.r.updateHardwareHealth()
	if hwLatchSet(f.r, latchdefs.LatchHardwareCorrupted) {
		t.Fatal("stale acute evidence held the latch past TTL")
	}
}

func TestGPUXidArmsGPUOnly(t *testing.T) {
	f := kfixture(t)
	seedHardwareFixture(t, f)
	kmsgFixture(t, f.deps,
		"NVRM: Xid (PCI:0000:01:00): 79, GPU has fallen off the bus.",
		"NVRM: Xid (PCI:0000:01:00): 13, Graphics Engine Exception — benign, must not latch")
	f.r.checkKernelDmesg(context.Background())
	f.r.updateHardwareHealth()
	if !hwLatchSet(f.r, latchdefs.LatchGPUHardwareError) {
		t.Fatal("fatal Xid 79 did not arm state-gpu-hardware-error")
	}
	if hwLatchSet(f.r, latchdefs.LatchHardwareCorrupted) {
		t.Fatal("GPU Xid armed the hardware-corrupted latch")
	}
	logData, err := os.ReadFile(f.log)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logData), "NVIDIA fatal Xid 79") {
		t.Fatalf("STATE-ENTER must name the Xid code:\n%s", logData)
	}
}

// The nvidia-uvm driver hang is the same GPUHardwareError latch class
// as a fatal Xid — a UVM channel error or global fatal error must arm
// state-gpu-hardware-error (the latchdefs contract names it) without
// touching the generic hardware latch.
func TestGPUUVHangArmsGPUOnly(t *testing.T) {
	f := kfixture(t)
	seedHardwareFixture(t, f)
	kmsgFixture(t, f.deps,
		"NVRM: uvm: GPU0: Detected a channel error on GPC 0",
		"uvm encountered global fatal error 0x00000001")
	f.r.checkKernelDmesg(context.Background())
	f.r.updateHardwareHealth()
	if !hwLatchSet(f.r, latchdefs.LatchGPUHardwareError) {
		t.Fatal("nvidia-uvm hang did not arm state-gpu-hardware-error")
	}
	if hwLatchSet(f.r, latchdefs.LatchHardwareCorrupted) {
		t.Fatal("GPU uvm hang armed the hardware-corrupted latch")
	}
}

// TestHardwareEvidenceSurvivesRestart is the P1-#7 regression: the
// acute kmsg evidence persists to hw-evidence in the state dir, so
// a fresh Runner over the same state dir (an agent restart) keeps
// the armed latch instead of Exiting it on the first clean-looking
// tick — and still clears once the evidence TTL genuinely expires.
func TestHardwareEvidenceSurvivesRestart(t *testing.T) {
	f := kfixture(t)
	seedHardwareFixture(t, f)
	f.r.noteGPUXid("NVRM: Xid (PCI:0000:01:00): 79, GPU has fallen off the bus.")
	f.r.updateHardwareHealth()
	if !hwLatchSet(f.r, latchdefs.LatchGPUHardwareError) {
		t.Fatal("fatal Xid did not arm state-gpu-hardware-error")
	}
	// Simulate the agent restart — a NEW Runner over the same
	// state dir must reload the persisted evidence.
	r2 := New(f.deps)
	r2.updateHardwareHealth()
	if !hwLatchSet(r2, latchdefs.LatchGPUHardwareError) {
		t.Fatal("restart cleared a still-fresh GPU hardware latch")
	}
	// Persistence must not pin the latch forever — past the
	// evidence TTL the reloaded stamp expires and the latch Exits.
	f.deps.Clock.Set(func() time.Time {
		return time.Now().Add(hwAcuteEvidenceTTL + time.Minute)
	})
	r3 := New(f.deps)
	r3.updateHardwareHealth()
	if hwLatchSet(r3, latchdefs.LatchGPUHardwareError) {
		t.Fatal("expired persisted evidence held the latch past TTL")
	}
}
