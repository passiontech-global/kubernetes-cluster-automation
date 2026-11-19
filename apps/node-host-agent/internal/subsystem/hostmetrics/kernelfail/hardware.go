// hardware.go — hardware-health updateHardwareHealth (self-healing
// P0-#3 + P2-#12): the ECC/EDAC + fatal-bus + NVIDIA-Xid evidence
// engine behind state-hardware-corrupted and
// state-gpu-hardware-error.
//
// Evidence classes, cheapest durable read first:
//
//   - /proc/meminfo "HardwareCorrupted: N kB" — pages the kernel
//     already poisoned and isolated (counted in kB, cumulative).
//   - EDAC sysfs — /sys/devices/system/edac/mc/mc*/{ue,ce}_count.
//     ue_count > 0 is an uncorrectable memory error the controller
//     could not repair; ce_count is correctable-error noise exported
//     for trending only. Hosts without EDAC (the Contabo virtio VMs)
//     glob to nothing — fail-safe, never a phantom latch.
//   - kmsg acute signatures recorded by the classifier
//     (kmsg_rules.go): uncorrected/fatal MCE, EDAC UE lines, memory-
//     failure SIGBUS, PCIe AER fatal, and >= nvmeResetStreak NVMe
//     controller resets inside nvmeResetWindow. Single-shot acute
//     evidence decays after hwAcuteEvidenceTTL so a transient fault
//     cannot cordon the node forever; a still-faulting device keeps
//     re-logging and refreshing the window. The NVMe streak has its
//     own tighter window — three resets in ten minutes is a dying
//     drive, not a hiccup.
//
// The latch is evidence-held (diskprefail shape): Enter while any
// evidence class is present, Exit only when ALL of them are absent.
// LatchGPUHardwareError is managed separately — a fatal Xid idles
// dormant on hosts with no NVIDIA device because the classifier
// only ever fires on NVRM lines.
package kernelfail

import (
	json "encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/fsx"
)

// Sysfs path defaults (Deps seam values — tests re-point them at
// the fixture tree).
const (
	defaultEDACGlob  = "/sys/devices/system/edac/mc/mc*"
	hardwarePromName = "node-agent-hardware.prom"
)

const (
	// hwAcuteEvidenceTTL bounds how long a single-shot kmsg hardware
	// signature counts as evidence — see the file header.
	hwAcuteEvidenceTTL = time.Hour
	// nvmeResetWindow/nvmeResetStreak: >=3 NVMe controller resets
	// inside 10m is a reset LOOP.
	nvmeResetWindow = 10 * time.Minute
	nvmeResetStreak = 3
	// gpuAcutePrefix marks the acute-evidence classes that feed
	// LatchGPUHardwareError instead of LatchHardwareCorrupted.
	gpuAcutePrefix = "gpu:"
)

// hwScanState is the Runner-held cross-tick hardware evidence.
// The durable half (meminfo HardwareCorrupted, EDAC ue_count)
// lives in sysfs/procfs and survives restarts on its own; the
// acute kmsg half persists to the hw-evidence file in the state
// dir (saveHwEvidence/loadHwEvidence) so a restart inside the
// evidence TTL keeps the latch armed instead of clearing it on
// the first clean-looking tick.
type hwScanState struct {
	// acute maps an evidence class ("hw", "pcie", "gpu:<xid>") to
	// the last signature detail + when it fired.
	acute map[string]hwAcute
	// nvmeResets holds the stamps of NVMe controller-reset kmsg
	// records — the >=3-in-10m streak input.
	nvmeResets []time.Time
}

// hwAcute is one acute kmsg evidence stamp.
type hwAcute struct {
	at     time.Time
	detail string
}

// hwNoteAcute records one acute kmsg signature — the classifiers in
// kmsg_rules.go dispatch into the note* wrappers below.
func (r *Runner) hwNoteAcute(class, detail string) {
	if r.hw.acute == nil {
		r.hw.acute = map[string]hwAcute{}
	}
	if len(detail) > 200 {
		detail = detail[:200]
	}
	r.hw.acute[class] = hwAcute{at: r.deps.Clock.Now(), detail: detail}
	r.saveHwEvidence()
}

// noteHardwareCorrupt handles the hwCorruptRe family — uncorrected
// or fatal MCE, an EDAC UE report, a memory-failure SIGBUS.
func (r *Runner) noteHardwareCorrupt(msg string) {
	r.hwNoteAcute("hw", "kernel hardware error: "+msg)
}

// notePCIeNVMeReset handles pcieNVMeResetRe — PCIe AER fatal arms
// the acute "pcie" evidence; an NVMe controller reset feeds the
// streak counter (a single reset is a hiccup, three in ten minutes
// is a dying drive).
func (r *Runner) notePCIeNVMeReset(msg string) {
	now := r.deps.Clock.Now()
	if pcieAERFatalRe.MatchString(msg) {
		r.hwNoteAcute("pcie", "PCIe AER fatal: "+msg)
	}
	if nvmeResetRe.MatchString(msg) {
		cutoff := now.Add(-nvmeResetWindow)
		kept := r.hw.nvmeResets[:0]
		for _, t := range r.hw.nvmeResets {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		r.hw.nvmeResets = append(kept, now)
		r.saveHwEvidence()
	}
}

// noteGPUXid handles gpuFatalXidRe — a fatal NVIDIA Xid idles
// dormant on hosts with no NVIDIA device (the classifier only ever
// fires on NVRM lines). The evidence class carries the Xid code so
// the STATE-ENTER line names the fault.
func (r *Runner) noteGPUXid(msg string) {
	code := "unknown"
	if m := gpuFatalXidRe.FindStringSubmatch(msg); m != nil {
		code = m[1]
	}
	r.hwNoteAcute(gpuAcutePrefix+code, "NVIDIA fatal Xid "+code)
}

// noteGPUUVHang handles gpuUVHangRe — an nvidia-uvm channel error or
// global fatal error is the driver-side half of a GPU hang: the same
// GPUHardwareError latch class as a fatal Xid, evidence class
// "gpu:uvm" so the STATE-ENTER line names the fault family.
func (r *Runner) noteGPUUVHang(msg string) {
	r.hwNoteAcute(gpuAcutePrefix+"uvm", "nvidia-uvm driver hang: "+msg)
}

// hwEvidenceFile is the on-disk half of hwScanState — acute kmsg
// evidence stamps and the NVMe reset streak persist across agent
// restarts so a reboot inside the evidence TTL cannot Exit a
// still-valid hardware latch on the first clean-looking tick.
// It lives in the watchdog state dir WITHOUT the state- prefix, so
// the janitor's latch reaper never touches it.
const hwEvidenceFile = "hw-evidence"

// hwEvidenceDisk is the persisted hwScanState shape — unix-second
// stamps so the file survives clock-format drift.
type hwEvidenceDisk struct {
	Acute      map[string]hwAcuteDisk `json:"acute"`
	NVMeResets []int64                `json:"nvme_resets"`
}

// hwAcuteDisk is one persisted hwAcute.
type hwAcuteDisk struct {
	At     int64  `json:"at"`
	Detail string `json:"detail"`
}

// hwEvidencePath resolves the persistence file — "" when no Store
// is wired (bare-Deps callers get RAM-only evidence, the pre-fix
// behavior).
func (r *Runner) hwEvidencePath() string {
	if r.deps.Store == nil {
		return ""
	}
	return filepath.Join(r.deps.Store.Dir, hwEvidenceFile)
}

// saveHwEvidence rewrites the evidence file after every mutation —
// the file is tiny (a handful of classes + a 10m reset window) and
// the writers are kmsg-line-rate at worst, so no debounce is worth
// the lost-durability window.
func (r *Runner) saveHwEvidence() {
	p := r.hwEvidencePath()
	if p == "" {
		return
	}
	d := hwEvidenceDisk{
		Acute:      map[string]hwAcuteDisk{},
		NVMeResets: make([]int64, 0, len(r.hw.nvmeResets)),
	}
	for class, a := range r.hw.acute {
		d.Acute[class] = hwAcuteDisk{At: a.at.Unix(), Detail: a.detail}
	}
	for _, t := range r.hw.nvmeResets {
		d.NVMeResets = append(d.NVMeResets, t.Unix())
	}
	data, err := json.Marshal(d)
	if err != nil {
		return
	}
	if err := fsx.WriteFileAtomicNoSync(p, string(data)); err != nil {
		logger().Debug("hostmetrics: hw-evidence persist failed",
			"path", p, "error", err)
	}
}

// loadHwEvidence restores the persisted evidence into the fresh
// Runner — called once from New before any goroutine touches hw.
// An unreadable/corrupt file starts clean (the durable sysfs/procfs
// half — meminfo, EDAC — still covers the latch); TTL/window
// filtering downstream expires stale entries naturally.
func (r *Runner) loadHwEvidence() {
	p := r.hwEvidencePath()
	if p == "" {
		return
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return
	}
	var d hwEvidenceDisk
	if err := json.Unmarshal(data, &d); err != nil {
		logger().Warn("hostmetrics: hw-evidence state unreadable — starting clean",
			"path", p, "error", err)
		return
	}
	if len(d.Acute) > 0 && r.hw.acute == nil {
		r.hw.acute = map[string]hwAcute{}
	}
	for class, a := range d.Acute {
		r.hw.acute[class] = hwAcute{at: time.Unix(a.At, 0), detail: a.Detail}
	}
	for _, ts := range d.NVMeResets {
		r.hw.nvmeResets = append(r.hw.nvmeResets, time.Unix(ts, 0))
	}
}

// meminfoHardwareCorruptedKB reads the "HardwareCorrupted:" field
// of /proc/meminfo — kB of poisoned pages the kernel isolated.
// ok=false when the field is absent (older kernels) or the file
// unreadable — inconclusive evidence must not move the latch.
func meminfoHardwareCorruptedKB(procRoot string) (uint64, bool) {
	data, err := os.ReadFile(filepath.Join(procRoot, "meminfo"))
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "HardwareCorrupted:" {
			v, err := strconv.ParseUint(f[1], 10, 64)
			if err != nil {
				return 0, false
			}
			return v, true
		}
	}
	return 0, false
}

// edacMC is one memory controller's parsed counters.
type edacMC struct {
	name string
	ue   uint64
	ce   uint64
}

// edacCounters scans every EDAC memory controller under EDACGlob.
// Controllers whose counter files don't parse contribute nothing
// (a mid-reset controller serves short reads — never fabricate
// zeros from them). Sorted by controller name so the textfile
// render and evidence strings stay deterministic.
func (r *Runner) edacCounters() []edacMC {
	var out []edacMC
	for _, dir := range globOr(r.deps.EDACGlob) {
		u, okU := fsx.ReadUintFile(filepath.Join(dir, "ue_count"))
		c, okC := fsx.ReadUintFile(filepath.Join(dir, "ce_count"))
		// A controller that serves only ONE of its two counters is
		// mid-reset, not healthy: including it would fabricate a
		// zero for the missing counter (a ue_count=0 series that
		// falsely reassures the scrape and hides the UE signal).
		// Skip unless BOTH parsed — the fail-safe direction.
		if !okU || !okC {
			continue
		}
		out = append(out, edacMC{name: filepath.Base(dir), ue: u, ce: c})
	}
	slices.SortFunc(out, func(a, b edacMC) int {
		return strings.Compare(a.name, b.name)
	})
	return out
}

// acuteEvidence returns the still-fresh acute kmsg evidence,
// partitioned into the hardware-corruption set and the GPU set.
// Map iteration order is random — sort the output so the
// STATE-ENTER evidence string is deterministic.
func (r *Runner) acuteEvidence(now time.Time) (hw, gpu []string) {
	pruned := false
	for class, a := range r.hw.acute {
		if now.Sub(a.at) >= hwAcuteEvidenceTTL {
			delete(r.hw.acute, class)
			pruned = true
			continue
		}
		if strings.HasPrefix(class, gpuAcutePrefix) {
			gpu = append(gpu, a.detail)
		} else {
			hw = append(hw, a.detail)
		}
	}
	if pruned {
		r.saveHwEvidence()
	}
	slices.Sort(hw)
	slices.Sort(gpu)
	return hw, gpu
}

// updateHardwareHealth drives state-hardware-corrupted and
// state-gpu-hardware-error — held while ANY evidence class is
// present, cleared only when all of them are absent (an unreadable
// source contributes nothing — the fs-readonly fail-safe rule).
func (r *Runner) updateHardwareHealth() {
	now := r.deps.Clock.Now()
	var evidence []string

	var corruptedKB uint64
	var corruptedOK bool
	if corruptedKB, corruptedOK = meminfoHardwareCorruptedKB(r.deps.ProcRoot); corruptedOK && corruptedKB > 0 {
		evidence = append(evidence,
			fmt.Sprintf("meminfo HardwareCorrupted=%d kB", corruptedKB))
	}
	eds := r.edacCounters()
	var ue, ce uint64
	for _, mc := range eds {
		ue += mc.ue
		ce += mc.ce
	}
	if ue > 0 {
		evidence = append(evidence,
			fmt.Sprintf("edac ue_count=%d ce_count=%d (%d controllers)",
				ue, ce, len(eds)))
	}
	// NVMe reset streak — prune to the window, then count.
	cutoff := now.Add(-nvmeResetWindow)
	kept := r.hw.nvmeResets[:0]
	for _, t := range r.hw.nvmeResets {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	r.hw.nvmeResets = kept
	if len(r.hw.nvmeResets) >= nvmeResetStreak {
		evidence = append(evidence, fmt.Sprintf(
			"nvme controller resets=%d in %s", len(r.hw.nvmeResets), nvmeResetWindow))
	}
	acuteHW, acuteGPU := r.acuteEvidence(now)
	evidence = append(evidence, acuteHW...)

	r.writeHardwareProm(corruptedKB, corruptedOK, eds)

	if len(evidence) == 0 {
		r.deps.Store.Exit(latchdefs.LatchHardwareCorrupted, nil)
	} else {
		r.deps.Store.Enter(latchdefs.LatchHardwareCorrupted,
			strings.Join(evidence, "; "))
	}
	if len(acuteGPU) == 0 {
		r.deps.Store.Exit(latchdefs.LatchGPUHardwareError, nil)
	} else {
		r.deps.Store.Enter(latchdefs.LatchGPUHardwareError,
			strings.Join(acuteGPU, "; "))
	}
}

// writeHardwareProm renders the hardware gauges — the EDAC
// ue/ce counters per memory controller and the meminfo
// HardwareCorrupted byte count. Each family emits only when its own
// source parsed (the writeDiskPreFailProm rule: no fake zeros).
func (r *Runner) writeHardwareProm(corruptedKB uint64, corruptedOK bool,
	eds []edacMC) {
	if !corruptedOK && len(eds) == 0 {
		return
	}
	var b promfile.Builder
	if corruptedOK {
		b.Gauge("node_agent_memory_hardware_corrupted_bytes",
			"Pages the kernel isolated as hardware-corrupted (/proc/meminfo HardwareCorrupted, kB→bytes) — nonzero means RAM is already known-bad.",
			float64(corruptedKB)*1024)
	}
	for _, mc := range eds {
		b.GaugeLabels("node_agent_edac_uncorrectable_errors",
			"EDAC uncorrectable-error count per memory controller — growth is unrepairable RAM damage.",
			fmt.Sprintf("mc=%q", mc.name), float64(mc.ue))
		b.GaugeLabels("node_agent_edac_correctable_errors",
			"EDAC correctable-error count per memory controller — trend-only; sustained growth precedes UE.",
			fmt.Sprintf("mc=%q", mc.name), float64(mc.ce))
	}
	dir := r.textfileDir()
	_ = promfile.WriteLogged(dir, hardwarePromName,
		[]byte(b.String()), func(dir, _ string, err error) {
			logger().Warn("hostmetrics: hardware textfile install failed",
				"dir", dir, "error", err)
		})
}
