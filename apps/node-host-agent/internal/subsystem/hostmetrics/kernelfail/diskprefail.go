// diskprefail.go — disk-pre-fail updateDiskPreFailEvidence (roadmap
// A5): the NVMe/SSD/ext4 soft-error counters climb days BEFORE
// FilesystemReadOnly fires (by then the LocalPV data is already
// unreadable), so this updater watches the pre-fail evidence and
// latches state-disk-pre-fail while any of it is present:
//
//   - /sys/fs/ext4/<dev>/errors_count (roadmap literal): the
//     superblock-resident metadata-error count — it survives agent
//     restarts AND remounts, so ">0 was once wrong" is a persistent
//     verdict, and an increase() on the exported gauge is the alert
//     shape. Averaged fleet posture: Contabo vda VMs carry ext4, so
//     this is the live signal today.
//   - NVMe SMART early indicators (roadmap literal set):
//     critical_warning != 0, media_errors > 0,
//     percentage_used > nvmePercentageUsedMax. Read from the
//     packed nvme_smart_log sysfs page where the kernel ships it
//     (little-endian, critical_warning@0, percentage_used@5,
//     media_errors@160 as a 128-bit LE counter — the low u64), with
//     a `nvme smart-log` RunHostCmd fallback for mainline kernels
//     that never exposed the attribute. On the current fleet (virtio
//     vda, no NVMe class) the whole NVMe half is dormant.
//
// The per-device values export through the node_agent_* textfile
// channel (steal_entropy/pidfd parity — no prometheus desc, no
// domainTable row); the latch is evidence-only (fs-readonly shape:
// held while evidence exists, cleared when all of it is gone — a
// burned cell never un-burns, so a healing latch here means the
// evidence read broke, not that the disk recovered).
package kernelfail

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/promfile"
)

// Sysfs path defaults (Deps seam values — tests re-point them at
// the fixture tree).
const (
	defaultExt4ErrorsGlob = "/sys/fs/ext4/*/errors_count"
	defaultNVMeSmartGlob  = "/sys/class/nvme/nvme*/smart_log"
	// diskPreFailPromName is the textfile family file (steal's
	// node-agent-steal.prom naming).
	diskPreFailPromName = "node-agent-disk-prefail.prom"
)

// Pre-fail thresholds (roadmap 1.2/§A5 literals):
//   - ext4: any recorded error counts (>0).
//   - critical_warning: any nonzero bit.
//   - media_errors: any nonzero count.
//   - percentage_used: past 90% of the vendor-rated endurance the
//     wear-out curve is in its knee — decommission before the
//     spare-block pool runs dry.
const (
	nvmePercentageUsedMax = 90
	// nvmeSmartLogMinLen is the byte length the three read offsets
	// need (media_errors ends at 176; the page itself is 512).
	nvmeSmartLogMinLen = 176
	// nvmeMediaErrorsOffset is the packed struct offset of the
	// 128-bit little-endian media_errors counter (include/uapi
	// nvme.h: critical_warning@0, temperature[2]@1, percent_used@5,
	// endu_grp_crit_warn_sumry@6, rsvd7[25]@7, 6×16-byte counters
	// @32.., unsafe_shutdowns@144, media_errors@160).
	nvmeMediaErrorsOffset = 160
)

// nvmeCliRe parses the `nvme smart-log` text the fallback gets from
// RunHostCmd — "critical_warning : 0", "percentage_used : 42%",
// "media_errors : 0" (the % and unit noise stay out of the capture).
var (
	nvmeCliCriticalRe = regexp.MustCompile(
		`(?m)^\s*critical_warning\s*:\s*(\S+)`)
	nvmeCliPctUsedRe = regexp.MustCompile(
		`(?m)^\s*percentage_used\s*:\s*(\d+)%`)
	nvmeCliMediaRe = regexp.MustCompile(
		`(?m)^\s*media_errors\s*:\s*(\d+)`)
)

// nvmeSmart is one controller's parsed early indicators.
type nvmeSmart struct {
	ctrl            string
	criticalWarning uint64
	mediaErrors     uint64
	percentageUsed  uint64
	// viaCLI marks a RunHostCmd fallback parse (the STATE-ENTER
	// evidence names the source so an operator can tell the sysfs
	// page from nvme-cli output).
	viaCLI bool
}

// ok reports the roadmap's pre-fail verdict for one controller.
func (s nvmeSmart) ok() bool {
	return s.criticalWarning != 0 ||
		s.mediaErrors != 0 ||
		s.percentageUsed > nvmePercentageUsedMax
}

// evidence renders the STATE-ENTER text for one controller.
func (s nvmeSmart) evidence() string {
	src := "sysfs"
	if s.viaCLI {
		src = "nvme-cli"
	}
	return fmt.Sprintf("nvme %s critical_warning=%d media_errors=%d percentage_used=%d (%s)",
		s.ctrl, s.criticalWarning, s.mediaErrors, s.percentageUsed, src)
}

// ext4Errors reads one filesystem's persistent metadata-error
// count. ok=false on an unreadable/unparseable file — inconclusive
// evidence must not move the latch (the kernelKeysUsedRatio rule).
func ext4Errors(path string) (uint64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// parseSmartLogPage decodes the packed sysfs nvme_smart_log page.
// ok=false on a truncated page (a controller mid-reset can serve a
// short read — never fabricate zeros from it).
func parseSmartLogPage(ctrl string, data []byte) (nvmeSmart, bool) {
	if len(data) < nvmeSmartLogMinLen {
		return nvmeSmart{}, false
	}
	return nvmeSmart{
		ctrl:            ctrl,
		criticalWarning: uint64(data[0]),
		percentageUsed:  uint64(data[5]),
		mediaErrors:     binary.LittleEndian.Uint64(data[nvmeMediaErrorsOffset:]),
	}, true
}

// parseSmartLogCLI decodes `nvme smart-log <dev>` text output. Any
// field missing → ok=false (partial tool output is inconclusive).
func parseSmartLogCLI(ctrl, out string) (nvmeSmart, bool) {
	cw := nvmeCliCriticalRe.FindStringSubmatch(out)
	pct := nvmeCliPctUsedRe.FindStringSubmatch(out)
	med := nvmeCliMediaRe.FindStringSubmatch(out)
	if cw == nil || pct == nil || med == nil {
		return nvmeSmart{}, false
	}
	critical, errC := strconv.ParseUint(strings.TrimPrefix(cw[1], "0x"), 0, 64)
	percentage, errP := strconv.ParseUint(pct[1], 10, 64)
	media, errM := strconv.ParseUint(med[1], 10, 64)
	if errC != nil || errP != nil || errM != nil {
		return nvmeSmart{}, false
	}
	return nvmeSmart{
		ctrl:            ctrl,
		criticalWarning: critical,
		percentageUsed:  percentage,
		mediaErrors:     media,
		viaCLI:          true,
	}, true
}

// nvmeSmartPages collects every controller's early indicators: the
// sysfs smart_log page first; when the attribute exists NOWHERE
// (mainline kernels never shipped it) but controllers do, one
// `nvme smart-log /dev/<ctrl>` RunHostCmd probe per controller —
// the chronyc/dmesg deep-failure-probe parity, and a failed probe
// (no nvme-cli installed) is silent at Debug: the 30s ticker must
// not spam the watchdog tail for a device class this host does not
// even carry.
func (r *Runner) nvmeSmartPages(ctx context.Context) []nvmeSmart {
	matches, _ := filepath.Glob(r.deps.NVMeSmartGlob)
	var out []nvmeSmart
	sysfsSeen := 0
	for _, p := range matches {
		ctrl := filepath.Base(filepath.Dir(p))
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		sysfsSeen++
		if s, ok := parseSmartLogPage(ctrl, data); ok {
			out = append(out, s)
		}
	}
	if sysfsSeen > 0 || len(matches) > 0 {
		return out
	}
	// No readable sysfs page anywhere — is there even an NVMe
	// controller here? The smart glob's parent pattern already ends
	// in the controller-class glob ("/sys/class/nvme/nvme*"), so
	// globbing IT lists the controllers whose attribute the kernel
	// never shipped — probe those with nvme-cli.
	ctrlDirs, _ := filepath.Glob(filepath.Dir(r.deps.NVMeSmartGlob))
	for _, dir := range ctrlDirs {
		ctrl := filepath.Base(dir)
		outBytes, err := r.deps.RunHostCmd(ctx,
			"nvme", "smart-log", "/dev/"+ctrl)
		if err != nil {
			logger().Debug("disk-pre-fail: nvme smart-log probe unavailable",
				"ctrl", ctrl, "error", err)
			continue
		}
		if s, ok := parseSmartLogCLI(ctrl, outBytes); ok {
			out = append(out, s)
		}
	}
	return out
}

// updateDiskPreFailEvidence drives state-disk-pre-fail — held while
// any ext4 filesystem has a nonzero metadata-error count or any
// NVMe controller trips an early SMART indicator; Exit clears only
// when BOTH evidence classes are absent (an unreadable source
// contributes nothing — fail-safe, not fail-latch).
func (r *Runner) updateDiskPreFailEvidence() {
	var evidence []string
	ext4ByDev := map[string]uint64{}
	ext4Readable := 0
	for _, p := range globOr(r.deps.Ext4ErrorsGlob) {
		dev := filepath.Base(filepath.Dir(p))
		count, ok := ext4Errors(p)
		if !ok {
			continue
		}
		ext4Readable++
		ext4ByDev[dev] = count
		if count > 0 {
			evidence = append(evidence,
				fmt.Sprintf("ext4 %s errors_count=%d", dev, count))
		}
	}
	smarts := r.nvmeSmartPages(context.Background())
	for _, s := range smarts {
		if s.ok() {
			evidence = append(evidence, s.evidence())
		}
	}
	r.writeDiskPreFailProm(ext4ByDev, ext4Readable, smarts)
	latchPath := r.deps.Store.Path(latchdefs.LatchDiskPreFail)
	if len(evidence) == 0 {
		r.deps.Store.Exit(latchdefs.LatchDiskPreFail, nil)
		return
	}
	r.ensureStateLatch(latchPath,
		latchdefs.LatchFilePrefix+latchdefs.LatchDiskPreFail,
		strings.Join(evidence, "; "))
}

// globOr globs a path, never failing — a missing sysfs class
// contributes nothing (fsreadonly's unreadable-mounts rule).
func globOr(pattern string) []string {
	m, _ := filepath.Glob(pattern)
	return m
}

// sortedKeys returns the map's keys in lexical order — the textfile
// render must be deterministic (a scrape diff must not flip on key
// order).
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// writeDiskPreFailProm renders the per-device gauges — each device
// only when its own source parsed (no fake 0s, the writeStealEntropyProm
// rule). Failures log at Warn (the other textfile emitters'
// converged posture).
func (r *Runner) writeDiskPreFailProm(ext4 map[string]uint64,
	ext4Readable int, smarts []nvmeSmart) {
	if len(ext4) == 0 && len(smarts) == 0 {
		return
	}
	var b promfile.Builder
	// Sorted devs — the textfile render must be deterministic or a
	// scrape diff flips on every tick.
	for _, dev := range sortedKeys(ext4) {
		b.GaugeLabels("node_agent_disk_ext4_prefail_errors_count",
			"Persistent ext4 metadata-error count (/sys/fs/ext4/<dev>/errors_count) — an increase means the kernel logged new filesystem errors.",
			fmt.Sprintf("dev=%q", dev), float64(ext4[dev]))
	}
	for _, s := range smarts {
		src := "sysfs"
		if s.viaCLI {
			src = "nvme-cli"
		}
		b.GaugeLabels("node_agent_nvme_smart_critical_warning",
			"NVMe SMART critical_warning bitmap — any nonzero bit is a controller-level fault (media/sparse/NVM set).",
			fmt.Sprintf("ctrl=%q,src=%q", s.ctrl, src),
			float64(s.criticalWarning))
		b.GaugeLabels("node_agent_nvme_smart_media_errors",
			"NVMe SMART media_errors — data-integrity errors the controller already corrected or flagged; growth is the pre-fail curve.",
			fmt.Sprintf("ctrl=%q,src=%q", s.ctrl, src),
			float64(s.mediaErrors))
		b.GaugeLabels("node_agent_nvme_smart_percentage_used",
			"NVMe SMART percentage_used — vendor-rated endurance consumed; >90% is the decommission-before-death knee.",
			fmt.Sprintf("ctrl=%q,src=%q", s.ctrl, src),
			float64(s.percentageUsed))
	}
	dir := r.textfileDir()
	_ = promfile.WriteLogged(dir, diskPreFailPromName,
		[]byte(b.String()), func(dir, _ string, err error) {
			logger().Warn("hostmetrics: disk pre-fail textfile install failed",
				"dir", dir, "error", err)
		})
}
