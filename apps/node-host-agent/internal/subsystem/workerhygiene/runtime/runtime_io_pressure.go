// runtime_io_pressure.go — the io-pressure-throttler guard
// (wdeps.CheckIOPressure). Bulk background IO (backups,
// vulnerability scans, fstrim, eBPF agents) starves latency-critical
// writes: the node shows healthy while every fsync queues behind a
// kopia stream. The check keeps a per-whole-disk io_ticks/util and
// write-await delta plus the PSI io `full` averages as gauges, and
// above the pressure bar puts the known background hogs into idle
// IO class + lowest CPU priority. Throttling is sticky per pid — a
// pid is deprioritized once, and a pid-slot reuse (same pid,
// different comm) re-qualifies.
package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const (
	// ioPSIFullHigh is the /proc/pressure/io `full` average
	// (percent) above which the node is IO-starved — same percent
	// scale as the memory PSI thresholds.
	ioPSIFullHigh = 25.0
	// diskWriteAwaitHighMs is the per-cycle mean write await above
	// which latency-critical IO is queued behind bulk writers.
	diskWriteAwaitHighMs = 200.0
	// diskSlowIOConsecNeeded is the consecutive-cycle count the
	// W12-KR4 DiskSlowIO gray-failure verdict must persist before
	// latching — ~10m at the default 2m interval, so a bursty
	// backup or fstrim spike can't cordon the node.
	diskSlowIOConsecNeeded = 5
)

var (
	// diskPartRe names block devices that are partitions, not
	// whole disks — nvme/mmc style pN suffixes and the classic
	// sdX#/vdX# letter-digit forms. A partition's io_ticks is
	// double-counted against its parent's, so only whole devices
	// feed the utilization/await gauges.
	diskPartRe = regexp.MustCompile(`p[0-9]+$|^(sd|vd|xvd|hd)[a-z]+[0-9]+$`)

	// ioThrottleTargets are the background IO-hog comms the
	// io-pressure throttler deprioritizes — backup, scanner and
	// maintenance agents whose bulk reads/writes starve
	// latency-critical work but tolerate idle-class scheduling.
	ioThrottleTargets = map[string]bool{
		"kopia": true, "velero": true, "trivy": true,
		"maltrail": true, "fstrim": true, "falco": true,
		"ig": true, "obi": true,
	}
)

// diskIOStat is one whole-disk row of /proc/diskstats, reduced to
// the counters the deltas need (all in kernel units: ios, ms).
type diskIOStat struct {
	rdIOS   uint64 // field 3  — reads completed
	rdTicks uint64 // field 6  — ms spent reading
	wrIOS   uint64 // field 7  — writes completed
	wrTicks uint64 // field 10 — ms spent writing
	ioTicks uint64 // field 12 — ms doing IO (utilization source)
}

// isWholeDisk reports whether a diskstats device name is a whole
// disk rather than a partition or virtual device — partition IO is
// double-counted in its parent and loop/dm/zram/ram devices are
// stacked layers, not the spindle that stalls.
func isWholeDisk(name string) bool {
	for _, p := range []string{
		"loop", "ram", "zram", "dm-", "md", "nbd", "sr", "fd", "pmem",
	} {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	return !diskPartRe.MatchString(name)
}

// parseDiskstats reduces /proc/diskstats to whole-disk rows.
// Malformed rows are skipped — the format is stable across kernels
// but extra trailing fields (discards, flush) must not matter.
func parseDiskstats(data []byte) map[string]diskIOStat {
	out := map[string]diskIOStat{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 14 || !isWholeDisk(f[2]) {
			continue
		}
		var s diskIOStat
		if v, err := strconv.ParseUint(f[3], 10, 64); err == nil {
			s.rdIOS = v
		}
		if v, err := strconv.ParseUint(f[6], 10, 64); err == nil {
			s.rdTicks = v
		}
		if v, err := strconv.ParseUint(f[7], 10, 64); err == nil {
			s.wrIOS = v
		}
		if v, err := strconv.ParseUint(f[10], 10, 64); err == nil {
			s.wrTicks = v
		}
		if v, err := strconv.ParseUint(f[12], 10, 64); err == nil {
			s.ioTicks = v
		}
		out[f[2]] = s
	}
	return out
}

// psiIOFullAvgs parses <ProcRoot>/pressure/io — the `full` avg60
// and avg300 values (percent of wall time ALL tasks stalled on IO).
// ok=false when PSI io is unavailable (old kernel / psi disabled)
// — the check then runs on the diskstats half alone.
func psiIOFullAvgs(d *wdeps.Deps) (avg60, avg300 float64, ok bool) {
	data, err := os.ReadFile(filepath.Join(d.Cfg.ProcRoot, "pressure", "io"))
	if err != nil {
		return 0, 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "full" {
			continue
		}
		for _, kv := range f[1:] {
			k, v, cut := strings.Cut(kv, "=")
			if !cut {
				continue
			}
			x, err := strconv.ParseFloat(v, 64)
			if err != nil {
				continue
			}
			switch k {
			case "avg60":
				avg60, ok = x, true
			case "avg300":
				avg300 = x
			}
		}
	}
	return avg60, avg300, ok
}

// IOPressureCheck is the disk-IO starvation guard as a Check. It
// keeps the previous diskstats snapshot for the delta math, the
// pid→comm throttle ledger (pid reuse protection) and the W12-KR4
// consecutive-cycle disk-slow-io streak.
type IOPressureCheck struct {
	d             *wdeps.Deps
	lastDisk      map[string]diskIOStat
	lastTime      time.Time
	throttled     map[int]string
	diskSlowFails int
}

// Name returns the check label / WD_SIG key.
func (c *IOPressureCheck) Name() string { return wdeps.CheckIOPressure }

// Run executes one io-pressure round.
func (c *IOPressureCheck) Run(_ context.Context, e *wdeps.CycleEnv) {
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckIOPressure, "gated").Inc()
		return
	}
	data, err := os.ReadFile(filepath.Join(c.d.Cfg.ProcRoot, "diskstats"))
	if err != nil {
		c.d.Cycles.WithLabelValues(wdeps.CheckIOPressure, "abort").Inc()
		return
	}
	now := c.d.Cfg.Seams.Host.Clock.Now()
	cur := parseDiskstats(data)
	util, await, maxAwait := 0.0, 0.0, 0.0
	if c.lastDisk != nil {
		dtMs := float64(now.Sub(c.lastTime).Milliseconds())
		if dtMs > 0 {
			var dWr, dWrMs uint64
			for name, s := range cur {
				prev, ok := c.lastDisk[name]
				// A wrapped/reset counter or a new device yields no
				// delta — skip rather than invent huge numbers.
				if !ok || s.ioTicks < prev.ioTicks {
					continue
				}
				if u := float64(s.ioTicks-prev.ioTicks) / dtMs; u > util {
					util = u
				}
				if s.wrIOS >= prev.wrIOS {
					dWr += s.wrIOS - prev.wrIOS
				}
				if s.wrTicks >= prev.wrTicks {
					dWrMs += s.wrTicks - prev.wrTicks
					// Per-disk max read/write await for the W12-KR4
					// DiskSlowIO latch — a single dying device
					// (bad-sector remap, RAID rebuild, slow SAN)
					// is the signal; the pooled await above
					// dilutes it across healthy disks.
					if dios := s.wrIOS - prev.wrIOS; dios > 0 {
						if a := float64(s.wrTicks-prev.wrTicks) /
							float64(dios); a > maxAwait {
							maxAwait = a
						}
					}
				}
				if s.rdTicks >= prev.rdTicks && s.rdIOS >= prev.rdIOS {
					if dios := s.rdIOS - prev.rdIOS; dios > 0 {
						if a := float64(s.rdTicks-prev.rdTicks) /
							float64(dios); a > maxAwait {
							maxAwait = a
						}
					}
				}
			}
			if dWr > 0 {
				await = float64(dWrMs) / float64(dWr)
			}
		}
	}
	c.lastDisk, c.lastTime = cur, now
	c.d.DiskIOUtilRatio = util
	c.d.DiskWriteAwaitMs = await
	avg60, avg300, psiOK := psiIOFullAvgs(c.d)
	c.d.IOPSIFullAvg60 = avg60
	c.d.IOPSIFullAvg300 = avg300
	// W12-KR4: the DiskSlowIO gray-failure latch — a whole disk
	// whose write await stays >200ms WHILE io PSI full avg60 sits
	// >= 25% for >=5 consecutive cycles (~10m) is a dying device
	// or a slow shared-storage path: ScyllaDB/PostgreSQL/kubelet
	// stall long before any task hits D-state (KernelHungTasks)
	// or the fs remounts ro (FilesystemReadOnly). Latch-only by
	// design: nodereporter maps it to the DiskSlowIO condition
	// for node-hang-precordon / descheduler-storm-gate so the
	// scheduler stops placing stateful pods here — it must NEVER
	// feed a reboot path (a shared SAN slowdown would
	// mass-reboot the fleet).
	if maxAwait > diskWriteAwaitHighMs && psiOK && avg60 >= ioPSIFullHigh {
		c.diskSlowFails++
		if c.diskSlowFails >= diskSlowIOConsecNeeded {
			c.d.State.Enter(hoststate.LatchDiskSlowIO, fmt.Sprintf(
				"max_await=%.1fms psi_avg60=%.1f fails=%d",
				maxAwait, avg60, c.diskSlowFails))
		} else {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: disk-slow-io max_await=%.1fms psi_avg60=%.1f (check %d/%d)",
				maxAwait, avg60, c.diskSlowFails, diskSlowIOConsecNeeded))
		}
	} else {
		c.diskSlowFails = 0
		c.d.State.Exit(hoststate.LatchDiskSlowIO, nil)
	}
	pressure := await > diskWriteAwaitHighMs ||
		(psiOK && (avg300 > ioPSIFullHigh || avg60 > ioPSIFullHigh))
	if !pressure {
		c.d.Cycles.WithLabelValues(wdeps.CheckIOPressure, "ok").Inc()
		return
	}
	if c.throttled == nil {
		c.throttled = map[int]string{}
	}
	pids := e.PidsOnce()
	// Prune dead pids from the ledger — and a recycled pid whose
	// comm changed re-qualifies below (the entry still matches only
	// the same comm).
	alive := map[int]bool{}
	for _, pid := range pids {
		alive[pid] = true
	}
	for pid := range c.throttled {
		if !alive[pid] {
			delete(c.throttled, pid)
		}
	}
	for _, pid := range pids {
		if _, done := c.throttled[pid]; done {
			continue
		}
		raw, err := os.ReadFile(c.d.Proc.File(pid, "comm"))
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(raw))
		if !ioThrottleTargets[comm] {
			continue
		}
		// Deprioritize BOTH dimensions: renice +19 (CPU) and ionice
		// idle (the process only gets the disk when nothing else
		// wants it). Either failing is logged, never fatal — a pid
		// can exit mid-sweep.
		if err := c.d.Cfg.Seams.Host.ReniceFn(pid); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: io-pressure-throttler renice +19 pid=%d (%s) failed: %v",
				pid, comm, err))
		}
		if err := c.d.Cfg.Seams.Host.IoniceIdleFn(pid); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: io-pressure-throttler ionice -c3 pid=%d (%s) failed: %v",
				pid, comm, err))
		}
		c.throttled[pid] = comm
		c.d.IOThrottledProcs++
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: io-pressure-throttler deprioritized pid=%d comm=%s (await=%.1fms psi60=%.1f psi300=%.1f)",
			pid, comm, await, avg60, avg300))
		c.d.Actions.WithLabelValues(wdeps.CheckIOPressure, "throttle").Inc()
	}
	c.d.Cycles.WithLabelValues(wdeps.CheckIOPressure, "ok").Inc()
}
