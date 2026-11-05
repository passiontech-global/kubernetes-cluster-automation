// collect_psi_cpu.go — PSI pressure signals and the cpu-delivered
// probe: the cpu some avg60 gauge + state-node-overloaded latch
// (the runner's overload signal), the W5.7 memory/io some+full
// avg60 gauges + vmstat swap-thrash counters, and the busy-loop
// hypervisor-steal canary. Split out of hostmetrics.go.
package hostmetrics

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
)

const (
	defaultPSIFile       = "/proc/pressure/cpu"
	defaultPSIMemoryFile = "/proc/pressure/memory"
	defaultPSIIOFile     = "/proc/pressure/io"
	defaultVMStatFile    = "/proc/vmstat"
	// psiOverloadedOn/Off are the node-overloaded hysteresis — the
	// runner's load15>4*ncpu test replaced by PSI some avg60 (actual
	// stall evidence, not raw load): enter the latch at >=40%,
	// release below 25%.
	psiOverloadedOn  = 40.0
	psiOverloadedOff = 25.0
	// cpuDeliveredTarget is the fixed busy-loop work (~0.3 cpu-s —
	// ~0.1% of a 5m cycle on a healthy node, ~6s wall at 95% steal).
	cpuDeliveredTarget    = 0.3
	cpuDeliveredMaxWall   = 60 * time.Second
	defaultCPUDeliveredIn = 2 * time.Minute
)

// --- PSI overload (runner's node-overloaded) ---

// psiAvg60 parses the "some avg60=" field of /proc/pressure/cpu.
// ok=false on a missing/malformed file — the latch is left untouched
// (inconclusive, like the other file-based signals).
func (c *Collector) psiAvg60() (float64, bool) {
	data, err := os.ReadFile(c.cfg.PSIFile)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "some" {
			continue
		}
		for _, kv := range f[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok || k != "avg60" {
				continue
			}
			x, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return 0, false
			}
			return x, true
		}
	}
	return 0, false
}

// updateOverloadLatch drives state-node-overloaded with hysteresis:
// >=psiOverloadedOn enters, <psiOverloadedOff exits, between the
// thresholds the current state persists. Written only on transition —
// the file content is when the condition STARTED.
func (c *Collector) updateOverloadLatch(avg60 float64) {
	p := c.state.Path(hoststate.LatchNodeOverloaded)
	_, err := os.Stat(p)
	switch {
	case avg60 >= psiOverloadedOn && err != nil:
		content := strconv.FormatInt(c.cfg.nowFn().Unix(), 10) + "\n"
		tmp := filepath.Join(filepath.Dir(p), ".tmp-"+filepath.Base(p))
		if werr := os.WriteFile(tmp, []byte(content), 0o644); werr != nil {
			logger().Warn("hostmetrics: node-overloaded latch write failed",
				"path", p, "error", werr)
		} else if rerr := os.Rename(tmp, p); rerr != nil {
			logger().Warn("hostmetrics: node-overloaded latch install failed",
				"path", p, "error", rerr)
		} else {
			logger().Info("hostmetrics: node-overloaded latch set — "+
				"PSI cpu some avg60 above threshold",
				"avg60", avg60,
				"enterThreshold", psiOverloadedOn, "path", p)
		}
	case avg60 < psiOverloadedOff && err == nil:
		if rerr := os.Remove(p); rerr != nil {
			logger().Warn("hostmetrics: node-overloaded latch remove failed",
				"path", p, "error", rerr)
		} else {
			logger().Info("hostmetrics: node-overloaded latch cleared — "+
				"PSI cpu some avg60 back below threshold",
				"avg60", avg60,
				"exitThreshold", psiOverloadedOff, "path", p)
		}
	}
}

// collectPSI emits the avg60 gauge only when PSI parsed.
func (c *Collector) collectPSI(ch chan<- prometheus.Metric, avg60 float64, ok bool) {
	if !ok {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.descPSI,
		prometheus.GaugeValue, avg60)
}

// --- cpu-delivered probe (lib.sh measure_cpu_delivered) ---

// maybeMeasureCPU re-arms the busy-loop probe every
// CPUDeliveredInterval. The probe itself runs in a goroutine so a
// scrape never blocks on wall-clock steal; the gauges serve the last
// completed measurement.
func (c *Collector) maybeMeasureCPU() {
	c.mu.Lock()
	if c.cpuRunning ||
		c.cfg.nowFn().Sub(c.cpuLast) < c.cfg.CPUDeliveredInterval {
		c.mu.Unlock()
		return
	}
	c.cpuRunning = true
	c.mu.Unlock()
	go func() {
		ratio, wall, ok := c.measureCPU()
		c.mu.Lock()
		c.cpuRunning = false
		c.cpuLast = c.cfg.nowFn()
		if ok {
			c.cpuRatio, c.cpuWall, c.cpuOK = ratio, wall, true
		}
		c.mu.Unlock()
		if !ok {
			logger().Warn("hostmetrics: cpu-delivered probe did not " +
				"complete — serving previous result",
			)
		}
	}()
}

// measureCPU burns a fixed ~0.3 cpu-s on a LOCKED thread and returns
// ratio = cpu_target / wall (capped 1.0 — jiffies overshoot can make
// wall slightly under target). RUSAGE_THREAD isolates the probe from
// other goroutines' CPU — the shell measured the whole-process
// jiffies; a locked thread is the closest Go equivalent.
func (c *Collector) measureCPU() (ratio, wall float64, ok bool) {
	if c.cfg.cpuMeasure != nil {
		return c.cfg.cpuMeasure()
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var ru0, ru1 unix.Rusage
	if unix.Getrusage(unix.RUSAGE_THREAD, &ru0) != nil {
		return 0, 0, false
	}
	cpuAt := func(r *unix.Rusage) float64 {
		return float64(r.Utime.Sec) + float64(r.Utime.Usec)/1e6 +
			float64(r.Stime.Sec) + float64(r.Stime.Usec)/1e6
	}
	wall0 := time.Now()
	var sink uint64
	for i := uint64(0); ; i++ {
		sink += i // any real work — jiffie-counted CPU
		if i%65536 == 0 {
			if unix.Getrusage(unix.RUSAGE_THREAD, &ru1) != nil {
				return 0, 0, false
			}
			if cpuAt(&ru1)-cpuAt(&ru0) >= cpuDeliveredTarget {
				break
			}
			if time.Since(wall0) > cpuDeliveredMaxWall {
				return 0, 0, false // probe itself stalled — no metric
			}
		}
	}
	c.mu.Lock()
	c.cpuSink = sink
	c.mu.Unlock()
	wall = time.Since(wall0).Seconds()
	if wall <= 0 {
		return 0, 0, false
	}
	ratio = cpuDeliveredTarget / wall
	if ratio > 1 {
		ratio = 1
	}
	return ratio, wall, true
}

// collectCPUDelivered emits the last completed probe — absent before
// the first measurement (shell: no cpu-delivered file → no metric,
// never a fake 0).
func (c *Collector) collectCPUDelivered(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	ok, ratio, wall := c.cpuOK, c.cpuRatio, c.cpuWall
	c.mu.Unlock()
	if !ok {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.descCPURatio,
		prometheus.GaugeValue, ratio)
	ch <- prometheus.MustNewConstMetric(c.descCPUWall,
		prometheus.GaugeValue, wall)
}

// --- W5.7: PSI memory/IO pressure + vmstat swap-thrash counters ---

// psiAvg60Full parses BOTH avg60 values of a PSI file — the "some"
// line (any-task stalled) and the "full" line (all-tasks stalled).
// A missing/unreadable file or a missing field reports that side as
// unparsed — PSI may be compiled out of the kernel and emitting a
// fake 0 would hide that.
func psiAvg60Full(path string) (some, full float64, someOK, fullOK bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, false, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || (f[0] != "some" && f[0] != "full") {
			continue
		}
		for _, kv := range f[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok || k != "avg60" {
				continue
			}
			x, err := strconv.ParseFloat(v, 64)
			if err != nil {
				continue
			}
			if f[0] == "some" {
				some, someOK = x, true
			} else {
				full, fullOK = x, true
			}
		}
	}
	return some, full, someOK, fullOK
}

// vmstatCounters extracts the named cumulative counters from
// /proc/vmstat — "key value" per line (pswpin/pswpout for W5.7).
// Missing keys are simply absent from the map.
func vmstatCounters(path string, keys ...string) map[string]uint64 {
	want := make(map[string]bool, len(keys))
	for _, k := range keys {
		want[k] = true
	}
	out := map[string]uint64{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || !want[f[0]] {
			continue
		}
		if v, err := strconv.ParseUint(f[1], 10, 64); err == nil {
			out[f[0]] = v
		}
	}
	return out
}

// collectMemoryIO emits the PSI memory/io some+full avg60 gauges and
// the vmstat pswpin/pswpout counters — each only when its own source
// parses (a kernel without PSI or a missing vmstat yields absent
// series, never a fake 0 — same emission rule as conntrack).
func (c *Collector) collectMemoryIO(ch chan<- prometheus.Metric) {
	if some, full, someOK, fullOK := psiAvg60Full(c.cfg.PSIMemoryFile); someOK || fullOK {
		if someOK {
			ch <- prometheus.MustNewConstMetric(c.descPSIMemSome,
				prometheus.GaugeValue, some, c.cfg.NodeName)
		}
		if fullOK {
			ch <- prometheus.MustNewConstMetric(c.descPSIMemFull,
				prometheus.GaugeValue, full, c.cfg.NodeName)
		}
	}
	if some, full, someOK, fullOK := psiAvg60Full(c.cfg.PSIIOFile); someOK || fullOK {
		if someOK {
			ch <- prometheus.MustNewConstMetric(c.descPSIIOSome,
				prometheus.GaugeValue, some, c.cfg.NodeName)
		}
		if fullOK {
			ch <- prometheus.MustNewConstMetric(c.descPSIIOFull,
				prometheus.GaugeValue, full, c.cfg.NodeName)
		}
	}
	vm := vmstatCounters(c.cfg.VMStatFile, "pswpin", "pswpout")
	for _, k := range []struct {
		key  string
		desc *prometheus.Desc
	}{
		{"pswpin", c.descPSWPIn},
		{"pswpout", c.descPSWPOut},
	} {
		if v, ok := vm[k.key]; ok {
			ch <- prometheus.MustNewConstMetric(k.desc,
				prometheus.CounterValue, float64(v), c.cfg.NodeName)
		}
	}
}
