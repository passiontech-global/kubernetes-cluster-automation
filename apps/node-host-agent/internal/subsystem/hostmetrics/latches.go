// latches.go — W8 latch maintenance (BUG-H5/H6, W8-KR3).
//
// hostmetrics was a pure scrape-time collector: the watchdog-state
// file contract (state-node-overloaded, state-filesystem-readonly,
// state-nebula-cert-expiring, state-kernel-keys-pressure) only moved
// when Prometheus scraped — a DaemonSet pod that isn't scraped every
// 30s (or at all) left stale or missing latches for the file
// consumers (nodereporter conditions, the restart gates). Run() is
// the scrape-independent 30s ticker that keeps them fresh — it runs
// in BOTH modes (Standalone only changes where series are rendered,
// not who owns the latches).
//
// While a latch stays held its mtime is refreshed (BUG-H6) so the
// janitor's 24h reap can't retire an active signal.
//
// The subsystem role lives on Latches, a thin wrapper over the
// Collector: the latch updaters share the collector's cfg + probe
// seams (probeFS, psiAvg60, nebulaCertDaysLeft, the hoststate
// Store), so the split keeps the same package — Latches reaches
// them via l.c. The Wave-10 kernel deep-failure block (kmsg drain,
// pid/fd pressure, steal/entropy, clock skew, fs-readonly evidence)
// delegates to l.c.kf — the kernelfail subpackage engine, which
// produces latch/marker files rather than scrape series.
package hostmetrics

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/cycle"
)

// Latches is the agent.Subsystem half of hostmetrics — the
// scrape-independent latch-maintenance ticker. The Collector keeps
// the prometheus.Collector role; the scrape-shared latch updaters
// share its cfg and probe seams via l.c, and the W10 kernel
// deep-failure checks delegate to l.c.kf (the kernelfail engine).
type Latches struct{ c *Collector }

// Latches returns the subsystem half of this Collector — the
// latch-ticker Name/Run the agent loop drives. The Collector itself
// stays a pure prometheus.Collector.
func (c *Collector) Latches() *Latches { return &Latches{c: c} }

// Collector returns the collector the latch runner wraps — the
// wiring layer's standalone textfile writer needs it for
// WriteTextfile.
func (l *Latches) Collector() *Collector { return l.c }

// Name identifies the subsystem for the agent loop.
func (l *Latches) Name() string { return "hostmetrics" }

// Run drives the latch-maintenance ticker until ctx is cancelled;
// the /dev/kmsg session the engine lazily opened is released on
// exit.
func (l *Latches) Run(ctx context.Context) {
	defer l.c.kf.Close()
	cycle.Every("hostmetrics", l.c.cfg.LatchInterval,
		func(context.Context) { l.refreshLatches() }).Run(ctx)
}

// refreshLatches re-evaluates every file-contract latch once — the
// same logic Collect runs per scrape, decoupled from scrapes
// (BUG-H5). Each updater is already idempotent + hysteresis-safe.
func (l *Latches) refreshLatches() {
	c := l.c
	if avg60, ok := c.psiAvg60(); ok {
		c.updateOverloadLatch(avg60)
	}
	days, certOK := c.nebulaCertDaysLeft()
	c.updateCertLatch(days, certOK)
	// Filesystem read-only: probe each target like collectFilesystem
	// but only for the latch (metrics are scrape-side).
	anyRO, probed := false, false
	for _, mount := range c.cfg.FilesystemTargets {
		st, _, ok := c.probeFS(mount)
		if !ok {
			continue
		}
		probed = true
		if st.Flags&1 != 0 { // unix.ST_RDONLY without importing unix twice
			anyRO = true
		}
	}
	c.updateFSReadonlyLatch(anyRO, probed)
	// W8-KR3: kernel keyring quota pressure.
	if ratio, ok := c.kernelKeysUsedRatio(); ok {
		l.updateKernelKeysLatch(ratio)
	}
	// W10-KR1/KR2/KR5 + W10-ST1 + cpu-steal-guard: the kernel
	// deep-failure block — the kmsg drain (evidence markers
	// kmsg-fs-error, kmsg-conntrack-drops, kmsg-host-oom-* the
	// fs-readonly latch and workerhygiene's SystemOOMVictim /
	// vm.compact_memory consumers read), pid/fd pressure,
	// steal/entropy, clock skew and fs-readonly evidence, in that
	// fixed order. Lives in the kernelfail subpackage; ticker-only
	// — a scrape-side drain would steal records from this loop.
	c.kf.Refresh()
	// BUG-H6: while a latch stays held keep its mtime fresh so the
	// janitor's LatchMaxAge reap can't retire an active signal.
	for _, name := range []string{
		latchdefs.LatchNodeOverloaded,
		latchdefs.LatchFilesystemReadonly,
		latchdefs.LatchNebulaCertExpiring,
		latchdefs.LatchKernelKeysPressure,
		// W10 maintained latches — same reap protection.
		latchdefs.LatchFSReadonly,
		latchdefs.LatchPIDFDPressure,
		latchdefs.LatchClockSkew,
		// Held latches minted elsewhere share the same reap
		// exposure: kubeconfig-cert-expiring is controllerhygiene's
		// signal and cpu-steal-pressure is the steal-guard's — a
		// touch here costs one stat per tick and keeps an active
		// episode from being reaped as stale.
		latchdefs.LatchKubeconfigCertExpiring,
		latchdefs.LatchCPUStealPressure,
	} {
		p := c.state.Path(name)
		if _, err := os.Stat(p); err == nil {
			now := c.cfg.Clock.Now()
			if cerr := os.Chtimes(p, now, now); cerr != nil {
				logger().Debug("hostmetrics: latch touch failed",
					"path", p, "error", cerr)
			}
		}
	}
}

// --- W8-KR3: /proc/key-users kernel keyring quota ---

// kernelKeysUsedRatio returns the highest fill ratio across the
// per-UID rows of /proc/key-users ("uid: usage nkeys nikeys maxkeys
// maxbytes" — nikeys vs maxkeys is the enforced quota). ok=false on
// a missing/unparseable file (kernel keyring disabled or proc
// absent) — inconclusive evidence must not move the latch.
func (c *Collector) kernelKeysUsedRatio() (float64, bool) {
	data, err := os.ReadFile(c.cfg.KeyUsersFile)
	if err != nil {
		return 0, false
	}
	best := -1.0
	seen := false
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		// Fields after the "uid:" label: usage nkeys nikeys maxkeys
		// maxbytes — column order of proc_key_users_show.
		nikeys, errN := strconv.ParseFloat(f[3], 64)
		maxkeys, errM := strconv.ParseFloat(f[4], 64)
		if errN != nil || errM != nil || maxkeys <= 0 {
			continue
		}
		seen = true
		if r := nikeys / maxkeys; r > best {
			best = r
		}
	}
	if !seen {
		return 0, false
	}
	return best, true
}

// updateKernelKeysLatch drives state-kernel-keys-pressure (W8-KR3):
// set above 0.80 of the enforced quota — a full keyring fails
// keyctl_join/add_key silently for new sessions. Enter/Exit carry
// the STATE-ENTER/STATE-EXIT lines nodereporter's KernelKeysPressure
// event rule consumes.
func (l *Latches) updateKernelKeysLatch(ratio float64) {
	if ratio > kernelKeysPressureRatio {
		l.c.state.Enter(latchdefs.LatchKernelKeysPressure,
			fmt.Sprintf("ratio=%.3f > %.2f", ratio, kernelKeysPressureRatio))
		return
	}
	l.c.state.Exit(latchdefs.LatchKernelKeysPressure, nil)
}

var descKernelKeys = prometheus.NewDesc(
	"node_host_agent_kernel_keys_used_ratio",
	"Highest per-UID keyring fill ratio from /proc/key-users (instantiated/max; >0.80 latches state-kernel-keys-pressure).",
	[]string{"node"}, nil)

// collectKernelKeys emits the W8-KR3 used-ratio gauge — absent when
// the file doesn't parse (no fake 0).
func (c *Collector) collectKernelKeys(ch chan<- prometheus.Metric) {
	ratio, ok := c.kernelKeysUsedRatio()
	if !ok {
		return
	}
	ch <- prometheus.MustNewConstMetric(descKernelKeys,
		prometheus.GaugeValue, ratio, c.cfg.NodeName)
}
