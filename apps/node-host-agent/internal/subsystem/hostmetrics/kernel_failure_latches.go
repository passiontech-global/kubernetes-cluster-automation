// kernel_failure_latches.go — the parent half of the
// kernel deep-failure contract.
//
// The engine itself — the /dev/kmsg drain, the pid/fd
// resource-pressure, clock-skew, fs-readonly-evidence and
// steal/entropy latch updaters plus their shared statePath /
// ensureStateLatch helpers — lives in the kernelfail subpackage:
// those checks produce state-* latches, evidence markers and
// node-exporter textfile gauges, never a prometheus series, so the
// split keeps the scrape-time Collector free of file-contract
// machinery. The contract overview moved with the code — see
// kernelfail's package doc.
//
// What stays here is the seam surface the engine's Deps closes
// over: the runHostCmd and kmsgDevicePaths package vars the
// hostmetrics test suite stubs in package (fixtureSeams pins them
// to the fixture root — the closures below read the var per call,
// so a post-New re-stub still lands exactly like the pre-split
// direct reads did).
package hostmetrics

import (
	"context"
	"errors"
	"time"

	"golang.org/x/sys/unix"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hostexec"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/kmsg"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/hostmetrics/kernelfail"
)

// defaultRunHostCmd builds the default host-command executor for
// hostRoot. Production gets a hostexec.Runner entering every host
// PID-1 namespace; HostRoot "/" (standalone) runs unwrapped.
func defaultRunHostCmd(hostRoot string) func(ctx context.Context, argv ...string) (string, error) {
	runner := hostexec.New(hostexec.Config{HostRoot: hostRoot,
		ScrubSystemdEnv: true})
	return func(ctx context.Context, argv ...string) (string, error) {
		if len(argv) == 0 {
			return "", errors.New("hostmetrics: empty host argv")
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		return runner.ExecCombined(cctx, hostexec.NSAll, argv[0], argv[1:]...)
	}
}

func defaultKmsgDevicePaths(hostRoot string) []string {
	return kmsg.DevicePaths("/dev/kmsg", hostRoot)
}

// kernelFailDeps assembles the engine's dependency surface off the
// Collector — the exported Config fields verbatim, the shared
// hoststate.Store and clock cell, and the three seams as late-bound
// closures so both packages' test stubs keep working (Adjtimex is
// the one Config knob private to this package; cfg.adjtimexFn
// re-stubs after New still land through the closure).
func (c *Collector) kernelFailDeps() kernelfail.Deps {
	return kernelfail.Deps{
		StateDir:         c.cfg.WatchdogStateDir,
		ProcRoot:         c.cfg.ProcRoot,
		HostRoot:         c.cfg.HostRoot,
		ConntrackMaxFile: c.cfg.ConntrackMaxFile,
		FileNRFile:       c.cfg.FileNRFile,
		OpenEBSLocalDir:  c.cfg.OpenEBSLocalDir,
		Store:            c.state,
		Clock:            c.cfg.Clock,
		TickInterval:     c.cfg.LatchInterval,
		Adjtimex: func(tx *unix.Timex) (int, error) {
			return c.cfg.adjtimexFn(tx)
		},
		RunHostCmd: func(ctx context.Context, argv ...string) (string, error) {
			return c.cfg.runHostCmd(ctx, argv...)
		},
		KmsgDevicePaths: func(hostRoot string) []string {
			return c.cfg.kmsgDevicePaths(hostRoot)
		},
		// Self-healing wave — the neighbor/NIC threshold knobs cross
		// verbatim (kernelfail.New defaults any <=0); RouteFile
		// reuses the collector's HOST_ROUTE_FILE knob so one override
		// moves both readers. The remaining path seams stay empty so
		// New() applies its HostRoot/ProcRoot joins.
		RouteFile:             c.cfg.RouteFile,
		NeighGCThresh1Ceiling: c.cfg.NeighGCThresh1Ceiling,
		NeighGCThresh2Ceiling: c.cfg.NeighGCThresh2Ceiling,
		NeighGCThresh3Ceiling: c.cfg.NeighGCThresh3Ceiling,
		// P0.4 flush guard — the knobs cross verbatim (kernelfail.New
		// defaults the unset ones).
		NeighFlushGuard:          c.cfg.NeighFlushGuard,
		NeighFlushEvictStale:     c.cfg.NeighFlushEvictStale,
		NeighFlushEvictNudFailed: c.cfg.NeighFlushEvictNudFailed,
		NeighFlushEvictReachable: c.cfg.NeighFlushEvictReachable,
		NeighFlushCooldown:       c.cfg.NeighFlushCooldown,
		NeighFlushArpCeiling:     c.cfg.NeighFlushArpCeiling,
		NeighFlushNdiscCeiling:   c.cfg.NeighFlushNdiscCeiling,
		NeighFlushTableFulls:     c.cfg.NeighFlushTableFulls,
		NICCarrierFlapThreshold:  c.cfg.NICCarrierFlapThreshold,
		NICTxTimeoutThreshold:    c.cfg.NICTxTimeoutThreshold,
		NICCRErrorThreshold:      c.cfg.NICCRErrorThreshold,
		// P2.12 GPU PCIe census — mode + expected count cross
		// verbatim (ModeAuto is the zero value; <=0 expected count
		// means learn-from-hardware).
		GPUGuardMode:     c.cfg.GPUGuardMode,
		GPUExpectedCount: c.cfg.GPUExpectedCount,
	}
}
