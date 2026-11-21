// network_mount_hung.go — Wave-4 #10-L1: Network/FUSE mount hung guard.
//
// Parses the per-cycle mountinfo snapshot for network and FUSE filesystems
// (nfs, nfs4, cifs, smb3, ceph, fuse.* excluding fusectl and fuse.lxcfs) and
// probes each unique topmost mountpoint via Host.StatfsSubprocess (`stat -f`).
// Each mountpoint is guarded by a 1-in-flight-probe mutex map so an
// uninterruptible D-state hang never spawns duplicate goroutines across cycles
// and instead immediately counts as hung while the original probe remains
// wedged. Streak >= max(ConsecNeeded, 2) raises LatchNetworkMountHung and
// populates node_agent_network_mount_hung{mountpoint,fstype} 1.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/checkkit"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/procfs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
	"github.com/passiontech-global/kubernetes-cluster-automation/libs/hostkit/ledger"
)

const (
	defaultMountProbeTimeout = 3 * time.Second
	mountHungSuspectGap      = 30 * time.Minute
	maxMountHungDetailLen    = 200
)

type mountProbeOutcome uint8

const (
	mountProbeHealthy mountProbeOutcome = iota
	mountProbeHung
	mountProbeInconclusive
)

type mountProbeFlight struct {
	done chan struct{}
	err  error
}

// NetworkMountHungCheck is the Wave-4 #10-L1 hung network/FUSE mount guard.
type NetworkMountHungCheck struct {
	d *wdeps.Deps
	// ProbeTimeout bounds each statfs probe attempt; <= 0 defaults to 3s.
	// Exported so external -race tests can run fast deterministic hangs.
	ProbeTimeout time.Duration

	mu       sync.Mutex
	inflight map[string]*mountProbeFlight
	streaks  ledger.StreakLedger
}

// Name returns the check label / WD_SIG key.
func (c *NetworkMountHungCheck) Name() string { return wdeps.CheckNetworkMountHung }

// Run executes one network/FUSE mount health probe round.
func (c *NetworkMountHungCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckNetworkMountHung) {
		return
	}
	if ctx.Err() != nil {
		c.d.CycleResult(wdeps.CheckNetworkMountHung, "abort")
		return
	}

	data, err := c.d.ReadMountinfo(e)
	if err != nil {
		c.d.State.SuspectLog(wdeps.CheckNetworkMountHung+"-mountinfo",
			fmt.Sprintf("suspect: network-mount-hung read mountinfo %s failed: %v",
				c.d.Cfg.MountinfoFile, err),
			mountHungSuspectGap)
		c.d.CycleResult(wdeps.CheckNetworkMountHung, "abort")
		return
	}

	targets := parseNetworkMounts(data)
	if len(targets) == 0 {
		c.streaks.Clear()
		c.d.Series.NetworkMountHung = nil
		c.d.State.ExitClearSuspect(latchdefs.LatchNetworkMountHung)
		c.d.CycleResult(wdeps.CheckNetworkMountHung, "ok")
		return
	}

	outcomes := make([]mountProbeOutcome, len(targets))
	anyInconclusive := false
	for i, target := range targets {
		outcomes[i] = c.probeMount(ctx, target.Mountpoint)
		if outcomes[i] == mountProbeInconclusive {
			anyInconclusive = true
		}
	}
	if anyInconclusive || ctx.Err() != nil {
		if ctx.Err() == nil {
			c.d.State.SuspectLog(wdeps.CheckNetworkMountHung+"-probe",
				"suspect: network-mount-hung statfs probe inconclusive — preserving state",
				mountHungSuspectGap)
		}
		c.d.CycleResult(wdeps.CheckNetworkMountHung, "abort")
		return
	}

	consecNeeded := max(c.d.Cfg.ConsecNeeded, 2)
	live := make(map[string]bool, len(targets))
	var confirmed []wdeps.NetworkMountHungEntry
	for i, target := range targets {
		live[target.Mountpoint] = true
		switch outcomes[i] {
		case mountProbeHealthy:
			c.streaks.Reset(target.Mountpoint)
		case mountProbeHung:
			n := c.streaks.Hit(target.Mountpoint)
			if n < consecNeeded {
				c.d.State.AppendLog(fmt.Sprintf("suspect: network mount hung mount=%s fstype=%s%s",
					target.Mountpoint, target.FSType, checkkit.Progress(n, consecNeeded)))
			} else {
				confirmed = append(confirmed, target)
			}
		}
	}
	c.streaks.Prune(func(k string) bool { return live[k] })
	c.d.Series.NetworkMountHung = confirmed

	if len(confirmed) > 0 {
		detail := formatMountHungDetail(confirmed)
		// nodereporter/events_rules.go emits the NetworkMountHung Warning Event on
		// STATE-ENTER: network-mount-hung and NetworkMountsHealthy Normal Event on
		// STATE-EXIT; do not double-emit via EmitCheckEvent here.
		c.d.State.Enter(latchdefs.LatchNetworkMountHung, detail)
		c.d.State.SuspectLog(latchdefs.LatchNetworkMountHung,
			"suspect: network-mount-hung "+detail, mountHungSuspectGap)
	} else {
		c.d.State.ExitClearSuspect(latchdefs.LatchNetworkMountHung)
	}
	c.d.CycleResult(wdeps.CheckNetworkMountHung, "ok")
}

func (c *NetworkMountHungCheck) probeMount(ctx context.Context, mp string) mountProbeOutcome {
	c.mu.Lock()
	if c.inflight == nil {
		c.inflight = make(map[string]*mountProbeFlight)
	}
	if c.inflight[mp] != nil {
		c.mu.Unlock()
		return mountProbeHung
	}
	if c.d.Cfg.Seams.Host.HostExecFn == nil {
		c.mu.Unlock()
		return mountProbeInconclusive
	}
	f := &mountProbeFlight{done: make(chan struct{})}
	c.inflight[mp] = f
	c.mu.Unlock()

	timeout := c.ProbeTimeout
	if timeout <= 0 {
		timeout = defaultMountProbeTimeout
	}
	host := c.d.Cfg.Seams.Host
	pctx, cancel := context.WithTimeout(ctx, timeout)
	go func() {
		defer cancel()
		err := host.StatfsSubprocess(pctx, mp)
		c.mu.Lock()
		f.err = err
		if c.inflight[mp] == f {
			delete(c.inflight, mp)
		}
		c.mu.Unlock()
		close(f.done)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-f.done:
		if ctx.Err() != nil {
			return mountProbeInconclusive
		}
		if f.err == nil {
			return mountProbeHealthy
		}
		if errors.Is(f.err, context.DeadlineExceeded) || errors.Is(pctx.Err(), context.DeadlineExceeded) {
			return mountProbeHung
		}
		return mountProbeInconclusive
	case <-timer.C:
		return mountProbeHung
	case <-ctx.Done():
		return mountProbeInconclusive
	}
}

func parseNetworkMounts(data []byte) []wdeps.NetworkMountHungEntry {
	lastByMount := make(map[string]string)
	for ln := range strings.SplitSeq(string(data), "\n") {
		f := strings.Fields(ln)
		if len(f) < 8 {
			continue
		}
		sep := -1
		for i := 6; i < len(f); i++ {
			if f[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+1 >= len(f) {
			continue
		}
		mp := procfs.UnescapeMountPath(f[4])
		fsType := f[sep+1]
		if mp == "" || fsType == "" {
			continue
		}
		lastByMount[mp] = fsType
	}
	var out []wdeps.NetworkMountHungEntry
	for mp, fsType := range lastByMount {
		if isNetworkOrFUSEFSType(fsType) {
			out = append(out, wdeps.NetworkMountHungEntry{
				Mountpoint: mp,
				FSType:     fsType,
			})
		}
	}
	slices.SortFunc(out, func(a, b wdeps.NetworkMountHungEntry) int {
		if cmp := strings.Compare(a.Mountpoint, b.Mountpoint); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.FSType, b.FSType)
	})
	return out
}

func isNetworkOrFUSEFSType(fsType string) bool {
	switch fsType {
	case "nfs", "nfs4", "cifs", "smb3", "ceph":
		return true
	case "fusectl", "fuse.lxcfs":
		return false
	}
	return strings.HasPrefix(fsType, "fuse.")
}

func formatMountHungDetail(confirmed []wdeps.NetworkMountHungEntry) string {
	parts := make([]string, 0, len(confirmed))
	for _, m := range confirmed {
		parts = append(parts, fmt.Sprintf("%s(%s)", m.Mountpoint, m.FSType))
	}
	detail := "mounts=" + strings.Join(parts, ",")
	if len(detail) > maxMountHungDetailLen {
		return detail[:maxMountHungDetailLen]
	}
	return detail
}
