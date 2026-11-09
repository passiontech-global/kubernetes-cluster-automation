// host_oom.go — the host-side SystemOOMVictim consumer: kernel
// global_oom_kill dmesg events become the host-oom latch +
// compact_memory remedy. Split out of deep_failure_checks.go.
package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/latchdefs"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

const lastHostOOMEventFile = "last-host-oom-event"

// The kernel-pressure producer latch this check consumes lives in the
// hoststate registry: hostmetrics' kmsg scanner enters
// latchdefs.LatchPageAllocFailure (state-page-alloc-failure) when
// the kernel logs "page allocation failure: order:N".

// memoryCompactEvery is the kernel-pressure compaction cooldown — one
// vm.compact_memory write per 30 minutes: direct compaction is a
// non-invasive buddy-allocator defrag pass but it still stalls
// page allocation while it runs.
const memoryCompactEvery = 30 * time.Minute

// HostOOMCheck is the kernel-dmesg hostmetrics kmsg-marker consumer as
// a Check (no streak — the dedup marker file is the state). It also
// owns the kernel-pressure memory-compaction remedy, consuming the
// state-page-alloc-failure latch produced by the hostmetrics kmsg
// scanner.
type HostOOMCheck struct{ d *wdeps.Deps }

// Name returns the check label / WD_SIG key.
func (c *HostOOMCheck) Name() string { return wdeps.CheckHostOOM }

// Run consumes the hostmetrics kmsg scanner's markers: a NEW
// host-level OOM kill (count advanced since the last emitted
// event) produces a Warning Event on this Node plus the
// node_agent_host_oom_kills_total delta. Pod-cgroup kills never
// reach the markers — hostmetrics already classified them out.
func (c *HostOOMCheck) Run(ctx context.Context, _ *wdeps.CycleEnv) {
	c.compactMemory()
	victim := strings.TrimSpace(wdeps.ReadSmallFile(c.d.Cfg.Host.OOMVictimFile))
	fv := strings.Fields(victim)
	if len(fv) < 2 {
		c.d.CycleResult(wdeps.CheckHostOOM, "ok")
		return
	}
	epoch, _ := strconv.ParseInt(fv[0], 10, 64)
	comm := fv[1]
	var count int64 = -1
	if b, err := os.ReadFile(c.d.Cfg.Host.OOMCountFile); err == nil {
		count, _ = strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	}
	// Dedup on the cumulative count — the marker's epoch only moves
	// forward anyway, but count is the authoritative "kills seen".
	lastCount := int64(-1)
	if b, err := os.ReadFile(filepath.Join(
		c.d.Cfg.WatchdogStateDir, lastHostOOMEventFile)); err == nil {
		lf := strings.Fields(string(b))
		if len(lf) > 0 {
			lastCount, _ = strconv.ParseInt(lf[0], 10, 64)
		}
	}
	if count >= 0 && count <= lastCount {
		c.d.CycleResult(wdeps.CheckHostOOM, "ok")
		return
	}
	delta := int64(1)
	if count >= 0 && lastCount >= 0 {
		delta = count - lastCount
	}
	if delta < 1 {
		delta = 1
	}
	// Record the emission only AFTER the event create succeeded —
	// a failed create leaves the count unseen so next cycle retries
	// instead of the kill being swallowed by an early marker.
	if emitOOMEvent(c.d, ctx, comm, epoch, delta, count) && count >= 0 {
		p := filepath.Join(c.d.Cfg.WatchdogStateDir, lastHostOOMEventFile)
		content := strconv.FormatInt(count, 10) + " " +
			strconv.FormatInt(epoch, 10) + "\n"
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: host-oom dedup marker write failed: %v", err))
		}
	}
	c.d.CycleResult(wdeps.CheckHostOOM, "ok")
}

// compactMemory is the kernel-pressure remedy half: while the hostmetrics
// kmsg scanner's state-page-alloc-failure latch is held (kernel
// "page allocation failure: order:N" — the buddy allocator can't
// serve a contiguous block, fragmentation is winning), write 1 to
// <ProcRoot>/sys/vm/compact_memory on the last-memory-compact 30m
// budget and count node_agent_memory_compaction_runs_total. Per the
// hoststate registry contract the consumer Exits the latch after a
// successful compaction — without it the latch would re-fire the
// 30m compact forever off a single past episode; the next kmsg
// sighting re-Enters it (Enter is idempotent).
func (c *HostOOMCheck) compactMemory() {
	if !c.d.State.Exists(latchdefs.LatchPageAllocFailure) {
		return
	}
	target := filepath.Join(c.d.Cfg.ProcRoot, "sys", "vm", "compact_memory")
	if _, err := os.Stat(target); err != nil {
		return // non-v2 sysctl or unmounted proc — nothing to poke
	}
	if !c.d.State.RateTrySpend("last-memory-compact", memoryCompactEvery) {
		return
	}
	if err := os.WriteFile(target, []byte("1"), 0o644); err != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: page-alloc-failure compact_memory write failed: %v", err))
		return
	}
	c.d.State.Exit(latchdefs.LatchPageAllocFailure, nil)
	c.d.MemoryCompactionRuns++
	c.d.State.AppendLog(
		"ACTION: page-alloc-failure latch held — triggered vm.compact_memory (kernel-pressure defrag)")
	c.d.Actions.WithLabelValues(wdeps.CheckHostOOM, "compact_memory").Inc()
}

// emitOOMEvent creates the SystemOOMVictim Warning Event on this
// Node — the events.k8s.io/v1 shape nodereporter's emitter uses
// (Action required, deprecated* fields unset). It reports whether
// the event was actually created: the caller's dedup marker may
// only advance on true.
func emitOOMEvent(d *wdeps.Deps, ctx context.Context, comm string,
	epoch, delta, total int64) bool {
	now := d.Cfg.Seams.Host.Clock.Now()
	when := now
	if epoch > 0 {
		when = time.Unix(epoch, 0)
	}
	if err := d.EmitCheckEvent(ctx, wdeps.CheckEvent{
		// events.v1 names are <regarding>.<hex> — count+epoch
		// keep repeat kills distinct even when the clock is frozen
		// (tests) or two kills land in the same nanosecond.
		Name:      fmt.Sprintf("%s.%x.%x", d.Cfg.NodeName, total, now.UnixNano()),
		Namespace: d.Cfg.Host.EventNamespace,
		Reason:    "SystemOOMVictim",
		Note: fmt.Sprintf(
			"host-level OOM kill: victim %s (+%d kills, %d total observed)",
			comm, delta, total),
		When: when,
		Regarding: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Node",
			Name:       d.Cfg.NodeName,
		},
	}); err != nil {
		return false
	}
	d.State.AppendLog(fmt.Sprintf(
		"ACTION: SystemOOMVictim event — host-level OOM kill victim=%s delta=%d total=%d",
		comm, delta, total))
	return true
}
