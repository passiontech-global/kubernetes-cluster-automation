// Check: systemd-scopes failed/deactivating/abandoned scope reaper.
// Split out of dstate_scopes.go (pure move).

package guards

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// --- Check: systemd-scopes (systemd-scopes) ---
// On high-churn nodes (cicd's Concourse/Tekton/Shipwright build
// pods, crashloop storms) PID 1 leaks transient
// cri-containerd-*.scope units in the failed state — they pile into
// systemd's unit hash table and every D-Bus call kubelet/containerd
// makes (sandbox create) slows from ms to seconds (kubernetes
// #104029). A 30m sweep lists the failed scopes and resets them —
// reset-failed is safe on live scopes (it only clears the failed
// bookkeeping of already-dead units).

// ScopesCheck is the systemd-scopes failed-scope reaper as a Check; it owns
// the 30m sweep stamp (ex-Hygiene.lastScopeScan) and the consecutive-sweep
// streak for units wedged in `deactivating` (deactivating-unit-detector).
type ScopesCheck struct {
	d           *wdeps.Deps
	lastScan    time.Time
	deactStreak int
	// prevDeact is the deactivating-scope-reaper per-unit deactivating ledger — unit
	// name → was deactivating at the previous sweep. A unit wedged
	// across ≥2 sweeps whose container id is absent from every
	// Running pod's container set is an orphaned teardown the
	// reaper force-stops.
	prevDeact map[string]bool
}

// Name returns the check label / WD_SIG key.
func (c *ScopesCheck) Name() string { return wdeps.CheckSysScopes }

// Run executes one systemd-scopes round.
func (c *ScopesCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if c.d.Gated(e, wdeps.CheckSysScopes) {
		return
	}
	if c.d.Cfg.Systemd == nil {
		c.d.CycleResult(wdeps.CheckSysScopes, "gated")
		return
	}
	if c.d.Cfg.Seams.Host.Clock.Now().Sub(c.lastScan) < systemdScopeScanInterval {
		c.d.CycleResult(wdeps.CheckSysScopes, "ok")
		return
	}
	out, err := c.d.Cfg.Systemd.Exec(ctx, "systemctl", "list-units",
		"--type=scope", "--state=failed", "--no-legend", "--plain",
		"cri-containerd-*.scope")
	if err != nil {
		// A transient systemctl/D-Bus failure is inconclusive — the
		// scan must NOT stamp (a stamped failure defers the retry a
		// full interval) and zero evidence was gathered.
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: systemd-scopes list-units failed: %v (%s) — scan skipped",
			err, strings.TrimSpace(out)))
		c.d.CycleResult(wdeps.CheckSysScopes, "abort")
		return
	}
	c.lastScan = c.d.Cfg.Seams.Host.Clock.Now()
	n := len(scopeUnitNames(out))
	c.checkDeactivating(ctx, e)
	c.checkAbandoned(ctx, e)
	if n == 0 {
		c.d.CycleResult(wdeps.CheckSysScopes, "ok")
		return
	}
	// NPD contract line (reset-failed evidence in the watchdog log).
	c.d.State.AppendLog(fmt.Sprintf("ACTION: systemd-scopes reset-failed count=%d", n))
	if rout, rerr := c.d.Cfg.Systemd.Exec(ctx,
		"systemctl", "reset-failed", "cri-containerd-*.scope"); rerr != nil {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: systemd-scopes reset-failed failed: %v (%s)",
			rerr, strings.TrimSpace(rout)))
	} else {
		c.d.Actions.WithLabelValues(wdeps.CheckSysScopes, "reset_failed").Inc()
	}
	c.d.CycleResult(wdeps.CheckSysScopes, "ok")
}

// checkDeactivating is the deactivating-unit-detector deactivating wedge detector:
// cri-containerd-*.scope units stuck in `deactivating` across
// consecutive sweeps mean container teardown is wedged inside
// systemd PID 1 (stop-sigterm/sigkill never completing) —
// reset-failed cannot clear these. Units still owned by a Running
// pod stay diagnose-only; orphaned ones (deactivating-scope-reaper) are force-stopped
// by reapDeactivating once the streak proves the wedge is real.
// The streak must survive ≥2 sweeps (~1h) before alerting so a
// normal stop-in-progress transient never pages. Runs even when no
// failed scopes exist — a node can wedge on deactivating alone.
func (c *ScopesCheck) checkDeactivating(ctx context.Context, e *wdeps.CycleEnv) {
	dout, derr := c.d.Cfg.Systemd.Exec(ctx, "systemctl", "list-units",
		"--type=scope", "--state=deactivating", "--no-legend", "--plain",
		"cri-containerd-*.scope")
	if derr != nil {
		// Inconclusive — leave the streak AND the per-unit ledger
		// untouched rather than resetting on a transient D-Bus
		// failure.
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: systemd-scopes deactivating list-units failed: %v (%s) — streak kept",
			derr, strings.TrimSpace(dout)))
	} else {
		units := scopeUnitNames(dout)
		if len(units) == 0 {
			c.deactStreak = 0
		} else {
			c.deactStreak++
			if c.deactStreak >= 2 {
				c.d.State.AppendLog(fmt.Sprintf(
					"suspect: systemd-scopes deactivating count=%d streak=%d",
					len(units), c.deactStreak))
			}
		}
		c.reapDeactivating(ctx, e, units)
		// Rebuild the per-unit ledger AFTER the reap read it —
		// prevDeact must hold LAST sweep's set when judging this
		// sweep's candidates.
		next := make(map[string]bool, len(units))
		for _, u := range units {
			next[u] = true
		}
		c.prevDeact = next
	}
	// No CycleResult here — Run owns the per-sweep cycle accounting;
	// a second "ok" from this helper would double-count every scan.
}

// reapDeactivating is the deactivating-scope-reaper orphaned-teardown reaper: a
// cri-containerd-*.scope wedged in `deactivating` across ≥2
// consecutive sweeps (prevDeact[unit] && deactStreak ≥ 2) whose
// container id is absent from every Running pod's container set is
// a dead teardown systemd will never finish — SIGKILL + stop
// forces the scope closed, capped at 5 units per sweep. A scope
// still owned by a live pod is diagnose-only: killing it would be
// a pod kill, which is not this check's remit.
func (c *ScopesCheck) reapDeactivating(ctx context.Context,
	e *wdeps.CycleEnv, units []string) {

	if c.deactStreak < 2 || len(c.prevDeact) == 0 {
		return
	}
	live, verified := liveScopeIDs(e)
	if !verified {
		c.d.State.AppendLog(
			"suspect: systemd-scopes deactivating reap skipped — pod/task ground truth unavailable")
		return
	}
	killed := 0
	for _, unit := range units {
		if killed >= 5 {
			break
		}
		if !c.prevDeact[unit] || containerIDLive(scopeContainerID(unit), live) {
			continue
		}
		if out, err := c.d.Cfg.Systemd.Exec(ctx, "systemctl",
			"kill", "--signal=SIGKILL", unit); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: systemd-scopes deactivating kill %s failed: %v (%s)",
				unit, err, strings.TrimSpace(out)))
			continue
		}
		if out, err := c.d.Cfg.Systemd.Exec(ctx, "systemctl",
			"stop", unit); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: systemd-scopes deactivating stop %s failed: %v (%s)",
				unit, err, strings.TrimSpace(out)))
			continue // the SIGKILL landed; stop retries next sweep
		}
		killed++
		c.d.Actions.WithLabelValues(wdeps.CheckSysScopes, "kill_deactivating").Inc()
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: systemd-scopes deactivating reap unit=%s — orphaned cri-containerd scope force-stopped after %d sweeps",
			unit, c.deactStreak))
	}
}

// checkAbandoned is the selfheal-alert-coverage abandoned-scope reaper: systemd marks a
// scope `abandoned` when its processes all exited while containerd
// was mid-restart — the unit is already dead but stays registered
// in PID 1's unit table, and on high-churn nodes the pile-up slows
// every D-Bus call kubelet/containerd makes (same failure shape as
// the failed/deactivating leaks this check already owns). Unlike
// `deactivating` there is no live teardown to protect: an abandoned
// scope's cgroup is empty, so `systemctl stop` only unregisters the
// corpse — safe to run without a persistence streak. Only scopes
// whose container id is absent from every Running pod's container
// set are stopped (a scope still owned by a live pod is diagnose-
// only), capped at 10 units per sweep. Runs even when no failed
// scopes exist — a node can leak abandoned units alone.
func (c *ScopesCheck) checkAbandoned(ctx context.Context, e *wdeps.CycleEnv) {
	aout, aerr := c.d.Cfg.Systemd.Exec(ctx, "systemctl", "list-units",
		"--type=scope", "--state=abandoned", "--no-legend", "--plain",
		"cri-containerd-*.scope")
	if aerr != nil {
		// Inconclusive — same contract as the deactivating probe:
		// a transient D-Bus failure is logged, never fatal.
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: systemd-scopes abandoned list-units failed: %v (%s) — sweep skipped",
			aerr, strings.TrimSpace(aout)))
		return
	}
	units := scopeUnitNames(aout)
	if len(units) == 0 {
		return
	}
	live, verified := liveScopeIDs(e)
	if !verified {
		c.d.State.AppendLog(
			"suspect: systemd-scopes abandoned reap skipped — pod/task ground truth unavailable")
		return
	}
	stopped := 0
	for i, unit := range units {
		if stopped >= 10 {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: systemd-scopes abandoned %d units left — cap 10/sweep reached",
				len(units)-i))
			break
		}
		if containerIDLive(scopeContainerID(unit), live) {
			continue // still owned by a Running pod — diagnose only
		}
		if out, err := c.d.Cfg.Systemd.Exec(ctx, "systemctl",
			"stop", unit); err != nil {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: systemd-scopes abandoned stop %s failed: %v (%s)",
				unit, err, strings.TrimSpace(out)))
			continue
		}
		stopped++
		c.d.Actions.WithLabelValues(wdeps.CheckSysScopes, "stop_abandoned").Inc()
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: systemd-scopes abandoned reap unit=%s — orphaned cri-containerd scope unregistered",
			unit))
	}
}

// scopeUnitNames extracts the unit names from a
// `systemctl list-units --no-legend --plain` reply — the first
// field of each non-empty line ending in .scope (the LOAD/ACTIVE/
// SUB/DESCRIPTION columns collapse to fields[0]).
func scopeUnitNames(out string) []string {
	var units []string
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) > 0 &&
			strings.HasSuffix(f[0], ".scope") {
			units = append(units, f[0])
		}
	}
	return units
}

// scopeContainerID extracts the containerd id out of a
// cri-containerd-<id>.scope unit name.
func scopeContainerID(unit string) string {
	return strings.TrimSuffix(
		strings.TrimPrefix(unit, "cri-containerd-"), ".scope")
}

// liveScopeIDs builds the "still owned" id set the scope reapers
// match against, and reports whether that set is VERIFIABLE. The
// pod-status half alone is not enough on its own:
//
//   - !e.APIOK means the pod list is absent/stale — every scope
//     would read as orphaned and a live container's teardown would
//     be SIGKILLed (the mass-kill shape this guard exists to
//     prevent). Fail closed.
//   - runningContainerIDs only sees CONTAINER statuses; the pod
//     sandbox (pause) container gets its own cri-containerd-*.scope
//     but appears in no ContainerStatuses list. The containerd task
//     map IS the node-side ground truth for those ids — its dir
//     names are the container/sandbox ids scope units carry, and it
//     does not depend on API reachability. An incomplete task map
//     (root unreadable) leaves sandbox ownership unverifiable →
//     fail closed as well.
//
// TasksOnce == nil only happens on hand-built CycleEnvs (unit
// tests); production always wires the lazy once-per-cycle map.
func liveScopeIDs(e *wdeps.CycleEnv) ([]string, bool) {
	if !e.APIOK {
		return nil, false
	}
	ids := runningContainerIDs(e)
	if e.TasksOnce != nil {
		tasks, complete := e.TasksOnce()
		if !complete {
			return nil, false
		}
		for _, list := range tasks {
			for _, t := range list {
				if t.Live && t.ID != "" {
					ids = append(ids, t.ID)
				}
			}
		}
	}
	return ids, true
}

// runningContainerIDs collects the containerd ids of every
// container status on this node's Running pods — init, ephemeral
// and regular. The deactivating reaper treats a scope whose id is
// absent here as orphaned teardown.
func runningContainerIDs(e *wdeps.CycleEnv) []string {
	var ids []string
	for i := range e.Pods {
		p := &e.Pods[i]
		if p.Status.Phase != corev1.PodRunning {
			continue
		}
		for _, cs := range p.Status.ContainerStatuses {
			ids = append(ids, containerStatusID(cs.ContainerID))
		}
		for _, cs := range p.Status.InitContainerStatuses {
			ids = append(ids, containerStatusID(cs.ContainerID))
		}
		for _, cs := range p.Status.EphemeralContainerStatuses {
			ids = append(ids, containerStatusID(cs.ContainerID))
		}
	}
	return ids
}

// containerStatusID strips the "<runtime>://" prefix off a pod
// status containerID — "" when the status carries no id yet
// (excluded by the caller's empty check via containerIDLive).
func containerStatusID(id string) string {
	if i := strings.Index(id, "://"); i >= 0 {
		return id[i+3:]
	}
	return id
}

// containerIDLive reports whether a scope's container id belongs to
// a Running pod — exact match or a truncated/prefixed variant
// (systemd unit-name limits can shorten the id either way).
func containerIDLive(scopeID string, live []string) bool {
	if scopeID == "" {
		return true // unparseable unit — never reap on a guess
	}
	for _, lid := range live {
		if lid == "" {
			continue
		}
		if lid == scopeID || strings.HasPrefix(lid, scopeID) ||
			strings.HasPrefix(scopeID, lid) {
			return true
		}
	}
	return false
}

// --- Check: cilium-envoy xDS NACK + node-local-dns LRP (envoy-xds-lrp) ---
// Two datapath wedges that leave every healthz green:
//   - envoy rejects xDS pushes (cds/lds/rds update_rejected
//     counters climbing) — the listener accepts connections but
//     never programs new routes; Gateway API objects report
//     Accepted:True while replies 404/503.
//   - the LocalRedirectPolicy sends cluster :53 to the local
//     node-local-dns pod whose UDP/TCP :53 listener is hung while
//     its :8080 healthz still answers — every pod on the node loses
//     DNS (the 8-day LRP outage shape). The API still reports the
//     pod Ready=True, so the pod itself is the remedy target.
