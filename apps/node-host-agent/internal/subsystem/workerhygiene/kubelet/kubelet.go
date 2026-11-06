// kubelet.go — the kubelet-health check family: shared probe/restart
// helpers plus the kubelet-stall (05) and kubelet-watch-wedge (06)
// checks. The T15 feeder/remediate lives in kubelet_feeder.go and
// the A4 syncloop/containerd-socket probes in kubelet_syncloop.go.
package kubelet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/platform/hoststate"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-host-agent/internal/subsystem/workerhygiene/wdeps"
)

// Kubelet-domain defaults — the 05/06 shell parity knobs plus the
// shared probe-series constants the other probe helpers reuse.
const (
	journalHitsThresh = 60 // shell JOURNAL_HITS_THRESHOLD
	PoddirThreshold   = 5  // shell PODDIR_THRESHOLD
	// k0sWorkerSettle mirrors the plan's k0sworker_settled >=180s gate:
	// a k0sworker restarted moments ago gets a settle window before
	// ANY new restart is spent on it — kubelet needs the window to
	// re-list pods / rebuild its watch stream.
	k0sWorkerSettle = 180 * time.Second
)

var (
	// Journal signatures (05/06) — grep -cE parity: count MATCHING
	// LINES, not occurrences.
	stallJournalRe = regexp.MustCompile(`node "[^"]+" not found|not registered yet`)
	watchJournalRe = regexp.MustCompile(`not registered|no relationship found between node`)
)

// countMatchingLines is grep -cE parity: lines matching re.
// strings.Cut iterates in place — no giant []string allocation on
// a multi-MiB journal snapshot.
func countMatchingLines(re *regexp.Regexp, s string) int {
	n := 0
	for rest := s; rest != ""; {
		line, after, _ := strings.Cut(rest, "\n")
		rest = after
		if re.MatchString(line) {
			n++
		}
	}
	return n
}

// dashedHost maps "ip[:port]" to the watchdog file suffix ip-dashed —
// same transform as apiprober's dashedIP (state-apiserver-backend-
// stale-<dashed> keying).
func dashedHost(addr string) string {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	} else if i := strings.LastIndexByte(addr, ':'); i >= 0 {
		host = addr[:i]
	}
	return strings.ReplaceAll(host, ".", "-")
}

// kubelet10250Alive runs the kubelet :10250 /healthz liveness series
// — the shell's `curl -ks` retry loop. ANY HTTP response proves the
// listener is alive; only a transport error/timeout counts as down.
// A 401/403 is kubelet answering an auth denial, NOT a dead listener
// — probing anonymously read that as "down" → kubelet-10250-down →
// k0sworker restarts spent on a healthy kubelet (same bug class the
// syncloop probe fixed by authenticating + treating unauth answers
// as non-verdicts). The SA bearer from KubeletTokenPath rides along
// so clusters requiring auth return the real healthz verdict; a
// missing token just falls back to anonymous, whose 401 still counts
// as alive.
func kubelet10250Alive(d *wdeps.Deps, ctx context.Context) bool {
	bearer := kubeletBearer(d)
	for i := 0; i < wdeps.ProbeAttempts; i++ {
		if _, err := d.Cfg.Seams.ProbeHTTPStatus(ctx,
			d.Cfg.Kubelet.HealthzURL, bearer, wdeps.ProbeTimeout); err == nil {
			return true
		}
		if i+1 < wdeps.ProbeAttempts {
			select {
			case <-ctx.Done():
				return false
			case <-time.After(d.Cfg.ProbeGap):
			}
		}
	}
	return false
}

// podDirCount counts kubelet pod dirs — the shell's
// `find $KUBELET_PODS_DIR -mindepth 1 -maxdepth 1 -type d | wc -l`.
// ok=false means the dir is unreadable (treated like missing).
func podDirCount(d *wdeps.Deps) (n int, ok bool) {
	entries, err := os.ReadDir(d.Cfg.Kubelet.PodsDir)
	if err != nil {
		return 0, false
	}
	for _, e := range entries {
		if e.IsDir() {
			n++
		}
	}
	return n, true
}

// taskRecordCount counts containerd task records — `ctr tasks ls |
// wc -l` parity for the phantom-pods signal: every task dir under the
// runtime + sandbox roots is a record, RUNNING or STOPPED alike (the
// shell counted output lines, never filtered on task state). A
// drained/evicted node holding stopped task dirs is NOT phantom —
// counting only live init pids would false-positive a k0sworker
// restart every MinRestartInterval.
func taskRecordCount(d *wdeps.Deps) int {
	n := 0
	for _, root := range []string{d.Cfg.CtrTaskRoot, d.Cfg.SandboxCtlRoot} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				n++
			}
		}
	}
	return n
}

// k0sWorkerSettled gates k0sworker restarts: the unit must have been
// continuously active for >=180s — restarting a kubelet that is still
// re-listing its pods turns a settle blip into a restart loop.
// nil Systemd (unwired/tests) can't answer → settled.
func k0sWorkerSettled(d *wdeps.Deps, ctx context.Context) bool {
	if d.Cfg.Systemd == nil {
		return true
	}
	age, err := d.Cfg.Systemd.ActiveAge(ctx, "k0sworker.service")
	return err == nil && age >= k0sWorkerSettle
}

// restartK0sWorker wraps Systemd.Restart — a nil client can't act
// (unwired agent) and reports so the action is logged not counted.
func restartK0sWorker(d *wdeps.Deps, ctx context.Context) error {
	if d.Cfg.Systemd == nil {
		return errors.New("no systemd client wired")
	}
	return d.Cfg.Systemd.Restart(ctx, "k0sworker.service")
}

// --- Check: kubelet-stall (05-kubelet-stall.sh) ---

// StallCheck detects a zombie kubelet: informer-zombie journal
// spam, phantom pods (pod dirs but zero task records), or a dead
// :10250 listener. 2 consecutive cycles → latch kubelet-runtime-stall
// + restart k0sworker through the shared last-restart budget, gated
// on overload / API reachability / settle. The streak stays on
// deps (stallFails) — pre-Check tests poke it directly.
type StallCheck struct{ d *wdeps.Deps }

// Name returns the check label / WD_SIG key.
func (c *StallCheck) Name() string { return wdeps.CheckStall }

// Run executes one kubelet-stall round.
func (c *StallCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckStall, "gated").Inc()
		return
	}
	reason := ""
	if hits := countMatchingLines(stallJournalRe, e.JournalOnce()); hits > journalHitsThresh {
		reason = fmt.Sprintf("informer-zombie hits=%d/10min", hits)
	}
	if reason == "" {
		if poddirs, ok := podDirCount(c.d); ok && poddirs >= PoddirThreshold {
			if _, err := os.ReadDir(c.d.Cfg.CtrTaskRoot); err != nil {
				reason = fmt.Sprintf("phantom-pods poddirs=%d ctr=unreachable", poddirs)
			} else if taskRecordCount(c.d) == 0 {
				reason = fmt.Sprintf("phantom-pods poddirs=%d tasks=0", poddirs)
			}
		}
	}
	if reason == "" {
		// kubelet-10250-down: the listener may take 30-60s after a
		// k0sworker restart — all 3 probes must fail (curl -ks parity:
		// ANY HTTP response, even 401/403, means the listener is
		// alive).
		if !kubelet10250Alive(c.d, ctx) {
			reason = "kubelet-10250-down"
		}
	}
	if reason == "" {
		c.d.StallFails = 0
		c.d.State.Exit(hoststate.LatchKubeletRuntimeStall, nil)
		c.d.Cycles.WithLabelValues(wdeps.CheckStall, "ok").Inc()
		return
	}
	c.d.StallFails++
	if c.d.StallFails < c.d.Cfg.ConsecNeeded {
		c.d.State.AppendLog(fmt.Sprintf("suspect: %s (check %d/%d)",
			reason, c.d.StallFails, c.d.Cfg.ConsecNeeded))
		c.d.Cycles.WithLabelValues(wdeps.CheckStall, "ok").Inc()
		return
	}
	overloaded := c.d.State.Exists(hoststate.LatchNodeOverloaded)
	if strings.HasPrefix(reason, "phantom-pods") || strings.HasPrefix(reason, "kubelet-10250-down") {
		if !overloaded {
			c.d.State.Enter(hoststate.LatchKubeletRuntimeStall, reason)
		} else if !c.d.State.Exists(hoststate.LatchKubeletRuntimeStall) {
			// Wedge under CPU starvation is a symptom, not a dead
			// node — latching would kick NHC→SNR and dump 100% of
			// load onto the survivors (amplifier). Log-only.
			c.d.State.AppendLog("runtime-stall-suppressed-overloaded - " + reason)
		}
	} else {
		c.d.State.Exit(hoststate.LatchKubeletRuntimeStall, nil)
	}
	switch {
	case overloaded:
		c.d.State.AppendLog(fmt.Sprintf("suspect: %s - node overloaded, skip restart k0sworker", reason))
	case !e.APIOK:
		c.d.State.AppendLog(fmt.Sprintf("suspect: %s - API unreachable (isolated?), skip restart k0sworker", reason))
	case !k0sWorkerSettled(c.d, ctx):
		c.d.State.AppendLog(fmt.Sprintf("suspect: %s - k0sworker not settled (<180s), skip restart", reason))
	case !c.d.State.RateTrySpend("last-restart", c.d.Cfg.MinRestartInterval):
		c.d.State.AppendLog(fmt.Sprintf("suspect: %s - in restart cooldown (<30m), skip", reason))
	default:
		// Budget already spent atomically by the rateTrySpend case —
		// the feeder goroutine competes for the same file.
		c.d.State.AppendLog(fmt.Sprintf("ACTION: restarting k0sworker - %s (persisted %dx)",
			reason, c.d.StallFails))
		c.d.StallFails = 0
		if err := restartK0sWorker(c.d, ctx); err != nil {
			c.d.State.AppendLog(fmt.Sprintf("k0sworker restart failed: %v", err))
		} else {
			c.d.Actions.WithLabelValues(wdeps.CheckStall, "restart").Inc()
		}
	}
	c.d.Cycles.WithLabelValues(wdeps.CheckStall, "ok").Inc()
}

// --- Check: kubelet-watch-wedge (06-kubelet-watch-wedge.sh) ---

// WatchWedgeCheck detects a wedged kubelet pod-watch stream: pods
// assigned to this node (not Terminating, not terminal, older than
// KubeletWatchMinAge) whose kubelet pod dir was never created.
// Journal spam is early-warning only. 2 consecutive cycles → latch
// kubelet-watch-wedge + restart k0sworker — unless EVERY apiserver
// backend is stale (upstream wedge: the missing pods are a phantom of
// stale LIST data, restarting kubelet is useless churn). fails is the
// consecutive unseen-pods streak (ex-Hygiene.watchFails).
type WatchWedgeCheck struct {
	d     *wdeps.Deps
	Fails int
}

// Name returns the check label / WD_SIG key.
func (c *WatchWedgeCheck) Name() string { return wdeps.CheckWatch }

// Run executes one watch-wedge round.
func (c *WatchWedgeCheck) Run(ctx context.Context, e *wdeps.CycleEnv) {
	if !e.WorkerActive {
		c.d.Cycles.WithLabelValues(wdeps.CheckWatch, "gated").Inc()
		return
	}
	if spam := countMatchingLines(watchJournalRe, e.JournalOnce()); spam > journalHitsThresh {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: kubelet-watch-wedge early-warn spam=%d/10min (not-registered/no-relationship)", spam))
	}
	if !e.APIOK {
		// Inconclusive — keep counters/latch exactly like the shell
		// (a flapping API must not clear wedge evidence). Only log
		// when there is something worth keeping.
		if c.d.State.Exists(hoststate.LatchKubeletWatchWedge) || c.Fails > 0 {
			c.d.State.AppendLog("suspect: kubelet-watch-wedge pods query fail — inconclusive, keeping state")
		}
		c.d.Cycles.WithLabelValues(wdeps.CheckWatch, "abort").Inc()
		return
	}
	// Stat the pods ROOT once before the per-pod sweep: with the dir
	// itself unreadable/vanished every per-pod stat fails and ALL
	// assigned pods count "missing" → false wedge latch + a k0sworker
	// restart spent on a filesystem blip. The IsDir half matters just
	// as much as the error half: a regular FILE at the path stats
	// cleanly but every per-pod join then fails ENOTDIR — the same
	// false wedge via a different syscall. Inconclusive — keep
	// counters/latch exactly like the !apiOK path.
	st, err := os.Stat(c.d.Cfg.Kubelet.PodsDir)
	if err != nil || !st.IsDir() {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: kubelet pods dir %s unstatable or not a directory (isdir=%v, err=%v) — watch-wedge inconclusive, keeping state",
			c.d.Cfg.Kubelet.PodsDir, err == nil && st.IsDir(), err))
		c.d.Cycles.WithLabelValues(wdeps.CheckWatch, "abort").Inc()
		return
	}
	now := c.d.Cfg.Seams.NowFn()
	missing := 0
	for i := range e.Pods {
		p := &e.Pods[i]
		if p.DeletionTimestamp != nil ||
			p.Status.Phase == corev1.PodSucceeded ||
			p.Status.Phase == corev1.PodFailed {
			continue
		}
		ct := p.CreationTimestamp.Time
		if ct.IsZero() || now.Sub(ct) < c.d.Cfg.Kubelet.WatchMinAge {
			continue
		}
		if st, err := os.Stat(filepath.Join(c.d.Cfg.Kubelet.PodsDir,
			string(p.UID))); err != nil || !st.IsDir() {
			missing++
		}
	}
	if missing == 0 {
		c.Fails = 0
		c.d.State.Exit(hoststate.LatchKubeletWatchWedge, nil)
		c.d.Cycles.WithLabelValues(wdeps.CheckWatch, "ok").Inc()
		return
	}
	c.Fails++
	if c.Fails < c.d.Cfg.ConsecNeeded {
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: kubelet-watch-wedge %d pod(s) assigned but no pod dir on node (check %d/%d)",
			missing, c.Fails, c.d.Cfg.ConsecNeeded))
		c.d.Cycles.WithLabelValues(wdeps.CheckWatch, "ok").Inc()
		return
	}
	c.d.State.Enter(hoststate.LatchKubeletWatchWedge, fmt.Sprintf("unseen-pods=%d", missing))
	// Upstream gate: EVERY apiserver backend stale → the unseen pods
	// are stale-LIST fallout, not a kubelet wedge (sig14 latches the
	// state-apiserver-backend-stale-<ip> files).
	if len(c.d.Cfg.APIBackends) > 0 {
		nstale := 0
		for _, be := range c.d.Cfg.APIBackends {
			if c.d.State.Exists(hoststate.LatchAPIServerBackendStalePrefix + dashedHost(be)) {
				nstale++
			}
		}
		if nstale == len(c.d.Cfg.APIBackends) {
			c.d.State.AppendLog(fmt.Sprintf(
				"suspect: kubelet-watch-wedge unseen=%d but %d/%d api backend stale — upstream wedge, skip restart k0sworker",
				missing, nstale, len(c.d.Cfg.APIBackends)))
			c.d.Cycles.WithLabelValues(wdeps.CheckWatch, "ok").Inc()
			return
		}
	}
	switch {
	case c.d.State.Exists(hoststate.LatchNodeOverloaded):
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: kubelet-watch-wedge unseen=%d - node overloaded, skip restart k0sworker", missing))
	case !k0sWorkerSettled(c.d, ctx):
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: kubelet-watch-wedge unseen=%d - k0sworker not settled (<180s), skip restart", missing))
	case !c.d.State.RateTrySpend("last-restart", c.d.Cfg.MinRestartInterval):
		c.d.State.AppendLog(fmt.Sprintf(
			"suspect: kubelet-watch-wedge unseen=%d - in restart cooldown (<30m), skip", missing))
	default:
		// Budget already spent atomically by the rateTrySpend case —
		// the feeder goroutine competes for the same file.
		c.d.State.AppendLog(fmt.Sprintf(
			"ACTION: restarting k0sworker - kubelet-watch-wedge unseen-pods=%d (persisted %dx)",
			missing, c.Fails))
		c.Fails = 0
		if err := restartK0sWorker(c.d, ctx); err != nil {
			c.d.State.AppendLog(fmt.Sprintf("k0sworker restart failed: %v", err))
		} else {
			c.d.Actions.WithLabelValues(wdeps.CheckWatch, "restart").Inc()
		}
	}
	c.d.Cycles.WithLabelValues(wdeps.CheckWatch, "ok").Inc()
}
