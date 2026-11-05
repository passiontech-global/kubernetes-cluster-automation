// kubelet.go — the kubelet-health check family: shared probe/restart
// helpers plus the kubelet-stall (05) and kubelet-watch-wedge (06)
// checks. The T15 feeder/remediate lives in kubelet_feeder.go and
// the A4 syncloop/containerd-socket probes in kubelet_syncloop.go.
package workerhygiene

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

// probeHTTPSeries runs up to `attempts` GET probes `gap` apart —
// the shell's curl retry loops (a single blip must not trigger a
// restart). Returns nil on the first success.
func (h *Hygiene) probeHTTPSeries(ctx context.Context, url string,
	attempts int, timeout, gap time.Duration) error {
	var last error
	for i := 0; i < attempts; i++ {
		last = h.cfg.Seams.probeHTTP(ctx, url, timeout)
		if last == nil {
			return nil
		}
		if i+1 < attempts {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(gap):
			}
		}
	}
	return last
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
func (h *Hygiene) kubelet10250Alive(ctx context.Context) bool {
	bearer := h.kubeletBearer()
	for i := 0; i < probeAttempts; i++ {
		if _, err := h.cfg.Seams.probeHTTPStatus(ctx,
			h.cfg.Kubelet.HealthzURL, bearer, probeTimeout); err == nil {
			return true
		}
		if i+1 < probeAttempts {
			select {
			case <-ctx.Done():
				return false
			case <-time.After(h.cfg.ProbeGap):
			}
		}
	}
	return false
}

// podDirCount counts kubelet pod dirs — the shell's
// `find $KUBELET_PODS_DIR -mindepth 1 -maxdepth 1 -type d | wc -l`.
// ok=false means the dir is unreadable (treated like missing).
func (h *Hygiene) podDirCount() (n int, ok bool) {
	entries, err := os.ReadDir(h.cfg.Kubelet.PodsDir)
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
func (h *Hygiene) taskRecordCount() int {
	n := 0
	for _, root := range []string{h.cfg.CtrTaskRoot, h.cfg.SandboxCtlRoot} {
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
func (h *Hygiene) k0sWorkerSettled(ctx context.Context) bool {
	if h.cfg.Systemd == nil {
		return true
	}
	age, err := h.cfg.Systemd.ActiveAge(ctx, "k0sworker.service")
	return err == nil && age >= k0sWorkerSettle
}

// restartK0sWorker wraps Systemd.Restart — a nil client can't act
// (unwired agent) and reports so the action is logged not counted.
func (h *Hygiene) restartK0sWorker(ctx context.Context) error {
	if h.cfg.Systemd == nil {
		return errors.New("no systemd client wired")
	}
	return h.cfg.Systemd.Restart(ctx, "k0sworker.service")
}

// --- Check: kubelet-stall (05-kubelet-stall.sh) ---

// stallCheck detects a zombie kubelet: informer-zombie journal
// spam, phantom pods (pod dirs but zero task records), or a dead
// :10250 listener. 2 consecutive cycles → latch kubelet-runtime-stall
// + restart k0sworker through the shared last-restart budget, gated
// on overload / API reachability / settle. The streak stays on
// Hygiene (stallFails) — pre-Check tests poke it directly.
type stallCheck struct{ h *Hygiene }

// Name returns the check label / WD_SIG key.
func (c *stallCheck) Name() string { return checkStall }

// Run executes one kubelet-stall round.
func (c *stallCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.h.cycles.WithLabelValues(checkStall, "gated").Inc()
		return
	}
	reason := ""
	if hits := countMatchingLines(stallJournalRe, e.journalOnce()); hits > journalHitsThresh {
		reason = fmt.Sprintf("informer-zombie hits=%d/10min", hits)
	}
	if reason == "" {
		if poddirs, ok := c.h.podDirCount(); ok && poddirs >= poddirThreshold {
			if _, err := os.ReadDir(c.h.cfg.CtrTaskRoot); err != nil {
				reason = fmt.Sprintf("phantom-pods poddirs=%d ctr=unreachable", poddirs)
			} else if c.h.taskRecordCount() == 0 {
				reason = fmt.Sprintf("phantom-pods poddirs=%d tasks=0", poddirs)
			}
		}
	}
	if reason == "" {
		// kubelet-10250-down: the listener may take 30-60s after a
		// k0sworker restart — all 3 probes must fail (curl -ks parity:
		// ANY HTTP response, even 401/403, means the listener is
		// alive).
		if !c.h.kubelet10250Alive(ctx) {
			reason = "kubelet-10250-down"
		}
	}
	if reason == "" {
		c.h.stallFails = 0
		c.h.state.Exit(hoststate.LatchKubeletRuntimeStall, nil)
		c.h.cycles.WithLabelValues(checkStall, "ok").Inc()
		return
	}
	c.h.stallFails++
	if c.h.stallFails < c.h.cfg.ConsecNeeded {
		c.h.state.AppendLog(fmt.Sprintf("suspect: %s (check %d/%d)",
			reason, c.h.stallFails, c.h.cfg.ConsecNeeded))
		c.h.cycles.WithLabelValues(checkStall, "ok").Inc()
		return
	}
	overloaded := c.h.state.Exists(hoststate.LatchNodeOverloaded)
	if strings.HasPrefix(reason, "phantom-pods") || strings.HasPrefix(reason, "kubelet-10250-down") {
		if !overloaded {
			c.h.state.Enter(hoststate.LatchKubeletRuntimeStall, reason)
		} else if !c.h.state.Exists(hoststate.LatchKubeletRuntimeStall) {
			// Wedge under CPU starvation is a symptom, not a dead
			// node — latching would kick NHC→SNR and dump 100% of
			// load onto the survivors (amplifier). Log-only.
			c.h.state.AppendLog("runtime-stall-suppressed-overloaded - " + reason)
		}
	} else {
		c.h.state.Exit(hoststate.LatchKubeletRuntimeStall, nil)
	}
	switch {
	case overloaded:
		c.h.state.AppendLog(fmt.Sprintf("suspect: %s - node overloaded, skip restart k0sworker", reason))
	case !e.apiOK:
		c.h.state.AppendLog(fmt.Sprintf("suspect: %s - API unreachable (isolated?), skip restart k0sworker", reason))
	case !c.h.k0sWorkerSettled(ctx):
		c.h.state.AppendLog(fmt.Sprintf("suspect: %s - k0sworker not settled (<180s), skip restart", reason))
	case !c.h.state.RateTrySpend("last-restart", c.h.cfg.MinRestartInterval):
		c.h.state.AppendLog(fmt.Sprintf("suspect: %s - in restart cooldown (<30m), skip", reason))
	default:
		// Budget already spent atomically by the rateTrySpend case —
		// the feeder goroutine competes for the same file.
		c.h.state.AppendLog(fmt.Sprintf("ACTION: restarting k0sworker - %s (persisted %dx)",
			reason, c.h.stallFails))
		c.h.stallFails = 0
		if err := c.h.restartK0sWorker(ctx); err != nil {
			c.h.state.AppendLog(fmt.Sprintf("k0sworker restart failed: %v", err))
		} else {
			c.h.actions.WithLabelValues(checkStall, "restart").Inc()
		}
	}
	c.h.cycles.WithLabelValues(checkStall, "ok").Inc()
}

// --- Check: kubelet-watch-wedge (06-kubelet-watch-wedge.sh) ---

// watchWedgeCheck detects a wedged kubelet pod-watch stream: pods
// assigned to this node (not Terminating, not terminal, older than
// KubeletWatchMinAge) whose kubelet pod dir was never created.
// Journal spam is early-warning only. 2 consecutive cycles → latch
// kubelet-watch-wedge + restart k0sworker — unless EVERY apiserver
// backend is stale (upstream wedge: the missing pods are a phantom of
// stale LIST data, restarting kubelet is useless churn). fails is the
// consecutive unseen-pods streak (ex-Hygiene.watchFails).
type watchWedgeCheck struct {
	h     *Hygiene
	fails int
}

// Name returns the check label / WD_SIG key.
func (c *watchWedgeCheck) Name() string { return checkWatch }

// Run executes one watch-wedge round.
func (c *watchWedgeCheck) Run(ctx context.Context, e *cycleEnv) {
	if !e.workerActive {
		c.h.cycles.WithLabelValues(checkWatch, "gated").Inc()
		return
	}
	if spam := countMatchingLines(watchJournalRe, e.journalOnce()); spam > journalHitsThresh {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: kubelet-watch-wedge early-warn spam=%d/10min (not-registered/no-relationship)", spam))
	}
	if !e.apiOK {
		// Inconclusive — keep counters/latch exactly like the shell
		// (a flapping API must not clear wedge evidence). Only log
		// when there is something worth keeping.
		if c.h.state.Exists(hoststate.LatchKubeletWatchWedge) || c.fails > 0 {
			c.h.state.AppendLog("suspect: kubelet-watch-wedge pods query fail — inconclusive, keeping state")
		}
		c.h.cycles.WithLabelValues(checkWatch, "abort").Inc()
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
	st, err := os.Stat(c.h.cfg.Kubelet.PodsDir)
	if err != nil || !st.IsDir() {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: kubelet pods dir %s unstatable or not a directory (isdir=%v, err=%v) — watch-wedge inconclusive, keeping state",
			c.h.cfg.Kubelet.PodsDir, err == nil && st.IsDir(), err))
		c.h.cycles.WithLabelValues(checkWatch, "abort").Inc()
		return
	}
	now := c.h.cfg.Seams.nowFn()
	missing := 0
	for i := range e.pods {
		p := &e.pods[i]
		if p.DeletionTimestamp != nil ||
			p.Status.Phase == corev1.PodSucceeded ||
			p.Status.Phase == corev1.PodFailed {
			continue
		}
		ct := p.CreationTimestamp.Time
		if ct.IsZero() || now.Sub(ct) < c.h.cfg.Kubelet.WatchMinAge {
			continue
		}
		if st, err := os.Stat(filepath.Join(c.h.cfg.Kubelet.PodsDir,
			string(p.UID))); err != nil || !st.IsDir() {
			missing++
		}
	}
	if missing == 0 {
		c.fails = 0
		c.h.state.Exit(hoststate.LatchKubeletWatchWedge, nil)
		c.h.cycles.WithLabelValues(checkWatch, "ok").Inc()
		return
	}
	c.fails++
	if c.fails < c.h.cfg.ConsecNeeded {
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: kubelet-watch-wedge %d pod(s) assigned but no pod dir on node (check %d/%d)",
			missing, c.fails, c.h.cfg.ConsecNeeded))
		c.h.cycles.WithLabelValues(checkWatch, "ok").Inc()
		return
	}
	c.h.state.Enter(hoststate.LatchKubeletWatchWedge, fmt.Sprintf("unseen-pods=%d", missing))
	// Upstream gate: EVERY apiserver backend stale → the unseen pods
	// are stale-LIST fallout, not a kubelet wedge (sig14 latches the
	// state-apiserver-backend-stale-<ip> files).
	if len(c.h.cfg.APIBackends) > 0 {
		nstale := 0
		for _, be := range c.h.cfg.APIBackends {
			if c.h.state.Exists(hoststate.LatchAPIServerBackendStalePrefix + dashedHost(be)) {
				nstale++
			}
		}
		if nstale == len(c.h.cfg.APIBackends) {
			c.h.state.AppendLog(fmt.Sprintf(
				"suspect: kubelet-watch-wedge unseen=%d but %d/%d api backend stale — upstream wedge, skip restart k0sworker",
				missing, nstale, len(c.h.cfg.APIBackends)))
			c.h.cycles.WithLabelValues(checkWatch, "ok").Inc()
			return
		}
	}
	switch {
	case c.h.state.Exists(hoststate.LatchNodeOverloaded):
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: kubelet-watch-wedge unseen=%d - node overloaded, skip restart k0sworker", missing))
	case !c.h.k0sWorkerSettled(ctx):
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: kubelet-watch-wedge unseen=%d - k0sworker not settled (<180s), skip restart", missing))
	case !c.h.state.RateTrySpend("last-restart", c.h.cfg.MinRestartInterval):
		c.h.state.AppendLog(fmt.Sprintf(
			"suspect: kubelet-watch-wedge unseen=%d - in restart cooldown (<30m), skip", missing))
	default:
		// Budget already spent atomically by the rateTrySpend case —
		// the feeder goroutine competes for the same file.
		c.h.state.AppendLog(fmt.Sprintf(
			"ACTION: restarting k0sworker - kubelet-watch-wedge unseen-pods=%d (persisted %dx)",
			missing, c.fails))
		c.fails = 0
		if err := c.h.restartK0sWorker(ctx); err != nil {
			c.h.state.AppendLog(fmt.Sprintf("k0sworker restart failed: %v", err))
		} else {
			c.h.actions.WithLabelValues(checkWatch, "restart").Inc()
		}
	}
	c.h.cycles.WithLabelValues(checkWatch, "ok").Inc()
}
