// wipe_cycle.go — the per-pod wipe cycle of the concourse work-dir
// janitor: processPod's land → drain → delete → prune → waitReady
// chain, with drain's in-flight-build wait and maybePruneWorker's
// post-delete ATC prune window (split out of concourse_janitor.go —
// see its header for the module contract).
package concoursejanitor

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// processPod runs stats → maybe-wipe for one worker pod and reports
// whether the pod was replaced. Errors abort the run, exactly like
// `set -eu` + `exit 1` did.
func (j *concourseWorkdirJanitor) processPod(ctx context.Context, podName string, flyOK bool, log logr.Logger) (bool, error) {
	pod, err := j.getPod(ctx, podName)
	if err != nil {
		// bash: any `kubectl get pod` failure → skip + continue.
		if apierrors.IsNotFound(err) {
			log.Info("SKIP: pod not found", "pod", podName)
		} else {
			log.Info("SKIP: pod get failed", "pod", podName, "error", err)
		}
		return false, nil
	}

	// A pod created < readyTimeout ago that is still not Ready is
	// almost certainly inside init-rm from an earlier wipe (a full
	// rm -rf can take most of that window) — deleting it again just
	// restarts the wipe without freeing anything new, and it is not
	// serving builds anyway. Once the window passes the guard lifts so
	// a wedged-not-Ready pod can still be replaced (bash had no such
	// guard; an interrupted CronJob could thrash the same pod).
	//
	// The guard runs BEFORE readStats: the stats/summary node-proxy
	// read costs an apiserver→kubelet round trip per worker, and its
	// verdict is moot for a pod this guard skips anyway.
	if !kube.PodReadyCond(pod) && j.now.Now().Sub(pod.CreationTimestamp.Time) < j.cfg.readyTimeout {
		log.Info("SKIP: not Ready after creation — mid init-rm",
			"pod", podName,
			"createdAgo", j.now.Now().Sub(pod.CreationTimestamp.Time).Truncate(time.Minute),
			"readyTimeout", j.cfg.readyTimeout)
		return false, nil
	}

	s := j.readStats(ctx, pod)
	log.Info("=== stats ===",
		"pod", podName, "node", strOr(s.node, "?"),
		"nodefsUsedGiB", intOr(s.usedGiB, s.nodefsOK),
		"nodefsCapGiB", intOr(s.capGiB, s.nodefsOK),
		"nodefsPct", intOr(s.pct, s.nodefsOK),
		"workdirGiB", intOr(s.workdirGiB, s.workdirOK),
		"workdirCapGiB", cjMaxWorkdirGiB)

	// Keep the cache only when we KNOW workdir <= cap AND nodefs has
	// headroom; over-cap, over-threshold or unreadable stats all wipe
	// (fail-open).
	if s.workdirOK && s.workdirGiB <= cjMaxWorkdirGiB &&
		s.nodefsOK && s.pct < cjMinNodefsPct {
		// concourse-worker-stall — a steady-state (Ready >= 15m) worker can still be
		// dead: the TSA records it `stalled`, or Garden hit
		// max-containers / baggageclaim ran out of volume space. Such
		// a worker takes no builds while the cache looks perfectly
		// healthy — keep-cache would skip it forever. Recovery runs
		// the exact same drain → delete → prune → waitReady chain as
		// the over-cap path (fall through).
		if why := j.staleWorkerReason(ctx, pod, podName, flyOK, log); why != "" {
			log.Info("WIPE: worker unhealthy despite under-cap cache — replacing",
				"pod", podName, "why", why,
				"workdirGiB", s.workdirGiB, "nodefsPct", s.pct)
		} else {
			log.Info("SKIP: under caps — keep cache",
				"pod", podName, "workdirGiB", s.workdirGiB,
				"workdirCapGiB", cjMaxWorkdirGiB,
				"nodefsPct", s.pct, "nodefsMinPct", cjMinNodefsPct)
			return false, nil
		}
	}
	if !s.nodefsOK || !s.workdirOK {
		// A blind wipe is deliberate fail-open policy; the unreadable
		// read itself was already metered once inside readStats —
		// counting the wipe decision again would double-count the
		// same broken fetch.
		log.Info("WARN: wiping with unreadable stats",
			"pod", podName, "nodefsOK", s.nodefsOK, "workdirOK", s.workdirOK)
	}

	if flyOK {
		j.drain(ctx, podName, log)
	}

	// Re-fetch right before delete: the pod snapshot from the top of
	// processPod is stale after prune+stats+drain (up to ~35m) — bash
	// captured old_uid at this exact point too. A pod that vanished
	// mid-drain is a run error, same as bash set -e.
	fresh, err := j.getPod(ctx, podName)
	if err != nil {
		return false, fmt.Errorf("re-get pod %s before delete: %w", podName, err)
	}
	oldUID := fresh.UID
	log.Info("=== delete — init-rm will wipe work-dir ===", "pod", podName)
	if err := j.deletePod(ctx, podName, oldUID); err != nil {
		return false, err
	}

	// Prune while the NEW pod is still inside init-rm — before the
	// worker container re-registers state=running (a running worker
	// cannot be pruned; its ghost volumes would linger in the DB).
	if flyOK {
		j.maybePruneWorker(ctx, podName, log)
	}

	if err := j.waitNewPod(ctx, podName, oldUID); err != nil {
		return false, err
	}
	log.Info("=== new pod created — waiting Ready ===", "pod", podName)
	if err := j.waitReady(ctx, podName); err != nil {
		return false, err
	}

	// Post-wipe: re-read stats and stamp the baseline (work-dir is
	// now ~empty, so current nodefs IS the baseline for the next
	// run). All failures are non-fatal — bash `|| true`.
	wd := "?"
	if np, err := j.getPod(ctx, podName); err != nil {
		log.Info("WARN: re-read pod after wipe failed", "pod", podName, "error", err)
	} else {
		s2 := j.readStatsMetered(ctx, np, false) // post-wipe re-read feeds no decision — never metered
		if s2.nodefsOK {
			if err := j.annotateBaseline(ctx, podName, s2.usedGiB); err != nil {
				log.Info("WARN: baseline annotate failed", "pod", podName, "error", err)
			}
			wd = "0"
		}
		log.Info("=== after wipe ===",
			"pod", podName,
			"nodefsUsedGiB", intOr(s2.usedGiB, s2.nodefsOK),
			"nodefsCapGiB", intOr(s2.capGiB, s2.nodefsOK),
			"nodefsPct", intOr(s2.pct, s2.nodefsOK),
			"workdirGiB", wd)
	}
	return true, nil
}

// drain lands the worker at the ATC (stop scheduling new builds) and
// waits for state=landed — all in-flight builds done. A drain timeout
// still proceeds to delete: the goal is reclaiming disk and builds
// running >30m get cut (accepted trade-off — used to be >60s).
// When land-worker itself fails the drain never started, so the wait
// is shortened to landFailWait — a state read of "running" is then
// the expected steady state, not a drain in progress.
func (j *concourseWorkdirJanitor) drain(ctx context.Context, podName string, log logr.Logger) {
	log.Info("=== land-worker ===", "pod", podName)
	bound := j.cfg.drainTimeout
	if err := j.atc.landWorker(ctx, podName); err != nil {
		log.Info("WARN: land-worker failed", "pod", podName, "error", err)
		bound = j.cfg.landFailWait
	}
	dctx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	err := wait.PollUntilContextCancel(dctx, j.cfg.slowPoll, true,
		func(ctx context.Context) (bool, error) {
			// "" only means drained when the ATC call SUCCEEDED — an
			// errored poll keeps waiting (up to the bound), so a
			// transient ATC blip cannot cut in-flight builds early.
			// (Bash could not tell the two apart; Go can.)
			st, werr := j.atc.workerState(ctx, podName)
			return (werr == nil && st == "") || st == "landed" || st == "retired", nil
		})
	if err != nil {
		log.Info("WARN: drain exceeded bound — still deleting pod",
			"pod", podName, "bound", bound)
	} else {
		log.Info("=== drained ===", "pod", podName)
	}
}

// maybePruneWorker issues prune-worker while the ATC still records a
// non-running state — inside the window between the old pod's
// termination and the new worker's re-registration. The ATC clears
// the worker record asynchronously, so state can still read
// "running" for a few seconds right after the pod died: poll
// (bounded by pruneStateWait) until it settles instead of deciding
// on a single laggy read.
func (j *concourseWorkdirJanitor) maybePruneWorker(ctx context.Context, podName string, log logr.Logger) {
	pctx, cancel := context.WithTimeout(ctx, j.cfg.pruneStateWait)
	defer cancel()
	var st string
	var lastErr error
	// The first check is immediate; a timeout just means the last
	// read stands — the decision below uses it either way.
	_ = wait.PollUntilContextCancel(pctx, j.cfg.fastPoll, true,
		func(ctx context.Context) (bool, error) {
			s, err := j.atc.workerState(ctx, podName)
			if err != nil {
				lastErr = err
				log.V(1).Info("worker state poll failed — keep polling",
					"pod", podName, "error", err)
				return false, nil // transient — keep polling inside the bound
			}
			lastErr = nil
			st = s
			return s != "running", nil
		})
	if lastErr != nil {
		log.Info("WARN: worker state unreadable — no prune",
			"pod", podName, "error", lastErr)
		return
	}
	switch st {
	// "landing" too: a drain that timed out mid-land still leaves a
	// ghost worker record (and its claimed volumes) at the ATC — the
	// worker already stopped picking up builds, so pruning is safe.
	case "stalled", "landing", "landed", "retired", "retiring":
		log.Info("=== worker prune before new pod Ready ===",
			"pod", podName, "workerState", st)
		if err := j.atc.pruneWorker(ctx, podName); err != nil {
			log.Info("WARN: prune-worker failed", "pod", podName, "error", err)
		}
	default:
		log.Info("=== worker state — no prune needed ===",
			"pod", podName, "workerState", strOr(st, "gone"))
	}
}
