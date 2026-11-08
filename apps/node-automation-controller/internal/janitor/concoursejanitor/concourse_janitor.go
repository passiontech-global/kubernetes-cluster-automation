// concourse-workdir-janitor — port of the bash CronJob in
// passiontech-fluxcd
// (infrastructure/passiontech-k0s-cicd/concourse/concourse-workdir-janitor.yaml).
//
// One job per run (every 30m): when the work-dir exceeds the cap OR
// nodefs crosses the threshold, replace worker pods ONE AT A TIME —
// the sts init container `concourse-worker-init-rm` (custom in
// values.yaml — cleanUpWorkDirOnStart=false) wipes /concourse-work-dir
// except shared-cache/{go-mod,mise,ci-tool,node-deps} at pod start.
//
// The shared-cache prune that used to be job 1 (pods/exec SPDY of a
// prune.sh ConfigMap into every worker pod) is gone: ns concourse is
// VAP workload-no-hostpath Deny so it was the only in-pod path, but
// node-host-agent now prunes <openebs>/pvc-*/shared-cache natively on
// the worker node every 15m (apps/node-host-agent/internal/sweeper/
// concourse_cache.go) — no pods/exec grant, no script ConfigMap.
//
// Why this exists: openebs-hostpath does NOT enforce PVC quota (the
// PVC `size` is metadata — the worker writes straight onto the node
// fs) and Concourse/baggageclaim has no byte cap either (it only
// sweeps volumes that lost their references, and
// containerPlacementStrategy=volume-locality deliberately keeps
// resource/task caches) → the work-dir grows unbounded (2026-10-29:
// ~250G, 831 live volumes on one node, nodefs 74%). Kubelet imageGC
// only collects images and nodefs eviction (<10%) does not remove PVC
// data — this janitor is the only mechanism bounding Concourse disk.
//
// Measurement: openebs-hostpath is a hostPath volume on the node root
// device, so kubelet never `du`s the PVC dir — statfs() makes
// `concourse-work-dir.usedBytes` in stats/summary identical to
// `node.fs.usedBytes` (which includes ~30GiB of OS + containerd
// imageFs + other pods), while `du -sk /concourse-work-dir` directly
// costs >90s over millions of overlay files. For an accurate,
// zero-I/O (<50ms) Concourse-only reading the janitor stamps the
// annotation `passiontech.dev/baseline-nodefs-gib` on the
// worker pod right after init-rm wiped the work-dir
// (workdir = nodefs_used - baseline). When the annotation is missing
// the baseline is estimated as imageFs_used + 32GiB (OS/k0s/other
// PVCs outside imageFs — measured 29-35GiB on the worker nodes).
//
// The host-agent prune runs continuously independent of this run, so
// freed cache disk is already reflected in the stats read here — the
// keep-cache check below still avoids unnecessary wipes. The cache is
// kept only when workdir <= cap AND nodefs is under the threshold;
// unreadable stats FAIL OPEN to a wipe (the cleanup ability must
// never be lost to a broken metrics path).
//
// Why sequential pod delete and not `rollout restart`: the worker sts
// uses podManagementPolicy=Parallel, so a rollout restarts ALL
// workers at once → "no workers" (incident 2026-10-28). The loop
// deletes one pod, waits for the replacement to go Ready (init-rm
// rm -rf of a hundreds-of-GB work-dir takes many minutes — the helm
// release itself had to raise its timeout to 30m) and only then moves
// on — hardAntiAffinity keeps the workers on separate nodes so ≥1
// worker always accepts builds.
//
// Why land-worker before delete (2026-10-29): previously only the
// pre-stop hook retired the worker and builds running past the 60s
// grace were cut. Now each pod is landed via the ATC first (no new
// builds scheduled to it), we wait for state=landed (running builds
// finish, bounded by drainTimeout) and only then delete. ATC login is
// fail-open: without it land/drain/prune are skipped and the pod is
// deleted as before — the pre-stop retire + grace remains the
// fallback.
//
// Why pod delete and not `fly retire-worker`: retire makes the worker
// process exit → the container restarts INSIDE the same pod → the
// init container never re-runs → the work-dir is not wiped. Pod
// delete is the only trigger for init-rm. `fly prune-worker` must run
// right after the old pod terminated — while the new pod is still
// inside init-rm, BEFORE the concourse-worker container starts and
// re-registers state=running — to delete the worker record plus its
// volumes/containers (ON DELETE CASCADE) from PostgreSQL; ATC skips
// prune on a `running` worker, which would leave ghost volumes.
//
// The whole run is bounded by context.WithTimeout(cjRunTimeout) — the
// replacement for the CronJob's activeDeadlineSeconds=11400.
//
// 2.7 — Cluster Maintenance Mutex: the whole wipe cycle defers while
// deliberate maintenance is in flight — replacing a worker pod
// mid-drain/upgrade fights the operator doing the work and can wedge
// a PDB for hours. The check itself is kube.MaintenanceActive —
// the canonical implementation every deferring module runs (cordon/
// drain, kured reboot lock, autopilot Plan):
//
//	a) any node spec.unschedulable — a cordon/drain is running;
//	b) DaemonSet kube-system/kured carrying the
//	   weave.works/kured-node-lock annotation — a reboot drain in
//	   progress;
//	c) an autopilot.k0sproject.io/v1beta2 Plan exists whose
//	   status.state is neither Schedulable nor Completed — a k0s
//	   cluster upgrade is in flight.
//
// A check that cannot be evaluated (API failure) errors the run —
// the wipe is destructive enough that "unknown" must mean "no".
//
// File layout: this file holds the module contract, the janitor
// struct and the run pipeline; kubelet_stats.go the stats/summary
// reading, pod_ops.go the pod lifecycle calls, helpers.go the ATC
// credential/baseline helpers, concourse_janitor_atc.go the ATC HTTP
// client.
package concoursejanitor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

const (
	cjNamespace   = "concourse"
	cjStatefulSet = "concourse-worker"
	// The controller runs in ns node-ops — the cross-namespace short
	// DNS name is required (bare "concourse-web" would not resolve).
	cjATCBase      = "http://concourse-web.concourse:8080"
	cjSecretName   = "concourse-web"
	cjSecretKey    = "local-users"
	cjBaselineAnno = kube.AnnoConcourseBaselineNodeFSGiB

	cjMaxWorkdirGiB = 100 // work-dir cap — the disk limit Concourse lacks
	cjMinNodefsPct  = 60  // nodefs above this forces a wipe too
	cjOSBaselineGiB = 32  // OS + k0s + other pods beyond imageFs (no anno)

	cjRunTimeout   = 190 * time.Minute // was activeDeadlineSeconds=11400
	cjDrainTimeout = 30 * time.Minute  // wait for in-flight builds post-land
	// cjLandFailWait bounds the drain confirmation when land-worker
	// itself failed — the drain never started, so waiting the full
	// drainTimeout only stalls the sweep while state reads
	// "running". The pod delete then proceeds on the same policy as
	// a timed-out drain.
	cjLandFailWait = time.Minute
	// cjPruneStateTimeout bounds the worker-state poll inside
	// maybePruneWorker — the ATC de-registers a dead worker
	// asynchronously, so a single "running" read right after pod
	// delete does not prove the prune window closed.
	cjPruneStateTimeout = time.Minute
	cjDeleteTimeout     = 5 * time.Minute
	cjUIDPollTimeout    = 5 * time.Minute  // wait for the replacement pod object
	cjReadyTimeout      = 45 * time.Minute // init-rm rm -rf of a huge work-dir
	cjReqTimeout        = 30 * time.Second // kubectl --request-timeout equivalent
	cjATCTimeout        = 15 * time.Second
	cjFastPoll          = 5 * time.Second  // uid/delete waits (bash `sleep 5`)
	cjSlowPoll          = 10 * time.Second // drain/ready waits (bash `sleep 10`)

	// W16-CI1 — stalled / Garden max-containers recovery. A worker
	// pod Running+Ready this long is steady-state; only a TSA or
	// Garden fault on such a pod justifies a wipe despite an
	// under-cap cache. Under 15m the pod may still be finishing
	// init-rm from a previous wipe — replacing it again would thrash.
	cjSteadyWorkerMinAge = 15 * time.Minute
	// The Garden/baggageclaim fault signatures appear in the
	// concourse-worker container's stdout; a bounded tail suffices —
	// the lines repeat on every volume/container creation attempt.
	cjWorkerContainer   = "concourse-worker"
	cjWorkerLogTailLine = 50
)

// nodeStatsReader reads kubelet stats/summary through the apiserver
// node proxy. Missing counters return -1 so callers can distinguish
// "absent" from a real 0 (the bash sed pipeline produced "" there).
type nodeStatsReader interface {
	Summary(ctx context.Context, node string) (nodefsUsed, nodefsCap, imageFsUsed int64, err error)
}

// atcIface is the slice of the Concourse ATC API the janitor needs
// (was `fly` in bash — see concourse_janitor_atc.go).
type atcIface interface {
	login(ctx context.Context, user, pass string) error
	workerState(ctx context.Context, name string) (string, error)
	landWorker(ctx context.Context, name string) error
	pruneWorker(ctx context.Context, name string) error
}

// cjConfig groups the timeout/poll knobs the wipe cycle waits on —
// populated from the cj* consts in Setup (production values match the
// bash ones); tests shrink them.
type cjConfig struct {
	runTimeout     time.Duration
	reqTimeout     time.Duration
	drainTimeout   time.Duration
	landFailWait   time.Duration
	pruneStateWait time.Duration
	deleteTimeout  time.Duration
	uidPollTimeout time.Duration
	readyTimeout   time.Duration
	fastPoll       time.Duration
	slowPoll       time.Duration
}

type concourseWorkdirJanitor struct {
	cs kubernetes.Interface
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and every IncError label
	// come from one place.
	queue string
	stats nodeStatsReader
	atc   atcIface
	// dyn reads the autopilot Plan CR for maintenance-mutex
	// signal (c) — no typed client exists for it.
	dyn dynamic.Interface
	// now is the clock seam — tests pin it so the mid-init-rm guard
	// is deterministic. nil → time.Now.
	now shared.Clock
	cfg cjConfig
	// workerLogTail fetches the tail of the pod's concourse-worker
	// container log — the injected seam in tests, the bounded
	// GetLogs tail in production (nil → real fetch).
	workerLogTail func(ctx context.Context, pod *corev1.Pod) (string, error)
}

// Setup registers the 30-minute sweep (was the
// CronJob schedule `7,37 * * * *`). The CONCOURSE_JANITOR_ENABLED
// gate is opt-in — resolved by setupModules into Deps.Disabled, so
// disabled clusters skip registration entirely, same contract as
// volumeattachment-cleaner.
func Setup(d shared.Deps) error {
	mgr, cs, dyn := d.Mgr, d.CS, d.Dyn
	return shared.SetupNoConfig(d, func() error {
		j := &concourseWorkdirJanitor{
			cs:    cs,
			queue: d.Name,
			stats: &kubeletStatsReader{cs: cs},
			atc:   newATCClient(cjATCBase, &http.Client{Timeout: cjATCTimeout}),
			dyn:   dyn,
			now:   shared.SystemClock,

			cfg: cjConfig{
				runTimeout:     cjRunTimeout,
				reqTimeout:     cjReqTimeout,
				drainTimeout:   cjDrainTimeout,
				landFailWait:   cjLandFailWait,
				pruneStateWait: cjPruneStateTimeout,
				deleteTimeout:  cjDeleteTimeout,
				uidPollTimeout: cjUIDPollTimeout,
				readyTimeout:   cjReadyTimeout,
				fastPoll:       cjFastPoll,
				slowPoll:       cjSlowPoll,
			},
		}
		return shared.AddPeriodic(mgr, j.queue, 30*time.Minute, j.run)
	})
}

func (j *concourseWorkdirJanitor) run(ctx context.Context) error {
	log := logf.FromContext(ctx)

	// 2.7 maintenance mutex — defer the whole wipe cycle while any
	// deliberate maintenance is in flight (cordon/drain, kured
	// reboot lock, autopilot upgrade). An unverifiable check errors
	// the run: the wipe is destructive enough that "unknown" must
	// mean "no".
	//
	// The mutex runs BEFORE the whole-run timeout installs, so the
	// check gets its own bound — an apiserver hang must not pin the
	// periodic sweep forever. One overall reqTimeout covers all
	// three signal reads inside kube.MaintenanceActive (the old
	// in-package copy wrapped each call separately; an aggregate
	// bound is strictly tighter and avoids growing a
	// per-call-timeout variant of the shared API).
	mctx, cancel := context.WithTimeout(ctx, j.cfg.reqTimeout)
	held, why, err := kube.MaintenanceActive(mctx, j.cs, j.dyn)
	cancel()
	if err != nil {
		return err
	}
	if held {
		log.Info("DEFER: cluster maintenance in progress — wipe cycle skipped",
			"why", why)
		return nil
	}

	// Whole-run bound — replaces the CronJob's activeDeadlineSeconds.
	ctx, cancel = context.WithTimeout(ctx, j.cfg.runTimeout)
	defer cancel()

	// ATC login is fail-open: on any failure land/drain/prune are
	// skipped and pods are deleted as before — the worker's pre-stop
	// retire + grace remains the fallback.
	flyOK := false
	if user, pass, err := j.atcCredentials(ctx); err != nil {
		log.Info("WARN: ATC credentials unreadable — land/drain/prune skipped, pod delete only",
			"secret", cjSecretName, "key", cjSecretKey, "error", err)
	} else if err := j.atc.login(ctx, user, pass); err != nil {
		log.Info("WARN: ATC login failed — land/drain/prune skipped, pod delete only",
			"error", err)
	} else {
		flyOK = true
		log.Info("fly login OK", "user", user)
	}

	replicas, err := j.workerReplicas(ctx)
	if err != nil {
		return err // bash: "FAIL: sts concourse-worker not found" + exit 1
	}
	log.Info("concourse-worker replicas", "statefulset", cjStatefulSet,
		"replicas", replicas)

	wiped, skipped := 0, 0
	// Descending ordinals — order is irrelevant (Parallel policy) as
	// long as it is sequential: ≥1 worker always serves builds.
	for i := replicas - 1; i >= 0; i-- {
		// Re-check the maintenance mutex before EACH worker: a run
		// with several wipes takes hours (drain+waitReady per pod), so
		// a cordon/drain, reboot lock or upgrade that starts mid-run
		// must stop the remaining wipes — replacing worker N while the
		// operator works fights them exactly like the pre-cycle check
		// prevents for the first worker. Same fail-closed contract: an
		// unverifiable check errors the run, "unknown" means "no".
		mctx, mcancel := context.WithTimeout(ctx, j.cfg.reqTimeout)
		held, why, merr := kube.MaintenanceActive(mctx, j.cs, j.dyn)
		mcancel()
		if merr != nil {
			return merr
		}
		if held {
			log.Info("DEFER: cluster maintenance started mid-run — remaining workers skipped",
				"why", why, "remainingWorkers", i+1)
			return nil
		}
		pod := fmt.Sprintf("%s-%d", cjStatefulSet, i)
		w, err := j.processPod(ctx, pod, flyOK, log)
		if err != nil {
			return err // bash `exit 1` — abort the whole run
		}
		if w {
			wiped++
		} else {
			skipped++
		}
	}
	log.Info("workdir-janitor done", "wiped", wiped, "skipped", skipped)
	return nil
}

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
		// W16-CI1 — a steady-state (Ready >= 15m) worker can still be
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
		s2 := j.readStats(ctx, np)
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

// ---------------------------------------------------------------------------
// W16-CI1 — stalled / Garden max-containers recovery. Detection only:
// the recovery itself is the standard drain → delete → prune →
// waitReady chain processPod already runs.
// ---------------------------------------------------------------------------

// staleWorkerReason reports WHY a steady-state worker pod must be
// replaced despite an under-cap cache, "" when it is healthy (or the
// check is inconclusive — an inconclusive read never wipes the
// cache). Gated on flyOK: without ATC login neither the TSA state nor
// a landed drain is available, and the wipe chain would lose the
// land step the stalled worker needs.
func (j *concourseWorkdirJanitor) staleWorkerReason(ctx context.Context,
	pod *corev1.Pod, podName string, flyOK bool, log logr.Logger) string {
	if !flyOK {
		return ""
	}
	var readyAt time.Time
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			readyAt = c.LastTransitionTime.Time
		}
	}
	if readyAt.IsZero() || j.now.Now().Sub(readyAt) < cjSteadyWorkerMinAge {
		// Young/never-ready pods are inside init-rm or churn — the
		// mid-init-rm guard downstream covers them; detection here
		// must not compound it.
		return ""
	}
	if state, err := j.atc.workerState(ctx, podName); err != nil {
		log.Info("WARN: worker state read failed — stalled detection degrades to the log tail",
			"pod", podName, "error", err)
	} else if state == "stalled" {
		return "tsa-state-stalled"
	}
	tail := j.workerLogTail
	if tail == nil {
		tail = j.fetchWorkerLogTail
	}
	logs, err := tail(ctx, pod)
	if err != nil {
		log.Info("WARN: worker log tail read failed — Garden fault detection inconclusive",
			"pod", podName, "error", err)
		return ""
	}
	return workerGardenFault(logs)
}

// fetchWorkerLogTail is the production half of the workerLogTail
// seam: a bounded GetLogs tail of the concourse-worker container.
func (j *concourseWorkdirJanitor) fetchWorkerLogTail(ctx context.Context,
	pod *corev1.Pod) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, j.cfg.reqTimeout)
	defer cancel()
	tail := int64(cjWorkerLogTailLine)
	stream, err := j.cs.CoreV1().Pods(pod.Namespace).GetLogs(pod.Name,
		&corev1.PodLogOptions{Container: cjWorkerContainer, TailLines: &tail}).Stream(cctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = stream.Close() }()
	data, err := io.ReadAll(io.LimitReader(stream, 256<<10))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// workerGardenFault matches the observed Garden/baggageclaim fault
// signatures (case-insensitive): the worker hit the container
// ceiling, or baggageclaim cannot create new volumes (full disk /
// leaked volumes). "" is healthy-or-inconclusive.
func workerGardenFault(logs string) string {
	l := strings.ToLower(logs)
	if strings.Contains(l, "max containers reached") {
		return "garden-max-containers"
	}
	if strings.Contains(l, "baggageclaim: failed to create volume") {
		return "baggageclaim-volume-create-failed"
	}
	return ""
}
