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
// annotation `concourse.passiontech.dev/baseline-nodefs-gib` on the
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
// a PDB for hours. Same three signals as descheduler-storm-gate
// (keep the checks in sync):
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
package concoursejanitor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	cjQueue       = "concourse-workdir-janitor"
	cjNamespace   = "concourse"
	cjStatefulSet = "concourse-worker"
	// The controller runs in ns node-ops — the cross-namespace short
	// DNS name is required (bare "concourse-web" would not resolve).
	cjATCBase      = "http://concourse-web.concourse:8080"
	cjSecretName   = "concourse-web"
	cjSecretKey    = "local-users"
	cjBaselineAnno = "concourse.passiontech.dev/baseline-nodefs-gib"

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

	// cjKuredLockAnno is the reboot-coordination lock kured holds
	// while a node drains for its reboot window (2.7 signal b).
	cjKuredLockAnno      = "weave.works/kured-node-lock"
	cjKuredDaemonSetNS   = "kube-system"
	cjKuredDaemonSetName = "kured"
)

// cjAutopilotPlanGVR is the k0s autopilot Plan resource — a Plan in a
// non-terminal state means a cluster upgrade is in flight (2.7
// signal c).
var cjAutopilotPlanGVR = shared.AutopilotPlanGVR

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

type concourseWorkdirJanitor struct {
	cs      kubernetes.Interface
	stats   nodeStatsReader
	atc     atcIface
	enabled bool
	mu      sync.Mutex
	// dyn reads the autopilot Plan CR for maintenance-mutex
	// signal (c) — no typed client exists for it.
	dyn dynamic.Interface

	// Timeouts/polls are fields (initialised from the consts) only so
	// tests can shrink them; production values match the bash ones.
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

// Setup registers the 30-minute sweep (was the
// CronJob schedule `7,37 * * * *`). The CONCOURSE_JANITOR_ENABLED
// gate is opt-in — resolved by setupModules into Deps.Disabled, so
// disabled clusters skip registration entirely, same contract as
// volumeattachment-cleaner.
func Setup(d shared.Deps) error {
	mgr, cs, dyn := d.Mgr, d.CS, d.Dyn
	if d.Disabled {
		return nil
	}
	j := &concourseWorkdirJanitor{
		cs:    cs,
		stats: &kubeletStatsReader{cs: cs},
		atc:   newATCClient(cjATCBase, &http.Client{Timeout: cjATCTimeout}),
		// Reaching this line means the registration gate was on, so
		// the field is unconditionally true — run()'s enabled check
		// now only guards literally-constructed janitors in tests.
		enabled: true,
		dyn:     dyn,

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
	}
	return shared.AddPeriodic(mgr, cjQueue, 30*time.Minute, j.run)
}

func (j *concourseWorkdirJanitor) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	if !j.enabled {
		log.Info("skip: concourse-workdir-janitor disabled")
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()

	// 2.7 maintenance mutex — defer the whole wipe cycle while any
	// deliberate maintenance is in flight (cordon/drain, kured
	// reboot lock, autopilot upgrade). An unverifiable check errors
	// the run: the wipe is destructive enough that "unknown" must
	// mean "no".
	if held, why, err := j.maintenanceHeld(ctx); err != nil {
		return err
	} else if held {
		log.Info(fmt.Sprintf(
			"DEFER: cluster maintenance in progress (%s) — wipe cycle skipped", why))
		return nil
	}

	// Whole-run bound — replaces the CronJob's activeDeadlineSeconds.
	ctx, cancel := context.WithTimeout(ctx, j.runTimeout)
	defer cancel()

	// ATC login is fail-open: on any failure land/drain/prune are
	// skipped and pods are deleted as before — the worker's pre-stop
	// retire + grace remains the fallback.
	flyOK := false
	if user, pass, err := j.atcCredentials(ctx); err != nil {
		log.Info(fmt.Sprintf(
			"WARN: %s/%s unreadable — land/drain/prune skipped, pod delete only: %v",
			cjSecretName, cjSecretKey, err))
	} else if err := j.atc.login(ctx, user, pass); err != nil {
		log.Info(fmt.Sprintf(
			"WARN: ATC login failed — land/drain/prune skipped, pod delete only: %v", err))
	} else {
		flyOK = true
		log.Info("fly login OK", "user", user)
	}

	replicas, err := j.workerReplicas(ctx)
	if err != nil {
		return err // bash: "FAIL: sts concourse-worker not found" + exit 1
	}
	log.Info(fmt.Sprintf("concourse-worker replicas=%d", replicas))

	wiped, skipped := 0, 0
	// Descending ordinals — order is irrelevant (Parallel policy) as
	// long as it is sequential: ≥1 worker always serves builds.
	for i := replicas - 1; i >= 0; i-- {
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
	log.Info(fmt.Sprintf("workdir-janitor done: wiped=%d skipped=%d", wiped, skipped))
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
			log.Info(fmt.Sprintf("SKIP %s: not found", podName))
		} else {
			log.Info(fmt.Sprintf("SKIP %s: get failed: %v", podName, err))
		}
		return false, nil
	}

	s := j.readStats(ctx, pod)
	log.Info(fmt.Sprintf("=== %s: nodefs %s %sGiB/%sGiB (%s%%), workdir %sGiB/%dGiB cap ===",
		podName, strOr(s.node, "?"), intOr(s.usedGiB, s.nodefsOK),
		intOr(s.capGiB, s.nodefsOK), intOr(s.pct, s.nodefsOK),
		intOr(s.workdirGiB, s.workdirOK), cjMaxWorkdirGiB))

	// Keep the cache only when we KNOW workdir <= cap AND nodefs has
	// headroom; over-cap, over-threshold or unreadable stats all wipe
	// (fail-open).
	if s.workdirOK && s.workdirGiB <= cjMaxWorkdirGiB &&
		s.nodefsOK && s.pct < cjMinNodefsPct {
		log.Info(fmt.Sprintf("SKIP %s: workdir %dGiB <= %dGiB, nodefs %d%% < %d%% — keep cache",
			podName, s.workdirGiB, cjMaxWorkdirGiB, s.pct, cjMinNodefsPct))
		return false, nil
	}
	if !s.nodefsOK || !s.workdirOK {
		// A blind wipe is deliberate fail-open policy, but a
		// persistently-unreadable stats path must be visible on the
		// error metric — not just in logs.
		metrics.IncError(cjQueue)
		log.Info(fmt.Sprintf("WARN %s: wiping with unreadable stats (nodefsOK=%v workdirOK=%v)",
			podName, s.nodefsOK, s.workdirOK))
	}

	// A pod created < readyTimeout ago that is still not Ready is
	// almost certainly inside init-rm from an earlier wipe (a full
	// rm -rf can take most of that window) — deleting it again just
	// restarts the wipe without freeing anything new, and it is not
	// serving builds anyway. Once the window passes the guard lifts so
	// a wedged-not-Ready pod can still be replaced (bash had no such
	// guard; an interrupted CronJob could thrash the same pod).
	if !shared.PodReadyCond(pod) && time.Since(pod.CreationTimestamp.Time) < j.readyTimeout {
		log.Info(fmt.Sprintf("SKIP %s: not Ready %s after creation (< %s) — mid init-rm",
			podName, time.Since(pod.CreationTimestamp.Time).Truncate(time.Minute),
			j.readyTimeout))
		return false, nil
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
	log.Info(fmt.Sprintf("=== %s: delete (init-rm will wipe work-dir) ===", podName))
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
	log.Info(fmt.Sprintf("=== %s: new pod created — waiting Ready ===", podName))
	if err := j.waitReady(ctx, podName); err != nil {
		return false, err
	}

	// Post-wipe: re-read stats and stamp the baseline (work-dir is
	// now ~empty, so current nodefs IS the baseline for the next
	// run). All failures are non-fatal — bash `|| true`.
	wd := "?"
	if np, err := j.getPod(ctx, podName); err != nil {
		log.Info(fmt.Sprintf("WARN %s: re-read pod after wipe failed: %v", podName, err))
	} else {
		s2 := j.readStats(ctx, np)
		if s2.nodefsOK {
			if err := j.annotateBaseline(ctx, podName, s2.usedGiB); err != nil {
				log.Info(fmt.Sprintf("WARN %s: baseline annotate failed: %v", podName, err))
			}
			wd = "0"
		}
		log.Info(fmt.Sprintf("=== %s: after wipe nodefs %sGiB/%sGiB (%s%%), workdir %sGiB ===",
			podName, intOr(s2.usedGiB, s2.nodefsOK), intOr(s2.capGiB, s2.nodefsOK),
			intOr(s2.pct, s2.nodefsOK), wd))
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
	log.Info(fmt.Sprintf("=== %s: land-worker ===", podName))
	bound := j.drainTimeout
	if err := j.atc.landWorker(ctx, podName); err != nil {
		log.Info(fmt.Sprintf("WARN %s: land-worker failed: %v", podName, err))
		bound = j.landFailWait
	}
	dctx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	err := wait.PollUntilContextCancel(dctx, j.slowPoll, true,
		func(ctx context.Context) (bool, error) {
			// "" only means drained when the ATC call SUCCEEDED — an
			// errored poll keeps waiting (up to the bound), so a
			// transient ATC blip cannot cut in-flight builds early.
			// (Bash could not tell the two apart; Go can.)
			st, werr := j.atc.workerState(ctx, podName)
			return (werr == nil && st == "") || st == "landed" || st == "retired", nil
		})
	if err != nil {
		log.Info(fmt.Sprintf("WARN %s: drain exceeded %s — still deleting pod",
			podName, bound))
	} else {
		log.Info(fmt.Sprintf("=== %s: drained ===", podName))
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
	pctx, cancel := context.WithTimeout(ctx, j.pruneStateWait)
	defer cancel()
	var st string
	var lastErr error
	// The first check is immediate; a timeout just means the last
	// read stands — the decision below uses it either way.
	_ = wait.PollUntilContextCancel(pctx, j.fastPoll, true,
		func(ctx context.Context) (bool, error) {
			s, err := j.atc.workerState(ctx, podName)
			if err != nil {
				lastErr = err
				return false, nil // transient — keep polling inside the bound
			}
			lastErr = nil
			st = s
			return s != "running", nil
		})
	if lastErr != nil {
		log.Info(fmt.Sprintf("WARN %s: worker state unreadable (%v) — no prune", podName, lastErr))
		return
	}
	switch st {
	// "landing" too: a drain that timed out mid-land still leaves a
	// ghost worker record (and its claimed volumes) at the ATC — the
	// worker already stopped picking up builds, so pruning is safe.
	case "stalled", "landing", "landed", "retired", "retiring":
		log.Info(fmt.Sprintf("=== %s: worker state=%s — prune before new pod Ready ===", podName, st))
		if err := j.atc.pruneWorker(ctx, podName); err != nil {
			log.Info(fmt.Sprintf("WARN %s: prune-worker failed: %v", podName, err))
		}
	default:
		log.Info(fmt.Sprintf("=== %s: worker state=%s — no prune needed ===",
			podName, strOr(st, "gone")))
	}
}

// ---------------------------------------------------------------------------
// Kubernetes API helpers — every call carries ctx (+ reqTimeout where
// bash used --request-timeout).
// ---------------------------------------------------------------------------

func (j *concourseWorkdirJanitor) getPod(ctx context.Context, name string) (*corev1.Pod, error) {
	cctx, cancel := context.WithTimeout(ctx, j.reqTimeout)
	defer cancel()
	return j.cs.CoreV1().Pods(cjNamespace).Get(cctx, name, metav1.GetOptions{})
}

func (j *concourseWorkdirJanitor) workerReplicas(ctx context.Context) (int32, error) {
	cctx, cancel := context.WithTimeout(ctx, j.reqTimeout)
	defer cancel()
	sts, err := j.cs.AppsV1().StatefulSets(cjNamespace).Get(cctx, cjStatefulSet, metav1.GetOptions{})
	if err != nil {
		return 0, fmt.Errorf("get sts %s: %w", cjStatefulSet, err)
	}
	if sts.Spec.Replicas == nil {
		return 0, fmt.Errorf("sts %s: spec.replicas unset", cjStatefulSet)
	}
	return *sts.Spec.Replicas, nil
}

// deletePod issues the delete and waits (bounded by deleteTimeout)
// until the OLD object is actually gone — `kubectl delete --wait`.
// "Gone" is uid-scoped: a same-named replacement created before our
// first poll still confirms the old object's deletion.
func (j *concourseWorkdirJanitor) deletePod(ctx context.Context, name string, oldUID types.UID) error {
	dctx, cancel := context.WithTimeout(ctx, j.deleteTimeout)
	defer cancel()
	// UID precondition: oldUID was re-fetched right before this call
	// — if the object already churned to a new UID, the delete must
	// conflict rather than remove a pod we never vetted.
	if err := j.cs.CoreV1().Pods(cjNamespace).Delete(dctx, name, metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{UID: &oldUID},
	}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete pod %s: %w", name, err)
	}
	err := wait.PollUntilContextCancel(dctx, j.fastPoll, true,
		func(ctx context.Context) (bool, error) {
			p, err := j.cs.CoreV1().Pods(cjNamespace).Get(ctx, name, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				return true, nil
			}
			if err != nil {
				return false, nil // transient — keep waiting
			}
			return p.UID != oldUID, nil // old object deleted (or still terminating)
		})
	if err != nil {
		return fmt.Errorf("pod %s still present after %s: %w", name, j.deleteTimeout, err)
	}
	return nil
}

// waitNewPod blocks until a pod with a DIFFERENT uid exists — the old
// object can linger in terminating, so waiting on the name alone
// would pin onto the old pod. No replacement inside uidPollTimeout is
// a run error (bash `exit 1`: "new pod not created").
func (j *concourseWorkdirJanitor) waitNewPod(ctx context.Context, name string, oldUID types.UID) error {
	dctx, cancel := context.WithTimeout(ctx, j.uidPollTimeout)
	defer cancel()
	err := wait.PollUntilContextCancel(dctx, j.fastPoll, true,
		func(ctx context.Context) (bool, error) {
			p, err := j.cs.CoreV1().Pods(cjNamespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return false, nil // not created yet / transient — keep polling
			}
			return p.UID != oldUID, nil
		})
	if err != nil {
		return fmt.Errorf("pod %s: new pod not created within %s: %w", name, j.uidPollTimeout, err)
	}
	return nil
}

// waitReady blocks until the pod's Ready condition is True — init-rm
// of a huge work-dir is why the window is so generous.
func (j *concourseWorkdirJanitor) waitReady(ctx context.Context, name string) error {
	dctx, cancel := context.WithTimeout(ctx, j.readyTimeout)
	defer cancel()
	err := wait.PollUntilContextCancel(dctx, j.slowPoll, true,
		func(ctx context.Context) (bool, error) {
			p, err := j.cs.CoreV1().Pods(cjNamespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return false, nil
			}
			return shared.PodReadyCond(p), nil
		})
	if err != nil {
		return fmt.Errorf("pod %s not Ready after %s: %w", name, j.readyTimeout, err)
	}
	return nil
}

// atcCredentials reads the break-glass local user from the
// concourse-web/local-users Secret (ES-managed): first line is
// "user:password", split on the FIRST colon (the password itself may
// contain colons).
func (j *concourseWorkdirJanitor) atcCredentials(ctx context.Context) (string, string, error) {
	cctx, cancel := context.WithTimeout(ctx, j.reqTimeout)
	defer cancel()
	sec, err := j.cs.CoreV1().Secrets(cjNamespace).Get(cctx, cjSecretName, metav1.GetOptions{})
	if err != nil {
		return "", "", err
	}
	line, _, _ := strings.Cut(string(sec.Data[cjSecretKey]), "\n")
	// Trim a possible CRLF — a stray \r inside the password would 401
	// every login and silently degrade the whole module to
	// delete-only mode.
	line = strings.TrimRight(line, "\r\n")
	user, pass, ok := strings.Cut(line, ":")
	if !ok || user == "" {
		return "", "", fmt.Errorf("secret %s key %s has no \"user:password\" first line",
			cjSecretName, cjSecretKey)
	}
	return user, pass, nil
}

// annotateBaseline merge-patches baseline-nodefs-gib=<nodefsGiB> onto
// the pod (kubectl annotate --overwrite). The annotation is what the
// next run subtracts from nodefs to get the work-dir usage.
func (j *concourseWorkdirJanitor) annotateBaseline(ctx context.Context, pod string, nodefsGiB int64) error {
	cctx, cancel := context.WithTimeout(ctx, j.reqTimeout)
	defer cancel()
	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{"annotations": map[string]string{
			cjBaselineAnno: strconv.FormatInt(nodefsGiB, 10),
		}},
	})
	if err != nil {
		return err
	}
	_, err = j.cs.CoreV1().Pods(cjNamespace).Patch(cctx, pod,
		types.MergePatchType, patch, metav1.PatchOptions{})
	return err
}

// ---------------------------------------------------------------------------
// Stats — replaces the read_stats() sed pipeline.
// ---------------------------------------------------------------------------

const gib = 1024 * 1024 * 1024

// cjStats is the typed projection of a pod's disk reading; the *OK
// flags mirror the bash "-n $VAR" checks (empty = unknown → fail-open).
type cjStats struct {
	node       string
	usedGiB    int64
	capGiB     int64
	pct        int64
	nodefsOK   bool
	workdirGiB int64
	workdirOK  bool
}

// readStats turns kubelet stats/summary + the baseline annotation
// into the numbers the wipe decision needs.
func (j *concourseWorkdirJanitor) readStats(ctx context.Context, pod *corev1.Pod) cjStats {
	s := cjStats{node: pod.Spec.NodeName}
	if s.node == "" {
		return s
	}
	cctx, cancel := context.WithTimeout(ctx, j.reqTimeout)
	defer cancel()
	used, capBytes, imgUsed, err := j.stats.Summary(cctx, s.node)
	if err != nil {
		// Fail-open is deliberate, but a persistently-broken
		// stats/summary path must show up on the error metric —
		// every pod will blind-wipe until it is fixed.
		metrics.IncError(cjQueue)
		logf.FromContext(ctx).Info(fmt.Sprintf(
			"WARN %s: stats/summary unreadable on node %s: %v — disk unknown, fail-open",
			pod.Name, s.node, err))
		return s
	}
	if used >= 0 && capBytes > 0 {
		s.usedGiB = used / gib
		s.capGiB = capBytes / gib
		s.pct = used * 100 / capBytes
		s.nodefsOK = true
	}
	if !s.nodefsOK {
		return s
	}
	// workdir = nodefs_used - baseline. Baseline comes from the
	// annotation when it is a non-negative integer (bash case-match
	// `''|*[!0-9]*`), else imageFs_used + 32GiB for OS/k0s/other pods.
	var wd int64
	switch base, err := strconv.ParseUint(pod.Annotations[cjBaselineAnno], 10, 64); {
	case err == nil:
		wd = s.usedGiB - int64(base)
	case imgUsed >= 0:
		if anno := pod.Annotations[cjBaselineAnno]; anno != "" {
			logf.FromContext(ctx).Info(fmt.Sprintf(
				"WARN %s: baseline annotation %q invalid — estimating from imageFs+%dGiB",
				pod.Name, anno, cjOSBaselineGiB))
		}
		wd = s.usedGiB - imgUsed/gib - cjOSBaselineGiB
	default:
		// No baseline path at all → workdir unknown → fail-open wipe.
		logf.FromContext(ctx).Info(fmt.Sprintf(
			"WARN %s: no usable baseline (annotation %q, imageFs missing) — workdir unknown, fail-open",
			pod.Name, pod.Annotations[cjBaselineAnno]))
		return s
	}
	if wd < 0 {
		wd = 0
	}
	s.workdirGiB = wd
	s.workdirOK = true
	return s
}

// ---------------------------------------------------------------------------
// Production implementations of the seams.
// ---------------------------------------------------------------------------

// kubeletSummary is the typed shape of GET
// /api/v1/nodes/<node>/proxy/stats/summary — replaces the bash sed
// pipeline that carved pretty-printed "fs"/"imageFs" blocks out of
// `kubectl get --raw` output.
type kubeletSummary struct {
	Node struct {
		FS struct {
			UsedBytes     *int64 `json:"usedBytes"`
			CapacityBytes *int64 `json:"capacityBytes"`
		} `json:"fs"`
		Runtime struct {
			ImageFS struct {
				UsedBytes *int64 `json:"usedBytes"`
			} `json:"imageFs"`
		} `json:"runtime"`
	} `json:"node"`
}

// kubeletStatsReader is the production nodeStatsReader — the apiserver
// node-proxy subresource, same path the bash hit via `get --raw`.
type kubeletStatsReader struct {
	cs kubernetes.Interface
}

func (r *kubeletStatsReader) Summary(ctx context.Context, node string) (nodefsUsed, nodefsCap, imageFsUsed int64, err error) {
	raw, err := r.cs.CoreV1().RESTClient().Get().
		Resource("nodes").Name(node).
		SubResource("proxy").Suffix("stats", "summary").
		DoRaw(ctx)
	if err != nil {
		return 0, 0, 0, err
	}
	var s kubeletSummary
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, 0, 0, fmt.Errorf("parse stats/summary for node %s: %w", node, err)
	}
	deref := func(p *int64) int64 {
		if p == nil {
			return -1 // absent counter — not a real 0
		}
		return *p
	}
	return deref(s.Node.FS.UsedBytes), deref(s.Node.FS.CapacityBytes), deref(s.Node.Runtime.ImageFS.UsedBytes), nil
}

// ---------------------------------------------------------------------------
// 2.7 — Cluster Maintenance Mutex. Keep in sync with the copy inside
// descheduler-storm-gate.
// ---------------------------------------------------------------------------

// maintenanceHeld reports whether deliberate cluster maintenance is
// in flight — the wipe cycle defers entirely while any signal holds:
//
//	a) any node spec.unschedulable — a cordon/drain is running;
//	b) DaemonSet kube-system/kured holding weave.works/kured-node-lock;
//	c) an autopilot Plan whose status.state is neither Schedulable
//	   nor Completed — a k0s upgrade in flight.
//
// Returns (held, human-readable why, error). A missing kured
// DaemonSet or absent autopilot CRD is not evidence; real API
// failures are errors — "cannot verify" must never read as "clear".
func (j *concourseWorkdirJanitor) maintenanceHeld(ctx context.Context) (bool, string, error) {
	// The mutex runs BEFORE the whole-run timeout installs, so every
	// call here carries its own reqTimeout — an apiserver hang must
	// not pin the periodic sweep forever.
	// (a) cordon/drain in progress. W10-FIX5: NodeActivelyCordoned —
	// a statically-cordoned node whose cordon-ttl already expired is
	// deliberate state, not a drain in flight, and must not freeze
	// the wipe cycle forever.
	nctx, cancel := context.WithTimeout(ctx, j.reqTimeout)
	nodes, err := shared.ListNodes(nctx, j.cs)
	cancel()
	if err != nil {
		return false, "", fmt.Errorf("list nodes (maintenance mutex): %w", err)
	}
	for i := range nodes {
		if shared.NodeActivelyCordoned(&nodes[i], time.Now()) {
			return true, "node " + nodes[i].Name + " actively cordoned", nil
		}
	}

	// (b) kured holding its node-lock annotation means a reboot
	// drain is in progress right now.
	dctx, cancel := context.WithTimeout(ctx, j.reqTimeout)
	ds, err := j.cs.AppsV1().DaemonSets(cjKuredDaemonSetNS).
		Get(dctx, cjKuredDaemonSetName, metav1.GetOptions{})
	cancel()
	switch {
	case apierrors.IsNotFound(err):
		// kured not installed on this cluster — no signal.
	case err != nil:
		return false, "", fmt.Errorf("get daemonset %s/%s (maintenance mutex): %w",
			cjKuredDaemonSetNS, cjKuredDaemonSetName, err)
	default:
		if v := ds.Annotations[cjKuredLockAnno]; v != "" {
			return true, "kured lock held by " + v, nil
		}
	}

	// (c) Any autopilot Plan outside its terminal states means a
	// k0s upgrade is in flight. An absent CRD is not evidence. A
	// missing dynamic client is a wiring bug, not "no signal" —
	// unverifiable fails closed like every other check here (the
	// run aborts, the wipe defers).
	if j.dyn == nil {
		return false, "", fmt.Errorf("no dynamic client — autopilot plan check unverifiable (maintenance mutex)")
	}
	pctx, cancel := context.WithTimeout(ctx, j.reqTimeout)
	plans, err := j.dyn.Resource(cjAutopilotPlanGVR).
		List(pctx, metav1.ListOptions{})
	cancel()
	switch {
	case apierrors.IsNotFound(err) || meta.IsNoMatchError(err):
		// autopilot CRD not installed — no signal.
	case err != nil:
		return false, "", fmt.Errorf("list autopilot plans (maintenance mutex): %w", err)
	default:
		for i := range plans.Items {
			state, _, _ := unstructured.NestedString(
				plans.Items[i].Object, "status", "state")
			if state != "Schedulable" && state != "Completed" {
				return true, fmt.Sprintf("autopilot plan %s state=%s",
					plans.Items[i].GetName(), state), nil
			}
		}
	}
	return false, "", nil
}

// ---------------------------------------------------------------------------
// Small formatting helpers (bash's ${VAR:-?} fallback).
// ---------------------------------------------------------------------------

func strOr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// intOr prints the number or "?" — used for both GiB and % fields
// (bash's ${VAR:-?} fallback).
func intOr(v int64, ok bool) string {
	if !ok {
		return "?"
	}
	return strconv.FormatInt(v, 10)
}
