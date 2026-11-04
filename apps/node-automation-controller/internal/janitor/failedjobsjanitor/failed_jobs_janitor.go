// Port of hooks/80-failed-jobs-janitor.sh, plus the C3b
// stuck-Terminating auditor.
//
// Deletes Jobs stuck in Failed=True for >24h. CronJob
// failedJobsHistoryLimit only keeps the N most recent failures — manual
// jobs and jobs that failed before the limit existed linger forever,
// wasting storage and cluttering `kubectl get jobs` (nonprod 2026-09-22).
//
// Safety: only Failed=True with a lastTransitionTime older than 24h —
// Active retries and fresh failures (still worth debugging) are kept,
// Complete/Running are never touched. Capped at 50 deletions per run.
//
// auditStuckTerminating (C3b — detect-only): Namespaces, PVCs and
// VolumeAttachments can wedge in Terminating forever when the
// controller that owns a finalizer is gone or itself deadlocked
// (namespace-controller cannot finish an ns whose remaining
// resources need a deleted API service; kubernetes.io/pvc-protection
// waits on a pod that will never exit; a VA's external-attacher
// finalizer never drains once its node is gone).
// Nothing in-tree alerts on it — the object just sits there for days.
// The audit marks each resource Terminating >2h on
// node_automation_stuck_terminating_resources and logs its finalizer
// list — the finalizer names the controller that stopped draining, so
// it is the debugging payload. Detection only: finalizers are never
// stripped automatically (a stripped finalizer on a still-mounted
// volume is a data-loss vector).
package failedjobsjanitor

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

const (
	failedJobQueue  = "failed-jobs-janitor"
	failedJobMaxAge = 24 * time.Hour
	failedJobCap    = 50 // bound delete churn per run

	// stuckTerminatingMaxAge: a DeletionTimestamp older than this is
	// genuinely stuck — every legitimate finalizer drain (pod exit,
	// PVC unprotect, resourcequota reconcile) finishes in seconds to
	// a couple of minutes.
	stuckTerminatingMaxAge = 2 * time.Hour
	// failedJobListPageSize bounds each cluster-wide List page —
	// continue-token pagination keeps a huge Job/PVC/VA fleet from
	// arriving as one giant response body.
	failedJobListPageSize = 500
)

// stuckTerminatingKey identifies one emitted
// StuckTerminatingResources series — the label triple needed to
// delete it again once the resource finishes terminating.
type stuckTerminatingKey struct {
	kind, ns, name string
}

type failedJobsJanitor struct {
	cs kubernetes.Interface
	// nowFn is the clock seam — tests pin it to a fixed instant.
	nowFn func() time.Time
	// stuckEmitted: the kind/ns/name triples the audit marked on the
	// previous sweep. A resource that finished terminating (or
	// vanished) gets its series deleted so /metrics never leaks a
	// stale "stuck" series.
	stuckEmitted map[stuckTerminatingKey]struct{}
}

// Setup registers the hourly sweep (was crontab 17 * * * *).
func Setup(mgr ctrl.Manager, cs kubernetes.Interface) error {
	j := &failedJobsJanitor{
		cs:           cs,
		nowFn:        time.Now,
		stuckEmitted: map[stuckTerminatingKey]struct{}{},
	}
	return shared.AddPeriodic(mgr, failedJobQueue, 60*time.Minute, j.run)
}

func (j *failedJobsJanitor) run(ctx context.Context) error {
	log := logf.FromContext(ctx)
	// Lazily arm the zero-value struct — unit tests construct the
	// module literally without the Setup path. stuckEmitted needs
	// no such guard: it is only ranged over (nil-safe) and replaced
	// wholesale each audit, never keyed-written like a cache.
	if j.nowFn == nil {
		j.nowFn = time.Now
	}

	var jobs []batchv1.Job
	cont := ""
	for {
		page, err := j.cs.BatchV1().Jobs(metav1.NamespaceAll).List(ctx, metav1.ListOptions{
			Limit: failedJobListPageSize, Continue: cont})
		if err != nil {
			return fmt.Errorf("list jobs: %w", err)
		}
		jobs = append(jobs, page.Items...)
		if cont = page.Continue; cont == "" {
			break
		}
	}

	type target struct {
		ns, name string
		uid      types.UID
		ageHours int
	}
	var targets []target
	capped := false
	for i := range jobs {
		job := &jobs[i]
		if job.DeletionTimestamp != nil {
			continue // already terminating — a second delete just burns a cap slot
		}
		var failedAt *metav1.Time
		for ci := range job.Status.Conditions {
			c := &job.Status.Conditions[ci]
			if c.Type == batchv1.JobFailed && c.Status == corev1.ConditionTrue && !c.LastTransitionTime.IsZero() {
				failedAt = &c.LastTransitionTime
				break
			}
		}
		if failedAt == nil {
			continue // not failed, or no timestamp — keep
		}
		age := j.nowFn().Sub(failedAt.Time)
		if age <= failedJobMaxAge {
			continue
		}
		if len(targets) >= failedJobCap {
			capped = true
			break
		}
		targets = append(targets, target{
			ns:       job.Namespace,
			name:     job.Name,
			uid:      job.UID,
			ageHours: int(age.Hours()),
		})
	}
	// Release the cluster-wide job slice before issuing Delete calls.
	jobs = nil

	background := metav1.DeletePropagationBackground
	deleted, failed := 0, 0
	for _, t := range targets {
		log.Info(fmt.Sprintf("DELETE %s/%s: Failed for %dh", t.ns, t.name, t.ageHours))
		// UID precondition: the listed object is what we vetted — a
		// same-named Job recreated in between must not inherit the
		// delete.
		if err := j.cs.BatchV1().Jobs(t.ns).Delete(ctx, t.name,
			metav1.DeleteOptions{PropagationPolicy: &background,
				Preconditions: &metav1.Preconditions{UID: &t.uid}}); err != nil {
			metrics.IncError(failedJobQueue)
			log.Error(err, "job delete failed",
				"job", t.ns+"/"+t.name, "failedForHours", t.ageHours)
			failed++
			continue
		}
		deleted++
	}
	if capped {
		log.Info(fmt.Sprintf("SKIP rest: cap=%d reached", failedJobCap))
	}
	log.Info("sweep done", "deleted", deleted, "failed", failed)

	// C3b audit rides the same hourly tick — detect-only, it shares
	// neither the job list nor the delete cap.
	return j.auditStuckTerminating(ctx)
}

// auditStuckTerminating marks every namespace/PVC/VolumeAttachment
// stuck in Terminating past stuckTerminatingMaxAge on
// metrics.StuckTerminatingResources and logs its finalizers — the
// finalizer list is the debugging payload: it names the controller
// that stopped draining (kubernetes.io/pvc-protection, a wedged
// external-attacher finalizer on a VA whose node is gone, a deleted
// operator's custom finalizer, ...). Detect-only — finalizers are
// never stripped automatically.
//
// Label convention: kind is "Namespace", "PersistentVolumeClaim" or
// "VolumeAttachment". For the cluster-scoped kinds (Namespace,
// VolumeAttachment) the "namespace" label is the empty string —
// there is no containing namespace, and repeating the object name
// would only make the two labels redundant.
func (j *failedJobsJanitor) auditStuckTerminating(ctx context.Context) error {
	log := logf.FromContext(ctx)
	now := j.nowFn()

	// All lists land before any series is emitted — a failed later
	// list must not leave the gauge half-populated for an hour.
	nss, err := j.cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("list namespaces: %w", err)
	}
	var pvcs []corev1.PersistentVolumeClaim
	cont := ""
	for {
		page, err := j.cs.CoreV1().PersistentVolumeClaims(metav1.NamespaceAll).
			List(ctx, metav1.ListOptions{Limit: failedJobListPageSize, Continue: cont})
		if err != nil {
			return fmt.Errorf("list persistentvolumeclaims: %w", err)
		}
		pvcs = append(pvcs, page.Items...)
		if cont = page.Continue; cont == "" {
			break
		}
	}
	var vas []storagev1.VolumeAttachment
	for {
		page, err := j.cs.StorageV1().VolumeAttachments().
			List(ctx, metav1.ListOptions{Limit: failedJobListPageSize, Continue: cont})
		if err != nil {
			return fmt.Errorf("list volumeattachments: %w", err)
		}
		vas = append(vas, page.Items...)
		if cont = page.Continue; cont == "" {
			break
		}
	}

	current := map[stuckTerminatingKey]struct{}{}
	mark := func(kind, ns, name string, terminatingSince *metav1.Time, finalizers []string) {
		if terminatingSince == nil ||
			now.Sub(terminatingSince.Time) <= stuckTerminatingMaxAge {
			return // not terminating, or still inside the grace window
		}
		current[stuckTerminatingKey{kind: kind, ns: ns, name: name}] = struct{}{}
		metrics.StuckTerminatingResources.WithLabelValues(kind, ns, name).Set(1)
		log.Info("STUCK: still Terminating past threshold — inspect finalizers",
			"kind", kind, "namespace", ns, "name", name,
			"terminatingFor", now.Sub(terminatingSince.Time).Truncate(time.Minute),
			"finalizers", finalizers)
	}
	for i := range nss.Items {
		n := &nss.Items[i]
		// spec.finalizers is the list the namespace controller drains
		// (metadata.finalizers is not what wedges a Terminating ns).
		mark("Namespace", "", n.Name, n.DeletionTimestamp, nsFinalizerNames(n))
	}
	nss = nil
	// W4: a PVC wedged past the threshold whose ONLY finalizer is
	// kubernetes.io/pvc-protection is stuck waiting on the protection
	// controller to prove no pod uses it — when zero pods in the
	// namespace still reference it, the finalizer is stripped. The
	// per-namespace reference scan is cached per audit pass.
	nsClaims := map[string]pvcUseProbe{}
	for i := range pvcs {
		p := &pvcs[i]
		mark("PersistentVolumeClaim", p.Namespace, p.Name, p.DeletionTimestamp, p.Finalizers)
		if p.DeletionTimestamp != nil &&
			now.Sub(p.DeletionTimestamp.Time) > stuckTerminatingMaxAge &&
			len(p.Finalizers) == 1 && p.Finalizers[0] == pvcProtectionFinalizer {
			j.unstickPVCProtection(ctx, p, nsClaims)
		}
	}
	pvcs = nil
	// VolumeAttachments: the volumeattachment-cleaner refuses to
	// touch a VA already Terminating — the wedged attacher finalizer
	// is exactly what this audit exists to surface.
	for i := range vas {
		v := &vas[i]
		mark("VolumeAttachment", "", v.Name, v.DeletionTimestamp, v.Finalizers)
	}
	vas = nil

	// Hygiene: series for resources that finished terminating are
	// deleted, not zeroed — a Set(0) leaves the label triple in
	// /metrics forever, which Prometheus still treats as a live
	// series. Same convention as metrics.ForgetAPIBackend.
	for key := range j.stuckEmitted {
		if _, ok := current[key]; !ok {
			metrics.StuckTerminatingResources.DeleteLabelValues(
				key.kind, key.ns, key.name)
		}
	}
	j.stuckEmitted = current

	log.Info("stuck-terminating audit done", "stuck", len(current))
	return nil
}

// pvcProtectionFinalizer is the in-tree claim-protection finalizer —
// it drains only after the pvc-protection-controller verifies no pod
// references the claim; a wedged controller (or a deleted pod whose
// reference the controller missed) leaves it forever (W4).
const pvcProtectionFinalizer = "kubernetes.io/pvc-protection"

// pvcUseProbe caches one namespace's "who still claims what" verdict
// per audit pass — a shared failure must not be re-listed per PVC.
type pvcUseProbe struct {
	claims map[string]bool // claim names still referenced by a live pod
	err    error
}

// unstickPVCProtection strips the pvc-protection finalizer from a
// stuck Terminating claim once a namespace pod scan proves nothing
// references it. Any list failure fails closed — the claim stays
// protected rather than risk an early unbind.
func (j *failedJobsJanitor) unstickPVCProtection(ctx context.Context,
	pvc *corev1.PersistentVolumeClaim, cache map[string]pvcUseProbe) {
	log := logf.FromContext(ctx)
	pr, ok := cache[pvc.Namespace]
	if !ok {
		pr = pvcUseProbe{claims: map[string]bool{}}
		pods, err := j.cs.CoreV1().Pods(pvc.Namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			pr.err = err
		} else {
			for i := range pods.Items {
				p := &pods.Items[i]
				if p.Status.Phase == corev1.PodSucceeded ||
					p.Status.Phase == corev1.PodFailed {
					continue
				}
				for _, v := range p.Spec.Volumes {
					if v.PersistentVolumeClaim != nil {
						pr.claims[v.PersistentVolumeClaim.ClaimName] = true
					}
				}
			}
		}
		cache[pvc.Namespace] = pr
	}
	if pr.err != nil {
		metrics.IncError(failedJobQueue)
		log.Error(pr.err, "pod list failed — keeping pvc-protection finalizer (fail closed)",
			"pvc", pvc.Namespace+"/"+pvc.Name)
		return
	}
	if pr.claims[pvc.Name] {
		return // still referenced — the finalizer is doing its job
	}
	log.Info("PATCH-FINALIZER: stuck PVC unreferenced by every live pod — removing pvc-protection",
		"pvc", pvc.Namespace+"/"+pvc.Name,
		"terminatingFor", j.nowFn().Sub(pvc.DeletionTimestamp.Time).Truncate(time.Minute))
	payload, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"resourceVersion": pvc.ResourceVersion,
			"finalizers":      nil,
		},
	})
	if err != nil {
		metrics.IncError(failedJobQueue)
		return
	}
	if _, err := j.cs.CoreV1().PersistentVolumeClaims(pvc.Namespace).Patch(ctx,
		pvc.Name, types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
		metrics.IncError(failedJobQueue)
		log.Error(err, "pvc-protection finalizer strip failed",
			"pvc", pvc.Namespace+"/"+pvc.Name)
	}
}

// nsFinalizerNames renders .spec.finalizers — the list that actually
// blocks a Terminating namespace — as plain strings for logging.
func nsFinalizerNames(n *corev1.Namespace) []string {
	out := make([]string, 0, len(n.Spec.Finalizers))
	for _, f := range n.Spec.Finalizers {
		out = append(out, string(f))
	}
	return out
}
