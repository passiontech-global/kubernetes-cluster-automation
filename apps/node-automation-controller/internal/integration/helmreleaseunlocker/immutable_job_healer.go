// immutable_job_healer.go — the immutable-job-heal immutable-Job apply error
// healer of helmrelease-unlocker: a Flux Kustomization Ready=False
// >=15m on a `field is immutable` Job apply error gets the
// completed/failed Job reaped so kustomize-controller can recreate
// it. The 30m cooldown rides the in-RAM ledger plus the persisted
// passiontech.dev/last-immutable-job-heal stamp on the Kustomization.
package helmreleaseunlocker

import (
	"context"
	"regexp"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

const (
	// immutable-job-heal — a Flux Kustomization Ready=False >=15m on an
	// immutable-Job apply error gets the completed/failed Job
	// deleted so kustomize-controller recreates it; the cooldown is
	// per-Kustomization (in-RAM + persisted annotation).
	immutableJobMinAge   = 15 * time.Minute
	immutableJobCooldown = 30 * time.Minute
	immutableJobHealAnno = kube.AnnoLastImmutableJobHeal
)

// immutableJobRe extracts the Job name out of the kustomize apply
// error `Job.batch "<name>" is invalid: ... field is immutable`.
var immutableJobRe = regexp.MustCompile(`Job\.batch "([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)" is invalid`)

// healImmutableJobs scans Kustomizations (listed by the caller —
// shared with the artifact-source healer so the sweep pages it
// once, nil on pre-v1 flux) for Ready=False >=15m whose
// message is the immutable-Job apply error: a Job manifest changed an
// immutable field (spec.template), so apply fails forever until the
// OLD Job object disappears — and a Job that already ran to Complete
// or Failed is pure residue. Deleting it unblocks the apply. The
// 30m cooldown rides the in-RAM ledger + the persisted
// passiontech.dev/last-immutable-job-heal stamp on the Kustomization.
func (u *helmReleaseUnlocker) healImmutableJobs(ctx context.Context,
	kustomizations *unstructured.UnstructuredList) {
	log := logf.FromContext(ctx)
	if kustomizations == nil {
		return // pre-v1 flux or a failed list — nothing to scan
	}
	now := u.now.Now()
	for i := range kustomizations.Items {
		k := &kustomizations.Items[i]
		if suspended, _ := kube.NestedBool(k.Object, "spec", "suspend"); suspended {
			continue
		}
		c, _ := kube.ConditionOf(k.Object, "Ready")
		if c.Status != "False" || !strings.Contains(strings.ToLower(c.Message), "field is immutable") {
			continue
		}
		m := immutableJobRe.FindStringSubmatch(c.Message)
		if m == nil {
			continue
		}
		since := c.LastTransitionTime
		if since.IsZero() {
			since = k.GetCreationTimestamp().Time
		}
		if now.Sub(since) < immutableJobMinAge {
			continue
		}
		key := k.GetNamespace() + "/" + k.GetName()
		// Cooldown: wider of the in-RAM ledger and the persisted stamp.
		if heal.PersistedCooledDown(&u.immutableJob.healed, k,
			immutableJobHealAnno, key, immutableJobCooldown, now) {
			continue
		}
		// The Job lives where the manifests apply — spec.targetNamespace
		// wins, else the Kustomization's own namespace.
		jobNS := k.GetNamespace()
		if tns, _ := kube.NestedString(k.Object, "spec", "targetNamespace"); tns != "" {
			jobNS = tns
		}
		job, err := u.cs.BatchV1().Jobs(jobNS).Get(ctx, m[1], metav1.GetOptions{})
		gone, err := kube.ConfirmAbsent(err)
		if err != nil {
			metrics.IncError(u.queue)
			log.Error(err, "immutable-job lookup failed", "kustomization", key, "job", jobNS+"/"+m[1])
			continue
		}
		if gone {
			continue // already gone — nothing to reap
		}
		done := job.Status.Succeeded >= 1 || jobFailed(job)
		for _, c := range job.Status.Conditions {
			if c.Type == batchv1.JobComplete && c.Status == corev1.ConditionTrue {
				done = true
			}
		}
		if !done {
			log.Info("skip: immutable Job still active — deleting it mid-run would orphan its pods",
				"kustomization", key, "job", jobNS+"/"+job.Name)
			continue
		}
		log.Info("ACTION: delete completed/failed immutable Job — apply can recreate it",
			"kustomization", key, "job", jobNS+"/"+job.Name)
		if err := u.cs.BatchV1().Jobs(jobNS).Delete(ctx, job.Name,
			kube.UIDDeleteOptions(job.UID, metav1.DeletePropagationBackground)); err != nil {
			if apierrors.IsNotFound(err) {
				// Raced with kustomize-controller's own recreate or a
				// prior heal — the apply is already unblocked. Benign:
				// a skip, not an error (cilium-identity janitor parity).
				log.Info("skip: immutable Job already gone — raced with its own cleanup",
					"kustomization", key, "job", jobNS+"/"+job.Name)
				continue
			}
			metrics.IncError(u.queue)
			log.Error(err, "immutable job delete failed", "job", jobNS+"/"+job.Name)
			continue
		}
		// The in-RAM stamp lands WITH the heal — the Job is already
		// deleted, so a failed annotation write below must not refund
		// the cooldown (the annotation is only the restart-proof half).
		u.immutableJob.healed.Stamp(key, now)
		// Persist the stamp — the durable half of the 30m cooldown.
		payload, err := kube.MergePatchAnnos(map[string]any{
			immutableJobHealAnno: now.UTC().Format(time.RFC3339),
		})
		if err != nil {
			continue
		}
		if _, err := u.dyn.Resource(fluxKustomizationGVR).Namespace(k.GetNamespace()).
			Patch(ctx, k.GetName(), types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
			metrics.IncError(u.queue)
			log.Error(err, "immutable-job heal stamp failed", "kustomization", key)
		}
	}
}
