// immutable_job_healer.go — the W8-GO1 immutable-Job apply error
// healer of helmrelease-unlocker: a Flux Kustomization Ready=False
// >=15m on a `field is immutable` Job apply error gets the
// completed/failed Job reaped so kustomize-controller can recreate
// it. The 30m cooldown rides the in-RAM ledger plus the persisted
// node.ops/last-immutable-job-heal stamp on the Kustomization.
package helmreleaseunlocker

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-node-automation/apps/node-automation-controller/internal/shared"
)

const (
	// W8-GO1 — a Flux Kustomization Ready=False >=15m on an
	// immutable-Job apply error gets the completed/failed Job
	// deleted so kustomize-controller recreates it; the cooldown is
	// per-Kustomization (in-RAM + persisted annotation).
	immutableJobMinAge   = 15 * time.Minute
	immutableJobCooldown = 30 * time.Minute
	immutableJobHealAnno = "node.ops/last-immutable-job-heal"
)

// immutableJobRe extracts the Job name out of the kustomize apply
// error `Job.batch "<name>" is invalid: ... field is immutable`.
var immutableJobRe = regexp.MustCompile(`Job\.batch "([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)" is invalid`)

// healImmutableJobs scans Kustomizations for Ready=False >=15m whose
// message is the immutable-Job apply error: a Job manifest changed an
// immutable field (spec.template), so apply fails forever until the
// OLD Job object disappears — and a Job that already ran to Complete
// or Failed is pure residue. Deleting it unblocks the apply. The
// 30m cooldown rides the in-RAM ledger + the persisted
// node.ops/last-immutable-job-heal stamp on the Kustomization.
func (u *helmReleaseUnlocker) healImmutableJobs(ctx context.Context) error {
	log := logf.FromContext(ctx)
	kustomizations, err := u.listAllPages(ctx, u.dyn.Resource(fluxKustomizationGVR))
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil // pre-v1 flux — nothing to scan
		}
		return fmt.Errorf("list kustomizations: %w", err)
	}
	now := time.Now()
	for i := range kustomizations.Items {
		k := &kustomizations.Items[i]
		if suspended, _ := shared.NestedBool(k.Object, "spec", "suspend"); suspended {
			continue
		}
		status, msg := shared.ReadyCond(k)
		if status != "False" || !strings.Contains(strings.ToLower(msg), "field is immutable") {
			continue
		}
		m := immutableJobRe.FindStringSubmatch(msg)
		if m == nil {
			continue
		}
		since, ok := shared.ReadySince(k)
		if !ok {
			since = k.GetCreationTimestamp().Time
		}
		if now.Sub(since) < immutableJobMinAge {
			continue
		}
		key := k.GetNamespace() + "/" + k.GetName()
		// Cooldown: wider of the in-RAM ledger and the persisted stamp.
		last := u.immutableJobHealed[key]
		if t, err := time.Parse(time.RFC3339,
			k.GetAnnotations()[immutableJobHealAnno]); err == nil && t.After(last) {
			last = t
		}
		if now.Sub(last) < immutableJobCooldown {
			u.immutableJobHealed[key] = last
			continue
		}
		// The Job lives where the manifests apply — spec.targetNamespace
		// wins, else the Kustomization's own namespace.
		jobNS := k.GetNamespace()
		if tns, _ := shared.NestedString(k.Object, "spec", "targetNamespace"); tns != "" {
			jobNS = tns
		}
		job, err := u.cs.BatchV1().Jobs(jobNS).Get(ctx, m[1], metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				continue // already gone — nothing to reap
			}
			metrics.IncError(helmUnlockQueue)
			log.Error(err, "immutable-job lookup failed", "kustomization", key, "job", jobNS+"/"+m[1])
			continue
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
		bg := metav1.DeletePropagationBackground
		if err := u.cs.BatchV1().Jobs(jobNS).Delete(ctx, job.Name,
			metav1.DeleteOptions{PropagationPolicy: &bg,
				Preconditions: &metav1.Preconditions{UID: &job.UID}}); err != nil {
			metrics.IncError(helmUnlockQueue)
			log.Error(err, "immutable job delete failed", "job", jobNS+"/"+job.Name)
			continue
		}
		// Persist the stamp — the durable half of the 30m cooldown.
		u.immutableJobHealed[key] = now
		payload, err := json.Marshal(map[string]any{
			"metadata": map[string]any{"annotations": map[string]string{
				immutableJobHealAnno: now.UTC().Format(time.RFC3339),
			}},
		})
		if err != nil {
			continue
		}
		if _, err := u.dyn.Resource(fluxKustomizationGVR).Namespace(k.GetNamespace()).
			Patch(ctx, k.GetName(), types.MergePatchType, payload, metav1.PatchOptions{}); err != nil {
			metrics.IncError(helmUnlockQueue)
			log.Error(err, "immutable-job heal stamp failed", "kustomization", key)
		}
	}
	return nil
}
