// converge-trigger — port of hooks/90-converge-trigger.sh.
//
// When a ConfigMap mounted by the converge CronJobs changes (Flux just
// rolled out a commit), clone the matching CronJob into a Job at once
// instead of waiting for the 6h schedule.
//
//	node-config-vars* / node-config-playbooks* / node-watchdog-scripts*
//	    -> ALL of hub-converge, nebula-hub-converge,
//	       controller-watchdog-converge, api-lb-guard-converge
//	api-lb-guard-files* -> api-lb-guard-converge only
//	other CMs           -> ignored
//
// Dedupe: skip a CronJob when a <cj>-trigger-* Job is still Active or
// younger than 120s. Converge jobs are idempotent — over-trigger is
// safe, missed trigger is not.
package controller

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/event"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/passiontech-global/node-automation-controller/internal/metrics"
)

// allConvergeCronJobs is the "all" target set from the bash mapping.
var allConvergeCronJobs = []string{
	"hub-converge",
	"nebula-hub-converge",
	"controller-watchdog-converge",
	"api-lb-guard-converge",
}

const (
	convergeNS        = "node-ops"
	convergeSettle    = 15 * time.Second  // bash `sleep 15`
	convergeDedupeWin = 120 * time.Second // bash DEDUPE_S
)

type convergeTrigger struct {
	cs kubernetes.Interface
	// pending debounces CM events: a fresh event arms the key and
	// requeues; when the requeue fires (~settle later) the whole set is
	// drained, so one Flux commit touching several CMs triggers once.
	mu      sync.Mutex
	pending map[string]struct{}
}

// SetupConvergeTrigger wires the converge-trigger reconciler. The
// informer is already scoped to namespace node-ops.
func SetupConvergeTrigger(mgr ctrl.Manager, cs kubernetes.Interface) error {
	r := &convergeTrigger{cs: cs, pending: map[string]struct{}{}}
	return ctrl.NewControllerManagedBy(mgr).
		Named("converge-trigger").
		For(&corev1.ConfigMap{}, builder.WithPredicates(convergePredicates(time.Now()))).
		Complete(r)
}

// convergePredicates is the bash binding translated: initial-sync
// creates never fire (executeHookOnSynchronization:false) but creates
// of genuinely new objects DO — the converge CMs are hash-suffixed
// (disableNameSuffixHash: false), so every Flux change is a create of
// a new CM + prune of the old, never an update. A create event is a
// real create only when the object's creationTimestamp postdates
// `startup`; the informer's initial list is older and gets skipped,
// which is what keeps a pod restart from spawning 4 SSH converge Jobs.
func convergePredicates(startup time.Time) predicate.Funcs {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return e.Object != nil &&
				e.Object.GetCreationTimestamp().After(startup)
		},
		DeleteFunc:  func(event.DeleteEvent) bool { return false },
		GenericFunc: func(event.GenericEvent) bool { return false },
		UpdateFunc: func(e event.UpdateEvent) bool {
			if e.ObjectOld == nil || e.ObjectNew == nil {
				return false
			}
			return e.ObjectNew.GetResourceVersion() != e.ObjectOld.GetResourceVersion()
		},
	}
}

func (r *convergeTrigger) Reconcile(ctx context.Context, req reconcile.Request) (ctrl.Result, error) {
	r.mu.Lock()
	if _, armed := r.pending[req.Name]; !armed {
		// Fresh CM event — arm the debounce. Flux applies the new CM
		// hash + CronJob spec rewrite near-atomically, but the CM event
		// can beat the spec update; the settle window keeps the cloned
		// Job from mounting the old hash (bash `sleep 15`).
		r.pending[req.Name] = struct{}{}
		r.mu.Unlock()
		return ctrl.Result{RequeueAfter: convergeSettle}, nil
	}
	// Settle timer fired — drain every CM queued since the last run.
	names := make([]string, 0, len(r.pending))
	for n := range r.pending {
		names = append(names, n)
	}
	clear(r.pending)
	r.mu.Unlock()

	if len(names) == 0 {
		return ctrl.Result{}, nil
	}
	log := logf.FromContext(ctx)

	// Union the target CronJobs across all drained CM events.
	cjs := map[string]struct{}{}
	for _, cm := range names {
		switch {
		case strings.HasPrefix(cm, "node-config-vars"),
			strings.HasPrefix(cm, "node-config-playbooks"),
			strings.HasPrefix(cm, "node-watchdog-scripts"):
			for _, c := range allConvergeCronJobs {
				cjs[c] = struct{}{}
			}
		case strings.HasPrefix(cm, "api-lb-guard-files"):
			cjs["api-lb-guard-converge"] = struct{}{}
		default:
			log.Info("skip event: not a converge ConfigMap", "configmap", cm)
		}
	}
	targets := slices.Sorted(maps.Keys(cjs))
	if len(targets) == 0 {
		return ctrl.Result{}, nil
	}
	log.Info("trigger set", "configmaps", names, "cronjobs", targets)

	now := time.Now().Unix() // shared suffix, like bash `now=$(date +%s)`
	failed := false
	for _, cjName := range targets {
		if !r.trigger(ctx, log, cjName, now) {
			failed = true
		}
	}
	if failed {
		// bash exited rc=1 → shell-operator retried the binding; a
		// missed trigger is unsafe (idempotent job anyway). Re-arm one
		// drained name so a settle pass retries — dedupe still blocks
		// the cronjobs that already succeeded.
		r.mu.Lock()
		r.pending[names[0]] = struct{}{}
		r.mu.Unlock()
		return ctrl.Result{RequeueAfter: convergeSettle}, nil
	}
	return ctrl.Result{}, nil
}

// trigger clones one CronJob into a Job unless deduped. Errors are
// logged/metered, not returned — bash tried every CronJob even after
// a failure. The bool reports only a job-CREATE failure so the caller
// can re-arm the debounce for a bounded retry.
func (r *convergeTrigger) trigger(ctx context.Context, log logr.Logger, cjName string, now int64) bool {
	cj, err := r.cs.BatchV1().CronJobs(convergeNS).Get(ctx, cjName, metav1.GetOptions{})
	if err != nil {
		// bash skips on ANY get failure — absent on this cluster or an
		// API blip, either way nothing to clone.
		log.Info("skip: cronjob does not exist on this cluster", "cronjob", cjName, "error", err)
		return true
	}

	// Dedupe: an Active or <120s-old <cj>-trigger-* Job means a trigger
	// already fired. List ALL jobs and filter by name prefix — the
	// created-by label is set post-create, so a selector could miss a
	// job inside the race (bash comment).
	jobs, err := r.cs.BatchV1().Jobs(convergeNS).List(ctx, metav1.ListOptions{})
	if err != nil {
		// bash `2>/dev/null`: list failure = empty dedupe list, still create.
		log.Info("WARN: list jobs failed — skipping dedupe", "cronjob", cjName, "error", err)
	} else {
		for i := range jobs.Items {
			j := &jobs.Items[i]
			if !strings.HasPrefix(j.Name, cjName+"-trigger-") {
				continue
			}
			if j.Status.Active > 0 {
				log.Info("skip: a trigger is already running", "cronjob", cjName, "job", j.Name)
				return true
			}
			if age := time.Since(j.CreationTimestamp.Time); age < convergeDedupeWin {
				log.Info("skip: a trigger was just created", "cronjob", cjName,
					"job", j.Name, "age", age.Round(time.Second))
				return true
			}
		}
	}

	// `kubectl create job --from=cronjob/<cj>` equivalent: clone the
	// JobTemplate metadata + spec, then stamp the created-by label
	// (bash: `kubectl label ... --overwrite` right after create).
	labels := maps.Clone(cj.Spec.JobTemplate.Labels)
	if labels == nil {
		labels = map[string]string{}
	}
	labels["app.kubernetes.io/created-by"] = "node-ops-operator"
	annotations := maps.Clone(cj.Spec.JobTemplate.Annotations)
	if annotations == nil {
		annotations = map[string]string{}
	}
	// kubectl create job --from=cronjob stamps this; keep the audit
	// trail identical.
	annotations["cronjob.kubernetes.io/instantiate"] = "manual"
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf("%s-trigger-%d", cj.Name, now),
			Namespace:   convergeNS,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: *cj.Spec.JobTemplate.Spec.DeepCopy(),
	}
	if _, err := r.cs.BatchV1().Jobs(convergeNS).Create(ctx, job, metav1.CreateOptions{}); err != nil {
		metrics.IncError("converge-trigger")
		log.Error(err, "ERR: create trigger job failed", "cronjob", cjName)
		return false
	}
	log.Info("TRIGGER job", "job", job.Name, "cronjob", cjName)
	return true
}
