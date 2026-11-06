// failed_jobs_janitor.go — the facade: module doc, shared struct,
// Setup and the run() coordinator for the three duties that ride the
// single hourly tick (was crontab 17 * * * *):
//
//   - failed_job_reap.go  — port of hooks/80-failed-jobs-janitor.sh:
//     deletes Jobs stuck in Failed=True for >24h. CronJob
//     failedJobsHistoryLimit only keeps the N most recent failures —
//     manual jobs and jobs that failed before the limit existed linger
//     forever, wasting storage and cluttering `kubectl get jobs`
//     (nonprod 2026-09-22).
//   - buildrun_reap.go    — W9-GO2: Shipwright BuildRun TTL sweep,
//     same 24h retention horizon.
//   - stuck_terminating.go — C3b: detect-only auditor for Namespaces,
//     PVCs and VolumeAttachments wedged in Terminating past 2h, plus
//     the W4 pvc-protection unstick.
//
// The duties are independent — a failure in one is joined into the
// run error without skipping the others (the failed-Job sweep still
// returns first: its list error historically aborted the whole run
// and that contract is kept).
package failedjobsjanitor

import (
	"context"
	"errors"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/state"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/shared"
)

// stuckTerminatingKey identifies one emitted
// StuckTerminatingResources series — the label triple needed to
// delete it again once the resource finishes terminating.
type stuckTerminatingKey struct {
	kind, ns, name string
}

type failedJobsJanitor struct {
	cs kubernetes.Interface
	// dyn reads/writes CRDs (Shipwright BuildRuns, W9-GO2) — nil
	// disables the BuildRun sweep only; every typed sweep is
	// unaffected. main.go always wires the manager's dynamic client.
	dyn dynamic.Interface
	// queue is the module's ops name — stamped from Deps.Name (the
	// registry row) so the periodic's name and every IncError label
	// come from one place.
	queue string
	// now is the clock seam — tests pin it to a fixed instant.
	now shared.Clock
	// stuckEmitted: the kind/ns/name triples the audit marked on the
	// previous sweep. A resource that finished terminating (or
	// vanished) gets its series deleted so /metrics never leaks a
	// stale "stuck" series.
	stuckEmitted state.GaugeLedger[stuckTerminatingKey]
}

// Setup registers the hourly sweep (was crontab 17 * * * *). d.Dyn
// carries the dynamic client the W9-GO2 BuildRun TTL sweep needs —
// pass nil only in tests that never exercise it.
func Setup(d shared.Deps) error {
	j := &failedJobsJanitor{
		cs:    d.CS,
		dyn:   d.Dyn,
		queue: d.Name,
		now:   shared.SystemClock,
	}
	return shared.AddPeriodic(d.Mgr, j.queue, 60*time.Minute, j.run)
}

func (j *failedJobsJanitor) run(ctx context.Context) error {
	// The failed-Job sweep historically aborted the run on a list
	// error — keep that contract (a flap on the typed list skips the
	// other duties rather than half-populating their ledgers).
	if err := j.sweepFailedJobs(ctx); err != nil {
		return err
	}
	// C3b audit rides the same hourly tick — detect-only, it shares
	// neither the job list nor the delete cap. W9-GO2's BuildRun TTL
	// sweep joins it: both are cluster-wide retention hygiene.
	return errors.Join(j.sweepBuildRuns(ctx), j.auditStuckTerminating(ctx))
}
