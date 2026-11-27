// schedule_audit.go — the Schedule half of velero-backup-auditor:
// auditSchedules (the per-Schedule sweep loop + ledger lifecycle)
// over flagMissingBackups (zero-backup-guard — a Schedule older than
// veleroMissingBackupMaxAge that produced ZERO Backup objects is
// silently unprotected) and flagBadBackup (the latest schedule-owned
// Backup's empty/errored/wedged signatures on
// VeleroBackupEmptyOrErrored{namespace,schedule,reason}).
package velerobackupauditor

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/metrics"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/heal"
	"github.com/passiontech-global/kubernetes-cluster-automation/apps/node-automation-controller/internal/platform/kube"
)

// auditSchedules runs the two per-Schedule rot checks over the listed
// Schedules and owns their ledger lifecycle: the paused>24h clock
// (firstSeenPaused measures the real pause duration — a Schedule
// carries no "paused since" timestamp) and the latest-backup rot
// signature via flagBadBackup / flagMissingBackups. When retryEnabled
// is set, unpaused Schedules whose latest Backup failed are also
// evaluated for a guarded one-shot retry. The trailing prunes clear
// series whose condition resolved — an unpaused Schedule or a fresh
// healthy backup must not pin the gauge at 1.
func (a *veleroBackupAuditor) auditSchedules(ctx context.Context,
	latest map[string]*unstructured.Unstructured,
	activeSchedules map[string]bool,
	log logr.Logger) (bool, int, error) {
	pausedNow := map[string]bool{}
	bslCache := map[string]bool{}
	count := 0
	err := a.veleroListEach(ctx, veleroScheduleGVR,
		func(page []unstructured.Unstructured) error {
			for i := range page {
				s := &page[i]
				count++
				ns, name := s.GetNamespace(), s.GetName()

				// Check 1 — spec.paused held past 24h. A Schedule carries no
				// "paused since" timestamp, so firstSeenPaused measures the
				// real pause duration from first sight; an entry pruned on
				// unpause means a re-pause restarts the clock, and the UID in
				// the key keeps a delete+recreate from inheriting pause time.
				isPaused, _ := kube.NestedBool(s.Object, "spec", "paused")
				if isPaused {
					lk := pausedLedgerKey(string(s.GetUID()), ns, name)
					pausedNow[lk] = true
					first, _ := a.firstSeenPaused.Observe(lk, a.now.Now())
					k := pausedKey{ns, name}
					v := 0.0
					if pausedFor := a.now.Now().Sub(first); pausedFor > veleroPausedMinAge {
						v = 1
						log.Info("velero schedule paused >24h — backups silently stopped",
							"schedule", ns+"/"+name, "pausedFor", pausedFor.Truncate(time.Hour))
					}
					a.seenPaused.Set(metrics.VeleroSchedulePaused, v, k, ns, name)
				}

				// Check 2 — the latest schedule-owned Backup empty/errored.
				b := latest[ns+"/"+name]
				if b == nil {
					// zero-backup-guard — zero Backup objects is not "nothing to
					// judge" once the Schedule itself is old enough to have
					// produced some. A paused Schedule is exempt: it
					// legitimately stops producing (check 1 already covers
					// it).
					if !isPaused {
						a.flagMissingBackups(ctx, s, ns, name)
					}
					continue
				}
				a.flagBadBackup(ctx, s, b, ns, name)
				if a.retryEnabled && !isPaused {
					a.maybeRetryFailedBackup(ctx, s, b, ns, name, activeSchedules, bslCache, log)
				}
			}
			return nil
		})
	if kube.IsCRDAbsent(err) {
		return false, count, nil // no Velero installed — caller prunes + skips
	}
	if err != nil {
		return true, count, fmt.Errorf("list velero schedules: %w", err)
	}

	// Prune series whose condition resolved since the last sweep —
	// a schedule unpaused or a fresh healthy backup must clear the
	// gauge, not pin it at 1.
	a.seenPaused.Prune(metrics.VeleroSchedulePaused.DeleteLabelValues)
	// Drop first-seen entries for schedules that unpaused or vanished
	// — a later re-pause measures a fresh duration, not the
	// cumulative time it once spent paused.
	a.firstSeenPaused.Prune(func(lk string) bool { return pausedNow[lk] })
	a.seenBad.Prune(metrics.VeleroBackupEmptyOrErrored.DeleteLabelValues)
	return true, count, nil
}

// flagMissingBackups is the zero-backup-guard zero-backup check: a Schedule
// older than veleroMissingBackupMaxAge (36h) that has produced ZERO
// Backup objects is silently unprotected — the schedule fires, the
// backups vanish (or never ran), and every other check sees
// "nothing to judge". Flags reason=missing on the same
// VeleroBackupEmptyOrErrored series the other rot signatures use.
// A zero creationTimestamp cannot prove age — skipped (fail closed).
func (a *veleroBackupAuditor) flagMissingBackups(ctx context.Context,
	s *unstructured.Unstructured, ns, schedule string) {
	log := logf.FromContext(ctx)
	created := s.GetCreationTimestamp()
	if created.IsZero() {
		return
	}
	age := a.now.Now().Sub(created.Time)
	if age <= veleroMissingBackupMaxAge {
		return
	}
	a.seenBad.Set(metrics.VeleroBackupEmptyOrErrored, 1,
		backupKey{ns, schedule, "missing"}, ns, schedule, "missing")
	log.Info("velero schedule older than 36h has zero backups — silently unprotected",
		"schedule", ns+"/"+schedule, "age", age.Truncate(time.Hour))
}

// flagBadBackup evaluates the latest Backup's status against the
// rot signatures and marks the matching reason series. All of them
// gate on phase=Completed: the signatures mean "a successful backup
// that protected nothing" — errors/warnings on an in-flight or
// failed backup are partial counters, not rot. s is the owning
// Schedule — the stale check needs its cron to exempt weekly and
// monthly cadences whose >36h-old newest backup is normal, not rot.
func (a *veleroBackupAuditor) flagBadBackup(ctx context.Context,
	s, b *unstructured.Unstructured, ns, schedule string) {
	log := logf.FromContext(ctx)
	phase, _ := kube.NestedString(b.Object, "status", "phase")
	// velero-bsl-audit — terminal failures and wedged in-flight phases are
	// flagged on their own reason series before the Completed path
	// runs: Failed/PartiallyFailed/FailedValidation flag immediately,
	// InProgress/Deleting only past 6h (measured from
	// status.startTimestamp, else creationTimestamp).
	if reason, watched := veleroStuckPhases[phase]; watched {
		flag := reason == "failed"
		if reason == "stuck" {
			since := b.GetCreationTimestamp().Time
			if st, ok := kube.NestedString(
				b.Object, "status", "startTimestamp"); ok {
				if t, err := time.Parse(time.RFC3339, st); err == nil {
					since = t
				}
			}
			flag = a.now.Now().Sub(since) > veleroStuckMaxAge
		}
		if flag {
			a.seenBad.Set(metrics.VeleroBackupEmptyOrErrored, 1,
				backupKey{ns, schedule, reason}, ns, schedule, reason)
			log.Info("velero backup in a bad phase",
				"backup", b.GetNamespace()+"/"+b.GetName(),
				"schedule", ns+"/"+schedule, "phase", phase)
		}
		return
	}
	if phase != "Completed" {
		return
	}
	// Velero's BackupProgress carries itemsBackedUp/totalItems — there
	// is no totalBytes field (reading one always yields 0). Both reads
	// gate on `found`: a Completed backup with no progress block at
	// all (older Velero, stripped status) is "can't tell", not empty —
	// without the gate every absent-progress backup false-flags.
	items, itemsFound := kube.NestedInt64(
		b.Object, "status", "progress", "itemsBackedUp")
	total, totalFound := kube.NestedInt64(
		b.Object, "status", "progress", "totalItems")
	if (itemsFound && items == 0) || (totalFound && total == 0) {
		a.seenBad.Set(metrics.VeleroBackupEmptyOrErrored, 1,
			backupKey{ns, schedule, "zero_items"}, ns, schedule, "zero_items")
		log.Info("velero backup completed with zero items",
			"backup", b.GetNamespace()+"/"+b.GetName(), "schedule", ns+"/"+schedule)
	}
	if errs, _ := kube.NestedInt64(b.Object, "status", "errors"); errs > 0 {
		a.seenBad.Set(metrics.VeleroBackupEmptyOrErrored, 1,
			backupKey{ns, schedule, "errors"}, ns, schedule, "errors")
		log.Info("velero backup completed with item errors",
			"backup", b.GetNamespace()+"/"+b.GetName(), "schedule", ns+"/"+schedule,
			"errors", errs)
	}
	if warns, _ := kube.NestedInt64(b.Object, "status", "warnings"); warns > 0 {
		a.seenBad.Set(metrics.VeleroBackupEmptyOrErrored, 1,
			backupKey{ns, schedule, "warnings"}, ns, schedule, "warnings")
		log.Info("velero backup completed with item warnings",
			"backup", b.GetNamespace()+"/"+b.GetName(), "schedule", ns+"/"+schedule,
			"warnings", warns)
	}
	// selfheal-alert-coverage Schrödinger's-backup stale check: a Completed backup older
	// than veleroMissingBackupMaxAge on a daily-or-faster Schedule
	// means the schedule silently stopped producing fresh restore
	// points — every other check sees a healthy "Completed" phase.
	// Weekly/monthly cadences are exempt: their newest backup is
	// legitimately older than the horizon between runs.
	if !scheduleRunsWeeklyOrMonthly(s) {
		if done := veleroBackupDoneAt(b); !done.IsZero() &&
			a.now.Now().Sub(done) > veleroMissingBackupMaxAge {
			a.seenBad.Set(metrics.VeleroBackupEmptyOrErrored, 1,
				backupKey{ns, schedule, "stale"}, ns, schedule, "stale")
			log.Info("velero schedule's newest completed backup is stale — schedule may have stopped firing",
				"backup", b.GetNamespace()+"/"+b.GetName(),
				"schedule", ns+"/"+schedule,
				"age", a.now.Now().Sub(done).Truncate(time.Hour))
		}
	}
}

// veleroBackupDoneAt is the stale-check age clock: the moment the
// restorable point landed — status.completionTimestamp, falling
// back to status.startTimestamp (older Velero without a completion
// stamp) and finally creationTimestamp. Both status fields are
// RFC3339 strings on the unstructured Backup; an unparseable value
// falls through to the next source rather than reading as zero-age.
func veleroBackupDoneAt(b *unstructured.Unstructured) time.Time {
	return kube.NestedStatusTimeOrCreated(b, "completionTimestamp", "startTimestamp")
}

// scheduleRunsWeeklyOrMonthly reports whether the Schedule's cron
// restricts its runs to specific days — day-of-month (monthly) or
// day-of-week (weekly) fields other than "*". Such cadences
// legitimately hold a newest backup older than the 36h stale
// horizon between runs, so flagBadBackup exempts them. An
// unparseable or absent cron reads as NOT exempt — a Schedule we
// cannot prove is infrequent still gets the stale check.
func scheduleRunsWeeklyOrMonthly(s *unstructured.Unstructured) bool {
	cron, _ := kube.NestedString(s.Object, "spec", "schedule")
	cron = strings.TrimSpace(cron)
	// Macro cadences: the weekly-or-slower aliases exempt; the
	// daily-or-faster ones (@hourly/@daily/@reboot) do not.
	switch cron {
	case "@weekly", "@monthly", "@yearly", "@annually":
		return true
	}
	f := strings.Fields(cron)
	// 5-field cron (min hour dom mon dow) or 6-field with a
	// leading seconds field (sec min hour dom mon dow) — pick the
	// day-of-month / day-of-week slots for either shape.
	var dom, dow string
	switch len(f) {
	case 5:
		dom, dow = f[2], f[4]
	case 6:
		dom, dow = f[3], f[5]
	default:
		return false
	}
	// "?" is the Quartz "no specific value" marker — it reads
	// exactly like "*" for restriction purposes, so a schedule
	// like "0 0 ? * MON" is still weekly via its day-of-week.
	restricted := func(v string) bool { return v != "*" && v != "?" }
	return restricted(dom) || restricted(dow)
}

// isFailedBackupPhase reports whether phase is one of Velero's terminal
// failure phases eligible for automatic one-shot retry.
func isFailedBackupPhase(phase string) bool {
	return phase == "Failed" || phase == "PartiallyFailed" || phase == "FailedValidation"
}

// maybeRetryFailedBackup creates one replacement velero.io/v1 Backup when an
// unpaused Schedule's latest Backup failed, subject to five safety gates:
//  1. Target BSL (schedule.spec.template.storageLocation, default "default")
//     is currently phase=Available.
//  2. No Backup for this Schedule is currently InProgress / New /
//     WaitingForPluginOperations.
//  3. The Schedule has not already retried this exact Backup
//     (AnnoLastVeleroBackupRetry != latestBackup.Name).
//  4. Per-Schedule retry cooldown (>= RetryCooldown, default 2h) has elapsed.
//  5. Maintenance mutex + heal budget pass via heal.AllowedV.
func (a *veleroBackupAuditor) maybeRetryFailedBackup(ctx context.Context,
	s, latestBackup *unstructured.Unstructured, ns, schedule string,
	activeSchedules map[string]bool, bslCache map[string]bool, log logr.Logger) {

	phase, _ := kube.NestedString(latestBackup.Object, "status", "phase")
	if !isFailedBackupPhase(phase) {
		return
	}
	schedKey := ns + "/" + schedule
	if activeSchedules[schedKey] {
		log.V(1).Info("skip velero backup retry: schedule already has an active backup",
			"schedule", schedKey, "failedBackup", latestBackup.GetName())
		return
	}
	if s.GetAnnotations()[kube.AnnoLastVeleroBackupRetry] == latestBackup.GetName() {
		log.V(1).Info("skip velero backup retry: failed backup already retried",
			"schedule", schedKey, "failedBackup", latestBackup.GetName())
		return
	}
	bslName, _ := kube.NestedString(s.Object, "spec", "template", "storageLocation")
	if bslName == "" {
		bslName = "default"
	}
	if !a.isBSLAvailable(ctx, ns, bslName, bslCache, log) {
		log.Info("skip velero backup retry: target BSL not Available",
			"schedule", schedKey, "bsl", ns+"/"+bslName, "failedBackup", latestBackup.GetName())
		return
	}

	now := a.now.Now()
	cooldownKey := "backup-retry/" + schedKey
	proceed, unverifiable := heal.AllowedV(ctx, log, a.verdict, a.cs, a.dyn,
		&a.backupRetried, cooldownKey, a.backupRetryCooldown(), now)
	switch {
	case unverifiable:
		metrics.IncError(a.queue)
		return
	case !proceed:
		return
	}

	retryBackup := buildRetryBackup(s, latestBackup, ns, schedule, now)
	if _, err := a.dyn.Resource(veleroBackupGVR).Namespace(ns).Create(
		ctx, retryBackup, metav1.CreateOptions{}); err != nil {
		heal.RefundGrant(now)
		metrics.IncError(a.queue)
		log.Error(err, "failed to create retry velero backup",
			"schedule", schedKey, "failedBackup", latestBackup.GetName(),
			"retryBackup", retryBackup.GetName())
		return
	}
	a.backupRetried.Stamp(cooldownKey, now)

	patch, err := kube.MergePatchAnnos(map[string]any{
		kube.AnnoLastVeleroBackupRetry: latestBackup.GetName(),
	})
	if err != nil {
		metrics.IncError(a.queue)
		log.Error(err, "failed to encode velero schedule retry annotation patch",
			"schedule", schedKey)
		return
	}
	if _, err := a.dyn.Resource(veleroScheduleGVR).Namespace(ns).Patch(
		ctx, schedule, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		metrics.IncError(a.queue)
		log.Error(err, "failed to patch retry annotation on velero schedule",
			"schedule", schedKey, "failedBackup", latestBackup.GetName())
		return
	}
	log.Info("ACTION: auto-retried failed velero scheduled backup",
		"schedule", schedKey, "failedBackup", latestBackup.GetName(),
		"retryBackup", retryBackup.GetName(), "bsl", bslName)
}

// isBSLAvailable checks whether the named BackupStorageLocation in ns
// reports status.phase == "Available", memoized per sweep in bslCache.
// Any lookup failure or missing BSL fails closed (false).
func (a *veleroBackupAuditor) isBSLAvailable(ctx context.Context,
	ns, name string, cache map[string]bool, log logr.Logger) bool {
	key := ns + "/" + name
	if avail, ok := cache[key]; ok {
		return avail
	}
	bsl, err := a.dyn.Resource(veleroBSLGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		log.V(1).Info("velero BSL lookup failed — treating as unavailable",
			"bsl", key, "error", err)
		cache[key] = false
		return false
	}
	phase, _ := kube.NestedString(bsl.Object, "status", "phase")
	avail := phase == "Available"
	cache[key] = avail
	return avail
}

// veleroRetryBackupName constructs a DNS-1123 safe backup name of the form
// "<schedule>-retry-<unix>" bounded to <= 63 characters.
func veleroRetryBackupName(schedule string, now time.Time) string {
	const maxLen = 63
	suffix := fmt.Sprintf("-retry-%d", now.Unix())
	maxPrefix := maxLen - len(suffix)
	prefix := schedule
	if len(prefix) > maxPrefix {
		prefix = strings.TrimRight(prefix[:maxPrefix], "-.")
	}
	if prefix == "" {
		prefix = "velero"
	}
	return prefix + suffix
}

// truncateDNSLabel trims a Kubernetes label value to <= 63 chars with valid
// trailing alphanumeric characters.
func truncateDNSLabel(v string) string {
	const maxLen = 63
	if len(v) <= maxLen {
		return v
	}
	return strings.TrimRight(v[:maxLen], "-._")
}

// buildRetryBackup constructs the unstructured velero.io/v1 Backup for a
// failed-backup retry, copying spec from schedule.spec.template and stamping
// velero.io/schedule-name + passiontech.dev/retry-of labels.
func buildRetryBackup(scheduleObj, failedBackup *unstructured.Unstructured,
	ns, schedule string, now time.Time) *unstructured.Unstructured {
	labels := map[string]string{}
	if tplMeta, ok, _ := unstructured.NestedStringMap(
		scheduleObj.Object, "spec", "template", "metadata", "labels"); ok {
		for k, v := range tplMeta {
			labels[k] = v
		}
	}
	labels[veleroScheduleLabel] = schedule
	labels[kube.LabelVeleroRetryOf] = truncateDNSLabel(failedBackup.GetName())

	specCopy := map[string]any{}
	if rawTpl, found, _ := unstructured.NestedMap(scheduleObj.Object, "spec", "template"); found && rawTpl != nil {
		if copied, ok := runtime.DeepCopyJSONValue(rawTpl).(map[string]any); ok {
			specCopy = copied
		}
	}

	u := &unstructured.Unstructured{
		Object: map[string]any{
			"apiVersion": veleroBackupGVR.GroupVersion().String(),
			"kind":       "Backup",
			"metadata": map[string]any{
				"name":      veleroRetryBackupName(schedule, now),
				"namespace": ns,
			},
			"spec": specCopy,
		},
	}
	u.SetLabels(labels)
	return u
}
