// Package janitor groups the resource-cleanup sweep modules: evicted
// pod GC (evicted_pod_janitor), stale failed Job deletion plus the
// stuck-Terminating namespace/PVC auditor (failed_jobs_janitor),
// missed-schedule CronJob catch-up (cronjob_catchup), the Concourse
// workdir/worker janitor (concourse_janitor + its minimal ATC client)
// and the orphaned VolumeAttachment reaper (volumeattachment_cleaner).
package janitor
