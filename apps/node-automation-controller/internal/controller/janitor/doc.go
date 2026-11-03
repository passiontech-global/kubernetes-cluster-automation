// Package janitor groups the resource-cleanup sweep modules: evicted
// pod GC (evicted_pod_janitor), stale failed Job deletion
// (failed_jobs_janitor), missed-schedule CronJob catch-up
// (cronjob_catchup) and the Concourse workdir/worker janitor
// (concourse_janitor + its minimal ATC client).
package janitor
