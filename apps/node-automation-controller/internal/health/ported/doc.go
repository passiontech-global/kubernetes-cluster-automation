// Package ported holds the five in-process ports of the kuberhealthy
// "passive" HealthChecks that used to run as periodic checker Pods in
// the kuberhealthy namespace (infrastructure/base/kuberhealthy/checks/
// in passiontech-fluxcd): dns-status-internal, http-content-check,
// pod-restarts, pod-status-check and resource-quota-check. The sixth
// check in that dir, cronjob-checker, is deliberately NOT ported —
// cronjob-catchup already sweeps CronJobs cluster-wide. Each check
// reports on the same kuberhealthy_check series under its original
// HealthCheck name.
package ported
