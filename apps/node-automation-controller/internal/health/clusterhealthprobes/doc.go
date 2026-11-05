// Package clusterhealthprobes is the cluster-health sweep module
// root: Setup, the prober and the checkDefs registry. The checks it
// drives — the in-process ports of the kuberhealthy "passive"
// HealthChecks plus the self-healing watchdog checks — live in
// per-domain subpackages under internal/health on top of the shared
// probefw framework.
package clusterhealthprobes
