// Package clusterhealthprobes is the cluster-health sweep module
// root: Setup and the prober. The checks it drives — the in-process
// ports of the kuberhealthy "passive" HealthChecks plus the
// self-healing watchdog checks — live in per-domain subpackages
// under internal/health on top of the shared probefw framework; the
// sweep-order roster itself is the health section's CheckReg rows
// in internal/registry, collected here via Deps.CheckRegs.
package clusterhealthprobes
