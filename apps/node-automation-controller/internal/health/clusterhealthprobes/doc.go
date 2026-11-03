// Package clusterhealthprobes is the in-process port of the kuberhealthy
// "passive" HealthChecks: periodic DNS, apiserver-endpoint and pod-DNS
// probes reporting on the same metric series the checker Pods used to
// emit.
package clusterhealthprobes
