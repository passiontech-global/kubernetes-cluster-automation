// Package unmeshed is the unmeshed-pod auditor — one of the independent
// duties behind the admission-webhook-guard sweep: it exports
// node_automation_unmeshed_pods{namespace,pod} for every Running pod
// that opted into linkerd injection but carries no linkerd-proxy
// sidecar (the signature of a pod admitted while the C1 breaker held
// the injector open) and — once the injector is provably healthy again
// (guardstate.InjectorHealthy) — evicts a bounded number of unmeshed
// pods so their owner controller recreates them meshed. Its state (the
// emitted-series ledger) lives on Auditor; shared deps and the run
// snapshot come from guardstate. The critical-namespace audits moved
// to the criticalns subpackage.
package unmeshed
