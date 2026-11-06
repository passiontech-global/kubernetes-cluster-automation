// Package unmeshed is the unmeshed-pod auditor — one of the four
// independent duties behind the admission-webhook-guard sweep: it
// exports node_automation_unmeshed_pods{namespace,pod} for every
// Running pod that opted into linkerd injection but carries no
// linkerd-proxy sidecar (the signature of a pod admitted while the
// C1 breaker held the injector open), audits fail-closed webhooks
// whose namespaceSelector still matches the critical self-healing
// namespaces, and — once the injector is provably healthy again —
// evicts a bounded number of unmeshed pods so their owner controller
// recreates them meshed. Its state (the emitted-series ledgers)
// lives on Auditor; shared deps and the run snapshot come from
// guardstate.
package unmeshed
