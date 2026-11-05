// Package shared holds the machinery every node-automation module
// (the sibling module packages under internal/<domain>/) is built on —
// ported 1:1 from the shell-operator bash hooks in passiontech-fluxcd
// (infrastructure/base/node-ops/node-ops-operator/hooks/*.sh).
//
// Contract shared by every module:
//   - Reads go through the kubernetes.Interface clientset (cs) — the
//     operator's RBAC intentionally has NO watch verb on most types
//     (pods, services, jobs, webhookconfigs, ...), so a cached client
//     would deadlock the informer. Only types with an explicit
//     informer (Node, DaemonSet/konnectivity-agent, Deployments and
//     k8s-app=cilium Pods in kube-system, Secret/passiontech-pipeline)
//     may be watched.
//   - `name` everywhere is the legacy shell-operator queue name so
//     metrics.IncError(name) keeps the alert contract.
//   - Error-metric ownership: Periodic.Start IncErrors the queue for
//     any error fn RETURNS, so a module must never IncError an error
//     it returns — that double-counts. IncError inside a module is
//     reserved for tolerated sub-operation failures the run absorbs
//     (logs, continues, and ultimately returns nil) — without it
//     those failures would go uncounted.
//   - Periodic modules register through AddPeriodic; event-driven
//     modules register a reconciler and use Result.RequeueAfter as the
//     old crontab safety-net.
//
// The old helpers.go grab-bag is split by concern: periodic.go
// (schedule runnable + sweep fan-in), node.go (taints/conditions/
// labels + ListNodes), pods.go (DaemonSet/pod checks), replicas.go
// (CPA replica math), maintenance.go (cluster maintenance mutex).
package shared
