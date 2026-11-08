// Package deadnodesweeper is the dead-node-sweeper module: force-evicts
// Terminating pods and cleans up after nodes confirmed dead (kubelet
// probe plus remediation CRs).
//
// dead-node-sweeper — port of hooks/90-dead-node-sweeper.sh.
//
// Force-evicts pods stuck in Terminating on a dead node. A pod whose
// kubelet stopped answering stays "Terminating" forever (grace-period
// timers run on the kubelet, not the apiserver): PVCs stay attached,
// Deployments/StatefulSets can't reschedule, and `kubectl delete pod
// --force` is a foot-gun because it can produce two writers on one
// volume if the node is only partitioned (incident 2026-11-02: 40+
// Terminating pods on a power-failed worker, DBs pending for hours).
//
// The fix is NOT force-delete — it is the out-of-service taint
// (node.kubernetes.io/out-of-service=nodeshutdown:NoExecute). On that
// taint the node-controller itself force-deletes the node's pods and
// the attach-detach controller force-detaches its volumes — the same
// code path kubectl-node-shell / medik8s SNR use, so failover is
// atomic with no split-brain window.
//
// SAFETY — fail closed, always. The taint is applied only when there
// is independent evidence the node is fenced:
//
//	(a) a medik8s remediation CR exists for the node
//	    (selfnoderemediations.self-node-remediation.medik8s.io or
//	    fenceagentsremediations.fence-agents-remediation.medik8s.io, any namespace,
//	    named after the node) — a fencer already declared it dead; or
//	(b) Ready=Unknown for >30m AND the kubelet /healthz probe through
//	    the apiserver proxy fails — kubelet is unreachable AND the
//	    node-controller gave up on its lease long ago.
//
// The split-brain gate hardens branch (b) further: that evidence is one-sided
// (we cannot hear the node — the node may not hear US), so a node
// holding an RWO VolumeAttachment or a StatefulSet pod is NOT
// tainted. The out-of-service taint on a partitioned-but-alive node
// is a split-brain on its volumes. The skip is exported as
// node_automation_dead_node_unfenced_stateful_skipped; fencing such a
// node requires a medik8s CR or the explicit
// DEAD_NODE_SWEEPER_FENCE_UNFENCED_STATEFUL=true override, and every
// fence applied without a CR is counted by
// node_automation_dead_node_fenced_without_snr_total.
//
// A node that is merely NotReady (Ready=False) with no remediation CR
// and a fresh-enough heartbeat window is left alone — that is the
// host-watchdog / NHC layer's job. Pods on Ready nodes are skipped
// entirely. At most one node is tainted per cycle, so even a wrong
// verdict bounds the blast radius. Pods are never deleted directly.
//
// Recovery: a node that comes back Ready=True while still carrying
// the out-of-service taint gets untainted so it rejoins scheduling.
package deadnodesweeper
