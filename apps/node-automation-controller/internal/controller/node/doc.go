// Package node groups the node-lifecycle and node-health modules:
// label re-assertion (node_labeler), kubelet "fake Ready" quarantine
// (kubelet_reaper), Terminating-pod force eviction on dead nodes
// (dead_node_sweeper), network-partition eviction (partition_evictor),
// PDB drain-deadlock detection (pdb_deadlock_watchdog), stale cilium
// taint reaping (cilium_taint_reaper), the descheduler storm gate
// (descheduler_storm_gate) and kubelet-serving CSR approval
// (csr_watcher).
package node
