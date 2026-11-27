// Package connectionskew implements the workload-connection-skew-guard health
// check: detects sustained L4 network byte-rate skew across Ready pods of a
// Deployment (matching the WorkloadConnectionSkewDetected recording rule) and,
// for allowlisted Deployments, deletes the single hottest Ready pod behind
// SafePodDelete so long-lived L4 tunnels rebalance cleanly.
package connectionskew
