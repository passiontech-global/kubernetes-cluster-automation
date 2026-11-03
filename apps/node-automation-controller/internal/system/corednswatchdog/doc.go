// Package corednswatchdog is the coredns-stale-watchdog module: detects
// a stale CoreDNS serving path (log signals, DNS probe, panic counts)
// and recovers it by rolling the Deployment.
package corednswatchdog
