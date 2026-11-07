// runtime_common.go — the W10 host runtime-resource hygiene guard
// family overview: the things a node can be silently dying of while
// every healthz is still green. One file per guard
// (runtime_<name>.go); there is deliberately no shared helper layer
// — every guard owns its own constants, parsers and evidence reads.
// All series land in the node_agent_* textfile family via the
// shared deps counters/gauges (WriteNodeAgentPromTextfile); all
// remedies are cooldown-budgeted.
//
//   - cgroup-dying-reclaim    — runtime_cgroup_dying.go: cgroup v2
//     nr_dying_descendants piling up pins page cache/dentries inside
//     cgroups the kernel already deleted (the dying-cgroup leak
//     behind phantom memory pressure + slow cgroup walks):
//     drop_caches + memory.reclaim on a 30m budget,
//     state-cgroup-dying-leak latch.
//   - systemd-session-hygiene — runtime_systemd_sessions.go:
//     abandoned logind sessions (ssh drops, cron remnants) pile up
//     and every loginctl/D-Bus call walks the whole list (D-Bus
//     stalls → systemctl/kubelet calls time out): terminate stale
//     sessions + reset-failed on a 30m budget,
//     state-systemd-session-bloat latch.
//   - overlayfs-stale-mount   — runtime_overlayfs_stale.go: pods
//     stuck Waiting/Failed on ESTALE/missing-lowerdir overlay errors
//     never heal by retrying: the corrupt layer is removed via
//     Ctr.RmImage so the next pull re-fetches (15m shared
//     last-ctr-image-rm budget).
//   - io-pressure-throttler   — runtime_io_pressure.go: disk
//     io_ticks util, write await and PSI io full avgs exported every
//     cycle; above the pressure bar the known background IO hogs
//     (backup/scan agents) get renice +19 + ionice idle so
//     latency-critical work wins the disk.
//   - conntrack-tcp-liberal-guard — runtime_conntrack_liberal.go: on
//     neb1 nodes (asymmetric overlay routing marks in-window ACK/RST
//     INVALID → silent drops) nf_conntrack_tcp_be_liberal must be 1.
//   - clock-jump-session-healer — runtime_clock_jump.go: a
//     wall-clock step (NTP slew, RTC catch-up) strands every
//     cached-token client: when a fresh clock-stepped-at marker
//     exists and konnectivity-agent logs 401/x509, recreate its pod
//     on a 30m budget.
package runtime
