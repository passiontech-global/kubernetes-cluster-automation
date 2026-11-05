# node-host-agent

Per-node agent (DaemonSet) for the kubernetes-node-automation stack.

Per-node agent (DaemonSet, or standalone systemd binary on API LB
VMs / control-plane nodes — `NODE_HOST_AGENT_HOST_ROOT=/`). Subsystems
(env-gated `NODE_HOST_AGENT_ENABLE_*`):

- `sweeper` — openebs orphan `pvc-*` dir cleanup + PV GC.
- `concourse-cache` — native pruner for
  `/var/openebs/local/pvc-*/shared-cache` every 15m (replaces the old
  CronJob + `pods/exec` janitor).
- `janitor` — reaper for stale `state-*` watchdog latches, legacy ghost
  systemd units, and orphan ip-monitor artifacts.
- `apiprober` — apiserver watch-cache wedge guard; drains/enables
  HAProxy `api-local-lb` servers over the admin socket, multi-backend
  (`CompanionBackends` + `API_BACKENDS` static config).
- `hostmetrics` — scrape-time collector: watchdog `state-*` latches,
  PSI/`node-overloaded`, cpu-delivered, fail2ban, nebula, k0s drift,
  clock/conntrack/inode/filefd/sockstat, **H8** inotify instances +
  watches used-ratio (`node_host_agent_inotify_instances_used_ratio`,
  `node_host_agent_inotify_watches_used_ratio`, top-3 consumer PIDs
  logged >80%), zombie count (`node_host_agent_processes_zombie_count`),
  cgroup pids ratio (`node_host_agent_cgroup_pids_used_ratio` for
  `k0sworker`/`k0scontroller`/`kubepods` slices), on-disk PKI expiry
  (`node_host_agent_pki_cert_days_left{path}` for `/var/lib/k0s/pki`,
  `/var/lib/k0s/pki/etcd`, `/var/lib/k0s/kubelet/pki/kubelet-client-current.pem`,
  `/etc/kine/pki`), and MTU drift
  (`node_host_agent_mtu_drift` — `cilium_net` vs `neb1`). All
  descriptors are also registered for the standalone textfile
  (`*.prom`) mode used on VM-only targets.
- `workerhygiene` — worker watchdog checks (pod-teardown, konnectivity
  drift, kubelet stall/watch-wedge, ctr tasks, cilium health +
  init-stuck) plus: kubelet `/healthz/syncloop` PLEG probe and
  `containerd.sock` ping (`state-kubelet-syncloop-down`,
  `state-containerd-sock-down`), `39-ctr-ingest-gc` stale ingest GC
  (`mtime >3h`, triggered at >75% `/var/lib/k0s` or every 6h,
  `node_host_agent_workerhygiene_ctr_ingests_cleaned_total`),
  `journald-integrity` auto-rotate (`journalctl --rotate
--vacuum-time=3d` on corrupt/empty journal while the unit is
  active), zombie-storm detection (>500 `<defunct>` per container for
  ≥2 cycles → `ZombieProcessStorm` K8s Event with the pod UID),
  `cilium-envoy` readiness (`127.0.0.1:9964/ready`, ≥2 bad cycles or a
  `cilium-agent` SIGKILL → `SIGKILL` `cilium-envoy`,
  `state-cilium-envoy-down`), `/run/cilium/cilium.sock` datapath
  health, and MTU drift checks (`state-cilium-mtu-drift` →
  `CiliumMTUExceedsOverlay` event).
- `nethealth` — DNS fallback (managed `/etc/hosts` block),
  coredns-stub, overlay egress relays, nebula health, fail2ban,
  clock-sync, conntrack pressure; flushes stale Nebula UDP `:45670`
  conntrack **per affected peer IP** (`conntrack -D -p udp -d
<peerIP>`) when a peer is isolated or switched relays.
- `nodereporter` — syncs `state-*` latches to the permanent
  `NodeCondition`s + K8s Events + `problem_gauge`/`problem_counter`
  (replaces the NPD watchdog-state/filelog monitors); filelog rules
  include the new `ZombieProcessStorm` and `CiliumMTUExceedsOverlay`
  reasons.
- `controllerhygiene` (`auto` when `k0scontroller.service` exists) —
  apiserver wedge + kine TTL/pool guards, OOM-loop shield, sd_notify
  watchdog feeder.
- `kinedb` — kine wire/auth/pool/horizon probes, advisory-lock
  compact-guard, daily reindex/repack.
- `hostconfig` (`auto` when the vars dir holds `defaults.yaml`) —
  declarative host converger (17 groups: sysctl, systemd drop-ins,
  resolved DNS, nftables, nebula mesh, coredns stub, api-local-lb,
  fail2ban, sshd, etcdctl…) replacing the ansible `node-config-agent`
  DaemonSet + `hub-converge` CronJob. A clean cycle updates
  `node_host_agent_hostconfig_last_success_seconds` +
  `node_host_agent_hostconfig_cycles_total{result="ok"}`; `converge-once`
  exits `1` when any group errors (`CycleWithErrors`).
- `hubsync` (pod mode, when the converge SSH key is mounted) — SSH
  converge of the standalone targets (controller VMs, DB VMs, API-LB
  VMs: binary mirror, systemd unit, config push, restart) behind a
  `coordination.k8s.io` Lease (`node-ops/node-host-agent-hubsync`) so
  only one replica converges at a time. Metrics:
  `node_host_agent_hubsync_target_up{target}`,
  `node_host_agent_hubsync_last_success_seconds`,
  `node_host_agent_hubsync_cycles_total`.

Interface contract: `:9115/metrics`, `:8081/healthz|readyz` (the
DaemonSet passes `--health-probe-bind-address=:8091` to avoid a
`hostNetwork` clash with `liqo-fabric`), `--version`, node identity
via downward API (`NODE_NAME`, `POD_NAME`, `POD_NAMESPACE`). The kube
client is built lazily — only when a subsystem that needs it
(sweeper, workerhygiene, nodereporter, hubsync) is enabled, so the
standalone binary runs without one.
