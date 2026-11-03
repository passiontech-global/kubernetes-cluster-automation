# kubernetes-node-automation

[Moon](https://moonrepo.dev) monorepo for node lifecycle automation on
Kubernetes. Formerly `node-automation-controller` — the operator is now
one app in this workspace, alongside the per-node host agent.

## Apps

| App                               | Moon project                 | Kind                                                  | Image                                                   |
| --------------------------------- | ---------------------------- | ----------------------------------------------------- | ------------------------------------------------------- |
| `apps/node-automation-controller` | `node-automation-controller` | Deployment (controller-runtime operator)              | `ghcr.io/passiontech-global/node-automation-controller` |
| `apps/node-host-agent`            | `node-host-agent`            | DaemonSet (per-node agent)                            | `ghcr.io/passiontech-global/node-host-agent`            |
| `apps/webhook-dispatcher`         | `webhook-dispatcher`         | Deployment (GitHub webhook → Concourse check fan-out) | `ghcr.io/passiontech-global/webhook-dispatcher`         |

### node-automation-controller

Lightweight Go operator (`sigs.k8s.io/controller-runtime`) that replaces
the `shell-operator` Deployment + 10 bash hooks previously deployed at
`infrastructure/base/node-ops/node-ops-operator`.

All logic is compiled in — no shell, no `kubectl`/`jq`/`curl`/`nslookup`
forks, no hook ConfigMap. The image is `distroless/static:nonroot`
(~18MB, ~20–35MiB RAM).

#### Modules

Each module is its own package under `internal/<domain>/` (one
package per module, grouped by domain — same convention as
`node-host-agent`). Shared machinery lives in `internal/shared`, test
fakes/builders in `internal/testutil`, metric vectors in
`internal/metrics`.
Queue names below are what `shell_operator_hook_run_errors_total{queue}` /
`node_automation_reconcile_errors_total{controller}` report.

##### `apiserver/` — apiserver guards

| Module                     | Mode     | Cadence                     | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| -------------------------- | -------- | --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `apiserver-endpoint-guard` | periodic | 30s (10s while quarantined) | Watch-cache wedge guard: per-backend live-RV vs cached-RV probe (`node_automation_apiserver_rv_gap`); pulls a wedged apiserver IP out of `default/kubernetes` Endpoints+EndpointSlice after 2 gapped/frozen cycles and re-adds after 2 healthy cycles. Evidence persisted in annotation `node.ops/quarantined-endpoints`.                                                                                                                                                                                                                                                                                                                            |
| `admission-webhook-guard`  | periodic | 5m                          | Remove webhook entries whose `clientConfig.service.namespace` was deleted (fail-closed). **C1 circuit breaker:** patches `failurePolicy: Fail → Ignore` when a `Fail` webhook loses all Ready endpoints ≥5m (`node_automation_webhook_circuit_broken`, `WEBHOOK_CIRCUIT_BREAKER_ENABLED`, default on). **unmeshed-pod-auditor:** detects Running pods that should have been injected with `linkerd-proxy` (ns or pod `linkerd.io/inject: enabled`, not hostNetwork/Job/opt-out) but have no sidecar — `node_automation_unmeshed_pods`; once the injector is healthy again, recreates ≤2 pods/cycle (`UNMESHED_POD_REMEDIATION_ENABLED`, default on). |
| `apiservice-guard`         | periodic | 5m                          | Aggregated-API guard (`apiregistration.k8s.io/v1`): fail-closed cleanup of `APIService`s whose `spec.service.namespace` no longer exists (would otherwise wedge namespace deletion + GC cluster-wide); gauge `node_automation_apiservice_unavailable` when `Available=False` >10m. `APISERVICE_GUARD_ENABLED`, default on.                                                                                                                                                                                                                                                                                                                           |

##### `node/` — node lifecycle

| Module                    | Mode                     | Cadence | What it does                                                                                                                                                                                                                                                                                                         |
| ------------------------- | ------------------------ | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cilium-taint-reaper`     | watch Node/Pod + requeue | 10m     | Remove stale `node.cilium.io/agent-not-ready` taints once the cilium pod on the node is Running+Ready. **Opt-in:** `CILIUM_TAINT_REAPER_ENABLED=true`.                                                                                                                                                               |
| `descheduler-storm-gate`  | watch Node + requeue     | 5m      | Scale `deploy/descheduler` to 0 while any node is NotReady / has a storm condition or `node.ops/*` taint; restore to 1 when clear. **Maintenance Mutex:** also holds descheduler at 0 while any node is `unschedulable`, `ds/kured` holds `weave.works/kured-node-lock`, or the k0s `Plan/autopilot` is mid-upgrade. |
| `node-labeler`            | watch Node + requeue     | 30m     | Assert `node-role.kubernetes.io/worker` + labels listed in `$NODE_LABELER_CONFIG_PATH` (default `/etc/node-labeler/labels.txt`).                                                                                                                                                                                     |
| `kubelet-liveness-reaper` | periodic                 | 2m      | Probe `/api/v1/nodes/<n>/proxy/healthz` ×4; taint `node.ops/kubelet-unresponsive` when kubelet is wedged but the lease still renews.                                                                                                                                                                                 |
| `partition-pod-evictor`   | periodic                 | 5m      | Taint `node.ops/network-partitioned` + evict `flux-system` pods off nodes with NWPD partition conditions (>10m).                                                                                                                                                                                                     |
| `dead-node-sweeper`       | periodic                 | 5m      | Force-delete pods stuck >15m on nodes `Ready=Unknown` >30m (dead-node pod leak).                                                                                                                                                                                                                                     |
| `pdb-deadlock-watchdog`   | periodic                 | 5m      | PDB drain-deadlock breaker: gauge `node_automation_pdb_drain_blocked{reason}` for impossible policies (>10m), cordoned-node blocks (>15m), and prolonged `disruptionsAllowed=0` (>30m). `PDB_WATCHDOG_ENABLED`, default on.                                                                                          |
| `csr-watcher`             | periodic                 | 10m     | Approve node/kubelet CSRs pending >15m. **Opt-in:** `CSR_APPROVER_ENABLED=true`.                                                                                                                                                                                                                                     |

##### `system/` — platform components

| Module                        | Mode                   | Cadence                | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ----------------------------- | ---------------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `konnectivity-patcher`        | watch DS + requeue     | 15m                    | Re-assert `system-node-critical` + resource requests on `ds/konnectivity-agent` (k0s stack applier reverts them).                                                                                                                                                                                                                                                                                                                                       |
| `coredns-patcher`             | periodic               | —                      | Proportional replica pinning for CoreDNS (replaces cluster-proportional-autoscaler): `COREDNS_MIN_REPLICAS`/`COREDNS_NODES_PER_REPLICA` (default 4/1), zone-aware scheduling. `COREDNS_PATCHER_ENABLED`, default on.                                                                                                                                                                                                                                    |
| `metrics-server-patcher`      | periodic               | —                      | Same pinning for `metrics-server`: `METRICS_SERVER_MIN_REPLICAS`/`METRICS_SERVER_NODES_PER_REPLICA` (default 3/1). `METRICS_SERVER_PATCHER_ENABLED`, default on.                                                                                                                                                                                                                                                                                        |
| `coredns-stale-watchdog`      | periodic               | 1m                     | Zero-write 3-layer stale-watch detection (pod logs → active DNS freshness → `:9153` panics); deletes stale pods or restarts the deployment. Cooldown 30m, storm-gated.                                                                                                                                                                                                                                                                                  |
| `cf-tunnel-proxy-watchdog`    | periodic               | env (default interval) | Restart `cloudflared` pods when the tunnel proxy wedges. `CF_TUNNEL_WATCHDOG_ENABLED`/`_NAMESPACE`/`_INTERVAL`, default on.                                                                                                                                                                                                                                                                                                                             |
| `fluent-bit-config-roller`    | watch Secret + requeue | 30m                    | Roll `ds/fluent-bit` when `fluent.io/config-hash` drifts from `passiontech.dev/rolled-config-hash`. **Opt-in:** `FLUENTBIT_ROLLER_ENABLED=true`.                                                                                                                                                                                                                                                                                                        |
| `statefulset-ondelete-roller` | periodic               | 10m                    | **Opt-in** sequential roller for `updateStrategy: OnDelete` StatefulSets annotated `node.ops/auto-roll-ondelete: "true"`: after `updateRevision != currentRevision` ≥30m, deletes one pod at a time (highest ordinal first), gated on 100% Ready nodes, every matching PDB `disruptionsAllowed >= 1`, and ≥5m stability of the newest pod. `node_automation_statefulset_ondelete_pods_rolled_total`. `STATEFULSET_ONDELETE_ROLLER_ENABLED`, default on. |

##### `janitor/` — cleanup

| Module                         | Mode     | Cadence | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ------------------------------ | -------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `failed-jobs-janitor`          | periodic | 60m     | Delete Jobs `Failed` for >24h (cap 50/run). **stuck-terminating auditor:** gauge `node_automation_stuck_terminating_resources` for Namespaces/PVCs Terminating >2h.                                                                                                                                                                                                                                                                                                   |
| `evicted-pod-janitor`          | periodic | 10m     | Delete pods in `Failed`/`Evicted` phase older than 1h.                                                                                                                                                                                                                                                                                                                                                                                                                |
| `cronjob-catchup`              | periodic | 15m     | Create a catch-up Job for CronJobs that missed a schedule window (dedupe 24h, grace `max(2×period, period+30m)`).                                                                                                                                                                                                                                                                                                                                                     |
| `concourse-workdir-janitor`    | periodic | 30m     | Cluster-level worker orchestration only — sequential land-worker → drain → delete pod → waitReady → annotate baseline on `concourse-worker` pods when work-dir exceeds the 100GiB cap or nodefs crosses 60%. Shared-cache pruning moved to the node-host-agent `concourse-cache` sweeper. **Maintenance Mutex:** defers a wipe cycle while nodes are unschedulable / kured holds the lock / `Plan/autopilot` is active. **Opt-in:** `CONCOURSE_JANITOR_ENABLED=true`. |
| `volumeattachment-cleaner`     | periodic | 5m      | Delete orphaned `VolumeAttachment`s — missing node >5m or out-of-service/NotReady node >15m (`node_automation_volumeattachments_cleaned_total{reason}`). `VOLUMEATTACHMENT_CLEANER_ENABLED`, default on.                                                                                                                                                                                                                                                              |
| `zombie-sidecar-reaper`        | periodic | 5m      | Reap `Job` pods stuck `Running (1/2)` because `linkerd-proxy`/`istio-proxy` never exited after the app containers terminated >5m: graceful `POST :4191/shutdown` first, delete the pod next cycle. `node_automation_zombie_sidecar_pods_reaped_total`. `ZOMBIE_SIDECAR_REAPER_ENABLED`, default on.                                                                                                                                                                   |
| `orphan-endpointslice-cleaner` | periodic | 15m     | Delete `EndpointSlice`s (label `kubernetes.io/service-name`) whose parent `Service` has been gone for ≥2 consecutive cycles and >15m age — fail-closed against empty Service lists (k8s bug #111820). `node_automation_orphan_endpointslices_cleaned_total`. `ORPHAN_ENDPOINTSLICE_CLEANER_ENABLED`, default on.                                                                                                                                                      |

##### `integration/` — Flux / ESO / cert-manager / Velero / Cilium

| Module                    | Mode     | Cadence | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ------------------------- | -------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `helmrelease-unlocker`    | periodic | 10m     | Unlock `HelmRelease`s stuck >30m (cooldown 24h persisted in annotation `node.ops/last-helm-unlock`) + reap failed helm-hook Jobs. **Flux Source Artifact Healer:** when an `HelmRelease`/`Kustomization` reports `artifact not found` / `failed to fetch` / `chart pull error` / `failed to untar` for ≥15m, patch `reconcile.fluxcd.io/requestedAt` onto the source (`HelmChart`/`GitRepository`/`HelmRepository`/`OCIRepository`, 30m cooldown via `node.ops/last-source-nudge`). `node_automation_flux_source_reconciles_triggered_total`. |
| `externalsecret-nudge`    | periodic | 10m     | State-based nudge: when the referenced `ClusterSecretStore` is `Ready=True` but an `ExternalSecret` stays `Ready=False` >15m, patch `force-sync=<unix-now>` (1h cooldown; respects a fresh `force-sync` stamp). No longer depends on an in-memory `False→True` transition. **Opt-in:** `EXTERNALSECRET_NUDGE_ENABLED=true`.                                                                                                                                                                                                                   |
| `certmanager-reaper`      | periodic | 15m     | Delete wedged ACME `Order`/`Challenge` (pending >30m) for `Certificate`s inside the 7d renewal window — max 1 reset/cert/hour and a hard budget of 3 resets per renewal, persisted in annotation `node.ops/acme-order-resets` so a controller restart can't burn the Let's Encrypt rate limit. **Opt-in:** `CERTMANAGER_REAPER_ENABLED=true`.                                                                                                                                                                                                 |
| `cilium-identity-auditor` | periodic | 15m     | Two-pass safe GC of orphaned `CiliumIdentity` objects (orphan >30m, 15m grace between passes). `node_automation_cilium_identities_collected_total`. **Opt-in:** `CILIUM_IDENTITY_AUDITOR_ENABLED=true`.                                                                                                                                                                                                                                                                                                                                       |
| `cert-drift-auditor`      | periodic | 15m     | 360° cert audit: `node_automation_webhook_ca_bundle_mismatch` when a caBundle drifts (or is empty on a `Fail` webhook); `node_automation_webhook_ca_bundle_days_to_expiry` parsed from **every** webhook `clientConfig.caBundle`; `node_automation_tls_secret_days_to_expiry` for `kubernetes.io/tls` Secrets; `node_automation_trust_bundle_days_to_expiry` for Linkerd trust bundles (`linkerd-identity-trust-roots` CM, `Opaque` issuer secrets). `CERT_DRIFT_AUDITOR_ENABLED`, default on.                                                |
| `velero-backup-auditor`   | periodic | 15m     | Silent-backup-rot auditor (`velero.io/v1`, no-ops when CRDs absent): `node_automation_velero_schedule_paused` for `spec.paused=true` >24h; `node_automation_velero_backup_empty_or_errored{reason=zero_items\|errors\|warnings}` when the latest `Backup` completed with 0 items/bytes or non-zero errors/warnings. `VELERO_BACKUP_AUDITOR_ENABLED`, default on.                                                                                                                                                                              |

##### `health/` — ported kuberhealthy checks + KCM watchdog

| Module                  | Mode     | Cadence                          | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ----------------------- | -------- | -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cluster-health-probes` | periodic | `CLUSTER_HEALTH_PROBES_INTERVAL` | Runs the 5 ported kuberhealthy `HealthCheck`s in-process, emitting the exact `kuberhealthy_check{check,namespace,status}` / `kuberhealthy_check_seconds_since_success` series so existing alerts keep firing. `CLUSTER_HEALTH_PROBES_ENABLED` + per-check `HEALTH_*` knobs, default on. **kcm-workqueue-watchdog:** `node_automation_kcm_workqueue_frozen{reason}` when kube-controller-manager renews its Lease but stops reconciling objects. |

#### Interface contract

- Metrics: `:9115/metrics` — emits `shell_operator_hook_run_errors_total{queue}`
  (backwards-compatible with existing PrometheusRule alerts) plus
  `node_automation_reconcile_errors_total{controller}` and the default
  controller-runtime/workqueue metrics.
- Module metrics (`internal/metrics/metrics.go`): `node_automation_apiserver_rv_gap{backend}`,
  `node_automation_apiserver_quarantined{backend}`, `node_automation_webhook_circuit_broken`,
  `node_automation_webhook_circuit_breaker_trips_total`, `node_automation_pdb_drain_blocked`,
  `node_automation_stuck_terminating_resources`, `node_automation_helm_hook_jobs_cleaned_total`,
  `node_automation_volumeattachments_cleaned_total`, `node_automation_cilium_identities_collected_total`,
  `node_automation_webhook_ca_bundle_mismatch`, `node_automation_tls_secret_days_to_expiry`,
  `node_automation_kcm_workqueue_frozen`, plus `kuberhealthy_check` /
  `kuberhealthy_check_seconds_since_success`. Waves 1–3 add:
  `node_automation_apiservice_unavailable{name,service_namespace,service_name}`,
  `node_automation_webhook_ca_bundle_days_to_expiry{kind,name,webhook}`,
  `node_automation_trust_bundle_days_to_expiry{namespace,name}`,
  `node_automation_unmeshed_pods{namespace,pod}`,
  `node_automation_unmeshed_pods_recreated_total{namespace}`,
  `node_automation_zombie_sidecar_pods_reaped_total{namespace}`,
  `node_automation_orphan_endpointslices_cleaned_total{namespace}`,
  `node_automation_flux_source_reconciles_triggered_total{kind,namespace,name}`,
  `node_automation_statefulset_ondelete_pods_rolled_total{namespace,statefulset}`,
  `node_automation_velero_schedule_paused{namespace,schedule}`,
  `node_automation_velero_backup_empty_or_errored{namespace,schedule,reason}`.
- Probes: `:8081/healthz`, `:8081/readyz`.
- Flags: `--metrics-bind-address` (default `:9115`),
  `--health-probe-bind-address` (default `:8081`), `--version`.
- Env (opt-in, default `"false"`): `CILIUM_TAINT_REAPER_ENABLED`,
  `FLUENTBIT_ROLLER_ENABLED`, `CONCOURSE_JANITOR_ENABLED`,
  `CERTMANAGER_REAPER_ENABLED`, `CILIUM_IDENTITY_AUDITOR_ENABLED`,
  `EXTERNALSECRET_NUDGE_ENABLED`, `CSR_APPROVER_ENABLED`,
  `NODE_LABELER_CONFIG_PATH`.
- Env (default `"true"`, set `"false"` to disable):
  `WEBHOOK_CIRCUIT_BREAKER_ENABLED`, `PDB_WATCHDOG_ENABLED`,
  `CERT_DRIFT_AUDITOR_ENABLED`, `VOLUMEATTACHMENT_CLEANER_ENABLED`,
  `COREDNS_PATCHER_ENABLED`, `METRICS_SERVER_PATCHER_ENABLED`,
  `CF_TUNNEL_WATCHDOG_ENABLED`, `CLUSTER_HEALTH_PROBES_ENABLED`,
  `APISERVICE_GUARD_ENABLED`, `ZOMBIE_SIDECAR_REAPER_ENABLED`,
  `ORPHAN_ENDPOINTSLICE_CLEANER_ENABLED`,
  `STATEFULSET_ONDELETE_ROLLER_ENABLED`, `UNMESHED_POD_REMEDIATION_ENABLED`,
  `VELERO_BACKUP_AUDITOR_ENABLED`, plus tunables
  `COREDNS_MIN_REPLICAS`/`COREDNS_NODES_PER_REPLICA`,
  `METRICS_SERVER_MIN_REPLICAS`/`METRICS_SERVER_NODES_PER_REPLICA`,
  `CF_TUNNEL_WATCHDOG_NAMESPACE`/`_INTERVAL`, `HEALTH_*`,
  `PARTITION_EVICT_NAMESPACES`.

### node-host-agent

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

### webhook-dispatcher

Receives GitHub org webhook deliveries and fans out instant resource
checks to the Concourse ATC — `push` deliveries check matching `git`
resources, `pull_request` deliveries check matching `github-pr`
resources — instead of waiting for the `check_every` polling interval.
Deliveries are verified against `X-Hub-Signature-256` (HMAC-SHA256 over
the raw body); a single resource failure never fails the delivery.

#### Interface contract

- Endpoints: `POST /webhook`, `GET /healthz` (returns `ok`).
- Flags: `--version`.
- Env:

| Var                     | Required | Default                     | Purpose                                           |
| ----------------------- | -------- | --------------------------- | ------------------------------------------------- |
| `GITHUB_WEBHOOK_SECRET` | yes      | —                           | HMAC key for `X-Hub-Signature-256`                |
| `CI_WEBHOOK_TOKEN`      | yes      | —                           | Concourse check-webhook token (`webhook_token=…`) |
| `LOCAL_USERS`           | yes      | —                           | Concourse basic auth, `user:password`             |
| `CONCOURSE_URL`         |          | `http://concourse-web:8080` | ATC base URL                                      |
| `CONCOURSE_TEAM`        |          | `main`                      | Team to index and fan out to                      |
| `LISTEN_ADDR`           |          | `:8080`                     | Listen address                                    |

## Repository layout

```
.moon/                       moon workspace config + shared tasks
apps/
  node-automation-controller/  moon project (own go.mod, cliff.toml, .ko.yaml, Dockerfile)
  node-host-agent/             moon project (own go.mod, cliff.toml, .ko.yaml, Dockerfile)
  webhook-dispatcher/          moon project (own go.mod, cliff.toml, .ko.yaml, Dockerfile)
.github/workflows/
  ci.yml                         PR gate — moon ci on affected projects
  release-app.yml                reusable release pipeline
  release-<app>.yml              per-app release triggers
mise.toml                      tool pins: go, git-cliff, ko, moon
```

Each app is an independent Go module with its own dependencies, image
build (`ko`), and release cadence.

## Development

```sh
mise install                 # go + git-cliff + ko + moon (all pinned)

moon query projects          # list workspace projects
moon run :format :vet :test  # shared tasks across all projects
moon run node-host-agent:build
moon run node-automation-controller:image   # ko build (needs KO_DOCKER_REPO)
```

Common tasks (`test`, `vet`, `format`) are defined once in
`.moon/tasks/all.yml` and inherited by every project; `build`/`image`
live in each app's `moon.yml`. All binaries come from mise — moon tasks
run on the `system` toolchain.

## Releases

Per-app, independent of each other. Tag scheme: `<app>/vX.Y.Z`.

- Push to `main` under `apps/<app>/**` → `release-<app>.yml` runs
  automatically (other apps untouched).
- Manual: `gh workflow run release-node-host-agent.yml` — optional
  `-f version=v0.1.0`, `-f prerelease=true`.
- Pipeline (`release-app.yml`): `git-cliff` semver bump over
  conventional commits scoped to `apps/<app>` → `moon` vet/test/build →
  `ko` pushes `ghcr.io/passiontech-global/<app>:{version,latest}` →
  GitHub Release `<app>/vX.Y.Z`.

Note: `node-automation-controller`'s pre-monorepo `vX.Y.Z` tags remain
valid for changelog history; new tags carry the app prefix.
