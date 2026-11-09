# Environment variables & CLI flags

Operator-facing catalog of every env var the controller reads. The table is
hand-maintained and **verified against source** by the envdoc coverage test
(`internal/envdoc`), which walks `internal/registry/registry.go`,
`cmd/manager/main.go`, and every `envx.Getenv*` / `envx.Gate` call under
`internal/` — update this file when adding a knob.

Parsing rules (`libs/hostkit/envx` — the strict `Getenv*`/`Gate` family):

- **Registration gates** live in the `GateEnv` column of the module registry
  (`internal/registry/registry.go`). `DefaultOn=false` = opt-in: enabled only when
  the value is exactly `"true"`. `DefaultOn=true` = opt-out: enabled unless
  the value is exactly `"false"`. A gated-off module registers nothing.
- **Run-behavior knobs** are read inside each module's `Setup` (or per sweep).
  Unparseable / out-of-range values warn and fall back to the default.
  Duration knobs below 1s are rejected.
- **Sub-feature gates** are `envx.Gate` calls inside a module — same
  `"true"`/`"false"` semantics as registration gates, but the module still
  registers when they're off.

## Manager / API client

| Env var | Module | Default | Notes |
|---|---|---|---|
| `NODE_AUTOMATION_KUBE_CLIENT_QPS` | manager | `50` | client-go QPS on the shared rest.Config every module sweeps/reconciles through (client-go's `5` was far under this fleet's aggregate rate). All three clients (manager, clientset, dynamic) share one token bucket installed on the config. |
| `NODE_AUTOMATION_KUBE_CLIENT_BURST` | manager | `100` | client-go burst paired with the QPS knob above. |
| `NODE_AUTOMATION_KUBE_CLIENT_TIMEOUT` | manager | `30s` | Per-request timeout on the direct (uncached) typed/dynamic clients the sweep loops use — bounds a hung apiserver call. NOT applied to the manager's client, where it would cut informer watch streams. |
| `NODE_AUTOMATION_PROBE_CLIENT_QPS` | manager | `20` | client-go QPS on the SECOND rest.Config built for the latency-sensitive probe modules (apiserver-endpoint-guard, kubelet-liveness-reaper, dead-node-sweeper — the `Module.ProbeClients` registry rows): their own token bucket, so janitor delete bursts draining the shared `NODE_AUTOMATION_KUBE_CLIENT_*` bucket cannot queue-delay a probe verdict mid-incident. |
| `NODE_AUTOMATION_PROBE_CLIENT_BURST` | manager | `40` | client-go burst paired with the probe QPS knob above; shares the per-request timeout inherited from the direct clients. |

## Global heal budget

| Env var | Module | Default | Notes |
|---|---|---|---|
| `NODE_AUTOMATION_HEAL_BUDGET_MAX` | manager (platform/heal) | `10` | Max heal grants (AllowedV "proceed" verdicts) per window across ALL heal-gated modules — the aggregate blast-radius cap. `0` disables the budget. Denials count on `node_automation_heal_budget_exhausted_total`. |
| `NODE_AUTOMATION_HEAL_BUDGET_WINDOW` | manager (platform/heal) | `5m` | Sliding window the heal-budget grant count is measured over. |

## System patchers / watchdogs

| Env var | Module | Default | Notes |
|---|---|---|---|
| `FLUENTBIT_ROLLER_ENABLED` | fluent-bit-config-roller | opt-in (`"true"`) | Registration gate — rolls the fluent-bit DaemonSet on config change. |
| `COREDNS_PATCHER_ENABLED` | coredns-patcher | on unless `"false"` | Registration gate — reconciles kube-system/coredns (topology spread + replica pin). |
| `COREDNS_PATCHER_ZONE_WHEN` | coredns-patcher | `DoNotSchedule` | `whenUnsatisfiable` in the rendered zone-spread patch; must be `DoNotSchedule` or `ScheduleAnyway` — anything else disables the module at boot (logged error + error metric). |
| `COREDNS_PATCHER_ZONE_MIN_DOMAINS` | coredns-patcher | `2` | `minDomains` for the zone topology-spread constraint. |
| `COREDNS_MIN_REPLICAS` | coredns-patcher | `4` | Floor of the CPA-linear replica pin; `<=0` disables the pin and leaves `.spec.replicas` untouched (standalone CPA can be re-enabled). |
| `COREDNS_NODES_PER_REPLICA` | coredns-patcher | `1` | Nodes-per-replica ratio for the proportional pin (counts every Node, incl. unschedulable). |
| `METRICS_SERVER_PATCHER_ENABLED` | metrics-server-patcher | on unless `"false"` | Registration gate — reconciles kube-system/metrics-server. |
| `METRICS_SERVER_MIN_REPLICAS` | metrics-server-patcher | `3` | Replica-pin floor; `<=0` disables the pin. |
| `METRICS_SERVER_NODES_PER_REPLICA` | metrics-server-patcher | `1` | Nodes-per-replica ratio for the proportional pin. |
| `CF_TUNNEL_WATCHDOG_ENABLED` | cf-tunnel-proxy-watchdog | on unless `"false"` | Registration gate — bounces wedged cloudflare-tunnel proxy pods. |
| `CF_TUNNEL_WATCHDOG_NAMESPACE` | cf-tunnel-proxy-watchdog | `cloudflare-tunnel-system` | Namespace of the tunnel deployment the watchdog heals. |
| `CF_TUNNEL_WATCHDOG_INTERVAL` | cf-tunnel-proxy-watchdog | `5m` | Sweep interval. |
| `STATEFULSET_ONDELETE_ROLLER_ENABLED` | statefulset-ondelete-roller | on unless `"false"` | Registration gate — rolls StatefulSets stuck on `OnDelete` update strategy. |

## Node lifecycle

| Env var | Module | Default | Notes |
|---|---|---|---|
| `CILIUM_TAINT_REAPER_ENABLED` | cilium-taint-reaper | opt-in (`"true"`) | Registration gate — removes cilium agent-not-ready taints; also gates the kube-system/cilium pods informer (no watch when off). |
| `PDB_WATCHDOG_ENABLED` | pdb-deadlock-watchdog | on unless `"false"` | Registration gate — detects PDBs deadlocking drains/evictions. |
| `CSR_APPROVER_ENABLED` | csr-watcher | off unless `"true"` | Sub-feature gate — approve mode. Off = detect/report pending CSRs only (module always registers). |
| `NODE_LABELER_CONFIG_PATH` | node-labeler | `/etc/node-labeler/labels.txt` | Path to the labels.txt file the reconciler applies to nodes. |
| `PARTITION_EVICT_NAMESPACES` | partition-pod-evictor | `flux-system` | Comma-separated namespace allow-list for partition eviction; unset/empty falls back to `flux-system`. Pods in any ns can opt in via `passiontech.dev/evict-on-partition`. |
| `DEAD_NODE_SWEEPER_FENCE_UNFENCED_STATEFUL` | dead-node-sweeper | off unless `"true"` | Sub-feature gate — authorizes fencing a branch-(b) dead node (no medik8s SNR CR) that holds an RWO VolumeAttachment or a StatefulSet pod; default skips the out-of-service taint (split-brain guard, `node_automation_dead_node_unfenced_stateful_skipped`). Without-SNR fences count on `node_automation_dead_node_fenced_without_snr_total`; re-read every sweep. |

## apiserver guards

| Env var | Module | Default | Notes |
|---|---|---|---|
| `APISERVICE_GUARD_ENABLED` | apiservice-guard | on unless `"false"` | Registration gate — reaps broken APIService registrations. |
| `WEBHOOK_CIRCUIT_BREAKER_ENABLED` | admission-webhook-guard | on unless `"false"` | Sub-feature gate — C1 fail-closed-webhook circuit breaker; re-read every sweep so a flip takes effect on the next cycle. |
| `UNMESHED_POD_REMEDIATION_ENABLED` | admission-webhook-guard | on unless `"false"` | Sub-feature gate — allows deleting unmeshed pods once the injector webhook is provably healthy (the audit gauge is exported regardless); re-read every sweep. |
| `WEBHOOK_CRITICAL_NS_ENFORCE_ENABLED` | admission-webhook-guard | off unless `"true"` | Sub-feature gate — auto-patch every fail-closed webhook whose namespaceSelector matches a critical self-healing namespace (kube-system, kube-node-lease, node-ops, medik8s) with the `kubernetes.io/metadata.name NotIn [...]` exclusion; allowlisted entries untouched. The audit gauges export regardless; re-read every sweep. |
| `MEDIK8S_BOOT_FAIL_OPEN_ENABLED` | admission-webhook-guard | on unless `"false"` | Sub-feature gate — one-way `FailurePolicy: Fail→Ignore` enforcement on the medik8s boot-path validating webhook entries (rules referencing only `selfnoderemediationconfigs`/`selfnoderemediationtemplates` of `self-node-remediation.medik8s.io`). The operators' startup default-CR ensure is validated by their own webhook; a stale/wrong endpoint set i/o-times the call and the manager exit-1 crash-loops (incident 2026-11-08). OLM re-asserts Fail from the CSV webhookdefinitions on reconcile/upgrade — the sweep re-heals that drift every 5m. Mutating configs, the remediation-CR entry and non-medik8s webhooks untouched; re-read every sweep. |

## Janitors

| Env var | Module | Default | Notes |
|---|---|---|---|
| `CONCOURSE_JANITOR_ENABLED` | concourse-workdir-janitor | opt-in (`"true"`) | Registration gate — cleans Concourse worker work-dir cruft. |
| `VOLUMEATTACHMENT_CLEANER_ENABLED` | volumeattachment-cleaner | on unless `"false"` | Registration gate — deletes orphaned VolumeAttachments. |
| `ZOMBIE_SIDECAR_REAPER_ENABLED` | zombie-sidecar-reaper | on unless `"false"` | Registration gate — kills sidecars outliving their main container. |
| `ORPHAN_ENDPOINTSLICE_CLEANER_ENABLED` | orphan-endpointslice-cleaner | on unless `"false"` | Registration gate — prunes EndpointSlices with no owning Service/endpoints. |

`failed-jobs-janitor`, `evicted-pod-janitor`, `cronjob-catchup` have no env
knobs (always-on, no gates).

## Integration unstuckers

| Env var | Module | Default | Notes |
|---|---|---|---|
| `CERTMANAGER_REAPER_ENABLED` | certmanager-reaper | opt-in (`"true"`) | Registration gate — reaps stuck cert-manager resources. |
| `CILIUM_IDENTITY_AUDITOR_ENABLED` | cilium-identity-auditor | opt-in (`"true"`) | Registration gate — 15m CiliumIdentity audit sweep (off on clusters without the cilium component — CRDs absent). |
| `CILIUM_IDENTITY_GC_ENABLED` | cilium-identity-auditor | on unless `"false"` | Sub-feature gate — enables identity GC (deletion); off = audit-only. |
| `CERT_DRIFT_AUDITOR_ENABLED` | cert-drift-auditor | on unless `"false"` | Registration gate — audits cert/secret drift. |
| `VELERO_BACKUP_AUDITOR_ENABLED` | velero-backup-auditor | on unless `"false"` | Registration gate — audits Velero backup health. |
| `HELM_STALL_UNWEDGE_ENABLED` | helmrelease-unlocker | off unless `"true"` | Sub-feature gate — gates ONLY the stalled-rollout unwedge pass; pending-secret unlock and artifact-source healing always run. |
| `EXTERNALSECRET_NUDGE_ENABLED` | externalsecret-nudge | off unless `"true"` | Registration gate — nudges stuck ExternalSecrets; off = module registers nothing (for clusters without ESO). |

`helmrelease-unlocker` itself has no registration gate (always-on).

## Cluster health probes

| Env var | Module | Default | Notes |
|---|---|---|---|
| `CLUSTER_HEALTH_PROBES_ENABLED` | cluster-health-probes | on unless `"false"` | Registration gate — the ported kuberhealthy check sweep (27 checks). |
| `CLUSTER_HEALTH_PROBES_INTERVAL` | cluster-health-probes | `5m` | Sweep interval for the whole check roster. |
| `HEALTH_CHECK_TIMEOUT` | cluster-health-probes | `30s` | Timeout wrapping each remote call (probe, PromQL query). |
| `HEALTH_PER_CHECK_TIMEOUT` | cluster-health-probes | `2m` | Bounds one check's share of the serial sweep — past it the check's ctx is cancelled and the sweep moves on. |
| `HEALTH_DNS_HOSTNAMES` | cluster-health-probes | `kubernetes.default.svc.cluster.local,kube-prometheus-stack-prometheus.prometheus-operator.svc.cluster.local` | Comma-separated hostnames dns-status-internal must resolve. Second entry is a ClusterIP svc so the check survives alertmanager pod restarts. |
| `HEALTH_HTTP_CONTENT_URL` | cluster-health-probes | `http://kube-prometheus-stack-prometheus.prometheus-operator.svc:9090/-/healthy` | http-content-check target (GET 200 + expected body); also the fallback host for the PromQL endpoint. |
| `HEALTH_HTTP_EXPECTED_CONTENT` | cluster-health-probes | `Healthy` | Substring the http-content-check body must contain. |
| `HEALTH_PROMETHEUS_QUERY_URL` | cluster-health-probes | `""` (derived) | Full Prometheus `/api/v1/query` URL override; empty = derive `scheme://host` from `HEALTH_HTTP_CONTENT_URL`. Re-read per call. |
| `HEALTH_POD_CHECK_NAMESPACE` | cluster-health-probes | `kube-system` | Namespace the pod-restarts and pod-status checks census. |
| `HEALTH_MAX_POD_RESTARTS` | cluster-health-probes | `10` | pod-restarts ceiling — a recently-active container above this count FAILs (parsed values <0 rejected). |
| `HEALTH_POD_SKIP_DURATION` | cluster-health-probes | `10m` | pod-status grace — pods younger than this may still be Pending without failing. |
| `HEALTH_RESOURCE_QUOTA_THRESHOLD` | cluster-health-probes | `0.9` | resource-quota-check used/hard ratio ceiling. |
| `HEALTH_KCM_LEASE_MAX_AGE` | cluster-health-probes | `30s` | kcm-workqueue-watchdog — max age of the KCM leader Lease renewTime before the holder reads as gone (2× the 15s lease duration). |
| `HEALTH_KCM_FREEZE_MIN_AGE` | cluster-health-probes | `10m` | kcm-workqueue-watchdog — a freeze signature must persist this long before the gauge fires. |
| `CILIUM_BPF_MAP_PRESSURE_THRESHOLD` | cluster-health-probes (nethealth) | `0.85` | cilium-bpf-map-pressure fill ratio threshold; `>1` disables the check, `<=0` falls back to default. |
| `CILIUM_NODE_IPAM_MIN_FREE_RATIO` | cluster-health-probes (nethealth) | `0.15` | cilium-node-ipam-exhaustion — min free-IP ratio before FAIL + per-node pod reap; `>1` disables, `<=0` falls back. |
| `LINKERD_OUTLIER_EVICT_ENABLED` | cluster-health-probes (nethealth) | on unless `"false"` | Sub-feature gate — linkerd-outlier-guard (linkerd-outlier) auto-evict: a confirmed single-pod 5xx outlier (>=80% err at >=1 rps, siblings <5% median) is evicted via policy/v1 Eviction behind the six safety gates. `"false"` keeps detection + `node_automation_linkerd_outlier_pods` live but never evicts. Resolved at Setup, not hot-reloaded. |
| `HEALTH_CNPG_UNHEALTHY_MIN_AGE` | cluster-health-probes (datastore) | `15m` | postgres-wal-archive-guard (cnpg-health) — a CloudNativePG Cluster wedged in a failover phase (`Failing over` / `Waiting for the instances to become active`) or holding `readyInstances < instances` must persist this long before `node_automation_cnpg_cluster_unhealthy` fires. |
| `HEALTH_PVC_RESIZE_STALL_MIN_AGE` | cluster-health-probes (datastore) | `30m` | pvc-resize-stall-guard (pvc-resize) — a PVC `FileSystemResizePending`/`Resizing` condition True past this window flags `node_automation_pvc_resize_stalled`. |

| `NODE_AUTOMATION_FLUX_KUSTOMIZATION_HEALTH_ENABLED` | flux-kustomization-health | on unless `"false"` | Registration gate — flux-stuck check row. Registers the check into the cluster-health-probes sweep roster (detects Ready=False Flux Kustomizations >=15m and stamps `reconcile.fluxcd.io/requestedAt` on a 30m cooldown when the dependsOn chain is Ready); requires the cluster-health-probes module to actually run the check. |
| `NODE_AUTOMATION_WORKLOAD_SCALE_FLAPPING_ENABLED` | workload-scale-flapping | on unless `"false"` | Registration gate — scale-flap check row. Registers the ScalingReplicaSet direction-flip detector (>=6 flips/hour → `node_automation_workload_scale_flapping`) into the sweep roster; requires cluster-health-probes. |
| `NODE_AUTOMATION_IMAGEPULL_SECRET_AUDITOR_ENABLED` | imagepull-secret-auditor | on unless `"false"` | Registration gate — pullsecret-audit check row. Registers the imagePullSecrets dockerconfigjson auditor (missing/malformed/wrong-type/JWT <7d → `node_automation_imagepull_secret_unhealthy`) into the sweep roster; requires cluster-health-probes. |

## CLI flags (`cmd/manager/main.go`)

| Flag | Default | Meaning |
|---|---|---|
| `-metrics-bind-address` | `:9115` | Address the Prometheus `/metrics` endpoint binds to. |
| `-health-probe-bind-address` | `:8081` | Address `/healthz` and `/readyz` bind to. |
| `-version` | `false` | Print version and exit. |
| `-leader-elect` | `false` | Enable active/passive HA via a `coordination.k8s.io` Lease (required for >1 replica; `ReleaseOnCancel` hands the lease over on graceful shutdown). |
| `-leader-elect-lease-duration` | `0` | Time non-leaders wait before force-acquiring the Lease; `0` = controller-runtime default (15s). |
| `-leader-elect-renew-deadline` | `0` | Time the leader retries renewing before giving up; `0` = default (10s). |
| `-leader-elect-retry-period` | `0` | Interval between Lease renew/acquire attempts; `0` = default (2s). |
| `-modules` | `""` (all) | Comma-separated allowlist of registry ops names or `@group` selectors (see `internal/registry`) — only those modules wire runnables. Groups: `@system`, `@node`, `@apiserver`, `@janitors`, `@integration`, `@health`. Unknown names/groups abort boot; metric series are predeclared for the full registry regardless. |
