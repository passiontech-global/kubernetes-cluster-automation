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
| `POD_NAME` | manager (leader election) | downward-API pod name | Preferred prefix for the leader-election `HolderIdentity` (`<pod>_<uuid>`) over `os.Hostname()` — `spec.hostname` can differ from `metadata.name`, and the lease preemptor parses the pod name back out of the holder identity, so a mismatched hostname would make a live leader read as `pod_missing`. Not a `NODE_AUTOMATION_*` knob — the standard Kubernetes downward-API variable. |
| `NODE_AUTOMATION_PPROF_BIND_ADDRESS` | manager | `127.0.0.1:9116` | Default loopback-only bind address for `/debug/pprof/*` (`httpx` + `pprofx`). Unset or empty `NODE_AUTOMATION_PPROF_BIND_ADDRESS` uses the default `127.0.0.1:9116` (`envx.String`); pass `-pprof-bind-address=""` to disable the pprof listener. Non-loopback addresses are rejected at startup. |

## Global heal budget

| Env var | Module | Default | Notes |
|---|---|---|---|
| `NODE_AUTOMATION_HEAL_BUDGET_MAX` | manager (platform/heal) | `10` | Max heal grants (AllowedV "proceed" verdicts) per window across ALL heal-gated modules — the aggregate blast-radius cap. `0` disables the budget. Denials count on `node_automation_heal_budget_exhausted_total`. |
| `NODE_AUTOMATION_HEAL_BUDGET_WINDOW` | manager (platform/heal) | `5m` | Sliding window the heal-budget grant count is measured over. |
| `NODE_AUTOMATION_HEAL_FLUX_CONFLICT_LOOP_MAX` | manager (platform/heal) | `3` | Repeats per object inside the window before a desired-state heal patch SKIPS as a Flux Heal-Revert Loop (SSA ping-pong — the object's managedFields carry a helm-controller/kustomize-controller manager). `0` disables the gate. Skips count on `node_automation_heal_gitops_conflict_total` (alert GitOpsAutoHealConflict) — fix the drift in Git. |
| `NODE_AUTOMATION_HEAL_FLUX_CONFLICT_WINDOW` | manager (platform/heal) | `30m` | Sliding window the per-object Heal-Revert-Loop repeat count is measured over; draining it re-arms one probe patch. |

## System patchers / watchdogs

| Env var | Module | Default | Notes |
|---|---|---|---|
| `FLUENTBIT_ROLLER_ENABLED` | fluent-bit-config-roller | opt-in (`"true"`) | Registration gate — rolls the fluent-bit DaemonSet on config change. |
| `COREDNS_PATCHER_ENABLED` | coredns-patcher | on unless `"false"` | Registration gate — reconciles kube-system/coredns (topology spread + replica pin). |
| `COREDNS_PATCHER_ZONE_WHEN` | coredns-patcher | `DoNotSchedule` | `whenUnsatisfiable` in the rendered zone-spread patch; must be `DoNotSchedule` or `ScheduleAnyway` — anything else disables the module at boot (logged error + error metric). |
| `COREDNS_PATCHER_ZONE_MIN_DOMAINS` | coredns-patcher | `2` | `minDomains` for the zone topology-spread constraint. |
| `COREDNS_MIN_REPLICAS` | coredns-patcher | `4` | Floor of the CPA-linear replica pin; `<=0` disables the pin and leaves `.spec.replicas` untouched (standalone CPA can be re-enabled). |
| `COREDNS_NODES_PER_REPLICA` | coredns-patcher | `1` | Nodes-per-replica ratio for the proportional pin (counts every Node, incl. unschedulable). |
| `COREDNS_SERVE_STALE_DURATION` | coredns-patcher | `1h` | `serve_stale <dur> immediate` window injected into every Corefile `cache` block that lacks it — stale answers keep resolving through a CoreDNS/apiserver backend outage. `"0"`/`"off"` disables the directive (the `denial 9984 5` cap still applies); unparseable values warn and fall back to `1h`. |
| `COREDNS_FORWARD_MAX_CONCURRENT` | coredns-patcher | `2000` | `max_concurrent <N>` injected into every Corefile `forward` block that lacks the option — the forward plugin's concurrency cap (P1.7a); a declared `max_concurrent` is never overwritten. Must be a positive integer — unparseable/non-positive values warn and fall back to `2000` (a malformed forward block would take cluster DNS down). |
| `COREDNS_SATURATION_BOOST_REPLICAS` | coredns-patcher | `2` | Replica surge the proportional pin adds while the coredns-forward-saturation check's `passiontech.dev/coredns-boost-until` stamp on the Deployment is fresh (P1.7b) — the patcher honors the boost instead of reverting it, and releases it when the window lapses. `<=0` disables the honor (the check's one-shot `.spec.replicas` bump still lands). |
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
| `CILIUM_TAINT_REAPER_ENABLED` | cilium-taint-reaper | opt-in (`"true"`) | Registration gate — removes cilium agent-not-ready taints (`kube-system` pods informer for `k8s-app in (cilium,kube-dns)` is registered in the manager cache for `cilium-taint-reaper` and `coredns-stale-watchdog` when startup SSAR proves `pods` list/watch RBAC in `kube-system`; otherwise both fall back to direct API reads). |
| `PDB_WATCHDOG_ENABLED` | pdb-deadlock-watchdog | on unless `"false"` | Registration gate — detects PDBs deadlocking drains/evictions. |
| `PDB_UNHEALTHY_EVICTION_PATCH_ENABLED` | pdb-deadlock-watchdog | on unless `"false"` | Sub-feature gate — cordoned-block relief: `"false"` disables patching `unhealthyPodEvictionPolicy=AlwaysAllow` on drain-blocked PDBs (report-only). Resolved at Setup. |
| `PDB_CORDONED_UNHEALTHY_RELIEF_ENABLED` | pdb-deadlock-watchdog | on unless `"false"` | Sub-feature gate — cordoned-block relief: `"false"` disables the wedged-pod delete fallback that reschedules an unhealthy pod off a cordoned node. Resolved at Setup. |
| `CSR_APPROVER_ENABLED` | csr-watcher | off unless `"true"` | Sub-feature gate — approve mode. Off = detect/report pending CSRs only (module always registers). |
| `NODE_LABELER_CONFIG_PATH` | node-labeler | `/etc/node-labeler/labels.txt` | Path to the labels.txt file the reconciler applies to nodes. |
| `NODE_AUTOMATION_DEPRECATED_SELECTOR_HEAL_ENABLED` | node-labeler | on unless `"false"` | P0.2b one-way GA→deprecated node-label sync (`kube.CompatNodeLabels`): fills `beta.kubernetes.io/os|arch`, `failure-domain.beta.kubernetes.io/zone|region`, and the master role labels on every node so DaemonSets still selecting the deprecated keys schedule again. `"false"` disables the sync (the critical-daemonset-starvation check's on-demand patch is unaffected). |
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
| `WEBHOOK_ERROR_RATE_THRESHOLD` | admission-webhook-guard | `0.5` | Error-rate threshold (`calling_webhook_error`\|`apiserver_internal_error`, excluding `no_error`) over `[5m]` triggering degraded admission webhook signal + stage-1 pod bounce at 10m and circuit trip at 15m. Resolved at Setup. |
| `WEBHOOK_LATENCY_P99_SECONDS` | admission-webhook-guard | `5.0` | p99 admission duration threshold (seconds) triggering degraded admission webhook signal + stage-1 pod bounce at 10m and circuit trip at 15m. Resolved at Setup. |
| `WEBHOOK_LATENCY_BREAKER_TRIP_ENABLED` | admission-webhook-guard | on unless `"false"` | Sub-feature gate — allows `admission-webhook-guard` to trip slow/5xx `failurePolicy: Fail` sub-webhooks to `Ignore` after 15m (unless annotated `passiontech.dev/webhook-never-fail-open=true`). Resolved at Setup. |
| `WEBHOOK_TIMEOUT_CLAMP_ENABLED` | admission-webhook-guard | on unless `"false"` | Sub-feature gate — clamps `failurePolicy: Fail` admission webhooks touching core control-plane resources with `timeoutSeconds > WEBHOOK_MAX_TIMEOUT_SECONDS` down to `5s` via `FluxPatchGate`. Resolved at Setup. |
| `WEBHOOK_MAX_TIMEOUT_SECONDS` | admission-webhook-guard | `10` | Maximum allowed `timeoutSeconds` before emitting `node_automation_webhook_excessive_timeout` (admission webhooks and CRD conversion audits) and clamping eligible admission webhooks to `5s`. Resolved at Setup. |
| `CEL_POLICY_CRITICAL_NS_ENFORCE_ENABLED` | admission-webhook-guard | on unless `"false"` | Sub-feature gate — auto-patches fail-closed `ValidatingAdmissionPolicy` / `MutatingAdmissionPolicy` `spec.matchConstraints.namespaceSelector` with `kubernetes.io/metadata.name NotIn` critical self-healing namespaces behind `FluxPatchGate` + `AllowedV`; re-read every sweep. |
| `CEL_POLICY_CIRCUIT_BREAKER_ENABLED` | admission-webhook-guard | on unless `"false"` | Sub-feature gate — trips fail-closed CEL admission policies to `failurePolicy: Ignore` (with `passiontech.dev/circuit-broken-cel-policy`) on sustained missing `paramRef` or CEL eval error storms, and restores after 2 clean sweeps (restore still runs when off); re-read every sweep. |

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
| `CERT_LIVE_DRIFT_ROLLOUT_ENABLED` | cert-drift-auditor | on unless `"false"` | Sub-feature gate — triggers guarded rollout restarts when a Service's live TLS socket serves an expired or `<7d` expiring cert whose serial differs from the mounted `kubernetes.io/tls` Secret (`Deployment`/`DaemonSet` by default, `StatefulSet` opt-in). Resolved at Setup. |
| `VELERO_BACKUP_AUDITOR_ENABLED` | velero-backup-auditor | on unless `"false"` | Registration gate — audits Velero backup health. |
| `VELERO_NAMESPACE` | velero-backup-auditor | `velero` | Namespace Velero is installed in — where the in-flight PVB/PVR wedge audit looks up the node-agent pod that owns the transfer's Kopia thread (PodVolumeBackups themselves live in the workload namespaces). |
| `HELM_STALL_UNWEDGE_ENABLED` | helmrelease-unlocker | off unless `"true"` | Sub-feature gate — gates ONLY the stalled-rollout unwedge pass; pending-secret unlock and artifact-source healing always run. |
| `EXTERNALSECRET_NUDGE_ENABLED` | externalsecret-nudge | off unless `"true"` | Registration gate — nudges stuck ExternalSecrets; off = module registers nothing (for clusters without ESO). |

`helmrelease-unlocker` itself has no registration gate (always-on).

## Cluster health probes

| Env var | Module | Default | Notes |
|---|---|---|---|
| `CLUSTER_HEALTH_PROBES_ENABLED` | cluster-health-probes | on unless `"false"` | Registration gate — the 68-check cluster-health sweep. |
| `CLUSTER_HEALTH_PROBES_INTERVAL` | cluster-health-probes | `5m` | Sweep interval for the whole check roster. |
| `HEALTH_CHECK_TIMEOUT` | cluster-health-probes | `30s` | Timeout wrapping each remote call (probe, PromQL query). |
| `HEALTH_PER_CHECK_TIMEOUT` | cluster-health-probes | `2m` | Bounds one check's share of the serial sweep — past it the check's ctx is cancelled and the sweep moves on. |
| `HEALTH_DNS_HOSTNAMES` | cluster-health-probes | `kubernetes.default.svc.cluster.local,<auto-detected>` | Comma-separated hostnames dns-status-internal must resolve. When unset, auto-detects the active backend (`kube-prometheus-stack-prometheus.prometheus-operator.svc.cluster.local`, `vmauth-victoria-metrics-k8s-stack.victoria-metrics.svc.cluster.local`, or `vmsingle-victoria-metrics-k8s-stack.victoria-metrics.svc.cluster.local`). |
| `HEALTH_HTTP_CONTENT_URL` | cluster-health-probes | auto-detected (`/-/healthy` or `/health`) | http-content-check target (GET 200 + expected body); also the fallback host for the PromQL endpoint. When unset, auto-detects Prometheus then VMAuth then VMSingle per sweep. |
| `HEALTH_HTTP_EXPECTED_CONTENT` | cluster-health-probes | `Healthy` (Prom) / `OK` (VM) | Substring the http-content-check body must contain; follows the auto-detected backend when unset. |
| `HEALTH_PROMETHEUS_QUERY_URL` | cluster-health-probes | `""` (auto-detected / derived) | Full Prometheus/VictoriaMetrics `/api/v1/query` URL override; empty = auto-detect active backend (or derive `scheme://host` from explicit `HEALTH_HTTP_CONTENT_URL`). |
| `NODE_AUTOMATION_OBS_BACKEND` | cluster-health-probes / admission-webhook-guard / statefulset-ondelete-roller | `auto` | Observability backend mode (`auto`, `prometheus`, `victoriametrics`). `auto` probes Prometheus (`:9090/-/healthy`), VMAuth (`:8427/health`), then VMSingle (`:8428/health`) with a 2m TTL cache; invalid values warn and fall back to `auto`. |
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
| `NODE_AUTOMATION_APISERVER_NODE_REACHABILITY_ENABLED` | apiserver-node-reachability | on unless `"false"` | Registration gate — apiserver-dark check row. Registers the check that probes `/api/v1/nodes/<node>/proxy/healthz` per Ready worker; a probe failure persisting >=10m with a fresh `kube-node-lease` fences the node with `passiontech.dev/apiserver-unreachable` and deletes its `failurePolicy: Fail` webhook backend pods (capped 4/sweep, 30m cooldown, maintenance-mutex gated); >=half the fleet dark reports mesh-wide and fences nothing (2026-11-12 nonprod lanit-04 Linkerd webhook EOF incident). Requires cluster-health-probes. |
| `NODE_AUTOMATION_APF_SHIELD_ENABLED` | apf-selfheal-shield | on unless `"false"` | Registration gate — apf-shield check row. Registers the check that keeps the APF `PriorityLevelConfiguration/selfheal-critical` + `FlowSchema/selfheal-controllers` pair converged so self-heal traffic keeps priority during API storms; requires cluster-health-probes. |
| `NODE_AUTOMATION_APF_SHIELD_ENFORCE` | cluster-health-probes (watchdogs) | on unless `"false"` | Sub-feature gate — apf-selfheal-shield writes: `"false"` makes the check report-only (degraded gauge + FAIL on missing/drifted objects, zero creates/updates). Resolved at check construction. |
| `NODE_AUTOMATION_APF_SHIELD_NAMESPACE` | cluster-health-probes (watchdogs) | `node-ops` | apf-selfheal-shield — namespace of the `node-automation-controller` ServiceAccount subject in the FlowSchema rule. |
| `NODE_AUTOMATION_APF_SHIELD_EXTRA_SAS` | cluster-health-probes (watchdogs) | `""` | apf-selfheal-shield — comma-separated `namespace/name` ServiceAccounts appended to the `selfheal-controllers` FlowSchema subjects; malformed entries warn and are skipped. |
| `NODE_AUTOMATION_STATEFULSET_ROLLOUT_UNSTICK_ENABLED` | statefulset-rollout-unstick | on unless `"false"` | Registration gate — statefulset-rollout-unstick check row. Requires cluster-health-probes. |
| `NODE_AUTOMATION_STATEFULSET_ROLLOUT_HEAL_ENABLED` | cluster-health-probes (watchdogs) | on unless `"false"` | Sub-feature gate — statefulset-rollout-unstick pod delete: `"false"` leaves the check detect+gauge only. Resolved at check construction. |
| `NODE_AUTOMATION_DAEMONSET_ROLLOUT_WEDGE_ENABLED` | daemonset-rollout-wedge | on unless `"false"` | Registration gate — daemonset-rollout-wedge check row. Requires cluster-health-probes. |
| `NODE_AUTOMATION_DAEMONSET_ROLLOUT_HEAL_ENABLED` | cluster-health-probes (watchdogs) | on unless `"false"` | Sub-feature gate — daemonset-rollout-wedge pod delete: `"false"` leaves the check detect+gauge only. Resolved at check construction. |
| `NODE_AUTOMATION_CRONJOB_FORBID_ZOMBIE_ENABLED` | cronjob-forbid-zombie | on unless `"false"` | Registration gate — cronjob-forbid-zombie check row. Requires cluster-health-probes. |
| `NODE_AUTOMATION_CRONJOB_FORBID_KILL_RUNAWAY` | cluster-health-probes (watchdogs) | off unless `"true"` | Sub-feature gate — cronjob-forbid-zombie runaway-Job kill without the per-CronJob `passiontech.dev/max-active-duration` annotation; zombie-ref deletes are always on. Resolved at check construction. |
| `NODE_AUTOMATION_WRITE_STORM_BREAKER_ENABLED` | apiserver-write-storm-breaker | on unless `"false"` | Registration gate — apiserver-write-storm-breaker check row (P0.1: sustained API write rate + p99 latency → suspends storm-causing Flux Kustomizations/HelmReleases via `spec.suspend` behind `passiontech.dev/write-storm-suspended-by`, auto-restores when the storm clears). Requires cluster-health-probes. |
| `NODE_AUTOMATION_WRITE_STORM_HEAL_ENABLED` | apiserver-write-storm-breaker | on unless `"false"` | P0.1 heal sub-gate — `"false"` keeps storm detection, the `node_automation_apiserver_write_storm` gauge and the deduped Event running but stands down the Flux suspend/restore passes (detect-only mode). |
| `NODE_AUTOMATION_CRITICAL_DS_STARVATION_ENABLED` | critical-daemonset-starvation | on unless `"false"` | Registration gate — critical-daemonset-starvation check row (P0.2a: DaemonSet `desiredNumberScheduled==0` ≥5m or deprecated nodeSelector/nodeAffinity → compat-label patch on Nodes). Requires cluster-health-probes. |
| `NODE_AUTOMATION_COREDNS_FORWARD_SATURATION_ENABLED` | coredns-forward-saturation | on unless `"false"` | Registration gate — coredns-forward-saturation check row (P1.7b: `coredns_forward_max_concurrent_rejects_total` rate >0 ≥5m → stamps `passiontech.dev/coredns-boost-until` +30m and bumps `kube-system/coredns` replicas by the boost). Requires cluster-health-probes. |
| `NODE_AUTOMATION_HPA_SCALING_GUARD_ENABLED` | hpa-scaling-guard | on unless `"false"` | Registration gate — hpa-scaling-guard check row (P1.8: autoscaling/v2 HPA `AbleToScale=False`/`ScalingActive=False` ≥15m → cold-start rescue 0→minReplicas + isolated metrics-server pod bounce). Requires cluster-health-probes. |
| `NODE_AUTOMATION_DEPLOYMENT_ROLLOUT_WEDGE_ENABLED` | deployment-rollout-wedge | on unless `"false"` | Registration gate — deployment-rollout-wedge check row (P1.9: `ProgressDeadlineExceeded`/`ReplicaFailure` ≥20m → GC terminal pods, scale-0 stale ReplicaSets, persisted-cooldown template nudge). Requires cluster-health-probes. |
| `NODE_AUTOMATION_SUBPATH_CONFIG_DRIFT_ENABLED` | subpath-config-drift | on unless `"false"` | Registration gate — subpath-config-drift check row (P1.10: 30m SHA-256 census of subPath-mounted ConfigMap/Secret keys → ≥15m drift → `RestartTemplatePatch`; excludes system namespaces, DB-quorum labels, `passiontech.dev/subpath-reload-opt-out=true` (`true`/`1`/`yes`)). Requires cluster-health-probes. |
| `NODE_AUTOMATION_SERVICE_BLACKHOLE_ENABLED` | service-selector-blackhole | on unless `"false"` | Registration gate — service-selector-blackhole check row (detects ClusterIP/Headless Services with `spec.selector` and 0 Ready endpoints ≥10m due to `selector_zero_match` or `target_port_mismatch`). Requires cluster-health-probes. |
| `NODE_AUTOMATION_TOPOLOGY_ZONE_DEADLOCK_ENABLED` | topology-spread-zone-deadlock | on unless `"false"` | Registration gate — topology-spread-zone-deadlock check row (detects zones with 0 Ready uncordoned workers ≥10m blocking Pending pods on `topology.kubernetes.io/zone` constraints). Requires cluster-health-probes. |
| `NODE_AUTOMATION_TOPOLOGY_ZONE_RELAX_ENABLED` | cluster-health-probes (watchdogs) | on unless `"false"` | Sub-feature gate — relaxes `topology.kubernetes.io/zone` `DoNotSchedule` → `ScheduleAnyway` (with `passiontech.dev/topology-relaxed-by` stamp) on eligible Deployments / opted-in StatefulSets during a dead zone and auto-restores after zone recovery. Resolved at check construction. |
| `NODE_AUTOMATION_OBS_HEAD_SERIES_WARN` | cluster-health-probes (watchdogs) | `1500000` | observability-pipeline-guard — `max(prometheus_tsdb_head_series)` (Prometheus) or `max(vm_cache_entries{type="storage/tsid"})` (VictoriaMetrics) threshold triggering `prometheus_cardinality` degradation + top-5 culprit attribution. Resolved at check construction. |
| `NODE_AUTOMATION_OBS_HEAD_SERIES_GROWTH_PER_HOUR` | cluster-health-probes (watchdogs) | `200000` | observability-pipeline-guard — `max(deriv(prometheus_tsdb_head_series[15m])) * 3600` (Prometheus) or `max(deriv(vm_cache_entries{type="storage/tsid"}[15m])) * 3600` (VictoriaMetrics) growth threshold sustained for 2 consecutive cycles triggering `prometheus_cardinality` degradation. Resolved at check construction. |
| `NODE_AUTOMATION_ADMISSION_SECURITY_GUARD_ENABLED` | admission-security-guard | on unless `"false"` | Registration gate — admission-security-guard check row (audits externally exposed or un-isolated admission/conversion webhook Services and anonymous/unauthenticated RBAC bindings). Requires cluster-health-probes. |
| `NODE_AUTOMATION_ADMISSION_SEC_EXEMPT_SERVICES` | cluster-health-probes (watchdogs) | `""` | admission-security-guard — comma-separated `namespace/name` webhook Services exempted from exposure/NetworkPolicy audits; malformed entries warn and are skipped. Resolved at check construction. |
| `NODE_AUTOMATION_ADMISSION_SEC_ALLOW_ANON_ROLES` | cluster-health-probes (watchdogs) | `""` | admission-security-guard — comma-separated extra ClusterRole/Role names allowed for `system:anonymous` / `system:unauthenticated` subjects alongside `system:public-info-viewer`, `system:discovery`, `system:basic-user`. Resolved at check construction. |
| `NODE_AUTOMATION_CILIUM_POLICY_BGP_GUARD_ENABLED` | cilium-policy-bgp-guard | on unless `"false"` | Registration gate — cilium-policy-bgp-guard check row (detects CiliumNetworkPolicy/CiliumClusterwideNetworkPolicy apply errors >=10m and CiliumBGPNodeConfig peer non-established >=5m). Requires cluster-health-probes. |
| `NODE_AUTOMATION_SERVICE_TRAFFIC_POLICY_GUARD_ENABLED` | service-traffic-policy-guard | on unless `"false"` | Registration gate — service-traffic-policy-guard check row (detects externalTrafficPolicy=Local single-node concentration / unschedulable-only endpoints >=10m, stuck Terminating EndpointSlice entries, and passive missing_prestop gauge). Requires cluster-health-probes. |
| `NODE_AUTOMATION_PVC_LIFECYCLE_GUARD_ENABLED` | pvc-lifecycle-guard | on unless `"false"` | Registration gate — pvc-lifecycle-guard check row (detects Pending PVC deadlocks >=10m, Pod fsGroup recursive chown stalls >=5m, stale Released PVs, and failed VolumeSnapshots >2h). Requires cluster-health-probes. |
| `NODE_AUTOMATION_PV_RELEASED_MAX_AGE` | cluster-health-probes (storage/pvc) | `168h` | pvc-lifecycle-guard — maximum age of a non-terminating `Released` PersistentVolume before `node_automation_pv_released_stale` fires. Resolved at check construction. |
| `NODE_AUTOMATION_WORKLOAD_ADMISSION_BLOCK_ENABLED` | workload-admission-block-guard | on unless `"false"` | Registration gate — workload-admission-block-guard check row (detects ReplicaSet `ReplicaFailure=True` and under-replicated StatefulSet/DaemonSet with recent `FailedCreate` events >=5m). Requires cluster-health-probes. |
| `NODE_AUTOMATION_SPRAWL_HISTORY_GC_ENABLED` | cluster-health-probes (watchdogs/sprawl) | on unless `"false"` | Sub-feature gate — api-object-sprawl-report-gc extended history GC: `"false"` keeps `node_automation_api_object_sprawl_count` census + findings live without deleting >24h 0-replica ReplicaSets, orphan ControllerRevisions, or orphan SA-token Secrets. Resolved at check construction. |
| `NODE_AUTOMATION_GITOPS_MASS_PRUNE_GUARD_ENABLED` | gitops-mass-prune-guard | on unless `"false"` | Registration gate — gitops-mass-prune-guard check row (detects >40% inventory drops from >=10 resources on prune-enabled Flux Kustomizations and ArgoCD Applications, with opt-in Flux suspend via `passiontech.dev/mass-prune-guard: suspend`). Requires cluster-health-probes. |
| `NODE_AUTOMATION_IMAGE_RESILIENCE_AUDITOR_ENABLED` | image-resilience-auditor | on unless `"false"` | Registration gate — image-resilience-auditor check row (audits critical-namespace workloads for `imagePullPolicy: Always` and mutable/unpinned image tags). Requires cluster-health-probes. |
| `NODE_AUTOMATION_IMAGE_AUDIT_NAMESPACES` | cluster-health-probes (nodehealth) | `kube-system,node-ops,linkerd,cilium,prometheus-operator,victoria-metrics,cert-manager,flux-system,argocd,medik8s` | image-resilience-auditor — comma-separated namespaces whose Deployments, StatefulSets, DaemonSets, and standalone Pods are audited for mutable images and `imagePullPolicy: Always`. Resolved at check construction. |
| `NODE_AUTOMATION_IMAGE_RESILIENCE_FAIL_ON_RISK` | cluster-health-probes (nodehealth) | off unless `"true"` | Sub-feature gate — image-resilience-auditor verdict mode: default `"false"` emits `node_automation_workload_image_resilience_risk` while keeping the check `PASS`; `"true"` fails the check on findings. Resolved at check construction. |
| `NODE_AUTOMATION_VOLUMESNAPSHOT_LIFECYCLE_GUARD_ENABLED` | volumesnapshot-lifecycle-guard | on unless `"false"` | Registration gate — volumesnapshot-lifecycle-guard check row (detects stuck not-ready, errored, or terminating VolumeSnapshots and VolumeSnapshotContents past `NODE_AUTOMATION_VOLUMESNAPSHOT_MIN_AGE`, emits `node_automation_volumesnapshot_stuck`, and optionally bounces hung CSI `snapshot-controller` pods). Requires cluster-health-probes. |
| `NODE_AUTOMATION_VOLUMESNAPSHOT_MIN_AGE` | cluster-health-probes (storage/pvc) | `15m` | volumesnapshot-lifecycle-guard — minimum age (from `creationTimestamp` for not-ready/errored or `deletionTimestamp` for terminating) before a VolumeSnapshot or VolumeSnapshotContent triggers `node_automation_volumesnapshot_stuck`; `<=0` falls back to `15m`. Resolved at check construction. |
| `NODE_AUTOMATION_VOLUMESNAPSHOT_HEAL_ENABLED` | cluster-health-probes (storage/pvc) | on unless `"false"` | Sub-feature gate — volumesnapshot-lifecycle-guard controller bounce: `"false"` keeps detection, `node_automation_volumesnapshot_stuck`, and Warning Events live without evicting hung CSI `snapshot-controller` pods. Resolved at check construction. |
| `NODE_AUTOMATION_DRA_CLAIM_WEDGE_GUARD_ENABLED` | dra-claim-wedge-guard | on unless `"false"` | Registration gate — dra-claim-wedge-guard check row (detects wedged `resource.k8s.io/v1` `ResourceClaim`s — terminating stuck, unallocated stuck, zombie `reservedFor`, or dead-node allocation — auto-skipping cleanly when the API is absent). Requires cluster-health-probes. |
| `NODE_AUTOMATION_DRA_CLAIM_MIN_AGE` | cluster-health-probes (nodehealth) | `15m` | dra-claim-wedge-guard — minimum age before a stuck `ResourceClaim` emits `node_automation_dra_claim_wedged` and becomes eligible for remediation; `<=0` falls back to `15m`. Resolved at check construction. |
| `NODE_AUTOMATION_DRA_CLAIM_REMEDIATE_ENABLED` | cluster-health-probes (nodehealth) | on unless `"false"` | Sub-feature gate — dra-claim-wedge-guard remediation: `"false"` disables clearing all-dead `status.reservedFor` via `/status` merge patch and bouncing wedged DRA driver DaemonSet pods (detect + gauge + event only). Resolved at check construction. |
| `NODE_AUTOMATION_POD_RESIZE_WEDGE_GUARD_ENABLED` | pod-resize-wedge-guard | on unless `"false"` | Registration gate — pod-resize-wedge-guard check row (detects Pods with `PodResizePending=True` or `PodResizeInProgress=True` past `NODE_AUTOMATION_POD_RESIZE_MIN_AGE` and emits `node_automation_pod_resize_wedged`). Requires cluster-health-probes. |
| `NODE_AUTOMATION_POD_RESIZE_MIN_AGE` | cluster-health-probes (watchdogs) | `15m` | pod-resize-wedge-guard — minimum duration a `PodResizePending` or `PodResizeInProgress` condition must persist before emitting `node_automation_pod_resize_wedged` and becoming eligible for eviction. Resolved at check construction. |
| `NODE_AUTOMATION_POD_RESIZE_EVICT_ENABLED` | cluster-health-probes (watchdogs) | off unless `"true"` | Sub-feature gate — pod-resize-wedge-guard eviction: `"true"` enables PDB-safe eviction (up to 4/sweep, excluding system namespaces and static/DaemonSet/singleton pods) of `PodResizePending` (`Deferred`) pods so they can reschedule. Resolved at check construction. |
| `NODE_AUTOMATION_INGRESS_NGINX_RETIREMENT_GUARD_ENABLED` | ingress-nginx-retirement-guard | on unless `"false"` | Registration gate — ingress-nginx-retirement-guard check row (read-only audit detecting remaining `ingress-nginx` controller Pods, `IngressClass`es with `k8s.io/ingress-nginx`, and targeting `Ingress` resources via `node_automation_ingress_nginx_retirement_detected`). Requires cluster-health-probes. |

## CLI flags (`cmd/manager/main.go`)

| Flag | Default | Meaning |
|---|---|---|
| `-metrics-bind-address` | `:9115` | Address the Prometheus `/metrics` endpoint binds to. |
| `-health-probe-bind-address` | `:8081` | Address `/healthz` and `/readyz` bind to. |
| `-pprof-bind-address` | `127.0.0.1:9116` | Loopback-only address `/debug/pprof/*` binds to (empty disables the listener; `NODE_AUTOMATION_PPROF_BIND_ADDRESS` feeds the default). |
| `-version` | `false` | Print version and exit. |
| `-leader-elect` | `false` | Enable active/passive HA via a `coordination.k8s.io` Lease (required for >1 replica; `ReleaseOnCancel` hands the lease over on graceful shutdown). |
| `-leader-elect-lease-duration` | `0` | Time non-leaders wait before force-acquiring the Lease; `0` = controller-runtime default (15s). |
| `-leader-elect-renew-deadline` | `0` | Time the leader retries renewing before giving up; `0` = default (10s). |
| `-leader-elect-retry-period` | `0` | Interval between Lease renew/acquire attempts; `0` = default (2s). |
| `-modules` | `""` (all) | Comma-separated allowlist of registry ops names or `@group` selectors (see `internal/registry`) — only those modules wire runnables. Groups: `@system`, `@node`, `@apiserver`, `@janitors`, `@integration`, `@health`. Unknown names/groups abort boot; metric series are predeclared for the full registry regardless. |
| `-zap-*` | `zap.Options` defaults | Standard controller-runtime zap logging flags (`-zap-devel`, `-zap-encoder`, `-zap-log-level`, `-zap-stacktrace-level`, `-zap-time-encoding`). |
