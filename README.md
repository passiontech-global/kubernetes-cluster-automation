# node-automation-controller

Lightweight Go operator (`sigs.k8s.io/controller-runtime`) that replaces
the `shell-operator` Deployment + 10 bash hooks in
[passiontech-fluxcd](https://github.com/passiontech-global/passiontech-fluxcd)
(`infrastructure/base/node-ops/node-ops-operator`).

All logic is compiled in — no shell, no `kubectl`/`jq`/`curl`/`nslookup`
forks, no hook ConfigMap. The image is `distroless/static:nonroot`
(~18MB, ~20–35MiB RAM).

## Modules (ported 1:1 from the bash hooks)

| Module | Mode | Cadence | What it does |
| --- | --- | --- | --- |
| `konnectivity-patcher` | watch DS + requeue | 15m | Re-assert `system-node-critical` + resource requests on `ds/konnectivity-agent` (k0s stack applier reverts them). |
| `cilium-taint-reaper` | watch Node/Pod + requeue | 10m | Remove stale `node.cilium.io/agent-not-ready` taints once the cilium pod on the node is Running+Ready. **Opt-in:** `CILIUM_TAINT_REAPER_ENABLED=true`. |
| `descheduler-storm-gate` | watch Node + requeue | 5m | Scale `deploy/descheduler` to 0 while any node is NotReady / has a storm condition or `node.ops/*` taint; restore to 1 when clear. |
| `node-labeler` | watch Node + requeue | 30m | Assert `node-role.kubernetes.io/worker` + labels listed in `$NODE_LABELER_CONFIG_PATH` (default `/etc/node-labeler/labels.txt`). |
| `fluent-bit-config-roller` | watch Secret + requeue | 30m | Roll `ds/fluent-bit` when `fluent.io/config-hash` drifts from `passiontech.dev/rolled-config-hash`. **Opt-in:** `FLUENTBIT_ROLLER_ENABLED=true`. |
| `coredns-stale-watchdog` | periodic | 1m | Zero-write 3-layer stale-watch detection (pod logs → active DNS freshness → `:9153` panics); deletes stale pods or restarts the deployment. Cooldown 30m, storm-gated. |
| `kubelet-liveness-reaper` | periodic | 2m | Probe `/api/v1/nodes/<n>/proxy/healthz` ×4; taint `node.ops/kubelet-unresponsive` when kubelet is wedged but the lease still renews. |
| `admission-webhook-guard` | periodic | 5m | Remove webhook entries whose `clientConfig.service.namespace` was deleted (fail-closed apiserver guard). |
| `partition-pod-evictor` | periodic | 5m | Taint `node.ops/network-partitioned` + evict `flux-system` pods off nodes with NWPD partition conditions (>10m). |
| `failed-jobs-janitor` | periodic | 60m | Delete Jobs `Failed` for >24h (cap 50/run). |
| `converge-trigger` | watch ConfigMap (node-ops) | event | Create converge Jobs from CronJob templates when mounted ConfigMaps change (15s debounce, 120s dedupe). |

## Interface contract

- Metrics: `:9115/metrics` — emits `shell_operator_hook_run_errors_total{queue}`
  (backwards-compatible with existing PrometheusRule alerts) plus
  `node_automation_reconcile_errors_total{controller}` and the default
  controller-runtime/workqueue metrics.
- Probes: `:8081/healthz`, `:8081/readyz`.
- Flags: `--metrics-bind-address` (default `:9115`),
  `--health-probe-bind-address` (default `:8081`), `--version`.
- Env: `CILIUM_TAINT_REAPER_ENABLED`, `FLUENTBIT_ROLLER_ENABLED`,
  `NODE_LABELER_CONFIG_PATH`.

## Development

```sh
mise install            # go + git-cliff
go test -race ./...
go build -o bin/node-automation-controller ./cmd/manager
```

Releases: push conventional commits to `main` —
`.github/workflows/release.yml` runs `git-cliff` for the semver bump,
builds the static binary, pushes
`ghcr.io/passiontech-global/node-automation-controller:{version,latest}`
and creates the GitHub Release.
