# kubernetes-node-automation

[Moon](https://moonrepo.dev) monorepo for node lifecycle automation on
Kubernetes. Formerly `node-automation-controller` — the operator is now
one app in this workspace, alongside the per-node host agent.

## Apps

| App | Moon project | Kind | Image |
| --- | --- | --- | --- |
| `apps/node-automation-controller` | `node-automation-controller` | Deployment (controller-runtime operator) | `ghcr.io/passiontech-global/node-automation-controller` |
| `apps/node-host-agent` | `node-host-agent` | DaemonSet (per-node agent) | `ghcr.io/passiontech-global/node-host-agent` |
| `apps/webhook-dispatcher` | `webhook-dispatcher` | Deployment (GitHub webhook → Concourse check fan-out) | `ghcr.io/passiontech-global/webhook-dispatcher` |

### node-automation-controller

Lightweight Go operator (`sigs.k8s.io/controller-runtime`) that replaces
the `shell-operator` Deployment + 10 bash hooks previously deployed at
`infrastructure/base/node-ops/node-ops-operator`.

All logic is compiled in — no shell, no `kubectl`/`jq`/`curl`/`nslookup`
forks, no hook ConfigMap. The image is `distroless/static:nonroot`
(~18MB, ~20–35MiB RAM).

#### Modules (ported 1:1 from the bash hooks)

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
| `concourse-workdir-janitor` | periodic | 30m | Prune shared-cache via exec + sequential land/drain/wipe of `concourse-worker` pods when work-dir exceeds the 100GiB cap or nodefs crosses 60%. **Opt-in:** `CONCOURSE_JANITOR_ENABLED=true`. |

#### Interface contract

- Metrics: `:9115/metrics` — emits `shell_operator_hook_run_errors_total{queue}`
  (backwards-compatible with existing PrometheusRule alerts) plus
  `node_automation_reconcile_errors_total{controller}` and the default
  controller-runtime/workqueue metrics.
- Probes: `:8081/healthz`, `:8081/readyz`.
- Flags: `--metrics-bind-address` (default `:9115`),
  `--health-probe-bind-address` (default `:8081`), `--version`.
- Env: `CILIUM_TAINT_REAPER_ENABLED`, `FLUENTBIT_ROLLER_ENABLED`,
  `NODE_LABELER_CONFIG_PATH`, `CONCOURSE_JANITOR_ENABLED`,
  `CONCOURSE_JANITOR_SCRIPT_PATH` (default
  `/etc/concourse-janitor/prune.sh`).

### node-host-agent

Per-node agent intended to run as a DaemonSet. Currently a skeleton:
serves `node_host_agent_info`/`node_host_agent_uptime_seconds` on
`:9115/metrics`, probes on `:8081/healthz` + `:8081/readyz`, `--version`,
graceful shutdown. Node identity comes from the downward API
(`NODE_NAME`, `POD_NAME`, `POD_NAMESPACE`).

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

| Var | Required | Default | Purpose |
| --- | --- | --- | --- |
| `GITHUB_WEBHOOK_SECRET` | yes | — | HMAC key for `X-Hub-Signature-256` |
| `CI_WEBHOOK_TOKEN` | yes | — | Concourse check-webhook token (`webhook_token=…`) |
| `LOCAL_USERS` | yes | — | Concourse basic auth, `user:password` |
| `CONCOURSE_URL` | | `http://concourse-web:8080` | ATC base URL |
| `CONCOURSE_TEAM` | | `main` | Team to index and fan out to |
| `LISTEN_ADDR` | | `:8080` | Listen address |

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
