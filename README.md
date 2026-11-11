# kubernetes-node-automation

[Moon](https://moonrepo.dev) monorepo for node lifecycle automation on
Kubernetes. Formerly `node-automation-controller` — the operator is now
one app in this workspace, alongside the per-node host agent.

## Apps

- [node-automation-controller](apps/node-automation-controller/README.md) — controller-runtime operator replacing the shell-operator Deployment + bash hooks for node lifecycle automation.
- [node-host-agent](apps/node-host-agent/README.md) — per-node agent (DaemonSet) for the kubernetes-node-automation stack.
- [webhook-dispatcher](apps/webhook-dispatcher/README.md) — GitHub org webhook fan-out to Concourse resource check webhooks (push/release/tag-create -> git, pull_request -> github-pr).

| App                               | Moon project                 | Kind                                                  | Image                                                   |
| --------------------------------- | ---------------------------- | ----------------------------------------------------- | ------------------------------------------------------- |
| `apps/node-automation-controller` | `node-automation-controller` | Deployment (controller-runtime operator)              | `ghcr.io/passiontech-global/node-automation-controller` |
| `apps/node-host-agent`            | `node-host-agent`            | DaemonSet (per-node agent)                            | `ghcr.io/passiontech-global/node-host-agent`            |
| `apps/webhook-dispatcher`         | `webhook-dispatcher`         | Deployment (GitHub webhook → Concourse check fan-out) | `ghcr.io/passiontech-global/webhook-dispatcher`         |

## Repository layout

```
.moon/                       moon workspace config + shared tasks
apps/
  node-automation-controller/  moon project (own go.mod, cliff.toml, .ko.yaml, Dockerfile)
  node-host-agent/             moon project (own go.mod, cliff.toml, Dockerfile)
  webhook-dispatcher/          moon project (own go.mod, cliff.toml, .ko.yaml, Dockerfile)
libs/
  hostkit/                   shared leaf module: envx, logx, httpx, timex, nodecond, fsx
  jinja/                     shared leaf module: mini-jinja2 evaluator (node-host-agent)
.github/workflows/
  ci.yml                         PR gate — moon ci on affected projects
  release-app.yml                reusable release pipeline
  release-<app>.yml              per-app release triggers
mise.toml                      tool pins: go, git-cliff, ko, golangci-lint, hadolint, moon
```

Each app is an independent Go module with its own dependencies, image
build (`ko`), and release cadence.

## Development

```sh
mise install                 # all tools pinned in mise.toml

moon query projects          # list workspace projects
moon run :format :vet :test  # shared tasks across all projects
moon run :lint-dockerfile    # hadolint — apps tagged `docker` only
moon run node-host-agent:build
moon run node-automation-controller:image   # ko build (needs KO_DOCKER_REPO)
```

Common tasks (`test`, `vet`, `format`) are defined once in
`.moon/tasks/all.yml` and inherited by every project;
`.moon/tasks/tag-docker.yml` adds `lint-dockerfile` (hadolint) to the
apps tagged `docker`; `build`/`image` live in each app's `moon.yml`. All
binaries come from mise — moon tasks run on the `system` toolchain.

A committed `go.work` covers all five modules (the three apps plus
`libs/hostkit` and `libs/jinja`), so `go` and gopls work
from the repo root. CI sets `GOWORK=off`, keeping release builds on
per-module dependency resolution.

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
