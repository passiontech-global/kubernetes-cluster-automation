# kubernetes-cluster-automation

Moonrepo monorepo for node lifecycle automation on Kubernetes: three
apps plus two shared leaf libraries, five independent Go modules wired
by a committed `go.work` (CI sets `GOWORK=off` — deps resolve
per-module there).

## Module map

| Module | Kind | Owns |
|--------|------|------|
| `apps/node-automation-controller` | Go module | controller-runtime operator: 32 modules + 52-check cluster-health sweep |
| `apps/node-host-agent` | Go module | per-node agent (DaemonSet + standalone systemd unit) |
| `apps/webhook-dispatcher` | Go module | GitHub org webhook → Concourse check fan-out |
| `libs/hostkit` | Go module, stdlib-only leaf | `envx` (env knobs), `envdoc` (AST env-coverage scanner), `logx`, `timex`, `nodecond`, `fsx` (atomic file IO), `ledger` (cooldown/first-seen/streak/seen ledgers), `httpx` (+`pprofx`) |
| `libs/jinja` | Go module, leaf | mini-Jinja2 evaluator + ordered-map/YAML values (only dep: `go.yaml.in/yaml/v3`) |

Dependency direction is strictly downward: apps → libs/hostkit,
libs/jinja. The leaf modules never import apps or each other
(depguard `hostkit-stdlib-only`/`jinja-allowed-deps` strict
allow-lists in `.golangci.yml`).
Prometheus/k8s types never leak into hostkit — apps inject them
through seams (httpx handlers, timex clocks, envx warn sink).

## Per-module docs

Each module carries its own `AGENTS.md` with the authoritative
directory map, layering rules, conventions, and verify commands —
read it before editing that module:

- `apps/node-automation-controller/AGENTS.md`
- `apps/node-host-agent/AGENTS.md`
- `apps/webhook-dispatcher/AGENTS.md`
- `libs/hostkit/AGENTS.md`
- `libs/jinja/AGENTS.md`

## Ops contracts (never change values)

- Prometheus metric names, label names/values, queue labels.
- Check/subsystem execution ordering (registry/wiring table order IS
  the contract).
- Annotation/taint keys, `UIDDeleteOptions` on deletes, node-watchdog
  latch paths, NPD log formats (`STATE-ENTER:`/`STATE-EXIT:`/`ACTION`).
- Env var names are contracts — documented in each app's `docs/env.md`
  (envdoc tests enforce coverage).

## Verify

```sh
# per module (moon equivalents: moon run <project>:test :vet :format :lint)
for m in libs/hostkit libs/jinja apps/webhook-dispatcher \
         apps/node-automation-controller apps/node-host-agent; do
  (cd "$m" && gofmt -l . && go vet ./... && go test -race ./...)
done
golangci-lint run ./...        # repo root — depguard layering rules
hadolint apps/*/Dockerfile
moon run :lint :vet :test :build
```

Release: per-app, tag `<app>/vX.Y.Z`; workflows under
`.github/workflows/release-<app>.yml` fire on `apps/<app>/**` (plus
the `libs/hostkit` subpackages each app actually imports — keep those
globs in sync when adding hostkit imports).
