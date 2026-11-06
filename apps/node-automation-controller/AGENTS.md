# node-automation-controller

controller-runtime operator replacing the shell-operator Deployment +
bash hooks for node lifecycle automation. All logic is compiled in —
no shell, no `kubectl`/`jq`/`curl` forks. One binary runs 32 modules
grouped in six domain trees; the interface contract is Prometheus
metrics on `:9115/metrics` plus `/healthz`+`/readyz` on `:8081` (kept
byte-stable with the shell-operator alerts).

## Directory map

- `cmd/manager` — entrypoint. `main.go` parses flags (incl.
  `-modules name,@group` blast-radius allowlist and the leader-elect
  lease knobs), builds the informer cache shape, and hands
  `shared.Deps` to `registry.SetupModules`.
- `internal/shared` — the module contract: `Module`/`Deps` (registry
  row + injected clients), `Periodic`/`AddPeriodic` (crontab
  replacement, panics recovered into run errors),
  `CountReconcile`/`ReconcileFunc` (reconciler error accounting),
  `SetupWithConfig` (parse-knobs-before-gate ordering), `Clock`.
- `internal/registry` — the single `[]shared.Module` registration
  table + `-modules` allowlist resolution + the boot wiring loop.
  Adding a module = one import + one row here.
- `internal/platform/*` — leaf libraries: `envx` (env knobs/gates),
  `kube` (paged lists, node/pod/patch helpers, the GVR registry,
  annotation keys + timestamp stamps, maintenance mutex),
  `state` (Cooldown/FirstSeen/Seen/Streak/Gauge ledgers),
  `heal` (cooldown → maintenance-mutex → UID-delete → stamp).
- `internal/metrics`, `internal/promq` — leaf packages: the metric
  vectors (per-domain files, ops-contract series live here forever)
  and the Prometheus instant-query client.
- `internal/{apiserver,health,integration,janitor,node,system}/*` —
  the 32 modules, one package per module grouped by domain. Health
  checks live under `health/<sub>/` on top of `health/probefw` with
  the `clusterhealthprobes.checkDefs` roster as sweep order.
- `internal/testutil` — shared fakes (StubManager, real-scheme
  dynamic fake + GVK table, `PeriodicContract` setup assertions).
- `internal/envdoc` — test-only package keeping `docs/env.md` honest:
  it walks the source for every env var and fails on undocumented
  knobs.

## Layering (enforced by depguard in the root .golangci.yml)

- `internal/platform`, `internal/metrics`, `internal/promq` are
  leaves: they must NEVER import shared/registry/testutil or a domain
  module (push shared logic down into platform).
- `internal/shared` may use metrics/platform but never a domain
  module or the registry.
- Domain trees are self-contained: `health/*` may not import
  `integration/*`, nothing imports `internal/registry` back, and
  non-test module code may not import `internal/testutil`
  (`health/probetest` is the one sanctioned exception — it IS test
  scaffolding shared across sibling packages).
- `internal/testutil` stays generic; `cmd/manager` may import
  anything.

## Conventions

- Every file opens with a `// file.go — purpose` header; comments
  explain WHY and cite parity with the ported bash hooks / the
  incident a check covers.
- Ops contract is byte-stable: registry `Name`/`Group` strings,
  queue-label values, metric names, and annotation/taint keys may
  never change value — keys live as consts in
  `internal/platform/kube/annos.go`.
- Error accounting: `Periodic.Start`/`CountReconcile` IncError every
  error the run RETURNS, so module code must never IncError an error
  it returns (double-count) — IncError is only for tolerated
  sub-failures the run absorbs (log + continue).
- Deletion is always UID-preconditioned (`kube.UIDDeleteOptions`)
  and destructive action is gated on `kube.MaintenanceActive`,
  failing closed when unverifiable.
- Env: registration gates live ONLY in the registry's `GateEnv`
  column (arrive as `Deps.Disabled`); run knobs are read inside
  `Setup` via `envx.*` — modules with knobs use
  `shared.SetupWithConfig` so parse warnings fire even when gated
  off. `docs/env.md` must document every knob (envdoc test enforces).
- Test seams: `now shared.Clock` (zero value = system time),
  `probeFn`/`dnsFn`/`httpClient` fields for paths the fake clientset
  cannot serve; ledgers are zero-value-ready so literal-constructed
  fixtures work.
- Reads go through the direct clientset `d.CS` (RBAC has no watch on
  most types); the informer cache only covers the few types with
  explicit watches — see `buildCacheOptions` in main.go.

## Verify

```sh
cd apps/node-automation-controller
go build ./... && test -z "$(gofmt -l .)" && go vet ./... && \
  go test ./... && golangci-lint run ./...
```

Moon equivalents (shared tasks come from .moon/tasks/all.yml):

```sh
moon run node-automation-controller:test \
  node-automation-controller:vet \
  node-automation-controller:format \
  node-automation-controller:lint
```

## Commits

Conventional commits scoped to the app —
`refactor(node-automation-controller): ...` (also `feat`/`fix`/...).
git-cliff drives release notes off these messages, so keep the scope
exact.
