# node-automation-controller

controller-runtime operator replacing the shell-operator Deployment +
bash hooks for node lifecycle automation. All logic is compiled in —
no shell, no `kubectl`/`jq`/`curl` forks. One binary runs 35 modules
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
  `SetupWithConfig`/`SetupNoConfig` (parse-knobs-before-gate
  ordering — every gated Setup goes through one of them, never a
  hand-rolled `if d.Disabled`), `Clock` (alias of
  `libs/hostkit/timex.Clock`).
- `internal/registry` — the single `[]shared.Module` registration
  table + `-modules` allowlist resolution + the boot wiring loop.
  Adding a module = one import + one row here.
- `internal/platform/*` — leaf libraries: `kube` (paged lists,
  node/pod/patch helpers, the GVR registry, annotation keys +
  timestamp stamps, maintenance mutex),
  `state` (Cooldown/FirstSeen/Seen/Streak/Gauge ledgers),
  `heal` (cooldown → maintenance-mutex → UID-delete → stamp;
  `PersistedCooledDown`/`StampPersisted` for the wider-of
  in-RAM+annotation cooldown), `reap` (the janitor
  collect-cap-confirm-UID-delete sweep skeleton),
  `testhelp` (leaf-level k8s fakes — importable by platform tests,
  which `internal/testutil` cannot reach).
- `internal/metrics`, `internal/promq` — leaf packages: the metric
  vectors (ops-contract and multi-consumer series live here forever;
  a single-check series colocates as a private var + `init()`
  registration inside the check file that consumes it) and the
  Prometheus instant-query client.
- `internal/{apiserver,health,integration,janitor,node,system}/*` —
  the 35 modules, one package per module grouped by domain. Health
  checks live under `health/<sub>/` on top of `health/probefw` with
  the `clusterhealthprobes.checkDefs` roster (plus the CheckReg
  registry rows' contributions collected into `Deps.CheckRegs`) as
  sweep order.
  `apiserver/webhookguard` is the one module with subpackages —
  `circuitbreaker`, `guardstate`, `orphansweep`, `unmeshed` are leaf
  duties the facade's single `Setup`/sweep orchestrates (one
  registry row, `errors.Join` of the four duty errors).
- `internal/testutil` — shared fakes (StubManager, `PeriodicContract`
  setup assertions) plus re-export shims over `platform/testhelp`
  (probe clientset, CRD-aware dynamic fake, `Unstructured`). Domain
  tests keep importing `testutil`; platform tests use `testhelp`
  directly.
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
- Deletion is always UID-preconditioned (`kube.UIDDeleteOptions`,
  incl. `policyv1.Eviction{DeleteOptions}`). Destructive action on
  LIVE workloads (pod deletes, restarts, evictions) gates on the
  maintenance mutex via `heal.AllowedV` — fail closed, an
  unverifiable check IncErrors the queue; the verdict memoizes per
  `kube.Verdict` field. Garbage collection of terminal/orphan
  objects (evicted pods, failed jobs, orphan CRs/EndpointSlices) is
  exempt — the mutex defers heal/restart churn, not cleanup.
- Sweep loops: janitor-style collect → cap → (Confirm) →
  UID-delete → IncError-and-continue goes through `reap.Sweep`;
  persistence windows go through `state.FirstSeenLedger` (health
  checks: `probefw.Persisted`); emitted-gauge lifecycle through
  `state.GaugeLedger` (`Set`/`Reconcile`+`vec.DeleteLabelValues`) —
  never `map[string]bool` + `SplitN` key reassembly.
- Env: registration gates live ONLY in the registry's `GateEnv`
  column (arrive as `Deps.Disabled`); run knobs are read inside
  `Setup` via `envx.*` — modules with knobs use
  `shared.SetupWithConfig`, modules without use
  `shared.SetupNoConfig`, so parse warnings fire even when gated
  off and no module hand-rolls `if d.Disabled`. Reading env inside
  a run/sweep is a bug — the ONE sanctioned
  exception is webhookguard's `WEBHOOK_CIRCUIT_BREAKER_ENABLED` /
  `UNMESHED_POD_REMEDIATION_ENABLED`, deliberately hot-reloaded per
  sweep as an ops lever. `os.Getenv`/`os.LookupEnv` is depguard-denied
  under `internal/` (envdoc also scans for it). `docs/env.md` must
  document every knob (envdoc test enforces).
- Test seams: `now shared.Clock` (alias of `libs/hostkit/timex.Clock`;
  zero value = system time),
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
  go test ./... && golangci-lint run ./... && hadolint Dockerfile
```

Moon equivalents (test/vet/format/lint come from .moon/tasks/all.yml;
lint-dockerfile from .moon/tasks/tag-docker.yml):

```sh
moon run node-automation-controller:test \
  node-automation-controller:vet \
  node-automation-controller:format \
  node-automation-controller:lint \
  node-automation-controller:lint-dockerfile
```

## Commits

Conventional commits scoped to the app —
`refactor(node-automation-controller): ...` (also `feat`/`fix`/...).
git-cliff drives release notes off these messages, so keep the scope
exact.
