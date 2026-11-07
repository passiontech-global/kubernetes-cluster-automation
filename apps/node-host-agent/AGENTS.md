# node-host-agent

Per-node agent for the kubernetes-node-automation stack. Ships two
ways from one binary: a DaemonSet pod on every cluster node and a
standalone systemd service on out-of-cluster hosts (`--standalone` /
`NODE_HOST_AGENT_STANDALONE=1`, e.g. the units hubsync writes). The
interface contract is Prometheus metrics on `:9115/metrics` plus
`/healthz`+`/readyz` on the probe port — `:8081` in pod mode, `:8091`
on standalone targets (hubsync picks 8091 because lixo-fabric owns
8081 there). All periodic subsystems are env-gated behind
`NODE_HOST_AGENT_ENABLE_*` knobs.

## Directory map

- `cmd/agent` — entrypoint. `main.go` parses flags/env and builds the
  agent config; `cli.go` is the argv[1] subcommand dispatch table
  (the table IS the usage text; runs before `flag.Parse`);
  `wiring.go` is the subsystem registry — one `Descriptor` per
  subsystem, table order IS startup order. `localbin.go`, `sigctx.go`
  hold small seams lifted out of main.
- `internal/agent` — the runtime: shared `prometheus.Registry`,
  metrics/probe HTTP servers, and the subsystem supervisor
  (`Subsystem` = `Name() + Run(ctx)`, a blocking loop).
- `internal/envnames` — the single source of truth for the
  `NODE_HOST_AGENT_*` env contract: every env var name the binary
  reads is declared once as an `Env*` const (files split per
  subsystem domain, `envnames_<subsystem>.go`; shared/core knobs
  and the `ENABLE_*` gates live in `envnames.go`). Leaf package —
  call sites reference `envnames.EnvX`, never the literal.
- `libs/hostkit` (repo root, separate Go module wired via replace +
  go.work) — shared leaf libraries that used to live here:
  `envx` (env knobs/Mode/Knob tables), `logx` (named slog loggers),
  `timex` (settable clock seam), and `jinja` (the mini-Jinja2
  evaluator + ordered-map/YAML values behind vars-file resolution).
- `internal/platform/*` — leaf libraries: cycle (period loop),
  checks (check-group dispatch),
  hoststate (`state-*`/`last-*` latch files), hostexec, hostutil,
  systemd, watchdogconf, probee, procfs, journalwatch, promfile,
  kmsg, pagecache, sshclient.
- `internal/subsystem/*` — the 12 periodic subsystems (sweeper,
  concoursecache, apiprober, hostmetrics, workerhygiene, nethealth,
  janitor, nodereporter, controllerhygiene, hostconfig, hubsync,
  kinedb). Convention: `Config` struct + `EnvDeps` (non-env inputs) +
  `ConfigFromEnv(EnvDeps) Config` + `New(cfg, reg)`.
- `internal/domain/*` — importable domain libraries shared by
  subsystems and ops (etcdmaint, eventpurge, topology): the
  `Run(ctx, Config, ...)`-style logic behind a one-shot op that a
  periodic subsystem also drives (topology is the inter-DC
  vars-files → derived-topology pass consumed by hostconfig,
  hubsync, workerhygiene, and ops/nebulasign). Domain pkgs sit
  above platform (they may use hostexec/hostkit) and below
  subsystem/ops — they must not import either.
- `internal/ops/*` — one-shot subcommand packages: thin
  `Cmd(ctx, args) int` wrappers (exit 0 clean / 1 runtime / 2 usage)
  over internal/domain libs (evpurge -> domain/eventpurge,
  etcdrescue -> domain/etcdmaint) or, for self-contained ops whose
  domain logic nobody else reuses, the logic lives inside the Cmd
  package itself (concourseinit, nebulasign). Ops MAY import
  internal/domain and internal/subsystem (ops/kinecheckdb wraps
  subsystem/kinedb; hostconverge -> hostconfig; k0sdrift ->
  hostmetrics) — the arrow is one-directional: subsystem must NOT
  import ops.
- `internal/testutil` — shared fakes/fixture builders for the
  internal test suites.
- `internal/subsystem/workerhygiene/wdepstest` — exported fixture
  builder (`Fixture` + `wdepstest.Check[T]` accessor) so the domain
  packages' external `package X_test` files can drive a full
  `*workerhygiene.Hygiene` without importing the parent package.

## Layering (enforced by depguard in the root .golangci.yml)

- `internal/envnames` is a leaf: it must NEVER import another
  package in this module — the const values ARE the contract.
- `internal/platform` is a leaf: it must NEVER import
  `internal/domain`, `internal/subsystem`, `internal/agent`, or
  `internal/ops` (prefix-denied, so subpackages count).
- `internal/domain` may import platform + libs/hostkit only — it
  must not import `internal/subsystem`, `internal/ops`,
  `internal/agent`, or `cmd`.
- `internal/agent` must not import `internal/domain`,
  `internal/subsystem`, or `internal/ops` — subsystems get wired in
  `cmd/agent`, not imported by the runtime.
- `internal/subsystem` must not import `internal/ops` (ops are Cmd
  wrappers, not a library layer). `internal/ops` may import
  `internal/domain` + `internal/subsystem` — that direction is the
  only ops<->subsystem edge allowed. `cmd/agent` may import
  anything.

## Conventions

- Every file opens with a `// file.go — purpose` header; comments
  explain WHY and cite parity with the shell modules each package
  ports (e.g. "module 13 owned this latch").
- Env surface: each package declares `envx.Knob` tables applied via
  `envx.Apply`; user-facing vars use the `NODE_HOST_AGENT_*` prefix
  and the NAME is always an `internal/envnames` const
  (`envnames.EnvFoo`), never a literal — the envnames package is
  the env contract. `NODE_HOST_AGENT_ENABLE_*` is tri-state —
  `envx.ModeEnv` + `envx.Mode{On,Off,Auto}`; ModeAuto resolves via
  the Descriptor's `Auto` func (e.g. controllerhygiene iff
  k0scontroller.service exists).
- Check dispatch goes through `platform/checks.Group` — declared
  check order and group order are LOAD-BEARING (state latch
  producers/consumers assume it).
- Watchdog files contract: `state-<name>` latches and `last-*`
  rate-limit budgets live in one dir behind `hoststate.Store`
  (ports lib.sh state_enter/state_exit semantics).
- Every package with logging has `logging.go` exposing
  `logger() *slog.Logger` via `logx.For("<pkg>")` — resolution is
  per call on purpose.
- Ops subcommands keep flag parsing + dispatch in `Cmd` and reusable
  domain logic in `internal/domain/<name>` so subsystems can share it
  without importing a CLI package (domain/eventpurge vs ops/evpurge
  is the pattern). Ops whose logic nobody else reuses keep it
  self-contained inside their own package (concourseinit,
  nebulasign).

## Verify

```sh
cd apps/node-host-agent
go build ./... && test -z "$(gofmt -l .)" && go vet ./... && \
  go test -race ./... && golangci-lint run ./... && hadolint Dockerfile
```

Moon equivalents (test/vet/format/lint come from .moon/tasks/all.yml —
test is exactly `go test -race ./...`; lint-dockerfile comes from
.moon/tasks/tag-docker.yml):

```sh
moon run node-host-agent:test node-host-agent:vet \
  node-host-agent:format node-host-agent:lint \
  node-host-agent:lint-dockerfile
```

## Commits

Conventional commits scoped to the app — `refactor(node-host-agent): ...`
(also `feat`/`fix`/...). git-cliff drives release notes off these
messages, so keep the scope exact.
