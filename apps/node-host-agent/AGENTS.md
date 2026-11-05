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
- `internal/platform/*` — leaf libraries: envx (env knobs/Mode),
  logx (slog), cycle (period loop), checks (check-group dispatch),
  hoststate (`state-*`/`last-*` latch files), hostexec, hostutil,
  systemd, watchdogconf, probee, procfs, journalwatch, promfile,
  kmsg, pagecache, topology, jinja, sshclient.
- `internal/subsystem/*` — the 12 periodic subsystems (sweeper,
  concoursecache, apiprober, hostmetrics, workerhygiene, nethealth,
  janitor, nodereporter, controllerhygiene, hostconfig, hubsync,
  kinedb). Convention: `Config` struct + `EnvDeps` (non-env inputs) +
  `ConfigFromEnv(EnvDeps) Config` + `New(cfg, reg)`.
- `internal/ops/*` — one-shot subcommand packages: thin
  `Cmd(ctx, args) int` wrappers (exit 0 clean / 1 runtime / 2 usage)
  over domain libs like etcdmaint, eventpurge. subsystem <-> ops
  cross-imports are INTENTIONAL: domain logic usable by both a
  periodic subsystem and a one-shot op lives in the lower layer
  (ops/kinecheckdb wraps subsystem/kinedb; controllerhygiene reuses
  ops/etcdmaint+eventpurge).
- `internal/testutil` — shared fakes/fixture builders for the
  internal test suites.

## Layering (enforced by depguard in the root .golangci.yml)

- `internal/platform` is a leaf: it must NEVER import
  `internal/subsystem`, `internal/agent`, or `internal/ops`
  (prefix-denied, so subpackages count).
- `internal/agent` must not import `internal/subsystem` or
  `internal/ops` — subsystems get wired in `cmd/agent`, not
  imported by the runtime.
- `internal/subsystem` <-> `internal/ops`: allowed both ways (see
  above). `cmd/agent` may import anything.

## Conventions

- Every file opens with a `// file.go — purpose` header; comments
  explain WHY and cite parity with the shell modules each package
  ports (e.g. "module 13 owned this latch").
- Env surface: each package declares `envx.Knob` tables applied via
  `envx.Apply`; user-facing vars use the `NODE_HOST_AGENT_*` prefix.
  `NODE_HOST_AGENT_ENABLE_*` is tri-state — `envx.ModeEnv` +
  `envx.Mode{On,Off,Auto}`; ModeAuto resolves via the Descriptor's
  `Auto` func (e.g. controllerhygiene iff k0scontroller.service
  exists).
- Check dispatch goes through `platform/checks.Group` — declared
  check order and group order are LOAD-BEARING (state latch
  producers/consumers assume it).
- Watchdog files contract: `state-<name>` latches and `last-*`
  rate-limit budgets live in one dir behind `hoststate.Store`
  (ports lib.sh state_enter/state_exit semantics).
- Every package with logging has `logging.go` exposing
  `logger() *slog.Logger` via `logx.For("<pkg>")` — resolution is
  per call on purpose.
- Ops subcommands keep flag parsing + dispatch in `Cmd` and domain
  logic in an importable sibling package so subsystems can reuse it
  (eventpurge vs evpurge is the pattern).

## Verify

```sh
cd apps/node-host-agent
go build ./... && test -z "$(gofmt -l .)" && go vet ./... && \
  go test -race ./... && golangci-lint run ./...
```

Moon equivalents (test/vet/format/lint come from .moon/tasks/all.yml;
test is exactly `go test -race ./...`):

```sh
moon run node-host-agent:test node-host-agent:vet \
  node-host-agent:format node-host-agent:lint
```

## Commits

Conventional commits scoped to the app — `refactor(node-host-agent): ...`
(also `feat`/`fix`/...). git-cliff drives release notes off these
messages, so keep the scope exact.
