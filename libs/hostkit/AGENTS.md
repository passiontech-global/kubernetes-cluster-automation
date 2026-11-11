# libs/hostkit

Shared leaf module for the host-agent stack: small, dependency-free
contracts that more than one app (or subsystem) needs. Shared via
`go.work` + `replace`, one Go module, `go.sum` stays empty.

## Package map

| Package  | Owns |
|----------|------|
| `envx`   | Env-knob getters: the lenient family (`String`, `Bool`, `Int`, `Duration`, `List`, the `*Knob` tables) and the strict family (`Getenv*`, `Gate`) ported from node-automation-controller's retired `internal/platform/envx`. Owns the `Warnf` diagnostic sink and its atomic rebind (`SetWarnf`). |
| `logx`   | Named slog loggers: `logx.For(component)` resolves and caches `slog.Default().With("logger", name)` per call. |
| `timex`  | The `Clock` seam (`nowFn func() time.Time` with nil-safe `Now()`), shared by every sweep/subsystem for tests. |
| `nodecond` | The single source of truth for NodeCondition names written by the agent and consumed by the controller; untyped strings so no k8s import. |
| `fsx`    | Atomic file writer (`WriteFile`): same-dir staging → fsync → chmod → rename → optional dir fsync. Ported verbatim from the agent's `hostutil.WriteAtomic` so hostutil can delegate without behavior drift. |
| `httpx`  | Bind-then-serve lifecycle for probe/metrics endpoints (`New` binds synchronously, `Serve`, `Shutdown` with a drain budget, `Timeout` per-route wrapper). Handler — including any promhttp mux — is injected by the caller. |

## The stdlib-only leaf invariant

This module is the bottom of the import graph: **Go stdlib only** — no
`apps/*`, no `libs/jinja`, no third-party modules. `go.mod` carries zero
requires and `go.sum` stays empty; the depguard rule
`hostkit-is-leaf` in the repo-root `.golangci.yml` enforces the import
ban (nodecond stays string-typed for exactly this reason — it must not
import `k8s.io/api`).

Consequences:

- Anything that needs a third-party dep (prometheus client,
  controller-runtime, k8s.io) lives app-local; the app injects it into
  the hostkit seam instead (httpx handlers, timex Clock, envx Warnf).
- Anything that only one app consumes stays in that app's
  `internal/` until a second consumer appears — hostkit is the shared
  floor, not a dumping ground. Promote by porting the code verbatim
  (keep the WHY comments) and updating every callsite in the same
  change; consumer adoption inside an app may follow in a later wave
  only if the app-side shape is kept compiling (see the envx.Warnf
  note below).

## Concurrency contract

- **logx**: `For` is safe from any goroutine, including package-var
  initializers. Hot path is one `atomic.Pointer` load over an
  immutable copy-on-write snapshot; misses take a build mutex, copy
  the current snapshot and publish by pointer swap, so racing first
  builds of the same name still return the identical `*slog.Logger`.
  A `slog.SetDefault` swap invalidates the snapshot on the next call.
  Never mutate a captured logger to add attributes — take a new `For`.
- **envx**: the `Warnf` diagnostic sink is a func var backed by an
  atomic hook. Rebind through `SetWarnf` — race-free against
  concurrent getter calls (hot read = one atomic load; `SetWarnf(nil)`
  restores the slog default). The plain-assignment shape
  (`envx.Warnf = f`) predates `SetWarnf` and is kept for the
  controller's startup init(): it must run before the first getter
  call and cannot be combined with `SetWarnf`. `Gate`'s intent-like
  misspelling warning is once per key per process (`sync.Map`), safe
  under concurrent resolution.
