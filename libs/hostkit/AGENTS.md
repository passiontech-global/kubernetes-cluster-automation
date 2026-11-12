# libs/hostkit

Shared leaf module for the host-agent stack: small, dependency-free
contracts that more than one app (or subsystem) needs. Shared via
`go.work` + `replace`, one Go module, `go.sum` stays empty.

## Package map

| Package  | Owns |
|----------|------|
| `envx`   | Env-knob getters: the lenient family (`String`, `Bool`, `Int`, `Duration`, `List`, `ModeEnv`) in `envx.go`, the strict family (`Getenv*`, `Gate`) in `strict.go`, and the `*Knob`/`Apply` table constructors in `knobs.go`. Owns the `Warnf` diagnostic sink and its atomic rebind (`SetWarnf`). |
| `envdoc` | The shared AST scanner behind each app's env-coverage test: `ScanTree` walks a module root collecting every env-var name its sources can read (envx helper first-args derived from the envx package's own files, package string consts, range-bound loop vars with proper scope, `GateEnv:` registry rows, raw `os.Getenv`-family sites). |
| `logx`   | Named slog loggers: `logx.For(component)` resolves and caches `slog.Default().With("logger", name)` per call. |
| `timex`  | The `Clock` seam (`nowFn func() time.Time` with nil-safe `Now()`) plus the settable `Cell`, shared by every sweep/subsystem for tests. |
| `nodecond` | The single source of truth for NodeCondition names written by the agent and consumed by the controller; untyped strings so no k8s import. Also owns the coordination-annotation helpers (`KuredLockAnno`, `ParseAnnoTime`, `EvaluateCoordAnnos`). |
| `fsx`    | Atomic file writer (`WriteFile`/`Promote`): same-dir staging → fsync → chmod → rename → optional dir fsync, plus the `WriteFileAtomic*` convenience family with the EBUSY/EXDEV bind-mount fallback (`stat_unix.go`/`stat_other.go` split), and the small read/stat helpers (`ReadTrimmed`, `ReadUintFile`, `TouchIfDue`, `HostSidePath`, `ShellQuote`, `FileStatKey`). Ported verbatim from the agent's `hostutil` so hostutil can delegate without behavior drift. |
| `ledger` | The time/count-keyed bookkeeping ledgers: `CooldownSet` (mutex-guarded last-action stamps), `FirstSeenLedger`, `StreakLedger`, `SeenSet` — ported verbatim from the controller's `platform/state`, which now aliases them. `GaugeLedger` stays app-side (typed on `*prometheus.GaugeVec`). |
| `httpx`  | Bind-then-serve lifecycle for probe/metrics endpoints (`New` binds synchronously, idempotent `Serve`, `Shutdown` with a drain budget, `Timeout` per-route wrapper, `PooledTransport` for shared client pools). Handler — including any promhttp mux — is injected by the caller; `httpx/pprofx` is the opt-in pprof registration subpackage (kept separate so `net/http/pprof`'s `DefaultServeMux` side effect only lands where wanted). |

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
- **envx**: `Warnf` is a plain func that dispatches through the
  `warnfHook` atomic pointer — one atomic load per call, race-free
  against concurrent getter traffic. `SetWarnf` is the ONLY rebind
  path (`SetWarnf(nil)` restores the slog default); there is no
  assignable var to write. `Gate`'s intent-like misspelling warning
  is once per key per process (a mutex-guarded table capped at 1024
  keys — overflow clears and warn-once restarts), safe under
  concurrent resolution.
