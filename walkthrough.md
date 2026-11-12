# Implementation Walkthrough — Monorepo Refactor & Optimization

Acceptance report for `implementation_plan.md` (8 waves across 5 Go
modules). All work is uncommitted in the working tree; no PR has been
opened.

## Scope delivered

| Wave | Module(s) | Outcome |
|---|---|---|
| 1 | `libs/hostkit` | New `envdoc` AST scanner, `ledger` ledgers, `nodecond` coord helpers, `httpx` opts + `pprofx`, `fsx` host-util port, `envx` split, `logx`/`timex` hardening. Still **zero external deps** (`go.mod` has no requires, `go.sum` empty). |
| 2 | `libs/jinja` | OMap merge-key fix, `NewOMapCap`, exact >2^53 sort keys, cache `RWMutex` + eviction fix, file splits. `go.mod` still yaml-only. |
| 3 | `apps/webhook-dispatcher` | verify/handler/concourse splits, O(1) resource index, `uri`-over-`repository` precedence, streaming HMAC, fan-out dispatch, dedicated metrics registry, public/internal listener split, `docs/env.md`. |
| 4–5 | `apps/node-automation-controller` | `platform/{maintenance,helmprune,flux}` extracted; `partial_meta.go` fallback narrowed to 406/unregistered-scheme; state ledgers aliased onto `hostkit/ledger`; sweep overlay (pod tombstones, cached censuses, disruption reservations); leader-election shutdown; `apiserver_node_reachability` split + heal ordering fix; paged webhook-config list; scylla single-pass scanner; snapshot/`AllX` wiring; large-file splits. |
| 6–7 | `apps/node-host-agent` | `platform/{subframe,checkkit,netlinkx,nodecoord,kmsg,pagecache,probee,sdnotify,sshclient,hostctx,fileconf}` and friends; nodecoord singleflight + fail-closed `HoldLocalAction` / fail-open `HoldEmergencyHeal`; netlink sock-diag replaces `ss -K` fork; journal zero-alloc line parsing + mux mutex release; D-Bus systemd client with CLI fallback; hubsync SSH staging/atomic writes + ProxyJump reuse; hostmetrics adjtimex/`nvme smart-log` caching/TCP table parsing; kinedb batched inspect; `wdeps` protected-pod consolidation; `internal/testutil/hostfixture`. |
| 8 | monorepo admin | `.golangci.yml` 789→432 lines with YAML anchors + strict depguard allowlists (`hostkit-stdlib-only`, `jinja-allowed-deps`, per-app leaf/domain/env rules, `nha-no-testutil`); targeted test-file lint exclusions replacing the blanket `_test.go` skip; shared moon `format` task (`golangci-lint fmt --diff`); per-project lint cache; CI `ko` build verification; release path filters synced to actual hostkit/jinja imports; root `AGENTS.md` + README module map; per-app `AGENTS.md`/`docs/env.md` updated. |

Diff stat vs HEAD: **285 tracked files, +5,838 / −14,557** plus
new files (maintenance split, hostfixture, platform leaf packages,
split files).

## Contracts preserved (verified)

- Prometheus metric names/labels, check & group ordering, queue
  labels, annotation/taint keys — untouched (depguard + envdoc +
  byte-stable ops contract enforced by tests).
- Node-watchdog latch paths `/var/run/node-watchdog/*`, NPD log
  formats (`STATE-ENTER:`/`STATE-EXIT:`/`ACTION`), `UIDDeleteOptions`
  on every destructive delete, maintenance fail-closed/fail-open
  semantics per gate.
- webhook-dispatcher listener split (`:8080` public / `:9115`
  metrics+pprof), 8 MiB body cap, HMAC fail-closed, sanitized
  delivery IDs, shutdown drain budgets.
- `libs/hostkit` stdlib-only; `libs/jinja` yaml-only; `webhook-dispatcher`
  does not import `libs/jinja`; apps import downward only.
- `*OMap` insertion ordering; jinja AST immutability under `-race`.

## Verification results — all gates pass

| Gate | Result |
|---|---|
| `golangci-lint fmt --diff apps/ libs/` | clean, 0 diff |
| `gofmt -l` | empty |
| `moon run :format :vet :lint :lint-dockerfile` | 18 tasks, **0 issues** on all 5 modules |
| `moon run :test` (`go test -race ./...`) | 5/5 projects pass |
| `moon run :build` (3 app binaries) | pass |
| `hadolint` (all Dockerfiles) | clean |
| `GOWORK=off go vet ./...` ×5 modules | clean |
| `GOWORK=off go test -race -count=1 ./...` ×5 modules | all pass |
| envdoc regen (`apps/node-host-agent/scripts/gen-envdoc.sh`) + envdoc tests | docs in sync, tests pass |
| `libs/hostkit/go.mod` | module + `go 1.27.3` only; `go.sum` empty |
| `libs/jinja/go.mod` | single require `go.yaml.in/yaml/v3` |
| Release workflow `paths`/`lib_paths` | audited against real imports: dispatcher `{envdoc,envx,httpx,logx}`, controller `{envdoc,envx,httpx,ledger,nodecond,timex}`, agent blanket `hostkit/**`+`jinja/**` — all correct (`httpx/**` covers `httpx/pprofx`) |

## Manual-check notes

- **File size**: all files touched by the refactor are ≤ ~500 LOC.
  Six production files remain above the threshold — every one was
  already >500 at HEAD and none appears in the plan's named split
  lists, so they are recorded as pre-existing exceptions rather than
  silently split late:
  `probfw/snapshot.go` (706, was 615),
  `health/nethealth/linkerd/linkerd_protocol_detection_stall_template.go` (630, was 612),
  `cmd/manager/main.go` (572, was 550),
  `libs/jinja/omap.go` (556, was 507),
  `apiserverendpointguard/apiserver_endpoint_guard.go` (536, was 507),
  `health/datastore/olm/olm_csv_autopatch.go` (510, was 505).
- **Deleted files audited**: every `D` in `git status` is a move —
  `platform/kube/{maintenance,helm_secret_prune,fluxconditions}` →
  `platform/{maintenance,helmprune,flux}`; `platform/state/*` →
  `hostkit/ledger` aliases; `platform/checks` → `platform/subframe`;
  `platform/hostutil` → `hostkit/fsx` + `platform/procfs`;
  `health/datastore/dragonfly_heals.go` → `health/datastore/dragonfly/`
  subpackage; `platform/httpx` → `hostkit/httpx`. Build+tests confirm
  no symbol was lost.
- `.github/workflows/release-app.yml` carried a **pre-existing**
  unrelated change (`--prefer-index=false` on `imagetools create`);
  left untouched.

## Known deviations (documented, accepted)

- **node-host-agent**: `nethealth`'s `nebula_*_test.go` stay in
  `package nethealth` — they exercise unexported `NetHealth`
  internals, so moving them into `nethealth/nebula` would require a
  rewrite. `hostfixture` shares only `KillRecord`; the three
  `*depstest` fixtures build different `wdeps`/`cdeps`/`kdeps`
  Config types and cannot merge without layering violations.
  `ip rule` mutations (`nebula/direct_tcp.go`, `overlay_egress.go`)
  remain on exec — `netlinkx` exposes reads only; rule mutation is
  new platform surface beyond this pass. The workerhygiene scopes
  sweep collapsed three `list-units` execs into one
  `ListUnitsByPatterns` + client-side state filter (fewer forks;
  failure granularity is sweep-level, strictly safer for streaks).
- **controller**: `partial_meta.go` fallback is restricted to HTTP
  406 and unregistered fake schemes — 404/403/429/cancel/transport
  errors now surface instead of being masked. Dynamic-list limits
  default 25 (CRDs) / 500 (core), explicit >500 clamped.
- Stale `checks.Group` comment references in three NHA files were
  updated to `subframe.Group` during final cleanup.
