# webhook-dispatcher

GitHub org webhook fan-out to the Concourse ATC: receives
`POST /webhook` deliveries, verifies `X-Hub-Signature-256`
(HMAC-SHA256 over the raw body), resolves the delivery's repo against
a cached pipeline/resource index, answers 202, and POSTs each
matching resource's check webhook on a detached, bounded fan-out
(`push`/published-`release`/tag-`create` → `git` resources,
`pull_request` → `github-pr` resources; other events are acknowledged
without touching the index). A single resource failure never fails
the delivery — GitHub redelivery would re-trigger every resource, not
just the failed one.

## Interface contract

Two listeners, deliberately split:

- PUBLIC (`LISTEN_ADDR`, default `:8080`): only what GitHub needs —
  `POST /webhook`, `GET /healthz` (liveness), `GET /readyz`
  (readiness). The public server carries the hostile-peer posture:
  `MaxHeaderBytes: 64<<10`, body capped by `MaxBytesReader` at 8 MiB,
  ReadTimeout 10s / ReadHeaderTimeout 5s / WriteTimeout 45s (covers
  the 30s request-path index-fetch budget; the fan-out itself is
  async), IdleTimeout 60s. No metrics, no pprof.
- INTERNAL (`METRICS_ADDR`, default `:9115`, via `httpx.New`):
  `GET /metrics` — served from a DEDICATED `prometheus.Registry`
  (`handler.RegisterMetrics` + `concourse.RegisterMetrics`; never
  `prometheus.DefaultRegisterer`, so index/fan-out internals cannot
  leak to GitHub's side) — and `net/http/pprof` under `/debug/pprof/`
  (handlers wired explicitly in `cmd/dispatcher/main.go`, never on
  DefaultServeMux).

Shutdown contract: on SIGINT/SIGTERM both listeners drain (10s
budget), then `Handler.Wait` waits for in-flight fan-outs with
`WaitBudget` (15s) — ~25s worst case, under the pod's 30s SIGKILL
grace, so the process exits on its own terms. Both listeners bind
BEFORE the signal loop: a port collision aborts boot, not readiness.

Env surface: `GITHUB_WEBHOOK_SECRET`, `CI_WEBHOOK_TOKEN`,
`LOCAL_USERS` required (missing vars abort boot with a logged list);
`CONCOURSE_URL`, `CONCOURSE_TEAM`, `LISTEN_ADDR`, `METRICS_ADDR`
optional via `envx.String`. Env is read in exactly one place —
`cmd/dispatcher/main.go`; the full operator-facing catalog lives in
`docs/env.md` (hand-maintained; update it when adding a knob).

## Directory map

- `cmd/dispatcher` — entrypoint: required-env check, `LOCAL_USERS`
  split (first colon), transport tuning (idle conns sized for
  16 fan-out + 8 index workers sharing one client), both muxes,
  bind-then-serve, the signal select, and the ordered shutdown
  (drain → `wh.Wait(waitCtx)` → `CloseIdleConnections`). `main.go`
  is the only file that reads env.
- `internal/verify` — the HMAC check: constant-time `sha256=` digest
  compare, empty-secret fails closed, `HasValidSignatureFormat` lets
  the handler reject malformed signatures before allocating for the
  body.
- `internal/handler` — `POST /webhook`: verification, event →
  resource-type mapping and payload filtering (non-actionable
  pull_request actions, branch deletions, non-published releases are
  skipped before the index lookup — they would only burn forced-
  refresh slots), the detached fan-out, and `Wait`. Metrics live in
  `metrics.go` (`webhook_dispatcher_deliveries_total{event,status}`,
  `webhook_dispatcher_fanout_total{result}`,
  `webhook_dispatcher_fanout_duration_seconds`).
- `internal/concourse` — the small ATC API slice: pipeline/resource
  listing → repo index, `CheckWebhook` POSTs, `NormalizeRepo`
  (scp-like SSH / SSH / HTTPS / bare `org/repo` → lowercase
  `org/repo`; the `github.com` host prefix strips only where github.com
  can actually be the host). Metrics in `metrics.go`
  (`webhook_dispatcher_concourse_index_last_refresh_timestamp_seconds`,
  `webhook_dispatcher_concourse_index_fetch_errors_total`).

## Conventions

- Every file opens with a `// file.go — purpose` header; comments
  explain WHY. Logging identity is `logx.For("<pkg>")` per package
  (`logging.go` in cmd/handler/concourse) — resolution is per call on
  purpose.
- Prometheus metrics register ONLY through each package's
  `RegisterMetrics(reg)` onto the dedicated internal-listener
  registry built in main. Metric names, labels and label-value sets
  are an ops contract — never rename or add label cardinality without
  checking the scrape side.
- Pre-verification inputs are attacker-controlled: the delivery GUID
  goes through `handler.logSafe` (hex+hyphen UUID alphabet, length
  cap) before ANY logging; the signature header is never logged; the
  event header is normalized onto the fixed
  `push|pull_request|release|create|none|other` label set
  (`metricEventLabel`) before it feeds `deliveriesTotal` or logs —
  raw header values must not be echoed (logs or metric series) ahead
  of the HMAC check. Post-verification logs may carry raw values.
- `CI_WEBHOOK_TOKEN` is the only credential on the check-webhook
  endpoint (query param, no basic auth); the client strips it out of
  transport-error strings so it cannot leak into logs.
- The Concourse resource `Source` decodes into the two-key `source`
  struct (`uri` wins over `repository`, the map decode's precedence) —
  never a `map[string]any` Source; the decode must tolerate every
  other key a resource carries.
- Index reads return COPIES (`slices.Clone` out of `Resources`/
  `Refresh`/publish paths; `Match` copies map values out) — callers
  cannot reach the client's snapshot, and the fetch's `prev` must not
  alias the cache the fetch replaces.
- Per-delivery matching is the O(1) `(resource type, repo)` lookup
  `Client.Match` runs over the map `newLookup` rebuilt on every index
  publish — not a linear scan of the team's resources.
- In-flight fetches are JOINED, not duplicated: `fetchFlight` (done
  channel + settled error) lets cold-start `Resources` callers and
  forced `Refresh` callers share the running fetch instead of
  stampeding the ATC; the mutex is never held across the network
  fetch. Failure handling: last-known index is served stale inside
  the TTL window (`lastAttemptAt` backoff = negative cache),
  forced refreshes throttle on their own `MinRefreshInterval` clock
  (30s), cold-start failures negative-cache for 3s, and the index
  freshness gauges move only on a successful publish.
- Fan-out shape: `fanoutStart` (WaitGroup register) MUST run before
  the index fetch (see `Handler.Wait` for the race this closes);
  per-dispatch worker pool (16 slots on a Handler-wide semaphore),
  per-target 15s timeout starting only once a slot is taken, whole
  dispatch bounded by `fanoutBudget` (30s); shutdown drain is bounded
  by `WaitBudget` — the budget constants are the shutdown contract,
  keep `main.go` deriving its wait ctx from `handler.WaitBudget`.
- Test seams are transport-level: `handler_test`/`concourse_test`
  stub HTTP with httptest ATC stubs and drive the real parsers and
  the real fan-out machinery.

## Layering (enforced by depguard in the root .golangci.yml)

- This module must NOT import `libs/jinja` (`whd-no-jinja` rule:
  template rendering is a node-host-agent concern).
- Internal deps point outward only: `internal/handler` imports
  `internal/concourse` + `internal/verify` (and `libs/hostkit`'s
  `logx`); `internal/concourse` and `internal/verify` import no
  internal packages — `verify` is stdlib-only, `concourse` uses only
  the shared `logx`. No cycle is possible: the concourse → handler
  edge must never appear.

## Verify

```sh
cd apps/webhook-dispatcher
GOWORK=off go build ./... && GOWORK=off go vet ./... && \
  GOWORK=off go test -race ./... && golangci-lint run ./...
```

Moon equivalents (test/vet/format/lint come from .moon/tasks/all.yml —
test is exactly `go test -race ./...`):

```sh
moon run webhook-dispatcher:test webhook-dispatcher:vet \
  webhook-dispatcher:format webhook-dispatcher:lint \
  webhook-dispatcher:lint-dockerfile
```

## Commits

Conventional commits scoped to the app —
`refactor(webhook-dispatcher): ...` (also `feat`/`fix`/...).
git-cliff drives release notes off these messages, so keep the scope
exact.
