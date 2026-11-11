# Environment variables & CLI flags

Operator-facing catalog of every env var the dispatcher reads. Hand-maintained
and verified against `cmd/dispatcher/main.go` (the only place env is read —
`envx.String` for the optional knobs, `os.Getenv` + the required-var check for
the rest). Update this file when adding a knob.

The dispatcher has no config file and no hot-reload: every value is read once
at boot. Missing required vars abort boot with a logged list (exit 1) instead
of guaranteeing 401s/502s at request time.

## Required

| Env var                | Default | Notes |
|---|---|---|
| `GITHUB_WEBHOOK_SECRET` | — | HMAC-SHA256 key configured on the GitHub org webhook. Deliveries whose `X-Hub-Signature-256` does not verify against it are rejected 401 before the body is read. |
| `CI_WEBHOOK_TOKEN` | — | Concourse check-webhook token, sent as the `webhook_token` query parameter on every fan-out POST. It is the only credential on that endpoint (no basic auth); the client strips it out of transport-error strings so it can't leak into logs. |
| `LOCAL_USERS` | — | Concourse basic auth as `user:password`, split on the FIRST colon so passwords containing colons (e.g. bcrypt hashes) survive intact. Empty user or password parts are rejected at boot. |

## Optional

| Env var | Default | Notes |
|---|---|---|
| `CONCOURSE_URL` | `http://concourse-web:8080` | Base URL of the Concourse ATC (web/landing endpoint, not a worker). All index fetches and check-webhook POSTs go here. |
| `CONCOURSE_TEAM` | `main` | Team whose pipelines form the resource index and receive the fan-out. Path-escaped into every ATC API path. |
| `LISTEN_ADDR` | `:8080` | PUBLIC listener: `POST /webhook`, `GET /healthz` (liveness), `GET /readyz` (readiness — `ok` once both listeners are serving). Keep this as what the GitHub-facing service/ingress exposes; `/metrics` was deliberately moved off it. |
| `METRICS_ADDR` | `:9115` | INTERNAL listener: `GET /metrics` (Prometheus, served from a dedicated `prometheus.Registry` — never the default one) and `net/http/pprof` under `/debug/pprof/`. Operational surface for the cluster's scrape/observability tooling; must not be reachable from GitHub's side (pipeline topology and ATC error rates leak through it). |

## Not env-tunable (for completeness)

- **Index TTL (60s), forced-refresh throttle (30s), cold-start negative cache
  (3s), fan-out budget/target timeout (30s/15s), body cap (8 MiB)** — constants
  in the source (`internal/concourse`, `internal/handler`), not knobs: the
  webhook path is latency-critical and every value is either dictated by
  GitHub's ~10s webhook timeout or by the pod's 30s SIGKILL grace period, so
  per-deployment overrides would only add ways to misconfigure the shutdown
  contract.
- **HTTP server timeouts** (public: read 10s / read-header 5s / write 45s /
  idle 60s; internal: read-header 10s, 5s shutdown budget) — likewise constants;
  the write timeout exists to cover the 30s request-path index-fetch budget.

## CLI flags

| Flag | Default | Meaning |
|---|---|---|
| `-version` | `false` | Print the version (`main.version`, stamped at build time via ko ldflag) and exit. |
