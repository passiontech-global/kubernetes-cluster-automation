# webhook-dispatcher

GitHub org webhook fan-out to Concourse resource check webhooks (push/release/tag-create -> git, pull_request -> github-pr).

Receives GitHub org webhook deliveries and fans out instant resource
checks to the Concourse ATC — `push` deliveries check matching `git`
resources, `pull_request` deliveries check matching `github-pr`
resources — instead of waiting for the `check_every` polling interval.
Deliveries are verified against `X-Hub-Signature-256` (HMAC-SHA256 over
the raw body); a single resource failure never fails the delivery.

## Interface contract

- Public listener (`LISTEN_ADDR`, default `:8080`): `POST /webhook`, `GET /healthz` (liveness, returns `ok`), `GET /readyz` (readiness, returns `ok` once both listeners are serving).
- Internal listener (`METRICS_ADDR`, default `:9115`): `GET /metrics` (Prometheus, dedicated registry) and `net/http/pprof` under `/debug/pprof/` — operational endpoints, never exposed to GitHub's side.
- Shutdown: on SIGTERM/SIGINT both listeners drain (10s), then in-flight fan-out POSTs get a 15s wait budget — ~25s worst case, under the pod's 30s SIGKILL grace.
- Flags: `--version`.
- Env (full catalog with rationale: [docs/env.md](docs/env.md)):

| Var                     | Required | Default                     | Purpose                                           |
| ----------------------- | -------- | --------------------------- | ------------------------------------------------- |
| `GITHUB_WEBHOOK_SECRET` | yes      | —                           | HMAC key for `X-Hub-Signature-256`                |
| `CI_WEBHOOK_TOKEN`      | yes      | —                           | Concourse check-webhook token (`webhook_token=…`) |
| `LOCAL_USERS`           | yes      | —                           | Concourse basic auth, `user:password`             |
| `CONCOURSE_URL`         |          | `http://concourse-web:8080` | ATC base URL                                      |
| `CONCOURSE_TEAM`        |          | `main`                      | Team to index and fan out to                      |
| `LISTEN_ADDR`           |          | `:8080`                     | Public listen address                             |
| `METRICS_ADDR`          |          | `:9115`                     | Internal listen address (`/metrics`, `/debug/pprof/*`) |
