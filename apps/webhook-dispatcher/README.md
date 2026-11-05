# webhook-dispatcher

GitHub org webhook fan-out to Concourse resource check webhooks (push/release/tag-create -> git, pull_request -> github-pr).

Receives GitHub org webhook deliveries and fans out instant resource
checks to the Concourse ATC — `push` deliveries check matching `git`
resources, `pull_request` deliveries check matching `github-pr`
resources — instead of waiting for the `check_every` polling interval.
Deliveries are verified against `X-Hub-Signature-256` (HMAC-SHA256 over
the raw body); a single resource failure never fails the delivery.

## Interface contract

- Endpoints: `POST /webhook`, `GET /healthz` (returns `ok`).
- Flags: `--version`.
- Env:

| Var                     | Required | Default                     | Purpose                                           |
| ----------------------- | -------- | --------------------------- | ------------------------------------------------- |
| `GITHUB_WEBHOOK_SECRET` | yes      | —                           | HMAC key for `X-Hub-Signature-256`                |
| `CI_WEBHOOK_TOKEN`      | yes      | —                           | Concourse check-webhook token (`webhook_token=…`) |
| `LOCAL_USERS`           | yes      | —                           | Concourse basic auth, `user:password`             |
| `CONCOURSE_URL`         |          | `http://concourse-web:8080` | ATC base URL                                      |
| `CONCOURSE_TEAM`        |          | `main`                      | Team to index and fan out to                      |
| `LISTEN_ADDR`           |          | `:8080`                     | Listen address                                    |
