# syntax=docker/dockerfile:1
# NOTE: CI releases build THIS Dockerfile (moon task `image` — plain
# docker build/push from release-app.yml), NOT ko: ko's
# defaultBaseImage is a fixed image ref and cannot install packages,
# while the agent needs real userspace tools IN the container fs (see
# the runtime stage below).
#
# The build CONTEXT is the repo ROOT — the moon task runs
# `docker build -f apps/node-host-agent/Dockerfile <root>` — so the
# go.mod `replace ../../libs/hostkit` target resolves inside the
# context at /src/libs/hostkit. No go.work is copied, so the build
# runs in plain module mode (the release path).
FROM golang:1.27 AS build
WORKDIR /src
# Dep manifests first so `go mod download` is a cacheable layer that only
# busts when go.mod/go.sum (or the hostkit replace target's go.mod) change —
# not on every source edit. libs/hostkit is go.mod-replaced, so `go mod
# download` only needs its go.mod, not its sources.
COPY libs/hostkit/go.* libs/hostkit/
COPY apps/node-host-agent/go.mod apps/node-host-agent/go.sum apps/node-host-agent/
WORKDIR /src/apps/node-host-agent
RUN go mod download
# Full source only after deps are cached. ARG VERSION sits just above
# `go build` so bumping it invalidates the link layer, not the downloads.
COPY libs/hostkit/ libs/hostkit/
COPY apps/node-host-agent/ apps/node-host-agent/
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/node-host-agent ./cmd/agent

# Runtime: alpine — NOT distroless. The agent execs binaries that must
# resolve in the CONTAINER mount namespace:
#   nsenter (util-linux) — wraps every host-namespace exec
#     (`nsenter -t 1 -m -u -i -n -p --` and nethealth's `-n`-only form)
#   ip + ss (iproute2)   — nethealth runHostCmd `nsenter -t 1 -n --`
#     (net ns only → argv resolves in container fs)
#   ping (iputils)       — reachability probes incl. -m fwmark pinning
#   sh + bash            — `sh -c` probe pipelines / fallbacks
# Host tools (systemctl, journalctl, nft, sshd, apt-get, haproxy, ...)
# are exec'd via `nsenter -m` → they resolve in the HOST mount ns and
# intentionally do NOT ship here.
FROM alpine:3.24
# apk repos prune old package builds, so pinning exact versions against
# the floating alpine:3.24 tag would break the build whenever upstream
# bumps a package.
# hadolint ignore=DL3018
RUN apk add --no-cache util-linux iproute2 iputils bash
COPY --from=build /out/node-host-agent /node-host-agent
USER 65532:65532
ENTRYPOINT ["/node-host-agent"]
