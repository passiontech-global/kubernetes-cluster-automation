# syntax=docker/dockerfile:1
# NOTE: CI releases build THIS Dockerfile (moon task `image` — plain
# docker build/push from release-app.yml), NOT ko: ko's
# defaultBaseImage is a fixed image ref and cannot install packages,
# while the agent needs real userspace tools IN the container fs (see
# the runtime stage below).
FROM golang:1.27 AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
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
RUN apk add --no-cache util-linux iproute2 iputils bash
COPY --from=build /out/node-host-agent /node-host-agent
USER 65532:65532
ENTRYPOINT ["/node-host-agent"]
