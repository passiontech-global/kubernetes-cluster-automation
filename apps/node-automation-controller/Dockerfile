# syntax=docker/dockerfile:1
# NOTE: CI releases build the image with `ko` (.ko.yaml) — ko runs
# `go build` inside the module and resolves the libs/hostkit replace
# transparently. This Dockerfile remains a valid fallback for
# local/manual builds; its build CONTEXT is the repo ROOT
# (`docker build -f apps/node-automation-controller/Dockerfile .`) so
# the go.mod `replace ../../libs/hostkit` target resolves inside the
# context at /src/libs/hostkit. No go.work is copied, so the build
# runs in plain module mode (the release path).
FROM golang:1.27.3 AS build
WORKDIR /src
# Dep manifests first so `go mod download` is a cacheable layer that only
# busts when go.mod/go.sum (or the hostkit replace target's go.mod) change —
# not on every source edit. libs/hostkit is go.mod-replaced, so `go mod
# download` only needs its go.mod, not its sources.
COPY libs/hostkit/go.* libs/hostkit/
COPY apps/node-automation-controller/go.mod apps/node-automation-controller/go.sum apps/node-automation-controller/
WORKDIR /src/apps/node-automation-controller
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download
# Full source only after deps are cached. ARG VERSION sits just above
# `go build` so bumping it invalidates the link layer, not the downloads.
COPY libs/hostkit/ /src/libs/hostkit/
COPY apps/node-automation-controller/ /src/apps/node-automation-controller/
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/node-automation-controller ./cmd/manager

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/node-automation-controller /node-automation-controller
USER 65532:65532
ENTRYPOINT ["/node-automation-controller"]
