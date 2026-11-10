# syntax=docker/dockerfile:1
# NOTE: CI releases build the image with `ko` (.ko.yaml) — ko runs
# `go build` inside the module and resolves the libs/hostkit replace
# transparently. This Dockerfile remains a valid fallback for
# local/manual builds; its build CONTEXT is the repo ROOT
# (`docker build -f apps/webhook-dispatcher/Dockerfile .`) so the
# go.mod `replace ../../libs/hostkit` target resolves inside the
# context at /src/libs/hostkit.
FROM golang:1.27.3 AS build
WORKDIR /src
# Dep manifests first so `go mod download` is a cacheable layer that only
# busts when go.mod/go.sum (or the hostkit replace target's go.mod) change —
# not on every source edit. libs/hostkit is go.mod-replaced, so `go mod
# download` only needs its go.mod, not its sources.
COPY libs/hostkit/go.* libs/hostkit/
COPY apps/webhook-dispatcher/go.mod apps/webhook-dispatcher/go.sum apps/webhook-dispatcher/
WORKDIR /src/apps/webhook-dispatcher
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download
# Full source only after deps are cached. ARG VERSION sits just above
# `go build` so bumping it invalidates the link layer, not the downloads.
COPY libs/hostkit/ /src/libs/hostkit/
COPY apps/webhook-dispatcher/ /src/apps/webhook-dispatcher/
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/webhook-dispatcher ./cmd/dispatcher

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/webhook-dispatcher /webhook-dispatcher
USER 65532:65532
ENTRYPOINT ["/webhook-dispatcher"]
