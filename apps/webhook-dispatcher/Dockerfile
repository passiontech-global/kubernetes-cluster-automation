# syntax=docker/dockerfile:1
# NOTE: CI releases build the image with `ko` (.ko.yaml) — ko runs
# `go build` inside the module and resolves the libs/hostkit replace
# transparently. This Dockerfile remains a valid fallback for
# local/manual builds; its build CONTEXT is the repo ROOT
# (`docker build -f apps/webhook-dispatcher/Dockerfile .`) so the
# go.mod `replace ../../libs/hostkit` target resolves inside the
# context at /src/libs/hostkit.
FROM golang:1.27 AS build
ARG VERSION=dev
WORKDIR /src
COPY libs/hostkit/ libs/hostkit/
COPY apps/webhook-dispatcher/ apps/webhook-dispatcher/
WORKDIR /src/apps/webhook-dispatcher
RUN go mod download
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/webhook-dispatcher ./cmd/dispatcher

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/webhook-dispatcher /webhook-dispatcher
USER 65532:65532
ENTRYPOINT ["/webhook-dispatcher"]
