# syntax=docker/dockerfile:1
# NOTE: CI releases build the image with `ko` (.ko.yaml) — ko runs
# `go build` inside the module and resolves the libs/hostkit replace
# transparently. This Dockerfile remains a valid fallback for
# local/manual builds; its build CONTEXT is the repo ROOT
# (`docker build -f apps/node-automation-controller/Dockerfile .`) so
# the go.mod `replace ../../libs/hostkit` target resolves inside the
# context at /src/libs/hostkit. No go.work is copied, so the build
# runs in plain module mode (the release path).
FROM golang:1.27 AS build
ARG VERSION=dev
WORKDIR /src
COPY libs/hostkit/ libs/hostkit/
COPY apps/node-automation-controller/ apps/node-automation-controller/
WORKDIR /src/apps/node-automation-controller
RUN go mod download && \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/node-automation-controller ./cmd/manager

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/node-automation-controller /node-automation-controller
USER 65532:65532
ENTRYPOINT ["/node-automation-controller"]
