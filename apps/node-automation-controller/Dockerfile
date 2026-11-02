# syntax=docker/dockerfile:1
# NOTE: CI releases build the image with `ko` (.ko.yaml); this Dockerfile
# remains a valid fallback for local/manual builds.
FROM golang:1.27 AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/node-automation-controller ./cmd/manager

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/node-automation-controller /node-automation-controller
USER 65532:65532
ENTRYPOINT ["/node-automation-controller"]
