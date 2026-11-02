# syntax=docker/dockerfile:1
# NOTE: CI releases build the image with `ko` (.ko.yaml); this Dockerfile
# remains a valid fallback for local/manual builds.
FROM golang:1.27 AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/webhook-dispatcher ./cmd/dispatcher

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/webhook-dispatcher /webhook-dispatcher
USER 65532:65532
ENTRYPOINT ["/webhook-dispatcher"]
