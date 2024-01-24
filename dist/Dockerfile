# syntax=docker/dockerfile:1

ARG BASE_IMAGE_DEBIAN=debian:bookworm-slim
ARG BASE_IMAGE_GO_ALPINE=golang:1-alpine


FROM ${BASE_IMAGE_GO_ALPINE} AS builder

ARG TARGETARCH
ARG TARGETOS

RUN apk -v --no-progress --no-cache add git

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build \
  go mod download

COPY internal ./internal/
COPY *.go ./
RUN --mount=type=cache,target=/root/.cache/go-build \
  CGO_ENABLED=0 \
  GOARCH=${TARGETARCH} \
  GOOS=${TARGETOS} \
  go build .


FROM ${BASE_IMAGE_DEBIAN}

RUN <<EOF sh -exs
DEBIAN_FRONTEND=noninteractive apt-get update
DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade
DEBIAN_FRONTEND=noninteractive apt-get clean
( find /var/lib/apt/lists -mindepth 1 -delete || true )
( find /var/tmp           -mindepth 1 -delete || true )
( find /tmp               -mindepth 1 -delete || true )
EOF

COPY --from=builder /src/discourse-auth-proxy /usr/local/bin/discourse-auth-proxy
COPY dist/docker-entrypoint /usr/local/bin/docker-entrypoint

ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
