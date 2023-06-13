FROM golang:1-alpine3.18 AS builder

RUN apk -v --no-progress --no-cache add git

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY internal ./internal/
COPY *.go ./
RUN CGO_ENABLED=0 GOARCH=amd64 go build .


FROM --platform=linux/amd64 debian:bullseye-slim

RUN DEBIAN_FRONTEND=noninteractive apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade \
  && DEBIAN_FRONTEND=noninteractive apt-get clean \
  && ( find /var/lib/apt/lists -mindepth 1 -delete || true ) \
  && ( find /var/tmp           -mindepth 1 -delete || true ) \
  && ( find /tmp               -mindepth 1 -delete || true )

COPY --from=builder \
  /src/discourse-auth-proxy \
  /usr/local/bin/discourse-auth-proxy
COPY docker-entrypoint /usr/local/bin/docker-entrypoint

ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
