FROM golang:1-alpine3.14 AS builder

RUN apk -v --no-progress --no-cache add git

WORKDIR /root/src

COPY go.mod go.sum ./
RUN go mod download

COPY internal ./internal/
COPY *.go ./
RUN CGO_ENABLED=0 go build .


FROM debian:bullseye-slim

RUN DEBIAN_FRONTEND=noninteractive apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade \
  && DEBIAN_FRONTEND=noninteractive apt-get clean \
  && ( find /var/lib/apt/lists -mindepth 1 -maxdepth 1 -delete || true ) \
  && ( find /var/tmp -mindepth 1 -maxdepth 1 -delete || true ) \
  && ( find /tmp -mindepth 1 -maxdepth 1 -delete || true )

COPY --from=builder \
  /root/src/discourse-auth-proxy \
  /usr/local/bin/discourse-auth-proxy
COPY docker-entrypoint /usr/local/bin/docker-entrypoint

ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
