FROM golang:1.16.5-alpine3.13 AS builder

RUN apk -v --no-progress --no-cache add git

WORKDIR /root/src

COPY go.mod go.sum ./
RUN go mod download

COPY internal ./internal/
COPY *.go ./
RUN go build .


FROM alpine:latest

COPY --from=builder \
  /root/src/discourse-auth-proxy \
  /usr/local/bin/discourse-auth-proxy
COPY docker-entrypoint /usr/local/bin/docker-entrypoint

ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
