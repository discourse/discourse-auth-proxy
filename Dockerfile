FROM golang:alpine as builder
COPY main.go /go/src/github.com/discourse/discourse-auth-proxy/
RUN apk add git
RUN cd /go/src/github.com/discourse/discourse-auth-proxy \
  && go get \
  && go build

FROM alpine:latest
COPY --from=builder /go/bin/discourse-auth-proxy /bin/
COPY start.sh /bin/start.sh
CMD ["/bin/start.sh"]
