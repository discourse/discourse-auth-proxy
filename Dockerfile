FROM alpine:3.5

COPY docker/start.sh /bin/start.sh
CMD ["/bin/start.sh"]

COPY main.go /go/src/github.com/discourse/discourse-auth-proxy/

RUN apk add --no-cache -t build-deps build-base git go mercurial \
	&& export GOPATH=/go \
	&& cd /go/src/github.com/discourse/discourse-auth-proxy \
	&& go get \
	&& go build -o /bin/discourse-auth-proxy \
	&& apk del --purge build-deps \
	# Don't ask me why, but purging the go package leaves behind about
	# 8MB of cruft in /usr/lib/go which we have to nuke by hand
	&& rm -rf /go /usr/lib/go
