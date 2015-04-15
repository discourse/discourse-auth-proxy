FROM gliderlabs/alpine

RUN apk --update add bash git go mercurial
RUN mkdir -p /gopath/src/github.com/discourse && cd /gopath/src/github.com/discourse && git clone https://github.com/discourse/discourse-auth-proxy
ENV GOPATH /gopath
RUN mkdir -p /gopath
RUN cd /gopath/src/github.com/discourse/discourse-auth-proxy && go get
RUN cd /gopath/src/github.com/discourse/discourse-auth-proxy && CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-w' .

CMD cp /gopath/src/github.com/discourse/discourse-auth-proxy/discourse-auth-proxy /shared

