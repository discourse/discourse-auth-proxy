# syntax=docker/dockerfile:1

ARG BASE_IMAGE_ALPINE=alpine:3


FROM ${BASE_IMAGE_ALPINE} AS py

RUN apk -v --no-progress --no-cache add --upgrade python3


FROM py AS test

RUN apk -v --no-progress --no-cache add --upgrade py3-pytest

WORKDIR /src
COPY test.py transform  .
RUN PYTHONDONTWRITEBYTECODE=1 ./test.py ./transform


FROM py

COPY --from=test /src/transform /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/transform"]
