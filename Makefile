IMAGE := discourse/auth-proxy
TAG := $(shell date -u +%Y%m%d.%H%M%S)

.PHONY: default
default: push
	@printf "${IMAGE}:${TAG} ready\n"

.PHONY: push
push: build
	docker push ${IMAGE}:${TAG}

.PHONY: build
build:
	docker build --pull -t ${IMAGE}:${TAG} .

.PHONY: release
release:
	docker tag ${IMAGE}:${TAG} ${IMAGE}:latest
	docker push ${IMAGE}:latest
