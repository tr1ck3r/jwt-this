.DEFAULT_GOAL := build

IMAGE ?= jwt-this:latest

export DOCKER_CLI_EXPERIMENTAL=enabled

.PHONY: build # Build the container image
build:
	@docker buildx create --use --name=crossplat --node=crossplat && \
	docker buildx build \
		--output "type=docker,push=false" \
		--tag $(IMAGE) \
		.

.PHONY: publish # Push the image to the remote registry
publish:
	@docker buildx create --use --name=crossplat --node=crossplat && \
	docker buildx build \
		--platform linux/386,linux/amd64,linux/arm/v6,linux/arm/v7,linux/arm64,linux/ppc64le,linux/s390x \
		--output "type=image,push=true" \
		--tag $(IMAGE) \
		.

binaries:
	GOOS=linux   GOARCH=amd64 go build -o jwt-this
	zip -j jwt-this_linux.zip -m jwt-this

	GOOS=windows GOARCH=amd64 go build -o jwt-this.exe
	zip -j jwt-this_windows.zip -m jwt-this.exe

	GOOS=darwin  GOARCH=amd64 go build -o jwt-this
	zip -j jwt-this_mac_amd64.zip -m jwt-this

	GOOS=darwin  GOARCH=arm64 go build -o jwt-this
	zip -j jwt-this_mac_arm64.zip -m jwt-this
