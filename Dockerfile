FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.23.6 AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH

ARG GOPROXY

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

# Copy build scripts
COPY main.go main.go
COPY crypto.go crypto.go

RUN GOPROXY=$GOPROXY go mod download

# Build
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-w -s" -o jwt-this main.go crypto.go

FROM --platform=${BUILDPLATFORM:-linux/amd64} scratch
LABEL description="jwt-this is a command line utility I created to simplify demonstration, evaluation, and simple testing with Venafi Firefly"

WORKDIR /
USER 1001
COPY --from=builder /workspace/jwt-this /usr/bin/jwt-this

ENTRYPOINT ["/usr/bin/jwt-this"]
