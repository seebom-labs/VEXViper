# syntax=docker/dockerfile:1
# VEXViper image. Includes git and a Go toolchain + govulncheck so the
# sidecar can clone product repositories and run reachability analysis.
FROM golang:1.27-alpine AS builder
ARG VERSION=dev
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/vexviper ./cmd/vexviper \
 && GOBIN=/out go install golang.org/x/vuln/cmd/govulncheck@latest

# Runtime keeps the Go toolchain: govulncheck needs `go` to load the product's
# packages (GOTOOLCHAIN=auto downloads newer toolchains on demand).
FROM golang:1.27-alpine
RUN apk add --no-cache git ca-certificates \
 && adduser -D -u 65532 vexviper \
 && mkdir -p /work /home/vexviper/go && chown -R vexviper /work /home/vexviper
COPY --from=builder /out/vexviper /out/govulncheck /usr/local/bin/
USER vexviper
ENV HOME=/home/vexviper GOPATH=/home/vexviper/go GOTOOLCHAIN=auto GOFLAGS=-mod=mod \
    GIT_TERMINAL_PROMPT=0 \
    VEXVIPER_REPO_CACHE_DIR=/work/cache VEXVIPER_VEX_OUT_DIR=/work/out \
    VEXVIPER_WATCH_STATE_FILE=/work/cache/watch-state.json
WORKDIR /work
VOLUME ["/work"]
ENTRYPOINT ["vexviper"]
CMD ["--help"]
