GO ?= go
BIN := bin/vexviper
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build test test-race test-integration lint fmt vet clean e2e e2e-ci release-rc release release-branch cherry-pick

all: build

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/vexviper

test:
	$(GO) test ./... -count=1

test-race:
	$(GO) test ./... -count=1 -race

# Requires a running BOMHort with AUTH_ENABLED=true; see hack/e2e-bomhort.sh
test-integration:
	$(GO) test ./test/integration/ -count=1 -tags=integration -v

fmt:
	@test -z "$$(gofmt -l cmd internal test | tee /dev/stderr)" || (echo "gofmt: files need formatting" && exit 1)

vet:
	$(GO) vet ./...

lint: fmt vet
	$(GO) vet -tags=integration ./test/...

e2e:
	./hack/e2e-bomhort.sh

# Same as CI (.github/workflows/e2e.yml): build BOMHort from $(BOMHORT_SRC), do not touch examples/.
e2e-ci:
	BOMHORT_BUILD=1 BOMHORT_IMAGE_PREFIX=vexviper-e2e/ BOMHORT_IMAGE_TAG=ci E2E_UPDATE_EXAMPLE=0 ./hack/e2e-bomhort.sh

release-rc:
	@test -n "$(VERSION)" || (echo "VERSION=X.Y.Z is required" >&2; exit 1)
	DRY_RUN="$(DRY_RUN)" YES="$(YES)" REMOTE="$(REMOTE)" REF="$(REF)" ./hack/cut-release.sh rc "$(VERSION)"

release:
	@test -n "$(VERSION)" || (echo "VERSION=X.Y.Z is required" >&2; exit 1)
	DRY_RUN="$(DRY_RUN)" YES="$(YES)" REMOTE="$(REMOTE)" REF="$(REF)" ./hack/cut-release.sh final "$(VERSION)"

release-branch:
	@test -n "$(VERSION)" || (echo "VERSION=X.Y is required" >&2; exit 1)
	DRY_RUN="$(DRY_RUN)" YES="$(YES)" REMOTE="$(REMOTE)" ./hack/cut-release.sh branch "$(VERSION)"

cherry-pick:
	@test -n "$(PR)" || (echo "PR=<number-or-commit> is required" >&2; exit 1)
	@test -n "$(BRANCH)" || (echo "BRANCH=X.Y is required" >&2; exit 1)
	DRY_RUN="$(DRY_RUN)" REMOTE="$(REMOTE)" PUSH_REMOTE="$(PUSH_REMOTE)" GH="$(GH)" ./hack/cherry-pick.sh "$(PR)" "$(BRANCH)"

clean:
	rm -rf bin dist .vexviper-cache
