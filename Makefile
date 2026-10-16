GO ?= go
VERSION ?= 0.1.0
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)
.PHONY: all build fmt fmt-check vet test race fuzz check integration bench benchmark clean
all: build
build:
	mkdir -p build
	CGO_ENABLED=1 $(GO) build -ldflags '$(LDFLAGS)' -o build/n-udptee ./cmd/n-udptee
fmt:
	gofmt -w cmd internal tests/integration/*.go
fmt-check:
	@test -z "$$(gofmt -l cmd internal tests/integration/*.go)"
vet:
	$(GO) vet ./...
test:
	$(GO) test ./...
	python3 -m unittest discover -s tests/release -v
race:
	$(GO) test -race ./...
fuzz:
	$(GO) test ./internal/decode -run '^$$' -fuzz '^FuzzDecode$$' -fuzztime=10s -parallel=2
check: build
	./build/n-udptee check --config configs/example.yaml
integration:
	N_UDPTEE_INTEGRATION=1 $(GO) test -v -count=1 -timeout=120s ./tests/integration
bench:
	$(GO) test ./internal/decode ./internal/engine -run '^$$' -bench . -benchmem
benchmark: build
	./tests/integration/run.sh --binary ./build/n-udptee --output ./build/benchmark --benchmark 20000
clean:
	rm -rf build
