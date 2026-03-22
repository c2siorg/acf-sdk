# ACF SDK - Go Sidecar Build System
BINARY_NAME=sidecar.exe

.PHONY: all build test clean run

all: test build

build:
	@echo "==> Building ACF Sidecar..."
	go build -o $(BINARY_NAME) ./cmd/sidecar

test:
	@echo "==> Running Unit Tests (Protocol & Kernel)..."
	go test ./internal/...

run: build
	@echo "==> Launching Sidecar..."
	./$(BINARY_NAME)

clean:
	@echo "==> Cleaning binaries..."
	if exist $(BINARY_NAME) del $(BINARY_NAME)