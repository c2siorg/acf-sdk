.PHONY: build test lint opa-test integration docker-up docker-down clean

# ── Sidecar ──────────────────────────────────────────────────────────────────
build:
	cd sidecar && go build -o ../bin/acf-sidecar ./cmd/sidecar

test:
	cd sidecar && go test ./...

lint:
	cd sidecar && go vet ./...

# ── Policies ─────────────────────────────────────────────────────────────────
opa-test:
	opa test policies/v1/ policies/tests/ -v

# ── Python SDK ───────────────────────────────────────────────────────────────
sdk-test-python:
	cd sdk/python && python -m pytest

# ── Integration ──────────────────────────────────────────────────────────────
integration:
	cd tests/integration && go test ./... -v -timeout 120s

# ── Docker ───────────────────────────────────────────────────────────────────
docker-up:
	docker compose up -d

docker-down:
	docker compose down

# ── Clean ────────────────────────────────────────────────────────────────────
clean:
	rm -rf bin/
