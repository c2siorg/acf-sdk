# Build: docker build -t acf-sidecar ./sidecar
# Run:  see repo root docker-compose.yml
FROM golang:1.22-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /acf-sidecar ./cmd/sidecar

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /acf-sidecar /usr/local/bin/acf-sidecar

# UDS default is /tmp/acf.sock — keep /tmp writable.
WORKDIR /tmp

ENV ACF_HMAC_KEY=""

ENTRYPOINT ["/usr/local/bin/acf-sidecar"]
