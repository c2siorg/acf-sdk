FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download
# Updated path to match your ls -Recurse output
RUN CGO_ENABLED=0 GOOS=linux go build -o sidecar ./cmd/sidecar/main.go

FROM alpine:latest
WORKDIR /
COPY --from=builder /app/sidecar /sidecar
ENTRYPOINT ["/sidecar"]
