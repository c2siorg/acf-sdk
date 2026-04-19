# Stage 1: Build the Go binary
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy the Go module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire source code
COPY . .

# Build the binary using the package path (Vibhor's fix)
RUN CGO_ENABLED=0 GOOS=linux go build -o sidecar ./cmd/sidecar

# Stage 2: Create the production image
FROM alpine:latest

WORKDIR /

# Copy the binary from the builder stage
COPY --from=builder /app/sidecar /sidecar

# Set the entrypoint to run the sidecar
ENTRYPOINT ["/sidecar"]