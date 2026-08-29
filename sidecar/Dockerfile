FROM golang:1.25-alpine3.22 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /acf-sidecar ./cmd/sidecar

FROM alpine:3.22

RUN apk add --no-cache ca-certificates \
    && addgroup -S acf \
    && adduser -S -G acf acf
COPY --from=build /acf-sidecar /usr/local/bin/acf-sidecar

USER acf
ENTRYPOINT ["/usr/local/bin/acf-sidecar"]
