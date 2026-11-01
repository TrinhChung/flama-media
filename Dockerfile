# Stage 1: Build the binary statically
FROM golang:1.27.3-alpine AS builder

WORKDIR /src

# Copy module definitions
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build statically linked binary with stripped debug symbols
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/flama-media ./cmd/server

# Stage 2: Minimal hardened runtime image
FROM alpine:3.24

# Create non-root user and media directories
RUN apk add --no-cache ca-certificates && \
    addgroup -g 10001 flama && \
    adduser -u 10001 -G flama -s /bin/sh -D flama && \
    mkdir -p /data/flama/media && \
    chown -R flama:flama /data/flama

WORKDIR /app

# Copy binary from builder
COPY --from=builder /bin/flama-media /app/flama-media
COPY licenses/ /app/licenses/

# Set non-root user
USER flama

EXPOSE 4792

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:4792/health || exit 1

ENTRYPOINT ["/app/flama-media"]
