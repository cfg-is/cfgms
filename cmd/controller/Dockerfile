# syntax=docker/dockerfile:1
# Build stage
FROM golang:1.26.5-alpine3.23 AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /src

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN --mount=type=cache,target=/go/pkg/mod go mod download

# Copy source code
COPY . .

# Build controller (GOCACHE + module cache mounts warm across builds; CGO_ENABLED=0
# already yields a static binary, so -a/-installsuffix are unneeded and only force
# cold recompiles)
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=linux go build -o controller ./cmd/controller

# Final stage - pinned to Alpine 3.23 (latest stable as of 2025-12)
FROM alpine:3.23

# Install runtime dependencies and apply security patches
RUN apk --no-cache upgrade && apk --no-cache add ca-certificates netcat-openbsd

# Create non-root user
RUN addgroup -g 1001 cfgms && \
    adduser -D -u 1001 -G cfgms cfgms

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /src/controller .

# Change ownership
RUN chown -R cfgms:cfgms /app

# Switch to non-root user
USER cfgms

# Expose default ports
# 1883: MQTT control plane
# 4433: QUIC data plane (UDP)
# 8080: HTTP API (legacy)
# 9080: HTTP API (default)
EXPOSE 1883 4433/udp 8080 9080

# Set default command: initialize on first boot (idempotent), then start controller
# The --init step exits 0 on success or non-zero if already initialized (expected on restarts)
CMD ["sh", "-c", "./controller --init 2>&1 || echo 'Init skipped (already initialized or cert management disabled)'; exec ./controller"]