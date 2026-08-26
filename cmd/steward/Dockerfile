# syntax=docker/dockerfile:1
# Build stage
FROM golang:1.27.0-alpine3.23@sha256:3747dcba41c8b0db3211fda4db61638b980e17ac5bb3c94460a975a9cfe19395 AS builder

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

# Build steward with compile-time controller URL (GOCACHE + module cache mounts warm
# across builds; CGO_ENABLED=0 already yields a static binary, so -a/-installsuffix
# are unneeded and only force cold recompiles)
ARG STEWARD_CONTROLLER_URL=https://localhost:9080
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.ControllerURL=${STEWARD_CONTROLLER_URL}" \
    -o steward ./cmd/steward

# Final stage - pinned to Alpine 3.23 (latest stable as of 2025-12)
FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40

# Install runtime dependencies and apply security patches
RUN apk --no-cache upgrade && apk --no-cache add ca-certificates netcat-openbsd

# Create non-root user
RUN addgroup -g 1001 cfgms && \
    adduser -D -u 1001 -G cfgms cfgms

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /src/steward .

# Change ownership
RUN chown -R cfgms:cfgms /app

# Switch to non-root user
USER cfgms

# Set default command
CMD ["./steward"]
