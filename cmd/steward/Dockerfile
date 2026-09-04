# syntax=docker/dockerfile:1
# Build stage
FROM golang:1.27.1-alpine3.24@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS builder

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

# Final stage - pinned to Alpine 3.24 (latest stable as of 2026-09)
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

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
