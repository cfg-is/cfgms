# No `# syntax=` pragma: the BuildKit frontend bundled with the Docker Engine
# that runs this already supports RUN --mount cache mounts, and resolving
# `docker/dockerfile:1` from Docker Hub was an anonymous-token network
# dependency this build doesn't need (Issue #4212).
# Build stage
FROM ghcr.io/cfg-is/ci-mirror/golang:1.27.3-alpine3.24@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS builder

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
FROM ghcr.io/cfg-is/ci-mirror/alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a

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
