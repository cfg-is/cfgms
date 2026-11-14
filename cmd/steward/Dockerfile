# No `# syntax=` pragma: the BuildKit frontend bundled with the Docker Engine
# that runs this already supports RUN --mount cache mounts, and resolving
# `docker/dockerfile:1` from Docker Hub was an anonymous-token network
# dependency this build doesn't need (Issue #4212).
# Build stage
FROM ghcr.io/cfg-is/ci-mirror/golang:1.27.4-alpine3.24@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS builder

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
# Optional controller root CA fingerprint list (comma-separated lowercase hex SHA-256).
# Unset stamps nothing; a malformed value is treated as no baked root by the binary.
ARG STEWARD_CONTROLLER_ROOT_FP=
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod \
    ROOT_FP_FLAG=""; \
    if [ -n "${STEWARD_CONTROLLER_ROOT_FP}" ]; then ROOT_FP_FLAG="-X main.ControllerRootFingerprints=${STEWARD_CONTROLLER_ROOT_FP}"; fi; \
    CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.ControllerURL=${STEWARD_CONTROLLER_URL} ${ROOT_FP_FLAG}" \
    -o steward ./cmd/steward

# Final stage - pinned to Alpine 3.24 (latest stable as of 2026-09)
FROM ghcr.io/cfg-is/ci-mirror/alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

# Install runtime dependencies and apply security patches
RUN apk --no-cache upgrade && apk --no-cache add ca-certificates netcat-openbsd

# Create non-root user
RUN addgroup -g 1001 cfgms && \
    adduser -D -u 1001 -G cfgms cfgms

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /src/steward .

# Pre-create the steward's state directory and hand it to the cfgms user. The
# steward runs as non-root and /var/lib is root-owned, so it cannot create
# /var/lib/cfgms/... at runtime; without it the device identity key store is
# skipped and registration is rejected. Created empty; no secrets are added.
RUN mkdir -p /var/lib/cfgms/steward/certs

# Change ownership
RUN chown -R cfgms:cfgms /app /var/lib/cfgms

# Switch to non-root user
USER cfgms

# Set default command
CMD ["./steward"]
