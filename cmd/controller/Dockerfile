# syntax=docker/dockerfile:1
# Multi-platform index digests are pinned so a mutable registry tag cannot alter
# a release build. Dependabot (or an explicit release change) must update both
# the human-readable tag and digest together.
FROM golang:1.26.5-alpine3.23@sha256:622e56dbc11a8cfe87cafa2331e9a201877271cbff918af53d3be315f3da88cc AS builder

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
    CGO_ENABLED=0 GOOS=linux go build -trimpath -buildvcs=false \
    -ldflags="-s -w" -o controller ./cmd/controller

# Final stage
FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40

# Install the runtime trust store and full wget client used by the verified-TLS
# healthcheck below. Alpine's BusyBox wget does not support --ca-certificate.
# Security updates are consumed by updating the pinned base digest rather than
# performing a non-reproducible package upgrade during the build.
RUN apk add --no-cache ca-certificates wget

# Create non-root user
RUN addgroup -g 1001 cfgms && \
    adduser -D -u 1001 -G cfgms cfgms

WORKDIR /app

COPY --from=builder --chown=cfgms:cfgms /src/controller /app/controller
RUN mkdir -p /var/lib/cfgms /var/log/cfgms && \
    chown cfgms:cfgms /var/lib/cfgms /var/log/cfgms && \
    chmod 0750 /var/lib/cfgms /var/log/cfgms

USER 1001:1001

# Only the public product interfaces are image metadata. The dedicated metrics
# listener is configured and host-loopback-published explicitly by Compose;
# omitting it here prevents `docker run -P` from publishing it accidentally.
EXPOSE 9080/tcp 4433/udp

# Verify application readiness with the generated CA and hostname instead of
# merely checking that PID 1 still exists.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD wget --quiet --output-document=/dev/null \
    --ca-certificate=/var/lib/cfgms/certs/ca/ca.crt \
    https://localhost:9080/api/v1/health || exit 1

# Initialization is deliberately a separate, fail-closed job. The runtime
# container never swallows initialization errors or generates credentials as a
# side effect of a restart.
ENTRYPOINT ["/app/controller"]
CMD ["--config", "/etc/cfgms/controller.cfg"]
