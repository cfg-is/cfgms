# syntax=docker/dockerfile:1
# Multi-platform index digests are pinned so a mutable registry tag cannot alter
# a release build. Dependabot (or an explicit release change) must update both
# the human-readable tag and digest together.
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

# Optional build tags. Empty by default so a production image can never contain
# tag-gated code: the integration-test administration endpoints live behind
# `cfgms_test_endpoints` and are not compiled into the binary unless a test
# compose service asks for them (they also require CFGMS_ENABLE_TEST_ENDPOINTS at
# runtime). Only docker-compose.test.yml sets this.
ARG GO_BUILD_TAGS=""

# Build controller (GOCACHE + module cache mounts warm across builds; CGO_ENABLED=0
# already yields a static binary, so -a/-installsuffix are unneeded and only force
# cold recompiles)
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -buildvcs=false \
    -tags "${GO_BUILD_TAGS}" \
    -ldflags="-s -w" -o controller ./cmd/controller

# Final stage
FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40

# Apply pending Alpine security updates, then install the runtime trust store and
# the full wget client used by the verified-TLS healthcheck below (Alpine's
# BusyBox wget does not support --ca-certificate).
#
# The upgrade is required, not belt-and-braces. Pinning the base digest bounds
# what the build starts from, but it cannot deliver a fix that upstream has not
# rebuilt the image with: alpine:3.23 (this digest, alpine 3.23.5) ships
# libssl3/libcrypto3 3.5.7-r0, which carries CVE-2026-14456 (HIGH) plus three
# MEDIUM openssl CVEs, all fixed in 3.5.8-r0. There is no newer alpine:3.23
# digest to move to — the tag still resolves to this digest, no 3.23.6 tag
# exists, and alpine:3.24 carries the identical openssl CVEs. Only `apk upgrade`
# closes them, which is why cmd/steward/Dockerfile has always done this and its
# image scan passes while the controller's did not.
#
# This does not trade away reproducibility that the pin was otherwise providing:
# the `apk add` on the next line already resolves whatever package versions the
# alpine 3.23 repository serves at build time, so the runtime layer was never
# byte-reproducible from the digest alone. The digest pin still does its real
# job — a mutable tag cannot swap the base image out from under a release build.
RUN apk --no-cache upgrade && apk add --no-cache ca-certificates wget

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
