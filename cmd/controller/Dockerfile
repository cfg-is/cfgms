# Build stage
FROM golang:1.25-alpine3.23 AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /src

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build controller
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o controller ./cmd/controller

# Final stage - pinned to Alpine 3.23 (latest stable as of 2025-12)
FROM alpine:3.23

# Install runtime dependencies
RUN apk --no-cache add ca-certificates netcat-openbsd

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

# Set default command
CMD ["./controller"]