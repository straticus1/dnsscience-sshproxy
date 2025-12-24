# =============================================================================
# SSH Proxy - Multi-stage Docker Build
# Lightweight bastion server with per-user ACL controls
# =============================================================================

# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -extldflags '-static'" \
    -o sshproxy .

# =============================================================================
# Runtime stage - minimal image
# =============================================================================
FROM alpine:3.19

# Add ca-certificates and create non-root user
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 1000 sshproxy

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/sshproxy /app/sshproxy

# Create directories for config and keys
RUN mkdir -p /app/config /app/keys && \
    chown -R sshproxy:sshproxy /app

# Switch to non-root user
USER sshproxy

# Expose SSH proxy port
EXPOSE 2222

# Health check - verify process is running
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD pgrep sshproxy || exit 1

# Default command
ENTRYPOINT ["/app/sshproxy"]
CMD ["-config", "/app/config/config.json"]
