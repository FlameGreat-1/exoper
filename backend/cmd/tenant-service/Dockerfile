# Multi-stage build for production-grade Tenant Service
FROM golang:1.21-alpine AS builder

# Install security updates and required packages
RUN apk update && apk add --no-cache \
    git \
    ca-certificates \
    tzdata \
    && update-ca-certificates

# Create appuser for security
RUN adduser -D -g '' appuser

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the binary with security flags
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o tenant-service ./cmd/tenant-service

# Final stage - minimal production image
FROM scratch

# Import from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/passwd /etc/passwd

# Copy binary
COPY --from=builder /build/tenant-service /tenant-service

# Copy configuration
COPY --from=builder /build/configs /configs

# Use non-root user
USER appuser

# Expose ports
EXPOSE 8082 9092

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/tenant-service", "health"]

# Run the binary
ENTRYPOINT ["/tenant-service"]
