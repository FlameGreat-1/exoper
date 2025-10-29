FROM golang:1.21-alpine AS builder

RUN apk update && apk add --no-cache \
    git \
    ca-certificates \
    tzdata \
    && update-ca-certificates

RUN adduser -D -g '' appuser

WORKDIR /build

COPY go.mod go.sum ./

RUN go mod download && go mod verify

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o policy-service ./cmd/policy-service

FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata curl

RUN adduser -D -g '' appuser

WORKDIR /app

COPY --from=builder /build/policy-service /app/policy-service
COPY --from=builder /build/configs /app/configs

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8080 9090 8085

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/policy-service"]
CMD ["--env=production"]
