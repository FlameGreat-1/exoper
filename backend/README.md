# EXOPER AI Security Platform - Backend

Enterprise-grade AI Security & Trust Layer for protecting AI interactions across organizations.

## Architecture

- **API Gateway/Orchestrator**: Central decision engine for request lifecycle management
- **Authentication Service**: mTLS, OIDC, JWT token management
- **Tenant Service**: Multi-tenant isolation and configuration
- **Threat Detection**: Real-time AI security monitoring
- **Audit System**: Immutable compliance logging

## Quick Start

```bash
# Install dependencies
make deps

# Build all services
make build

# Run development setup
make dev-setup


# Navigate to your project
cd ~/exoper/backend

# Start OPA
docker run --rm -d -p 8181:8181 --name opa-server \
  openpolicyagent/opa:latest run --server --addr 0.0.0.0:8181

# Test OPA is working
curl http://localhost:8181/health

# Continue with integration testing...



go build -o bin/policy-service ./cmd/policy-service