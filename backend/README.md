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
