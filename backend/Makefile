# Enterprise AI Security Platform - Build Management
.PHONY: help build test clean deps proto docker k8s

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build parameters
BINARY_NAME=exoper-platform
BUILD_DIR=bin
VERSION?=latest

# Directories
CMD_DIR=./cmd
INTERNAL_DIR=./internal
PKG_DIR=./pkg

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

deps: ## Download and verify dependencies
	$(GOMOD) download
	$(GOMOD) verify
	$(GOMOD) tidy

build-gateway: ## Build API Gateway
	CGO_ENABLED=0 GOOS=linux $(GOBUILD) -a -installsuffix cgo -ldflags '-extldflags "-static"' -o $(BUILD_DIR)/gateway $(CMD_DIR)/gateway

build-auth: ## Build Auth Service
	CGO_ENABLED=0 GOOS=linux $(GOBUILD) -a -installsuffix cgo -ldflags '-extldflags "-static"' -o $(BUILD_DIR)/auth-service $(CMD_DIR)/auth-service

# build-tenant: ## Build Tenant Service - NOT IMPLEMENTED YET
# 	CGO_ENABLED=0 GOOS=linux $(GOBUILD) -a -installsuffix cgo -ldflags '-extldflags "-static"' -o $(BUILD_DIR)/tenant-service $(CMD_DIR)/tenant-service

build: deps build-gateway build-auth ## Build implemented services only

test: ## Run tests
	$(GOTEST) -v -race -coverprofile=coverage.out ./...

test-coverage: test ## Run tests with coverage report
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

clean: ## Clean build artifacts
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

proto: ## Generate protobuf files
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		pkg/api/proto/**/*.proto

security-scan: ## Run security vulnerability scan
	govulncheck ./...

lint: ## Run linters
	golangci-lint run

format: ## Format code
	gofmt -s -w .

dev-setup: deps ## Setup development environment
	@echo "Setting up development environment..."
	@mkdir -p $(BUILD_DIR)
	@echo "Development environment ready!"

.DEFAULT_GOAL := help
