#!/bin/bash
set -e

echo "Installing protobuf tools..."
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

echo "Generating Go files from proto definitions..."

# Generate common proto
protoc --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
       pkg/api/proto/common/common.proto

# Generate auth proto  
protoc --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
       pkg/api/proto/auth/auth.proto

# Generate gateway proto
protoc --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
       pkg/api/proto/gateway/gateway.proto

echo "Proto generation completed successfully!"
