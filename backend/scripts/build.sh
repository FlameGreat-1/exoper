#!/bin/bash
set -euo pipefail

# =============================================================================
# EXOPER AI Security Platform - Enterprise Build Script
# =============================================================================
# Description: Production-grade build automation for all services
# Usage: ./scripts/build.sh [service] [environment] [options]
# Author: EXOPER Platform Team
# Version: 1.0.0
# =============================================================================

# =============================================================================
# GLOBAL CONFIGURATION AND VARIABLES
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/bin"
DIST_DIR="$PROJECT_ROOT/dist"
COVERAGE_DIR="$PROJECT_ROOT/coverage"

# Version and build information
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')}"
COMMIT_SHA="${COMMIT_SHA:-$(git rev-parse HEAD 2>/dev/null || echo 'unknown')}"
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
BUILD_USER="${USER:-$(whoami)}"
BUILD_HOST="$(hostname)"

# Build configuration
SERVICES=("gateway" "auth-service" "tenant-service")
ENVIRONMENTS=("local" "staging" "production")
ARCHITECTURES=("amd64" "arm64")
PLATFORMS=("linux" "darwin" "windows")

# Default values
DEFAULT_SERVICE="all"
DEFAULT_ENVIRONMENT="local"
DEFAULT_ARCHITECTURE="amd64"
DEFAULT_PLATFORM="linux"

# Parse command line arguments
SERVICE="${1:-$DEFAULT_SERVICE}"
ENVIRONMENT="${2:-$DEFAULT_ENVIRONMENT}"
ARCHITECTURE="${3:-$DEFAULT_ARCHITECTURE}"
PLATFORM="${4:-$DEFAULT_PLATFORM}"

# =============================================================================
# COLOR DEFINITIONS AND LOGGING FUNCTIONS
# =============================================================================

# ANSI Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

# Logging functions with timestamps
log_info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] [INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] [SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] [WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] [ERROR]${NC} $1"
}

log_debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo -e "${PURPLE}[$(date +'%Y-%m-%d %H:%M:%S')] [DEBUG]${NC} $1"
    fi
}

log_header() {
    echo -e "${CYAN}${BOLD}"
    echo "============================================================================="
    echo " $1"
    echo "============================================================================="
    echo -e "${NC}"
}

# =============================================================================
# UTILITY AND VALIDATION FUNCTIONS
# =============================================================================

# Display script usage information
show_usage() {
    cat << EOF
${BOLD}EXOPER AI Security Platform - Build Script${NC}

${BOLD}USAGE:${NC}
    $0 [service] [environment] [architecture] [platform] [options]

${BOLD}PARAMETERS:${NC}
    service      Service to build (default: all)
                 Options: all, gateway, auth-service, tenant-service
    
    environment  Target environment (default: local)
                 Options: local, staging, production
    
    architecture Target architecture (default: amd64)
                 Options: amd64, arm64
    
    platform     Target platform (default: linux)
                 Options: linux, darwin, windows

${BOLD}OPTIONS:${NC}
    --help, -h          Show this help message
    --debug             Enable debug logging
    --clean             Clean build artifacts before building
    --no-tests          Skip running tests
    --no-security       Skip security checks
    --cross-compile     Build for all platforms and architectures
    --docker            Build Docker images after binaries
    --push              Push Docker images to registry

${BOLD}EXAMPLES:${NC}
    $0                                    # Build all services for local/linux/amd64
    $0 gateway                           # Build gateway service only
    $0 all production                    # Build all services for production
    $0 gateway staging amd64 linux       # Build gateway for staging/linux/amd64
    $0 --clean --docker                  # Clean build and create Docker images
    $0 --cross-compile                   # Build for all platforms/architectures

${BOLD}ENVIRONMENT VARIABLES:${NC}
    VERSION             Override version (default: git describe)
    COMMIT_SHA          Override commit SHA (default: git rev-parse HEAD)
    DEBUG               Enable debug mode (true/false)
    DOCKER_REGISTRY     Docker registry for image builds
    SKIP_TESTS          Skip test execution (true/false)
    SKIP_SECURITY       Skip security checks (true/false)

EOF
}

# Validate input parameters
validate_parameters() {
    log_debug "Validating input parameters..."
    
    # Validate service
    if [[ "$SERVICE" != "all" ]] && [[ ! " ${SERVICES[*]} " =~ " $SERVICE " ]]; then
        log_error "Invalid service: $SERVICE"
        log_info "Available services: all, ${SERVICES[*]}"
        exit 1
    fi
    
    # Validate environment
    if [[ ! " ${ENVIRONMENTS[*]} " =~ " $ENVIRONMENT " ]]; then
        log_error "Invalid environment: $ENVIRONMENT"
        log_info "Available environments: ${ENVIRONMENTS[*]}"
        exit 1
    fi
    
    # Validate architecture
    if [[ ! " ${ARCHITECTURES[*]} " =~ " $ARCHITECTURE " ]]; then
        log_error "Invalid architecture: $ARCHITECTURE"
        log_info "Available architectures: ${ARCHITECTURES[*]}"
        exit 1
    fi
    
    # Validate platform
    if [[ ! " ${PLATFORMS[*]} " =~ " $PLATFORM " ]]; then
        log_error "Invalid platform: $PLATFORM"
        log_info "Available platforms: ${PLATFORMS[*]}"
        exit 1
    fi
    
    log_success "Parameter validation completed"
}

# Check system prerequisites
check_prerequisites() {
    log_info "Checking system prerequisites..."
    
    # Required tools
    local required_tools=("go" "git")
    local optional_tools=("docker" "govulncheck" "gosec" "golangci-lint")
    
    # Check required tools
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            log_error "Required tool not found: $tool"
            exit 1
        else
            local version=$(${tool} version 2>/dev/null | head -n1 || echo "unknown")
            log_debug "$tool: $version"
        fi
    done
    
    # Check optional tools
    for tool in "${optional_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            local version=$(${tool} version 2>/dev/null | head -n1 || echo "unknown")
            log_debug "$tool: $version"
        else
            log_warning "Optional tool not found: $tool"
        fi
    done
    
    # Check Go version
    local go_version=$(go version | awk '{print $3}' | sed 's/go//')
    local required_go_version="1.21"
    
    if ! printf '%s\n%s\n' "$required_go_version" "$go_version" | sort -V -C; then
        log_error "Go version $go_version is too old. Required: $required_go_version+"
        exit 1
    fi
    
    log_success "Prerequisites check completed"
}

# Create necessary directories
create_directories() {
    log_info "Creating build directories..."
    
    local directories=("$BUILD_DIR" "$DIST_DIR" "$COVERAGE_DIR")
    
    for dir in "${directories[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            log_debug "Created directory: $dir"
        fi
    done
    
    log_success "Build directories ready"
}

# Clean build artifacts
clean_build_artifacts() {
    if [[ "${CLEAN_BUILD:-false}" == "true" ]]; then
        log_info "Cleaning build artifacts..."
        
        # Remove build directories
        rm -rf "$BUILD_DIR" "$DIST_DIR" "$COVERAGE_DIR"
        
        # Clean Go cache
        go clean -cache -modcache -testcache
        
        log_success "Build artifacts cleaned"
        
        # Recreate directories
        create_directories
    fi
}

# =============================================================================
# DEPENDENCY AND MODULE MANAGEMENT
# =============================================================================

# Download and verify Go modules
manage_dependencies() {
    log_info "Managing Go dependencies..."
    
    # Change to project root
    cd "$PROJECT_ROOT"
    
    # Download dependencies
    log_debug "Downloading Go modules..."
    if ! go mod download; then
        log_error "Failed to download Go modules"
        exit 1
    fi
    
    # Verify dependencies
    log_debug "Verifying Go modules..."
    if ! go mod verify; then
        log_error "Go module verification failed"
        exit 1
    fi
    
    # Tidy up modules
    log_debug "Tidying Go modules..."
    if ! go mod tidy; then
        log_error "Failed to tidy Go modules"
        exit 1
    fi
    
    # Check for vulnerabilities if govulncheck is available
    if command -v govulncheck >/dev/null 2>&1 && [[ "${SKIP_SECURITY:-false}" != "true" ]]; then
        log_info "Checking for known vulnerabilities..."
        if ! govulncheck ./...; then
            log_warning "Vulnerability check found issues"
        else
            log_success "No known vulnerabilities found"
        fi
    fi
    
    log_success "Dependency management completed"
}

# =============================================================================
# TESTING AND QUALITY ASSURANCE FUNCTIONS
# =============================================================================

# Run comprehensive test suite
run_tests() {
    if [[ "${SKIP_TESTS:-false}" == "true" ]]; then
        log_warning "Skipping tests (SKIP_TESTS=true)"
        return 0
    fi
    
    log_info "Running test suite..."
    
    # Change to project root
    cd "$PROJECT_ROOT"
    
    # Create coverage directory
    mkdir -p "$COVERAGE_DIR"
    
    # Run tests with coverage
    local coverage_file="$COVERAGE_DIR/coverage.out"
    local coverage_html="$COVERAGE_DIR/coverage.html"
    
    log_debug "Running tests with race detection and coverage..."
    if go test -v -race -coverprofile="$coverage_file" -covermode=atomic ./...; then
        log_success "All tests passed"
        
        # Generate coverage report
        if [[ -f "$coverage_file" ]]; then
            go tool cover -html="$coverage_file" -o "$coverage_html"
            
            # Calculate coverage percentage
            local coverage_percent=$(go tool cover -func="$coverage_file" | grep total | awk '{print substr($3, 1, length($3)-1)}')
            log_info "Test coverage: ${coverage_percent}%"
            
            # Check coverage threshold
            local min_coverage="${MIN_COVERAGE:-80}"
            if (( $(echo "$coverage_percent < $min_coverage" | bc -l 2>/dev/null || echo "0") )); then
                log_warning "Coverage ${coverage_percent}% is below minimum threshold ${min_coverage}%"
                if [[ "$ENVIRONMENT" == "production" ]]; then
                    log_error "Production builds require minimum ${min_coverage}% coverage"
                    exit 1
                fi
            else
                log_success "Coverage threshold met: ${coverage_percent}% >= ${min_coverage}%"
            fi
        fi
        
        return 0
    else
        log_error "Tests failed"
        return 1
    fi
}

# Run security analysis
run_security_checks() {
    if [[ "${SKIP_SECURITY:-false}" == "true" ]]; then
        log_warning "Skipping security checks (SKIP_SECURITY=true)"
        return 0
    fi
    
    log_info "Running security analysis..."
    
    # Run gosec if available
    if command -v gosec >/dev/null 2>&1; then
        log_debug "Running gosec security scanner..."
        if gosec -fmt json -out "$COVERAGE_DIR/gosec-report.json" -stdout -verbose=text ./...; then
            log_success "Security analysis passed"
        else
            log_warning "Security analysis found potential issues"
            if [[ "$ENVIRONMENT" == "production" ]]; then
                log_error "Production builds cannot have security issues"
                exit 1
            fi
        fi
    else
        log_warning "gosec not available, skipping security analysis"
    fi
    
    # Run additional security checks for production
    if [[ "$ENVIRONMENT" == "production" ]]; then
        log_info "Running additional production security checks..."
        
        # Check for hardcoded secrets
        if command -v git >/dev/null 2>&1; then
            log_debug "Scanning for potential secrets..."
            if git log --all --full-history -- "*.go" | grep -i -E "(password|secret|key|token)" >/dev/null; then
                log_warning "Potential secrets found in git history"
            fi
        fi
        
        # Check for debug statements
        if grep -r "fmt.Print\|log.Print\|println" --include="*.go" . >/dev/null 2>&1; then
            log_warning "Debug print statements found in code"
        fi
    fi
    
    log_success "Security checks completed"
}

# Run code quality checks
run_quality_checks() {
    log_info "Running code quality checks..."
    
    # Run go vet
    log_debug "Running go vet..."
    if ! go vet ./...; then
        log_error "go vet found issues"
        return 1
    fi
    
    # Run gofmt check
    log_debug "Checking code formatting..."
    local unformatted_files=$(gofmt -l .)
    if [[ -n "$unformatted_files" ]]; then
        log_error "Code formatting issues found in:"
        echo "$unformatted_files"
        log_info "Run 'gofmt -w .' to fix formatting"
        return 1
    fi
    
    # Run golangci-lint if available
    if command -v golangci-lint >/dev/null 2>&1; then
        log_debug "Running golangci-lint..."
        if ! golangci-lint run --timeout=10m; then
            log_warning "golangci-lint found issues"
            if [[ "$ENVIRONMENT" == "production" ]]; then
                return 1
            fi
        fi
    else
        log_warning "golangci-lint not available, skipping advanced linting"
    fi
    
    log_success "Code quality checks passed"
}

# =============================================================================
# BUILD AND COMPILATION FUNCTIONS
# =============================================================================

# Get build flags for specific environment
get_build_flags() {
    local env="$1"
    local service="$2"
    
    local ldflags=(
        "-s" "-w"  # Strip debug info and symbol table
        "-X main.version=$VERSION"
        "-X main.commit=$COMMIT_SHA"
        "-X main.buildTime=$BUILD_TIME"
        "-X main.buildUser=$BUILD_USER"
        "-X main.buildHost=$BUILD_HOST"
        "-X main.environment=$env"
    )
    
    # Environment-specific flags
    case "$env" in
        "production")
            ldflags+=("-X main.debug=false")
            ;;
        "staging")
            ldflags+=("-X main.debug=false")
            ;;
        "local")
            ldflags+=("-X main.debug=true")
            ;;
    esac
    
    # Build flags
    local build_flags=(
        "-ldflags=${ldflags[*]}"
        "-a"
        "-installsuffix=cgo"
    )
    
    # Production-specific flags
    if [[ "$env" == "production" ]]; then
        build_flags+=("-trimpath")
    fi
    
    echo "${build_flags[@]}"
}

# Build a single service
build_service() {
    local service="$1"
    local env="$2"
    local arch="$3"
    local platform="$4"
    
    log_info "Building $service for $platform/$arch ($env)..."
    
    # Validate service directory exists
    local service_dir="$PROJECT_ROOT/cmd/$service"
    if [[ ! -d "$service_dir" ]]; then
        log_error "Service directory not found: $service_dir"
        return 1
    fi
    
    # Set build environment
    export CGO_ENABLED=0
    export GOOS="$platform"
    export GOARCH="$arch"
    
    # Determine output filename
    local binary_name="$service"
    if [[ "$platform" == "windows" ]]; then
        binary_name="${service}.exe"
    fi
    
    # Create platform-specific output directory
    local output_dir="$BUILD_DIR/$platform-$arch"
    mkdir -p "$output_dir"
    local output_path="$output_dir/$binary_name"
    
    # Get build flags
    local build_flags
    read -ra build_flags <<< "$(get_build_flags "$env" "$service")"
    
    # Build the service
    log_debug "Compiling $service..."
    local start_time=$(date +%s)
    
    if go build "${build_flags[@]}" -o "$output_path" "$service_dir"; then
        local end_time=$(date +%s)
        local build_duration=$((end_time - start_time))
        
        # Get binary information
        local binary_size=$(du -h "$output_path" | cut -f1)
        
        log_success "Built $service successfully"
        log_debug "  Output: $output_path"
        log_debug "  Size: $binary_size"
        log_debug "  Build time: ${build_duration}s"
        
        # Make executable
        chmod +x "$output_path"
        
        # Create symlink for default platform
        if [[ "$platform" == "$DEFAULT_PLATFORM" ]] && [[ "$arch" == "$DEFAULT_ARCHITECTURE" ]]; then
            local default_output="$BUILD_DIR/$binary_name"
            ln -sf "$output_path" "$default_output"
            log_debug "Created default symlink: $default_output"
        fi
        
        return 0
    else
        log_error "Failed to build $service"
        return 1
    fi
}

# Build all services for cross-compilation
cross_compile_services() {
    if [[ "${CROSS_COMPILE:-false}" != "true" ]]; then
        return 0
    fi
    
    log_header "Cross-Compilation Build"
    
    local services_to_build=()
    if [[ "$SERVICE" == "all" ]]; then
        services_to_build=("${SERVICES[@]}")
    else
        services_to_build=("$SERVICE")
    fi
    
    local failed_builds=()
    local total_builds=0
    local successful_builds=0
    
    for platform in "${PLATFORMS[@]}"; do
        for arch in "${ARCHITECTURES[@]}"; do
            # Skip invalid combinations
            if [[ "$platform" == "darwin" ]] && [[ "$arch" == "arm64" ]]; then
                continue  # macOS ARM64 support varies
            fi
            
            for service in "${services_to_build[@]}"; do
                total_builds=$((total_builds + 1))
                
                if build_service "$service" "$ENVIRONMENT" "$arch" "$platform"; then
                    successful_builds=$((successful_builds + 1))
                else
                    failed_builds+=("$service-$platform-$arch")
                fi
            done
        done
    done
    
    log_info "Cross-compilation summary:"
    log_info "  Total builds: $total_builds"
    log_info "  Successful: $successful_builds"
    log_info "  Failed: $((total_builds - successful_builds))"
    
    if [[ ${#failed_builds[@]} -gt 0 ]]; then
        log_warning "Failed builds: ${failed_builds[*]}"
        return 1
    fi
    
    return 0
}

# =============================================================================
# PACKAGING AND DISTRIBUTION FUNCTIONS
# =============================================================================

# Create distribution packages
create_distribution_packages() {
    log_info "Creating distribution packages..."
    
    # Create distribution directory structure
    local dist_base="$DIST_DIR/$VERSION"
    mkdir -p "$dist_base"
    
    # Package each platform/architecture combination
    for platform_arch_dir in "$BUILD_DIR"/*-*; do
        if [[ -d "$platform_arch_dir" ]]; then
            local platform_arch=$(basename "$platform_arch_dir")
            local package_dir="$dist_base/exoper-platform-$VERSION-$platform_arch"
            
            mkdir -p "$package_dir"
            
            # Copy binaries
            cp "$platform_arch_dir"/* "$package_dir/"
            
            # Copy configuration files
            cp -r "$PROJECT_ROOT/configs" "$package_dir/"
            
            # Copy documentation
            cp "$PROJECT_ROOT/README.md" "$package_dir/"
            
            # Create archive
            local archive_name="exoper-platform-$VERSION-$platform_arch.tar.gz"
            tar -czf "$dist_base/$archive_name" -C "$dist_base" "$(basename "$package_dir")"
            
            log_debug "Created package: $archive_name"
        fi
    done
    
    log_success "Distribution packages created in $dist_base"
}

# Generate build manifest
generate_build_manifest() {
    log_info "Generating build manifest..."
    
    local manifest_file="$BUILD_DIR/build-manifest.json"
    
    cat > "$manifest_file" << EOF
{
  "version": "$VERSION",
  "commit": "$COMMIT_SHA",
  "buildTime": "$BUILD_TIME",
  "buildUser": "$BUILD_USER",
  "buildHost": "$BUILD_HOST",
  "environment": "$ENVIRONMENT",
  "goVersion": "$(go version | awk '{print $3}')",
  "services": [
$(for service in "${SERVICES[@]}"; do
    echo "    \"$service\""
    [[ "$service" != "${SERVICES[-1]}" ]] && echo ","
done)
  ],
  "artifacts": [
$(find "$BUILD_DIR" -name "*" -type f -executable | while read -r file; do
    local size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo "0")
    local checksum=$(sha256sum "$file" 2>/dev/null | cut -d' ' -f1 || echo "unknown")
    echo "    {"
    echo "      \"path\": \"$(basename "$file")\","
    echo "      \"size\": $size,"
    echo "      \"checksum\": \"$checksum\""
    echo "    }"
    echo ","
done | sed '$ s/,$//')
  ]
}
EOF
    
    log_success "Build manifest generated: $manifest_file"
}

# =============================================================================
# MAIN EXECUTION LOGIC
# =============================================================================

# Main build function
main() {
    # Parse command line options
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_usage
                exit 0
                ;;
            --debug)
                export DEBUG=true
                shift
                ;;
            --clean)
                export CLEAN_BUILD=true
                shift
                ;;
            --no-tests)
                export SKIP_TESTS=true
                shift
                ;;
            --no-security)
                export SKIP_SECURITY=true
                shift
                ;;
            --cross-compile)
                export CROSS_COMPILE=true
                shift
                ;;
            --docker)
                export BUILD_DOCKER=true
                shift
                ;;
            --push)
                export PUSH_DOCKER=true
                shift
                ;;
            -*)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                break
                ;;
        esac
    done
    
    # Display build information
    log_header "EXOPER AI Security Platform - Build Process"
    log_info "Version: $VERSION"
    log_info "Commit: $COMMIT_SHA"
    log_info "Build Time: $BUILD_TIME"
    log_info "Environment: $ENVIRONMENT"
    log_info "Service: $SERVICE"
    log_info "Platform: $PLATFORM"
    log_info "Architecture: $ARCHITECTURE"
    
    # Change to project root
    cd "$PROJECT_ROOT"
    
    # Execute build pipeline
    validate_parameters
    check_prerequisites
    clean_build_artifacts
    create_directories
    manage_dependencies
    
    # Run quality checks for non-local environments
    if [[ "$ENVIRONMENT" != "local" ]]; then
        run_quality_checks || exit 1
        run_tests || exit 1
        run_security_checks || exit 1
    fi
    
    # Build services
    if [[ "${CROSS_COMPILE:-false}" == "true" ]]; then
        cross_compile_services || exit 1
    else
        local services_to_build=()
        if [[ "$SERVICE" == "all" ]]; then
            services_to_build=("${SERVICES[@]}")
        else
            services_to_build=("$SERVICE")
        fi
        
        local failed_builds=()
        for svc in "${services_to_build[@]}"; do
            if ! build_service "$svc" "$ENVIRONMENT" "$ARCHITECTURE" "$PLATFORM"; then
                failed_builds+=("$svc")
            fi
        done
        
        if [[ ${#failed_builds[@]} -gt 0 ]]; then
            log_error "Failed to build: ${failed_builds[*]}"
            exit 1
        fi
    fi
    
    # Generate build artifacts
    generate_build_manifest
    
    # Create distribution packages for production
    if [[ "$ENVIRONMENT" == "production" ]]; then
        create_distribution_packages
    fi
    
    # Build summary
    log_header "Build Summary"
    log_success "Build process completed successfully!"
    log_info "Built artifacts are available in: $BUILD_DIR"
    
    if [[ -d "$DIST_DIR" ]]; then
        log_info "Distribution packages are available in: $DIST_DIR"
    fi
    
    # Display build artifacts
    log_info "Build artifacts:"
    find "$BUILD_DIR" -type f -executable | while read -r file; do
        local size=$(du -h "$file" | cut -f1)
        log_info "  $(basename "$file") ($size)"
    done
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
