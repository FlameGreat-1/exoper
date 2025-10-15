#!/bin/bash
set -euo pipefail

# Enterprise Deployment Script for EXOPER AI Security Platform
# Usage: ./scripts/deploy.sh [environment] [service]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENVIRONMENT="${1:-staging}"
SERVICE="${2:-all}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Configuration
SERVICES=("gateway" "auth-service" "tenant-service")
NAMESPACE="exoper-system"
HELM_RELEASE="exoper-platform"
TIMEOUT="600s"

# Environment-specific configuration
case "$ENVIRONMENT" in
    "local")
        CLUSTER_NAME="minikube"
        REGISTRY="localhost:5000"
        DOMAIN="localhost"
        ;;
    "staging")
        CLUSTER_NAME="exoper-staging-cluster"
        REGISTRY="ghcr.io/exoper"
        DOMAIN="staging.exoper.com"
        ;;
    "production")
        CLUSTER_NAME="exoper-production-cluster"
        REGISTRY="ghcr.io/exoper"
        DOMAIN="app.exoper.com"
        ;;
    *)
        log_error "Unknown environment: $ENVIRONMENT"
        exit 1
        ;;
esac

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check required tools
    local required_tools=("kubectl" "helm" "docker")
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            log_error "$tool is not installed"
            exit 1
        fi
    done
    
    # Check kubectl context
    local current_context=$(kubectl config current-context 2>/dev/null || echo "none")
    log_info "Current kubectl context: $current_context"
    
    # Verify cluster connectivity
    if ! kubectl cluster-info >/dev/null 2>&1; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

create_namespace() {
    log_info "Creating namespace if not exists..."
    
    if ! kubectl get namespace "$NAMESPACE" >/dev/null 2>&1; then
        kubectl create namespace "$NAMESPACE"
        log_success "Created namespace: $NAMESPACE"
    else
        log_info "Namespace already exists: $NAMESPACE"
    fi
}

deploy_secrets() {
    log_info "Deploying secrets..."
    
    # Apply secrets from Kubernetes manifests
    kubectl apply -f "$PROJECT_ROOT/deployments/kubernetes/gateway/secret.yaml" -n "$NAMESPACE"
    kubectl apply -f "$PROJECT_ROOT/deployments/kubernetes/auth-service/secret.yaml" -n "$NAMESPACE"
    kubectl apply -f "$PROJECT_ROOT/deployments/kubernetes/tenant-service/secret.yaml" -n "$NAMESPACE"
    
    log_success "Secrets deployed"
}

deploy_configmaps() {
    log_info "Deploying configuration..."
    
    # Apply configmaps
    kubectl apply -f "$PROJECT_ROOT/deployments/kubernetes/gateway/configmap.yaml" -n "$NAMESPACE"
    kubectl apply -f "$PROJECT_ROOT/deployments/kubernetes/auth-service/configmap.yaml" -n "$NAMESPACE"
    kubectl apply -f "$PROJECT_ROOT/deployments/kubernetes/tenant-service/configmap.yaml" -n "$NAMESPACE"
    
    log_success "Configuration deployed"
}

deploy_service() {
    local service="$1"
    
    log_info "Deploying $service..."
    
    # Apply service manifests
    kubectl apply -f "$PROJECT_ROOT/deployments/kubernetes/$service/" -n "$NAMESPACE"
    
    # Wait for deployment to be ready
    kubectl rollout status deployment/exoper-$service -n "$NAMESPACE" --timeout="$TIMEOUT"
    
    log_success "$service deployed successfully"
}

run_health_checks() {
    log_info "Running health checks..."
    
    # Wait for all pods to be ready
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=gateway -n "$NAMESPACE" --timeout="$TIMEOUT"
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=auth -n "$NAMESPACE" --timeout="$TIMEOUT"
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/component=tenant -n "$NAMESPACE" --timeout="$TIMEOUT"
    
    # Test service endpoints
    local gateway_pod=$(kubectl get pods -l app.kubernetes.io/component=gateway -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}')
    
    if kubectl exec "$gateway_pod" -n "$NAMESPACE" -- wget -q --spider http://localhost:8080/health; then
        log_success "Gateway health check passed"
    else
        log_error "Gateway health check failed"
        return 1
    fi
    
    log_success "All health checks passed"
}

rollback_deployment() {
    local service="$1"
    
    log_warning "Rolling back $service deployment..."
    
    kubectl rollout undo deployment/exoper-$service -n "$NAMESPACE"
    kubectl rollout status deployment/exoper-$service -n "$NAMESPACE" --timeout="$TIMEOUT"
    
    log_info "$service rolled back successfully"
}

cleanup_failed_deployment() {
    log_warning "Cleaning up failed deployment..."
    
    # Get failed pods
    local failed_pods=$(kubectl get pods -n "$NAMESPACE" --field-selector=status.phase=Failed -o jsonpath='{.items[*].metadata.name}')
    
    if [[ -n "$failed_pods" ]]; then
        log_info "Removing failed pods: $failed_pods"
        kubectl delete pods $failed_pods -n "$NAMESPACE"
    fi
}

backup_database() {
    if [[ "$ENVIRONMENT" == "production" ]]; then
        log_info "Creating database backup before deployment..."
        
        # Trigger backup job
        kubectl create job backup-$(date +%Y%m%d-%H%M%S) \
            --from=cronjob/database-backup \
            -n "$NAMESPACE" || log_warning "Backup job creation failed"
    fi
}

deploy_monitoring() {
    log_info "Deploying monitoring configuration..."
    
    # Apply ServiceMonitor for Prometheus
    cat <<EOF | kubectl apply -f -
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: exoper-platform
  namespace: $NAMESPACE
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: exoper-gateway
  endpoints:
  - port: metrics
    path: /metrics
    interval: 30s
EOF
    
    log_success "Monitoring configuration deployed"
}

main() {
    log_info "Starting deployment to $ENVIRONMENT..."
    
    # Change to project root
    cd "$PROJECT_ROOT"
    
    # Run prerequisite checks
    check_prerequisites
    
    # Create namespace
    create_namespace
    
    # Backup database for production
    backup_database
    
    # Deploy configuration and secrets
    deploy_configmaps
    deploy_secrets
    
    # Deploy services
    if [[ "$SERVICE" == "all" ]]; then
        local failed_deployments=()
        
        for svc in "${SERVICES[@]}"; do
            if ! deploy_service "$svc"; then
                failed_deployments+=("$svc")
                cleanup_failed_deployment
            fi
        done
        
        if [[ ${#failed_deployments[@]} -gt 0 ]]; then
            log_error "Failed deployments: ${failed_deployments[*]}"
            
            # Rollback failed deployments
            for svc in "${failed_deployments[@]}"; do
                rollback_deployment "$svc"
            done
            
            exit 1
        fi
    else
        if [[ " ${SERVICES[*]} " =~ " $SERVICE " ]]; then
            if ! deploy_service "$SERVICE"; then
                cleanup_failed_deployment
                rollback_deployment "$SERVICE"
                exit 1
            fi
        else
            log_error "Unknown service: $SERVICE"
            log_info "Available services: all, ${SERVICES[*]}"
            exit 1
        fi
    fi
    
    # Deploy monitoring
    deploy_monitoring
    
    # Run health checks
    if ! run_health_checks; then
        log_error "Health checks failed"
        exit 1
    fi
    
    # Display deployment information
    log_success "Deployment completed successfully!"
    log_info "Environment: $ENVIRONMENT"
    log_info "Domain: $DOMAIN"
    log_info "Namespace: $NAMESPACE"
    
    # Show service status
    kubectl get pods -n "$NAMESPACE" -o wide
    kubectl get services -n "$NAMESPACE"
}

# Show usage if help requested
if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    echo "Usage: $0 [environment] [service]"
    echo ""
    echo "Environments: local, staging, production"
    echo "Services: all, ${SERVICES[*]}"
    echo ""
    echo "Examples:"
    echo "  $0 staging           # Deploy all services to staging"
    echo "  $0 production gateway # Deploy gateway to production"
    echo "  $0 local all         # Deploy all services locally"
    exit 0
fi

main "$@"
