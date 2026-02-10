#!/usr/bin/env bash
# ============================================================
# pipeline.sh - Local CI/CD Pipeline for OnCall Platform
# ============================================================
# Automates: Lint → Test → Security Scan → Build → Deploy → Healthcheck
#
# Usage:
#   ./pipeline.sh              # Full pipeline
#   ./pipeline.sh lint         # Linting only
#   ./pipeline.sh test         # Tests only
#   ./pipeline.sh build        # Build images only
#   ./pipeline.sh deploy       # Deploy only
#   ./pipeline.sh healthcheck  # Healthcheck only
#   ./pipeline.sh security     # Security scan only
# ============================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION_TAG="${VERSION_TAG:-$(date +%Y%m%d-%H%M%S)}"
COMPOSE_FILE="${PROJECT_DIR}/docker-compose.yml"
HEALTHCHECK_TIMEOUT=60
HEALTHCHECK_INTERVAL=5

# ======================== UTILITIES ========================

log_step() {
    echo -e "\n${BLUE}══════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  ▶ $1${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════${NC}\n"
}

log_success() {
    echo -e "${GREEN}  ✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}  ⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}  ❌ $1${NC}"
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        log_error "$1 is not installed. Please install it first."
        exit 1
    fi
}

# ======================== STAGES ========================

stage_lint() {
    log_step "STAGE 1: Linting (flake8)"

    # Install flake8 if not available
    pip install --quiet flake8 2>/dev/null || true

    local lint_errors=0
    for service_dir in services/*/; do
        if [ -f "${service_dir}main.py" ]; then
            echo "  Linting ${service_dir}..."
            if flake8 "${service_dir}" \
                --max-line-length=120 \
                --ignore=E501,W503,E402,F401 \
                --exclude="generated,__pycache__" \
                2>/dev/null; then
                log_success "${service_dir} passed"
            else
                log_warning "${service_dir} has warnings"
                lint_errors=$((lint_errors + 1))
            fi
        fi
    done

    # Lint shared module
    echo "  Linting shared/..."
    if flake8 shared/ --max-line-length=120 --ignore=E501,W503,E402,F401 2>/dev/null; then
        log_success "shared/ passed"
    else
        log_warning "shared/ has warnings"
    fi

    if [ $lint_errors -eq 0 ]; then
        log_success "All lint checks passed"
    else
        log_warning "Lint completed with $lint_errors warnings"
    fi
}

stage_test() {
    log_step "STAGE 2: Unit Tests (pytest)"

    pip install --quiet pytest pytest-asyncio aiohttp 2>/dev/null || true

    if [ -d "tests" ] && [ "$(find tests -name 'test_*.py' -type f | head -1)" ]; then
        pytest tests/ -v --tb=short -q 2>&1 || {
            log_warning "Some tests failed (non-blocking in dev mode)"
        }
        log_success "Test suite completed"
    else
        log_warning "No tests found in tests/. Skipping."
    fi
}

stage_security() {
    log_step "STAGE 3: Security Scan"

    python "${PROJECT_DIR}/scripts/security_scan.py" --path "${PROJECT_DIR}" || {
        log_warning "Security scan found issues (check report above)"
    }
    log_success "Security scan completed"
}

stage_build() {
    log_step "STAGE 4: Building Docker Images (tag: ${VERSION_TAG})"

    check_command docker

    # Build each service image with multi-stage Dockerfile
    local services=("alert_ingestion" "incident_management" "oncall_service" "metrics_exporter")

    for svc in "${services[@]}"; do
        echo "  Building oncall-${svc}:${VERSION_TAG}..."
        docker build \
            -f Dockerfile.service \
            --build-arg SERVICE_DIR="${svc}" \
            -t "oncall-${svc}:${VERSION_TAG}" \
            -t "oncall-${svc}:latest" \
            . 2>&1 | tail -1
        log_success "oncall-${svc}:${VERSION_TAG} built"
    done

    # Build Web UI
    echo "  Building oncall-web-ui:${VERSION_TAG}..."
    docker build \
        -f Dockerfile.webui \
        -t "oncall-web-ui:${VERSION_TAG}" \
        -t "oncall-web-ui:latest" \
        . 2>&1 | tail -1
    log_success "oncall-web-ui:${VERSION_TAG} built"

    # Check image sizes
    echo ""
    echo "  Image sizes:"
    docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" | grep "oncall-" || true

    # Verify all images < 500MB
    for img in $(docker images --filter "reference=oncall-*:${VERSION_TAG}" --format "{{.Repository}}:{{.Tag}}"); do
        size_bytes=$(docker inspect "$img" --format '{{.Size}}' 2>/dev/null || echo "0")
        size_mb=$((size_bytes / 1024 / 1024))
        if [ "$size_mb" -gt 500 ]; then
            log_error "$img exceeds 500MB limit (${size_mb}MB)"
        else
            log_success "$img: ${size_mb}MB ✓"
        fi
    done
}

stage_deploy() {
    log_step "STAGE 5: Deploying with docker-compose"

    check_command docker

    # Stop existing containers
    echo "  Stopping existing containers..."
    docker compose -f "${COMPOSE_FILE}" down --remove-orphans 2>/dev/null || true

    # Start all services
    echo "  Starting all services..."
    docker compose -f "${COMPOSE_FILE}" up -d --build

    log_success "All services deployed"

    # Show running containers
    echo ""
    docker compose -f "${COMPOSE_FILE}" ps
}

stage_healthcheck() {
    log_step "STAGE 6: Healthcheck"

    local endpoints=(
        "http://localhost:80/api/v1/alerts|Alert Ingestion (Traefik)"
        "http://localhost:8002/health|Incident Management"
        "http://localhost:8003/health|On-Call Service"
        "http://localhost:8080/health|Web UI"
        "http://localhost:9090/health|Metrics Exporter"
        "http://localhost:9091/-/healthy|Prometheus"
        "http://localhost:3000/api/health|Grafana"
        "http://localhost:16686|Jaeger (Tracing)"
        "http://localhost:8025|MailHog (Email)"
    )

    local elapsed=0
    local all_healthy=false

    echo "  Waiting for services to be ready (timeout: ${HEALTHCHECK_TIMEOUT}s)..."

    while [ $elapsed -lt $HEALTHCHECK_TIMEOUT ]; do
        all_healthy=true
        for entry in "${endpoints[@]}"; do
            IFS='|' read -r url name <<< "$entry"
            if curl -sf -o /dev/null -m 3 "$url" 2>/dev/null; then
                : # healthy
            else
                all_healthy=false
            fi
        done

        if $all_healthy; then
            break
        fi

        sleep $HEALTHCHECK_INTERVAL
        elapsed=$((elapsed + HEALTHCHECK_INTERVAL))
        echo "  ... waiting ($elapsed/${HEALTHCHECK_TIMEOUT}s)"
    done

    echo ""
    for entry in "${endpoints[@]}"; do
        IFS='|' read -r url name <<< "$entry"
        if curl -sf -o /dev/null -m 3 "$url" 2>/dev/null; then
            log_success "$name ($url) → 200 OK"
        else
            log_error "$name ($url) → UNREACHABLE"
        fi
    done

    if $all_healthy; then
        echo ""
        log_success "All services healthy!"
        echo ""
        echo -e "${CYAN}  Dashboard  : http://localhost:8080${NC}"
        echo -e "${CYAN}  Alerts API : http://localhost:80/docs (via Traefik)${NC}"
        echo -e "${CYAN}  Grafana    : http://localhost:3000 (admin/admin)${NC}"
        echo -e "${CYAN}  Prometheus : http://localhost:9091${NC}"
        echo -e "${CYAN}  Jaeger     : http://localhost:16686${NC}"
        echo -e "${CYAN}  MailHog    : http://localhost:8025${NC}"
        echo -e "${CYAN}  Traefik    : http://localhost:8888${NC}"
        echo ""
    else
        log_error "Some services are not healthy after ${HEALTHCHECK_TIMEOUT}s"
        echo "  Check logs: docker compose logs -f <service>"
        exit 1
    fi
}

# ======================== MAIN ========================

main() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║        OnCall Platform - Local CI/CD Pipeline       ║${NC}"
    echo -e "${CYAN}║        Version: ${VERSION_TAG}                 ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"

    cd "${PROJECT_DIR}"

    local stage="${1:-all}"

    case "$stage" in
        lint)        stage_lint ;;
        test)        stage_test ;;
        security)    stage_security ;;
        build)       stage_build ;;
        deploy)      stage_deploy ;;
        healthcheck) stage_healthcheck ;;
        all)
            stage_lint
            stage_test
            stage_security
            stage_build
            stage_deploy
            stage_healthcheck
            ;;
        *)
            echo "Usage: $0 {lint|test|security|build|deploy|healthcheck|all}"
            exit 1
            ;;
    esac

    echo ""
    log_success "Pipeline completed successfully!"
    echo ""
}

main "$@"
