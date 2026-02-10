# ============================================================
# Makefile - OnCall Platform (with Bonus Features)
# ============================================================
# Usage:  make <target>
# Windows: Use `make` via Git Bash or WSL, or see PowerShell
#          equivalents in README.md
# ============================================================

.PHONY: all lint test security build deploy up down healthcheck clean logs proto \
        test-alert test-batch status scale demo webhooks analytics

VERSION ?= $(shell date +%Y%m%d-%H%M%S)

# ==================== FULL PIPELINE ====================
all: lint test security build deploy healthcheck

# ==================== SETUP ====================
setup:
	@echo "Creating required directories..."
	mkdir -p config/loki config/traefik/dynamic config/grafana/provisioning/datasources config/grafana/provisioning/dashboards/json
	@echo "Setup complete. Run 'make deploy' to start."

# ==================== PROTOBUF ====================
proto:
	@echo "Generating protobuf stubs..."
	python -m grpc_tools.protoc \
		-Iproto \
		--python_out=services/alert_ingestion/generated \
		--grpc_python_out=services/alert_ingestion/generated \
		proto/incidents.proto
	python -m grpc_tools.protoc \
		-Iproto \
		--python_out=services/incident_management/generated \
		--grpc_python_out=services/incident_management/generated \
		proto/incidents.proto
	python -m grpc_tools.protoc \
		-Iproto \
		--python_out=services/oncall_service/generated \
		--grpc_python_out=services/oncall_service/generated \
		proto/incidents.proto
	@echo "Fixing imports..."
	@for dir in services/*/generated; do \
		if [ -f "$$dir/incidents_pb2_grpc.py" ]; then \
			sed -i 's/import incidents_pb2/from . import incidents_pb2/' "$$dir/incidents_pb2_grpc.py"; \
		fi; \
	done
	@echo "Done."

# ==================== LINTING ====================
lint:
	@echo "Running flake8..."
	flake8 services/ shared/ --max-line-length=120 --ignore=E501,W503,E402,F401 --exclude=generated,__pycache__

# ==================== TESTING ====================
test:
	pytest tests/ -v --tb=short -q

# ==================== SECURITY SCAN ====================
security:
	python scripts/security_scan.py

# ==================== BUILD & DEPLOY ====================
build:
	docker compose build

deploy: up
up:
	docker compose up -d --build

down:
	docker compose down

restart:
	docker compose down && docker compose up -d --build

# ==================== HEALTHCHECK ====================
healthcheck:
	@echo "=== Service Health ==="
	@curl -sf http://localhost:8002/health 2>/dev/null && echo "  ✓ Incident Mgmt:  OK" || echo "  ✗ Incident Mgmt:  DOWN"
	@curl -sf http://localhost:8003/health 2>/dev/null && echo "  ✓ On-Call:         OK" || echo "  ✗ On-Call:         DOWN"
	@curl -sf http://localhost:8080/health 2>/dev/null && echo "  ✓ Web UI:          OK" || echo "  ✗ Web UI:          DOWN"
	@curl -sf http://localhost:9090/health 2>/dev/null && echo "  ✓ Metrics:         OK" || echo "  ✗ Metrics:         DOWN"
	@echo ""
	@echo "=== Infrastructure ==="
	@curl -sf http://localhost:9091/-/healthy 2>/dev/null && echo "  ✓ Prometheus:      OK" || echo "  ✗ Prometheus:      DOWN"
	@curl -sf http://localhost:3000/api/health 2>/dev/null && echo "  ✓ Grafana:         OK" || echo "  ✗ Grafana:         DOWN"
	@curl -sf http://localhost:16686 2>/dev/null && echo "  ✓ Jaeger:          OK" || echo "  ✗ Jaeger:          DOWN"
	@curl -sf http://localhost:8025 2>/dev/null && echo "  ✓ MailHog:         OK" || echo "  ✗ MailHog:         DOWN"
	@curl -sf http://localhost:3100/ready 2>/dev/null && echo "  ✓ Loki:            OK" || echo "  ✗ Loki:            DOWN"

# ==================== LOGS ====================
logs:
	docker compose logs -f

logs-%:
	docker compose logs -f $*

# ==================== CLEAN ====================
clean:
	docker compose down -v --remove-orphans
	docker image prune -f
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name '*.pyc' -delete 2>/dev/null || true

# ==================== DEMO & TEST ALERTS ====================
demo:
	python scripts/demo_alerts.py

test-alert:
	@echo "Sending single test alert via Traefik..."
	curl -X POST http://localhost:80/api/v1/alerts \
		-H "Content-Type: application/json" \
		-d '{ \
			"source": "prometheus", \
			"service_name": "api-gateway", \
			"severity": "critical", \
			"title": "High CPU Usage on api-gateway", \
			"description": "CPU usage exceeded 95% for 5 minutes", \
			"labels": {"host": "node-1", "region": "eu-west-1"} \
		}'
	@echo ""

test-batch:
	@echo "Sending batch alerts via Traefik..."
	curl -X POST http://localhost:80/api/v1/alerts/batch \
		-H "Content-Type: application/json" \
		-d '{ \
			"alerts": [ \
				{"source":"grafana","service_name":"payment-service","severity":"high","title":"Payment latency > 2s","description":"P99 latency spike"}, \
				{"source":"prometheus","service_name":"auth-service","severity":"critical","title":"Auth service 503","description":"Multiple 503 errors"}, \
				{"source":"custom","service_name":"api-gateway","severity":"medium","title":"Connection pool near limit","description":"80% pool utilization"} \
			] \
		}'
	@echo ""

# ==================== BONUS: SCALING (Bonus 7) ====================
scale:
	@echo "Scaling alert-ingestion to 3 replicas..."
	docker compose up -d --scale alert-ingestion=3
	@echo ""
	docker compose ps | grep alert-ingestion

scale-down:
	@echo "Scaling alert-ingestion back to 1..."
	docker compose up -d --scale alert-ingestion=1

# ==================== BONUS: WEBHOOKS (Bonus 2) ====================
webhooks:
	@echo "=== Registered Webhooks ==="
	curl -sf http://localhost:8002/api/v1/webhooks | python -m json.tool

webhook-register:
	@echo "Registering test webhook..."
	curl -X POST http://localhost:8002/api/v1/webhooks \
		-H "Content-Type: application/json" \
		-d '{"url":"http://incident-management:8002/api/v1/webhooks/test","events":["incident.new","incident.resolved","incident.escalated"]}'
	@echo ""

# ==================== BONUS: ANALYTICS (Bonus 4) ====================
analytics:
	@echo "=== Incident Trends (7d) ==="
	curl -sf "http://localhost:8002/api/v1/analytics/trends?period=7d&bucket=1d" | python -m json.tool
	@echo ""
	@echo "=== MTTR Distribution ==="
	curl -sf http://localhost:8002/api/v1/analytics/mttr-distribution | python -m json.tool

# ==================== STATUS ====================
status:
	@echo "=== Running Containers ==="
	docker compose ps
	@echo ""
	@make healthcheck
