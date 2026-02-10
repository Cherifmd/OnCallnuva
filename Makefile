# ============================================================
# Makefile - OnCall Platform (Linux / macOS)
# ============================================================
#
#  Equivalent complet du run.ps1 (Windows PowerShell).
#  Sur Linux le Docker socket fonctionne nativement, donc
#  Traefik route correctement via le port 80.
#
#  COMMANDES DISPONIBLES :
#  ─────────────────────────────────────────────────────────
#  DEMARRAGE / ARRET :
#    make deploy          Demarrer toute la plateforme (14 conteneurs)
#    make build           Build les images Docker
#    make down            Arreter la plateforme
#    make restart         Redemarrer tout
#    make clean           Supprimer containers + volumes + caches
#
#  MONITORING :
#    make status          Conteneurs + sante de chaque service
#    make health          Verifier la sante de chaque service
#    make logs            Tous les logs en temps reel
#    make logs-<svc>      Logs d'un service (ex: make logs-alert-ingestion)
#
#  TESTS & DEMO :
#    make test-alert      Envoyer 1 alerte de test
#    make test-batch      Envoyer 3 alertes batch
#    make demo            Scenario demo (demo_alerts.py)
#    make full-demo       Demo complete pour le jury (7 etapes)
#
#  BONUS FEATURES :
#    make scale           Bonus 7: Scaler a 3 replicas
#    make scale-down      Revenir a 1 replica
#    make webhooks        Bonus 2: Lister les webhooks
#    make webhook-register  Bonus 2: Enregistrer un webhook
#    make analytics       Bonus 4: Trends + MTTR
#    make security        Scan de securite
#
#  QUALITE :
#    make lint            Linter flake8
#    make test            Tests unitaires
#    make proto           Regenerer les stubs Protobuf
#    make all             Pipeline complete (lint+test+security+build+deploy+health)
#
#  INTERFACES WEB :
#    Grafana:    http://localhost:3000  (admin/admin)
#    Jaeger:     http://localhost:16686
#    MailHog:    http://localhost:8025
#    Prometheus: http://localhost:9091
#    Traefik:    http://localhost:8888
#    Web UI:     http://localhost:8080  (login requis)
#
# ============================================================

.PHONY: all setup proto lint test security build deploy up down restart \
        health healthcheck clean logs demo test-alert test-batch \
        scale scale-down webhooks webhook-register analytics status \
        full-demo help

# Traefik fonctionne sur Linux (Docker socket OK) — on passe par le port 80
BASE_URL   ?= http://localhost:80
INCIDENT_URL ?= http://localhost:8002
VERSION    ?= $(shell date +%Y%m%d-%H%M%S)
WAIT       ?= 15

# ==================== HELP (default) ====================
help:
	@echo ""
	@echo "  OnCall Platform — Commandes disponibles (Linux/macOS)"
	@echo "  ======================================================"
	@echo ""
	@echo "  DEMARRAGE / ARRET :"
	@echo "    make deploy          Demarrer toute la plateforme"
	@echo "    make build           Build les images Docker"
	@echo "    make down            Arreter la plateforme"
	@echo "    make restart         Redemarrer tout"
	@echo "    make clean           Supprimer containers + volumes"
	@echo ""
	@echo "  MONITORING :"
	@echo "    make status          Conteneurs + sante des services"
	@echo "    make health          Verifier la sante de chaque service"
	@echo "    make logs            Voir les logs (tous)"
	@echo "    make logs-<svc>      Logs d'un service specifique"
	@echo ""
	@echo "  TESTS & DEMO :"
	@echo "    make test-alert      Envoyer 1 alerte de test"
	@echo "    make test-batch      Envoyer 3 alertes batch"
	@echo "    make demo            Scenario demo complet"
	@echo "    make full-demo       Demo complete pour le jury (7 etapes)"
	@echo ""
	@echo "  BONUS FEATURES :"
	@echo "    make scale           Bonus 7: Scaler a 3 replicas"
	@echo "    make scale-down      Revenir a 1 replica"
	@echo "    make webhooks        Bonus 2: Lister les webhooks"
	@echo "    make webhook-register  Bonus 2: Enregistrer un webhook"
	@echo "    make analytics       Bonus 4: Trends + MTTR"
	@echo ""
	@echo "  QUALITE :"
	@echo "    make lint            Linter (flake8)"
	@echo "    make test            Tests unitaires"
	@echo "    make security        Scan de securite"
	@echo "    make all             Pipeline complete"
	@echo ""
	@echo "  INTERFACES WEB :"
	@echo "    Traefik Dashboard:  http://localhost:8888"
	@echo "    Grafana:            http://localhost:3000  (admin/admin)"
	@echo "    Prometheus:         http://localhost:9091"
	@echo "    Jaeger (Tracing):   http://localhost:16686"
	@echo "    MailHog (Emails):   http://localhost:8025"
	@echo "    Web UI:             http://localhost:8080"
	@echo ""

# ==================== FULL PIPELINE ====================
all: lint test security build deploy health

# ==================== SETUP ====================
setup:
	@echo "Creating required directories..."
	mkdir -p config/loki config/traefik/dynamic \
		config/grafana/provisioning/datasources \
		config/grafana/provisioning/dashboards/json
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
	@echo "============================================"
	@echo "  BUILD DES IMAGES"
	@echo "============================================"
	docker compose build

deploy: up
up:
	@echo "============================================"
	@echo "  DEMARRAGE DE LA PLATEFORME"
	@echo "============================================"
	docker compose up -d --build
	@echo ""
	@echo "  En attente du demarrage ($(WAIT)s)..."
	@sleep $(WAIT)
	@$(MAKE) --no-print-directory health
	@echo ""
	@echo "  Plateforme prete !"
	@echo "  Web UI:   http://localhost:8080"
	@echo "  Grafana:  http://localhost:3000"
	@echo "  Jaeger:   http://localhost:16686"
	@echo "  MailHog:  http://localhost:8025"
	@echo ""

down:
	@echo "============================================"
	@echo "  ARRET DE LA PLATEFORME"
	@echo "============================================"
	docker compose down

restart:
	@echo "============================================"
	@echo "  REDEMARRAGE"
	@echo "============================================"
	docker compose down
	docker compose up -d --build
	@sleep $(WAIT)
	@$(MAKE) --no-print-directory health

# ==================== HEALTHCHECK ====================
health: healthcheck
healthcheck:
	@echo "============================================"
	@echo "  SANTE DES SERVICES"
	@echo "============================================"
	@echo ""
	@echo "  --- Microservices ---"
	@curl -sf http://localhost:8001/health 2>/dev/null && echo "  [OK]   Alert Ingestion" || echo "  [DOWN] Alert Ingestion"
	@curl -sf http://localhost:8002/health 2>/dev/null && echo "  [OK]   Incident Management" || echo "  [DOWN] Incident Management"
	@curl -sf http://localhost:8003/health 2>/dev/null && echo "  [OK]   On-Call Service" || echo "  [DOWN] On-Call Service"
	@curl -sf http://localhost:8080/health 2>/dev/null && echo "  [OK]   Web UI" || echo "  [DOWN] Web UI"
	@curl -sf http://localhost:9090/health 2>/dev/null && echo "  [OK]   Metrics Exporter" || echo "  [DOWN] Metrics Exporter"
	@echo ""
	@echo "  --- Infrastructure ---"
	@curl -sf http://localhost:9091/-/healthy 2>/dev/null && echo "  [OK]   Prometheus" || echo "  [DOWN] Prometheus"
	@curl -sf http://localhost:3000/api/health 2>/dev/null && echo "  [OK]   Grafana" || echo "  [DOWN] Grafana"
	@curl -sf http://localhost:16686 2>/dev/null && echo "  [OK]   Jaeger (Tracing)" || echo "  [DOWN] Jaeger (Tracing)"
	@curl -sf http://localhost:8025 2>/dev/null && echo "  [OK]   MailHog (Email)" || echo "  [DOWN] MailHog (Email)"
	@curl -sf http://localhost:3100/ready 2>/dev/null && echo "  [OK]   Loki (Logs)" || echo "  [DOWN] Loki (Logs)"
	@echo ""

# ==================== LOGS ====================
logs:
	docker compose logs -f

logs-%:
	docker compose logs -f $*

# ==================== CLEAN ====================
clean:
	@echo "============================================"
	@echo "  NETTOYAGE COMPLET"
	@echo "============================================"
	docker compose down -v --remove-orphans
	docker image prune -f
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name '*.pyc' -delete 2>/dev/null || true
	@echo "  Nettoyage termine."

# ==================== DEMO & TEST ALERTS ====================
demo:
	@echo "============================================"
	@echo "  SCENARIO DE DEMO COMPLET"
	@echo "============================================"
	python scripts/demo_alerts.py

test-alert:
	@echo "============================================"
	@echo "  ENVOI D'UNE ALERTE DE TEST"
	@echo "============================================"
	@curl -s -X POST $(BASE_URL)/api/v1/alerts \
		-H "Content-Type: application/json" \
		-d '{"source":"prometheus","service_name":"api-gateway","severity":"critical","title":"High CPU Usage on api-gateway","description":"CPU usage exceeded 95% for 5 minutes","labels":{"host":"node-1","region":"eu-west-1"}}' \
		| python -m json.tool 2>/dev/null || echo "  Erreur lors de l'envoi"
	@echo ""

test-batch:
	@echo "============================================"
	@echo "  ENVOI DE 3 ALERTES BATCH"
	@echo "============================================"
	@curl -s -X POST $(BASE_URL)/api/v1/alerts/batch \
		-H "Content-Type: application/json" \
		-d '{"alerts":[{"source":"grafana","service_name":"payment-service","severity":"high","title":"Payment latency > 2s","description":"P99 latency spike"},{"source":"prometheus","service_name":"auth-service","severity":"critical","title":"Auth service 503","description":"Multiple 503 errors"},{"source":"custom","service_name":"api-gateway","severity":"medium","title":"Connection pool near limit","description":"80% pool utilization"}]}' \
		| python -m json.tool 2>/dev/null || echo "  Erreur lors de l'envoi"
	@echo ""

# ==================== BONUS: SCALING (Bonus 7) ====================
scale:
	@echo "============================================"
	@echo "  BONUS 7 : SCALING HORIZONTAL"
	@echo "============================================"
	@echo "  Scaling alert-ingestion a 3 replicas..."
	docker compose up -d --scale alert-ingestion=3
	@sleep 5
	@echo ""
	@echo "  Replicas actifs:"
	@docker compose ps | grep alert-ingestion
	@echo ""
	@echo "  Le load balancer Traefik repartit automatiquement le trafic."

scale-down:
	@echo "============================================"
	@echo "  RETOUR A 1 REPLICA"
	@echo "============================================"
	docker compose up -d --scale alert-ingestion=1
	@echo "  alert-ingestion: 1 replica"

# ==================== BONUS: WEBHOOKS (Bonus 2) ====================
webhooks:
	@echo "============================================"
	@echo "  BONUS 2 : WEBHOOKS ENREGISTRES"
	@echo "============================================"
	@curl -sf $(INCIDENT_URL)/api/v1/webhooks | python -m json.tool 2>/dev/null || echo "  Aucun webhook ou service indisponible"

webhook-register:
	@echo "============================================"
	@echo "  ENREGISTREMENT D'UN WEBHOOK"
	@echo "============================================"
	@curl -s -X POST $(INCIDENT_URL)/api/v1/webhooks \
		-H "Content-Type: application/json" \
		-d '{"url":"http://incident-management:8002/api/v1/webhooks/test","events":["incident.new","incident.resolved","incident.escalated"]}' \
		| python -m json.tool 2>/dev/null || echo "  Erreur lors de l'enregistrement"
	@echo ""

# ==================== BONUS: ANALYTICS (Bonus 4) ====================
analytics:
	@echo "============================================"
	@echo "  BONUS 4 : ANALYTICS"
	@echo "============================================"
	@echo ""
	@echo "  --- Trends (7 derniers jours) ---"
	@curl -sf "$(INCIDENT_URL)/api/v1/analytics/trends?period=7d&bucket=1d" | python -m json.tool 2>/dev/null || echo "  Erreur trends"
	@echo ""
	@echo "  --- Distribution MTTR ---"
	@curl -sf $(INCIDENT_URL)/api/v1/analytics/mttr-distribution | python -m json.tool 2>/dev/null || echo "  Erreur MTTR"

# ==================== STATUS ====================
status:
	@echo "============================================"
	@echo "  ETAT DES CONTENEURS"
	@echo "============================================"
	@docker compose ps
	@echo ""
	@$(MAKE) --no-print-directory health

# ==================== FULL DEMO (JURY) ====================
full-demo:
	@echo "============================================"
	@echo "  DEMO COMPLETE DEVANT JURY"
	@echo "============================================"
	@echo "  Ce scenario montre TOUTES les fonctionnalites."
	@echo ""
	@echo "  [1/7] Verification de la plateforme..."
	@$(MAKE) --no-print-directory health
	@sleep 2
	@echo "  [2/7] Envoi d'alertes..."
	@$(MAKE) --no-print-directory test-alert
	@sleep 3
	@$(MAKE) --no-print-directory test-batch
	@sleep 3
	@echo "  [3/7] Configuration des webhooks..."
	@$(MAKE) --no-print-directory webhook-register
	@sleep 2
	@echo "  [4/7] Analytics et metriques..."
	@$(MAKE) --no-print-directory analytics
	@sleep 2
	@echo "  [5/7] Demo du scaling horizontal..."
	@$(MAKE) --no-print-directory scale
	@sleep 5
	@echo "  [6/7] Envoi d'alertes sur les 3 replicas..."
	@$(MAKE) --no-print-directory test-batch
	@sleep 3
	@echo "  [7/7] Retour a 1 replica..."
	@$(MAKE) --no-print-directory scale-down
	@echo ""
	@echo "============================================"
	@echo "  DEMO TERMINEE"
	@echo "============================================"
	@echo ""
	@echo "  Interfaces a montrer au jury:"
	@echo ""
	@echo "  Grafana (dashboards):     http://localhost:3000"
	@echo "  Jaeger (traces):          http://localhost:16686"
	@echo "  MailHog (emails):         http://localhost:8025"
	@echo "  Prometheus (metriques):   http://localhost:9091"
	@echo "  Traefik (load balancer):  http://localhost:8888"
	@echo "  Web UI:                   http://localhost:8080"
	@echo ""
