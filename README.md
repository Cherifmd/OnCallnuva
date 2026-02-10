# OnCall Platform — Incident Management (PagerDuty-like, 100% Local)

> Plateforme de gestion d'incidents temps réel, 100% locale, avec microservices, gRPC, observabilité complète et scaling horizontal.

---

## Architecture

```
                          ┌────────────────────────────────────────────────────────────┐
                          │                    OBSERVABILITE                           │
                          │  Prometheus :9091 ─▶ Grafana :3000                        │
                          │  Jaeger     :16686  (distributed tracing)                 │
                          │  Loki       :3100   (log aggregation)                     │
                          │  MailHog    :8025   (email testing)                       │
                          └────────────────────────────────────────────────────────────┘

                 ┌──────────────────────────────────────────────────────────────┐
  Utilisateur    │                     Traefik :80                             │
  ──────────────▶│  API Gateway / Load Balancer / Rate Limiter                 │
                 │  Dashboard :8888                                            │
                 └───┬──────────┬──────────────┬────────────────┬──────────────┘
                     │          │              │                │
                     ▼          ▼              ▼                ▼
              ┌────────────┐ ┌──────────┐ ┌──────────────┐ ┌──────────────┐
              │  Alert     │ │  Web UI  │ │  Metrics     │ │  Incident    │
              │  Ingestion │ │  :8080   │ │  Exporter    │ │  Management  │
              │  (x1..xN)  │ │  Jinja2  │ │  :9090       │ │  :8002       │
              └─────┬──────┘ └──────────┘ └──────────────┘ └──────┬───────┘
                    │  gRPC                                       │ gRPC
                    ▼                                             ▼
              ┌──────────────────┐                      ┌──────────────────┐
              │  Incident Mgmt   │◀────── gRPC ────────▶│  On-Call Service │
              │  :8002 / :50052  │                      │  :8003 / :50053  │
              └────────┬─────────┘                      └──────────────────┘
                       │
            ┌──────────┴──────────┐
            ▼                     ▼
     ┌─────────────┐      ┌─────────────┐
     │  PostgreSQL  │      │    Redis    │
     │  :5432       │      │   :6379     │
     │  (données)   │      │ (cache/pub) │
     └─────────────┘      └─────────────┘
```

---

## Services

| Service | Port HTTP | Port gRPC | Description |
|---|---|---|---|
| **Alert Ingestion** | via Traefik :80 | — | Reception, validation, deduplication des alertes |
| **Incident Management** | 8002 | 50052 | Correlation, cycle de vie, MTTA/MTTR, webhooks, analytics |
| **On-Call Service** | 8003 | 50053 | Calendriers de garde, escalade automatique |
| **Web UI** | 8080 | — | Dashboard Jinja2 temps reel |
| **Metrics Exporter** | 9090 | — | Metriques business → Prometheus |

## Infrastructure

| Composant | Port | Role |
|---|---|---|
| **Traefik** | 80 / 8888 | API Gateway, Load Balancer, Rate Limiting |
| **PostgreSQL** | 5432 | Base de donnees principale |
| **Redis** | 6379 | Cache, Pub/Sub temps reel |
| **Prometheus** | 9091 | Collecte de metriques (scrape 5s) |
| **Grafana** | 3000 | Dashboards (admin/admin) |
| **Jaeger** | 16686 | Distributed Tracing (OpenTelemetry) |
| **MailHog** | 8025 | Test d'emails (SMTP sur :1025) |
| **Loki** | 3100 | Aggregation de logs |

---

## Demarrage rapide

### Prerequis

- Docker Desktop (avec Docker Compose v2)
- Python 3.10+ (pour les scripts de demo)
- Windows PowerShell (Windows) ou Bash (Linux/Mac)

### Lancer la plateforme

```powershell
# Windows PowerShell — une seule commande
powershell -ExecutionPolicy Bypass -File .\run.ps1 deploy
```

```bash
# Linux / Mac
make deploy
```

### Verifier que tout fonctionne

```powershell
powershell -ExecutionPolicy Bypass -File .\run.ps1 status
```

### Lancer la demo complete

```powershell
powershell -ExecutionPolicy Bypass -File .\run.ps1 full-demo
```

---

## Commandes disponibles (run.ps1)

> Sur Windows, prefixer chaque commande par :
> `powershell -ExecutionPolicy Bypass -File .\run.ps1 <commande>`

### Pipeline CI/CD

| Commande | Description |
|---|---|
| `deploy` | Demarrer toute la plateforme (build + up + healthcheck) |
| `build` | Build les images Docker uniquement |
| `down` | Arreter la plateforme |
| `restart` | Redemarrer tout |
| `clean` | Supprimer containers + volumes + cache |

### Monitoring

| Commande | Description |
|---|---|
| `status` | Conteneurs + sante de tous les services |
| `health` | Verifier la sante de chaque service et infra |
| `logs` | Tous les logs en temps reel |
| `logs <service>` | Logs d'un service specifique |

### Tests et Demo

| Commande | Description |
|---|---|
| `test-alert` | Envoyer 1 alerte de test |
| `test-batch` | Envoyer 3 alertes batch |
| `demo` | Scenario de demo (demo_alerts.py) |
| **`full-demo`** | **Demo complete automatisee en 7 etapes (pour le jury)** |

### Bonus Features

| Commande | Description | Bonus |
|---|---|---|
| `scale` | Scaler alert-ingestion a 3 replicas | Bonus 7 |
| `scale-down` | Revenir a 1 replica | Bonus 7 |
| `webhook-add` | Enregistrer un webhook de test | Bonus 2 |
| `webhooks` | Lister les webhooks enregistres | Bonus 2 |
| `analytics` | Afficher trends + distribution MTTR | Bonus 4 |
| `security` | Scan de securite | — |

---

## Bonus implementes

### Bonus 1 — Notifications par Email

- Integration SMTP via MailHog (test local) ou SendGrid (production)
- Email envoye automatiquement au responsable d'astreinte lors de la creation d'un incident
- Interface MailHog : http://localhost:8025

### Bonus 2 — Notifications Webhook

- API CRUD pour enregistrer des webhooks (`POST/GET/DELETE /api/v1/webhooks`)
- Declenchement automatique sur evenements : `incident.new`, `incident.acknowledged`, `incident.resolved`, `incident.escalated`
- Signature HMAC-SHA256 pour la securite des payloads
- Stockage en memoire + persistance Redis

### Bonus 3 — Escalade automatique

- Timer configurable (`ESCALATION_TIMEOUT_SECONDS=120`)
- Si un incident n'est pas acquitte dans le delai, escalade automatique au niveau superieur
- Appel gRPC vers le service On-Call pour notifier le prochain responsable

### Bonus 4 — Analytics historiques

- `GET /api/v1/analytics/trends?period=7d&bucket=1h` — tendances d'incidents par bucket temporel
- `GET /api/v1/analytics/mttr-distribution` — distribution du temps moyen de resolution

### Bonus 5 — Aggregation de logs (Loki)

- Configuration Loki + Promtail incluse
- Handler Python (`shared/loki_logger.py`) pour push direct vers Loki HTTP API
- Datasource Loki provisionnee dans Grafana
- _Note : peut necessiter une configuration Docker specifique selon l'OS_

### Bonus 6 — Distributed Tracing (Jaeger)

- OpenTelemetry SDK integre dans chaque microservice
- Instrumentation automatique FastAPI + gRPC
- Traces visibles dans Jaeger : http://localhost:16686
- Datasource Jaeger provisionnee dans Grafana

### Bonus 7 — Scaling horizontal

- Alert-ingestion scalable a N replicas : `.\run.ps1 scale`
- Traefik fait le load balancing automatiquement (round-robin)
- Les replicas partagent PostgreSQL et Redis (stateless)

---

## Algorithme de Correlation

```
Cle de correlation = (service_name, severity)
Fenetre temporelle = 5 minutes (configurable via CORRELATION_WINDOW_SECONDS)

1. Nouvelle alerte recue via Traefik → Alert Ingestion
2. Envoi gRPC vers Incident Management
3. Recherche d'un incident OUVERT avec la meme cle dans la fenetre
   a. Si trouve → Rattacher l'alerte (deduplication)
   b. Si non   → Creer un nouvel incident
4. Notification de l'astreinte via gRPC → On-Call Service
5. Envoi email + declenchement webhooks
6. Si pas d'acquittement dans 120s → Escalade automatique
```

---

## Structure du projet

```
hackathonOPcELLUNOVA/
├── .env                              # Variables d'environnement
├── .gitignore                        # Fichiers ignores par Git
├── docker-compose.yml                # Orchestration des 14 conteneurs
├── Dockerfile.service                # Multi-stage build (services gRPC)
├── Dockerfile.webui                  # Multi-stage build (Web UI)
├── Makefile                          # Commandes make (Linux/Mac)
├── run.ps1                           # CLI PowerShell (Windows)
├── pipeline.sh                       # Pipeline CI/CD local (Bash)
├── pytest.ini                        # Configuration pytest
├── README.md                         # Ce fichier
│
├── proto/
│   └── incidents.proto               # Definitions Protobuf/gRPC
│
├── shared/                           # Code partage entre services
│   ├── models.py                     # Modeles SQLAlchemy (DB)
│   ├── redis_client.py               # Client Redis (cache/pub-sub)
│   ├── auth.py                       # Authentification JWT (HS256)
│   ├── notifications.py              # Email (SMTP/SendGrid) + Webhooks
│   ├── tracing.py                    # OpenTelemetry / Jaeger
│   ├── loki_logger.py                # Push logs vers Loki
│   └── requirements.txt              # Dependances partagees
│
├── services/
│   ├── alert_ingestion/              # Service 1 : Reception des alertes
│   ├── incident_management/          # Service 2 : Gestion des incidents
│   ├── oncall_service/               # Service 3 : Gestion d'astreinte
│   ├── web_ui/                       # Service 4 : Dashboard HTML
│   └── metrics_exporter/             # Service 5 : Export metriques
│
├── config/
│   ├── prometheus.yml                # Config Prometheus (scrape 5s)
│   ├── traefik/dynamic/              # Rate limiting Traefik
│   ├── grafana/provisioning/         # Datasources + dashboards auto
│   └── loki/                         # Config Loki + Promtail
│
├── scripts/
│   ├── demo_alerts.py                # Script de demo (alertes + lifecycle)
│   ├── security_scan.py              # Scanner de securite
│   └── gen_proto.sh                  # Generation des stubs gRPC
│
└── tests/
    ├── test_alert_ingestion.py       # Tests unitaires
    ├── test_correlation.py           # Tests correlation
    └── test_security.py              # Tests securite
```

---

## Securite

- **Authentification JWT** : Login obligatoire sur le Web UI, tokens HS256 avec expiration 24h
- **Cookies HttpOnly** : Tokens stockes en cookies securises (pas de localStorage)
- **Protection des routes** : Middleware d'authentification sur toutes les pages du dashboard
- **API Bearer Token** : Endpoint `/api/v1/auth/token` pour obtenir un token API
- **Rate Limiting** : Traefik middleware (100 req/s avg, burst 50)
- **Security Headers** : X-Frame-Options, HSTS, XSS Protection
- **SQL Injection** : Validation Pydantic + SQLAlchemy ORM (pas de raw SQL)
- **HMAC-SHA256** : Signature des payloads webhook
- **Scanner** : `python scripts/security_scan.py` (zero dependance tierce)
- **Docker** : Images Alpine < 500MB, non-root user, multi-stage build
- **Credentials** : Configurables via variables d'environnement (`.env`)

---

## Interfaces Web

| Interface | URL | Identifiants |
|---|---|---|
| Web UI (Dashboard) | http://localhost:8080 | Configures dans .env |
| Alert API (Swagger) | http://localhost:80/docs | — |
| Incident API (Swagger) | http://localhost:8002/docs | — |
| On-Call API (Swagger) | http://localhost:8003/docs | — |
| Grafana | http://localhost:3000 | admin / admin |
| Prometheus | http://localhost:9091 | — |
| Jaeger (Tracing) | http://localhost:16686 | — |
| MailHog (Emails) | http://localhost:8025 | — |
| Traefik Dashboard | http://localhost:8888 | — |

---

## Technologies

| Categorie | Technologies |
|---|---|
| Langage | Python 3.11 |
| Framework HTTP | FastAPI 0.109 |
| Communication inter-services | gRPC (protobuf) |
| Base de donnees | PostgreSQL 16 + SQLAlchemy Async |
| Cache / Pub-Sub | Redis 7 |
| API Gateway | Traefik v3.0 |
| Monitoring | Prometheus + Grafana 10.3 |
| Tracing | Jaeger 1.54 + OpenTelemetry |
| Logs | Loki 3.0 |
| Email | MailHog (dev) / SendGrid (prod) |
| Conteneurisation | Docker + Docker Compose |
| CI/CD | pipeline.sh + Makefile + run.ps1 |
