# ============================================================
#  run.ps1 - OnCall Platform CLI (Windows PowerShell)
# ============================================================
#
#  IMPORTANT: Si "execution de scripts desactivee", lancer avec:
#    powershell -ExecutionPolicy Bypass -File .\run.ps1 <command>
#
#  Ou activer les scripts une fois pour toutes:
#    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force
#    (apres ca, .\run.ps1 <command> marche directement)
#
# ------------------------------------------------------------
#  COMMANDES DISPONIBLES:
# ------------------------------------------------------------
#
#  DEMARRAGE / ARRET:
#    .\run.ps1 deploy       -> Demarrer toute la plateforme
#    .\run.ps1 down         -> Arreter la plateforme
#    .\run.ps1 restart      -> Redemarrer tout
#    .\run.ps1 clean        -> Supprimer containers + volumes
#
#  MONITORING:
#    .\run.ps1 status       -> Conteneurs + sante des services
#    .\run.ps1 health       -> Verifier la sante de chaque service
#    .\run.ps1 logs         -> Tous les logs en temps reel
#    .\run.ps1 logs <svc>   -> Logs d'un service (ex: alert-ingestion)
#
#  TESTS:
#    .\run.ps1 test-alert   -> Envoyer 1 alerte de test
#    .\run.ps1 test-batch   -> Envoyer 3 alertes batch
#    .\run.ps1 demo         -> Scenario demo (demo_alerts.py)
#
#  BONUS FEATURES:
#    .\run.ps1 scale        -> Bonus 7: Scaler a 3 replicas
#    .\run.ps1 scale-down   -> Revenir a 1 replica
#    .\run.ps1 webhooks     -> Bonus 2: Lister les webhooks
#    .\run.ps1 webhook-add  -> Bonus 2: Enregistrer un webhook
#    .\run.ps1 analytics    -> Bonus 4: Trends + MTTR
#    .\run.ps1 security     -> Scan de securite
#
#  DEMO JURY :
#    .\run.ps1 full-demo    -> Execute TOUT automatiquement (7 etapes)
#
#  INTERFACES WEB:
#    Grafana:    http://localhost:3000  (admin/admin)
#    Jaeger:     http://localhost:16686
#    MailHog:    http://localhost:8025
#    Prometheus: http://localhost:9091
#    Traefik:    http://localhost:8888
#    Web UI:     http://localhost:8080  (login requis, credentials dans .env)
#
# ============================================================

param(
    [Parameter(Position=0)]
    [string]$Command = "help",

    [Parameter(Position=1)]
    [string]$Arg1 = ""
)

$ErrorActionPreference = "Continue"
$BASE = "http://localhost:8001"
$INCIDENT = "http://localhost:8002"

# ---------- Helpers ----------
function Write-Header($text) {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
}

function Check-Health($name, $url) {
    try {
        $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
        if ($r.StatusCode -eq 200) {
            Write-Host "  [OK]   $name" -ForegroundColor Green
        } else {
            Write-Host "  [DOWN] $name" -ForegroundColor Red
        }
    } catch {
        Write-Host "  [DOWN] $name" -ForegroundColor Red
    }
}

# ==================== COMMANDS ====================

function Cmd-Help {
    Write-Host ""
    Write-Host "  OnCall Platform - Commandes disponibles" -ForegroundColor Yellow
    Write-Host "  =======================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  PIPELINE CI/CD:" -ForegroundColor Cyan
    Write-Host "    .\run.ps1 deploy       Demarrer toute la plateforme"
    Write-Host "    .\run.ps1 build        Build les images Docker"
    Write-Host "    .\run.ps1 down         Arreter la plateforme"
    Write-Host "    .\run.ps1 restart      Redemarrer tout"
    Write-Host "    .\run.ps1 clean        Supprimer containers + volumes"
    Write-Host ""
    Write-Host "  MONITORING:" -ForegroundColor Cyan
    Write-Host "    .\run.ps1 status       Conteneurs + sante des services"
    Write-Host "    .\run.ps1 health       Verifier la sante de chaque service"
    Write-Host "    .\run.ps1 logs         Voir les logs (tous)"
    Write-Host "    .\run.ps1 logs <svc>   Logs d'un service specifique"
    Write-Host ""
    Write-Host "  TESTS & DEMO:" -ForegroundColor Cyan
    Write-Host "    .\run.ps1 demo         Scenario de demo complet"
    Write-Host "    .\run.ps1 test-alert   Envoyer 1 alerte de test"
    Write-Host "    .\run.ps1 test-batch   Envoyer 3 alertes batch"
    Write-Host ""
    Write-Host "  BONUS FEATURES:" -ForegroundColor Cyan
    Write-Host "    .\run.ps1 scale        Bonus 7: Scaler a 3 replicas"
    Write-Host "    .\run.ps1 scale-down   Revenir a 1 replica"
    Write-Host "    .\run.ps1 webhooks     Bonus 2: Lister les webhooks"
    Write-Host "    .\run.ps1 webhook-add  Bonus 2: Enregistrer un webhook"
    Write-Host "    .\run.ps1 analytics    Bonus 4: Trends + MTTR"
    Write-Host ""
    Write-Host "  QUALITE:" -ForegroundColor Cyan
    Write-Host "    .\run.ps1 security     Scan de securite"
    Write-Host ""
    Write-Host "  URLS DES INTERFACES:" -ForegroundColor Cyan
    Write-Host "    Traefik Dashboard:  http://localhost:8888"
    Write-Host "    Grafana:            http://localhost:3000  (admin/admin)"
    Write-Host "    Prometheus:         http://localhost:9091"
    Write-Host "    Jaeger (Tracing):   http://localhost:16686"
    Write-Host "    MailHog (Emails):   http://localhost:8025"
    Write-Host "    Web UI:             http://localhost:8080"
    Write-Host ""
}

# ---------- Pipeline ----------

function Cmd-Build {
    Write-Header "BUILD DES IMAGES"
    docker compose build
}

function Cmd-Deploy {
    Write-Header "DEMARRAGE DE LA PLATEFORME"
    docker compose up -d --build
    Write-Host ""
    Write-Host "  En attente du demarrage (15s)..." -ForegroundColor Yellow
    Start-Sleep -Seconds 15
    Cmd-Health
    Write-Host ""
    Write-Host "  Plateforme prete !" -ForegroundColor Green
    Write-Host "  Web UI:   http://localhost:8080" -ForegroundColor White
    Write-Host "  Grafana:  http://localhost:3000" -ForegroundColor White
    Write-Host "  Jaeger:   http://localhost:16686" -ForegroundColor White
    Write-Host "  MailHog:  http://localhost:8025" -ForegroundColor White
    Write-Host ""
}

function Cmd-Down {
    Write-Header "ARRET DE LA PLATEFORME"
    docker compose down
}

function Cmd-Restart {
    Write-Header "REDEMARRAGE"
    docker compose down
    docker compose up -d --build
    Start-Sleep -Seconds 15
    Cmd-Health
}

function Cmd-Clean {
    Write-Header "NETTOYAGE COMPLET"
    docker compose down -v --remove-orphans
    docker image prune -f
    Write-Host "  Nettoyage termine." -ForegroundColor Green
}

# ---------- Monitoring ----------

function Cmd-Health {
    Write-Header "SANTE DES SERVICES"

    Write-Host "  --- Microservices ---" -ForegroundColor Yellow
    Check-Health "Alert Ingestion"               "$BASE/health"
    Check-Health "Incident Management"           "$INCIDENT/health"
    Check-Health "On-Call Service"                "http://localhost:8003/health"
    Check-Health "Web UI"                         "http://localhost:8080/health"
    Check-Health "Metrics Exporter"               "http://localhost:9090/health"

    Write-Host ""
    Write-Host "  --- Infrastructure ---" -ForegroundColor Yellow
    Check-Health "Prometheus"                     "http://localhost:9091/-/healthy"
    Check-Health "Grafana"                        "http://localhost:3000/api/health"
    Check-Health "Jaeger (Tracing)"               "http://localhost:16686"
    Check-Health "MailHog (Email)"                "http://localhost:8025"
    Check-Health "Loki (Logs)"                    "http://localhost:3100/ready"
    Write-Host ""
}

function Cmd-Status {
    Write-Header "ETAT DES CONTENEURS"
    docker compose ps
    Cmd-Health
}

function Cmd-Logs {
    if ($Arg1 -ne "") {
        Write-Header "LOGS: $Arg1"
        docker compose logs -f $Arg1
    } else {
        Write-Header "LOGS (tous les services)"
        docker compose logs -f
    }
}

# ---------- Demo & Test ----------

function Cmd-Demo {
    Write-Header "SCENARIO DE DEMO COMPLET"
    python scripts/demo_alerts.py
}

function Cmd-TestAlert {
    Write-Header "ENVOI D'UNE ALERTE DE TEST"
    $body = @{
        source       = "prometheus"
        service_name = "api-gateway"
        severity     = "critical"
        title        = "High CPU Usage on api-gateway"
        description  = "CPU usage exceeded 95% for 5 minutes"
        labels       = @{ host = "node-1"; region = "eu-west-1" }
    } | ConvertTo-Json -Depth 3

    try {
        $response = Invoke-RestMethod -Uri "$BASE/api/v1/alerts" -Method Post -Body $body -ContentType "application/json"
        Write-Host "  Alerte envoyee avec succes !" -ForegroundColor Green
        $response | ConvertTo-Json -Depth 5 | Write-Host
    } catch {
        Write-Host "  Erreur: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Cmd-TestBatch {
    Write-Header "ENVOI DE 3 ALERTES BATCH"
    $body = @{
        alerts = @(
            @{ source="grafana";     service_name="payment-service"; severity="high";     title="Payment latency > 2s";           description="P99 latency spike" }
            @{ source="prometheus";  service_name="auth-service";    severity="critical";  title="Auth service 503";               description="Multiple 503 errors" }
            @{ source="custom";      service_name="api-gateway";     severity="medium";    title="Connection pool near limit";     description="80% pool utilization" }
        )
    } | ConvertTo-Json -Depth 3

    try {
        $response = Invoke-RestMethod -Uri "$BASE/api/v1/alerts/batch" -Method Post -Body $body -ContentType "application/json"
        Write-Host "  3 alertes envoyees avec succes !" -ForegroundColor Green
        $response | ConvertTo-Json -Depth 5 | Write-Host
    } catch {
        Write-Host "  Erreur: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ---------- Bonus: Scaling (Bonus 7) ----------

function Cmd-Scale {
    Write-Header "BONUS 7 : SCALING HORIZONTAL"
    Write-Host "  Scaling alert-ingestion a 3 replicas..." -ForegroundColor Yellow
    docker compose up -d --scale alert-ingestion=3
    Start-Sleep -Seconds 5
    Write-Host ""
    Write-Host "  Replicas actifs:" -ForegroundColor Green
    docker compose ps | Select-String "alert-ingestion"
    Write-Host ""
    Write-Host "  Le load balancer Traefik repartit automatiquement le trafic." -ForegroundColor White
}

function Cmd-ScaleDown {
    Write-Header "RETOUR A 1 REPLICA"
    docker compose up -d --scale alert-ingestion=1
    Write-Host "  alert-ingestion: 1 replica" -ForegroundColor Green
}

# ---------- Bonus: Webhooks (Bonus 2) ----------

function Cmd-Webhooks {
    Write-Header "BONUS 2 : WEBHOOKS ENREGISTRES"
    try {
        $response = Invoke-RestMethod -Uri "$INCIDENT/api/v1/webhooks" -Method Get
        if ($response.Count -eq 0) {
            Write-Host "  Aucun webhook enregistre." -ForegroundColor Yellow
            Write-Host "  Utilisez: .\run.ps1 webhook-add" -ForegroundColor White
        } else {
            $response | ConvertTo-Json -Depth 5 | Write-Host
        }
    } catch {
        Write-Host "  Erreur: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Cmd-WebhookAdd {
    Write-Header "ENREGISTREMENT D'UN WEBHOOK"
    $body = @{
        url    = "https://httpbin.org/post"
        events = @("incident.new", "incident.resolved", "incident.escalated")
    } | ConvertTo-Json -Depth 3

    try {
        $response = Invoke-RestMethod -Uri "$INCIDENT/api/v1/webhooks" -Method Post -Body $body -ContentType "application/json"
        Write-Host "  Webhook enregistre !" -ForegroundColor Green
        $response | ConvertTo-Json -Depth 5 | Write-Host
    } catch {
        Write-Host "  Erreur: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ---------- Bonus: Analytics (Bonus 4) ----------

function Cmd-Analytics {
    Write-Header "BONUS 4 : ANALYTICS"

    Write-Host "  --- Trends (7 derniers jours) ---" -ForegroundColor Yellow
    try {
        $trends = Invoke-RestMethod -Uri "$INCIDENT/api/v1/analytics/trends?period=7d&bucket=1d" -Method Get
        $trends | ConvertTo-Json -Depth 5 | Write-Host
    } catch {
        Write-Host "  Erreur trends: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "  --- Distribution MTTR ---" -ForegroundColor Yellow
    try {
        $mttr = Invoke-RestMethod -Uri "$INCIDENT/api/v1/analytics/mttr-distribution" -Method Get
        $mttr | ConvertTo-Json -Depth 5 | Write-Host
    } catch {
        Write-Host "  Erreur MTTR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ---------- Security ----------

function Cmd-Security {
    Write-Header "SCAN DE SECURITE"
    python scripts/security_scan.py
}

# ==================== FULL DEMO SCENARIO ====================

function Cmd-FullDemo {
    Write-Header "DEMO COMPLETE DEVANT JURY"
    Write-Host "  Ce scenario montre TOUTES les fonctionnalites." -ForegroundColor Yellow
    Write-Host ""

    # 1. Status
    Write-Host "  [1/7] Verification de la plateforme..." -ForegroundColor Cyan
    Cmd-Health
    Start-Sleep -Seconds 2

    # 2. Send alerts
    Write-Host "  [2/7] Envoi d'alertes..." -ForegroundColor Cyan
    Cmd-TestAlert
    Start-Sleep -Seconds 3
    Cmd-TestBatch
    Start-Sleep -Seconds 3

    # 3. Webhooks
    Write-Host "  [3/7] Configuration des webhooks..." -ForegroundColor Cyan
    Cmd-WebhookAdd
    Start-Sleep -Seconds 2

    # 4. Analytics
    Write-Host "  [4/7] Analytics et metriques..." -ForegroundColor Cyan
    Cmd-Analytics
    Start-Sleep -Seconds 2

    # 5. Scaling
    Write-Host "  [5/7] Demo du scaling horizontal..." -ForegroundColor Cyan
    Cmd-Scale
    Start-Sleep -Seconds 5

    # 6. Test load-balanced alerts
    Write-Host "  [6/7] Envoi d'alertes sur les 3 replicas..." -ForegroundColor Cyan
    Cmd-TestBatch
    Start-Sleep -Seconds 3

    # 7. Scale down
    Write-Host "  [7/7] Retour a 1 replica..." -ForegroundColor Cyan
    Cmd-ScaleDown

    Write-Header "DEMO TERMINEE"
    Write-Host "  Interfaces a montrer au jury:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Grafana (dashboards):     http://localhost:3000" -ForegroundColor White
    Write-Host "  Jaeger (traces):          http://localhost:16686" -ForegroundColor White
    Write-Host "  MailHog (emails):         http://localhost:8025" -ForegroundColor White
    Write-Host "  Prometheus (metriques):   http://localhost:9091" -ForegroundColor White
    Write-Host "  Traefik (load balancer):  http://localhost:8888" -ForegroundColor White
    Write-Host "  Web UI:                   http://localhost:8080" -ForegroundColor White
    Write-Host ""
}

# ==================== DISPATCHER ====================

switch ($Command.ToLower()) {
    "help"          { Cmd-Help }
    "build"         { Cmd-Build }
    "deploy"        { Cmd-Deploy }
    "up"            { Cmd-Deploy }
    "down"          { Cmd-Down }
    "stop"          { Cmd-Down }
    "restart"       { Cmd-Restart }
    "clean"         { Cmd-Clean }
    "health"        { Cmd-Health }
    "healthcheck"   { Cmd-Health }
    "status"        { Cmd-Status }
    "logs"          { Cmd-Logs }
    "demo"          { Cmd-Demo }
    "test-alert"    { Cmd-TestAlert }
    "test-batch"    { Cmd-TestBatch }
    "scale"         { Cmd-Scale }
    "scale-down"    { Cmd-ScaleDown }
    "webhooks"      { Cmd-Webhooks }
    "webhook-add"   { Cmd-WebhookAdd }
    "analytics"     { Cmd-Analytics }
    "security"      { Cmd-Security }
    "full-demo"     { Cmd-FullDemo }
    default {
        Write-Host "  Commande inconnue: '$Command'" -ForegroundColor Red
        Write-Host "  Tapez: .\run.ps1 help" -ForegroundColor Yellow
    }
}
