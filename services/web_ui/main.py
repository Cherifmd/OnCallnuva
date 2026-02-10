"""
Service 4 - Web UI (Port 8080)
Modern dashboard to visualize incidents, on-call schedules, and metrics.
Uses FastAPI + Jinja2 templates.
"""
import os
import sys
import logging
from datetime import datetime
from contextlib import asynccontextmanager

import aiohttp
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response

# Add parent to path for shared modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from shared.auth import (
    authenticate_user, create_jwt_token, verify_jwt_token,
    get_token_from_request, require_auth, init_default_users
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("web-ui")

# ======================== METRICS ========================
PAGE_VIEWS = Counter("page_views_total", "Page views", ["page"])

# ======================== BACKEND SERVICE URLS ========================
INCIDENT_API = os.getenv("INCIDENT_API_URL", "http://incident-management:8002")
ONCALL_API = os.getenv("ONCALL_API_URL", "http://oncall-service:8003")
ALERT_API = os.getenv("ALERT_API_URL", "http://alert-ingestion:8001")

# HTTP client session
_http_session = None


async def get_http_session():
    global _http_session
    if _http_session is None or _http_session.closed:
        _http_session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10))
    return _http_session


async def api_get(url: str) -> dict:
    """Make GET request to internal service."""
    try:
        session = await get_http_session()
        async with session.get(url) as resp:
            if resp.status == 200:
                return await resp.json()
            logger.warning(f"API call to {url} returned {resp.status}")
            return {}
    except Exception as e:
        logger.error(f"API call failed: {url} - {e}")
        return {}


async def api_post(url: str, data: dict) -> dict:
    try:
        session = await get_http_session()
        async with session.post(url, json=data) as resp:
            return await resp.json()
    except Exception as e:
        logger.error(f"API POST failed: {url} - {e}")
        return {"error": str(e)}


# ======================== APP ========================
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Web UI starting...")
    init_default_users()
    logger.info("JWT authentication initialized.")
    yield
    if _http_session and not _http_session.closed:
        await _http_session.close()
    logger.info("Web UI shutdown.")


app = FastAPI(title="Incident Dashboard", version="1.0.0", lifespan=lifespan)

templates_dir = os.path.join(os.path.dirname(__file__), "templates")
static_dir = os.path.join(os.path.dirname(__file__), "static")

templates = Jinja2Templates(directory=templates_dir)
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "web-ui", "timestamp": datetime.utcnow().isoformat()}


@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


# ======================== AUTH ROUTES ========================

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = ""):
    """Login page — accessible without authentication."""
    # If already logged in, redirect to dashboard
    user = require_auth(request)
    if user:
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": error,
    })


@app.post("/login")
async def login_submit(request: Request):
    """Handle login form submission."""
    form = await request.form()
    username = form.get("username", "").strip()
    password = form.get("password", "")

    user = authenticate_user(username, password)
    if not user:
        logger.warning(f"Failed login attempt for user: {username}")
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Nom d'utilisateur ou mot de passe incorrect.",
        })

    # Create JWT token
    token = create_jwt_token(username=user["username"], role=user["role"])
    logger.info(f"User '{username}' logged in successfully.")

    # Set cookie and redirect to dashboard
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=86400,  # 24h
    )
    return response


@app.get("/logout")
async def logout(request: Request):
    """Clear auth cookie and redirect to login."""
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(key="access_token")
    logger.info("User logged out.")
    return response


@app.get("/api/v1/auth/token")
async def get_api_token(request: Request):
    """Get a Bearer token for API access (must be logged in via cookie)."""
    user = require_auth(request)
    if not user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    token = create_jwt_token(username=user["sub"], role=user.get("role", "admin"))
    return {"access_token": token, "token_type": "bearer", "expires_in": 86400}


# ======================== AUTH MIDDLEWARE ========================

def _is_public_path(path: str) -> bool:
    """Check if path is accessible without authentication."""
    public = ["/login", "/health", "/metrics", "/static", "/favicon.ico"]
    return any(path.startswith(p) for p in public)


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Protect all routes except public ones."""
    if _is_public_path(request.url.path):
        return await call_next(request)

    user = require_auth(request)
    if not user:
        # API requests get 401, browser requests get redirected
        if "application/json" in request.headers.get("accept", ""):
            return JSONResponse({"error": "Authentication required"}, status_code=401)
        return RedirectResponse(url="/login", status_code=303)

    # Attach user to request state for use in templates
    request.state.user = user
    return await call_next(request)


# ======================== DASHBOARD ROUTES ========================

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    PAGE_VIEWS.labels(page="dashboard").inc()
    stats = await api_get(f"{INCIDENT_API}/api/v1/stats")
    incidents_data = await api_get(f"{INCIDENT_API}/api/v1/incidents?limit=20")
    incidents = incidents_data.get("incidents", [])
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "stats": stats,
        "incidents": incidents,
        "now": datetime.utcnow().isoformat(),
        "user": getattr(request.state, 'user', None),
    })


@app.get("/incidents", response_class=HTMLResponse)
async def incidents_page(request: Request, status: str = "", severity: str = ""):
    PAGE_VIEWS.labels(page="incidents").inc()
    params = "?"
    if status:
        params += f"status={status}&"
    if severity:
        params += f"severity={severity}&"
    data = await api_get(f"{INCIDENT_API}/api/v1/incidents{params}limit=100")
    return templates.TemplateResponse("incidents.html", {
        "request": request,
        "incidents": data.get("incidents", []),
        "total": data.get("total", 0),
        "filter_status": status,
        "filter_severity": severity,
        "user": getattr(request.state, 'user', None),
    })


@app.get("/incidents/{incident_id}", response_class=HTMLResponse)
async def incident_detail(request: Request, incident_id: str):
    PAGE_VIEWS.labels(page="incident_detail").inc()
    data = await api_get(f"{INCIDENT_API}/api/v1/incidents/{incident_id}")
    return templates.TemplateResponse("incident_detail.html", {
        "request": request,
        "incident": data,
        "user": getattr(request.state, 'user', None),
    })


@app.post("/incidents/{incident_id}/acknowledge")
async def ack_incident(incident_id: str, request: Request):
    form = await request.form()
    user_id = form.get("user_id", "web-user")
    result = await api_post(
        f"{INCIDENT_API}/api/v1/incidents/{incident_id}/acknowledge",
        {"user_id": user_id}
    )
    from starlette.responses import RedirectResponse
    return RedirectResponse(url=f"/incidents/{incident_id}", status_code=303)


@app.post("/incidents/{incident_id}/resolve")
async def resolve_incident(incident_id: str, request: Request):
    form = await request.form()
    user_id = form.get("user_id", "web-user")
    note = form.get("resolution_note", "")
    result = await api_post(
        f"{INCIDENT_API}/api/v1/incidents/{incident_id}/resolve",
        {"user_id": user_id, "resolution_note": note}
    )
    from starlette.responses import RedirectResponse
    return RedirectResponse(url=f"/incidents/{incident_id}", status_code=303)


@app.get("/oncall", response_class=HTMLResponse)
async def oncall_page(request: Request):
    PAGE_VIEWS.labels(page="oncall").inc()
    services = ["api-gateway", "payment-service", "auth-service", "database-service"]
    schedules = {}
    for svc in services:
        data = await api_get(f"{ONCALL_API}/api/v1/schedules/{svc}")
        schedules[svc] = data.get("entries", [])
    return templates.TemplateResponse("oncall.html", {
        "request": request,
        "schedules": schedules,
        "user": getattr(request.state, 'user', None),
    })


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("WEB_UI_HTTP_PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
