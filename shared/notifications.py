"""
Shared Notification Module
Handles email (SendGrid) and webhook dispatch for incident events.

Bonus 1: Real email integration via SendGrid HTTP API (no SDK dependency).
Bonus 2: Webhook notifications to registered endpoints.
"""
import os
import json
import logging
import asyncio
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional, Dict, List, Any

logger = logging.getLogger("notifications")

# ======================== EMAIL (SendGrid HTTP API) ========================

SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY", "")
SENDGRID_FROM_EMAIL = os.getenv("SENDGRID_FROM_EMAIL", "oncall@incident-platform.local")
SENDGRID_ENABLED = bool(SENDGRID_API_KEY)

# Fallback: SMTP for local testing (MailHog compatible)
SMTP_HOST = os.getenv("SMTP_HOST", "mailhog")
SMTP_PORT = int(os.getenv("SMTP_PORT", "1025"))
SMTP_ENABLED = os.getenv("SMTP_ENABLED", "true").lower() == "true"


async def send_email_sendgrid(to_email: str, subject: str, html_body: str) -> bool:
    """Send email via SendGrid v3 HTTP API (zero SDK dependency)."""
    import aiohttp
    if not SENDGRID_ENABLED:
        logger.debug("SendGrid not configured, skipping email")
        return False

    url = "https://api.sendgrid.com/v3/mail/send"
    payload = {
        "personalizations": [{"to": [{"email": to_email}]}],
        "from": {"email": SENDGRID_FROM_EMAIL, "name": "OnCall Platform"},
        "subject": subject,
        "content": [{"type": "text/html", "value": html_body}],
    }
    headers = {
        "Authorization": f"Bearer {SENDGRID_API_KEY}",
        "Content-Type": "application/json",
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status in (200, 201, 202):
                    logger.info(f"SendGrid email sent to {to_email}: {subject}")
                    return True
                else:
                    body = await resp.text()
                    logger.warning(f"SendGrid error {resp.status}: {body}")
                    return False
    except Exception as e:
        logger.error(f"SendGrid request failed: {e}")
        return False


async def send_email_smtp(to_email: str, subject: str, html_body: str) -> bool:
    """Send email via SMTP (local MailHog for testing)."""
    if not SMTP_ENABLED:
        logger.debug("SMTP not enabled, skipping email")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SENDGRID_FROM_EMAIL
        msg["To"] = to_email
        msg.attach(MIMEText(html_body, "html"))

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _smtp_send, msg, to_email)
        logger.info(f"SMTP email sent to {to_email}: {subject}")
        return True
    except Exception as e:
        logger.warning(f"SMTP send failed: {e}")
        return False


def _smtp_send(msg, to_email: str):
    """Blocking SMTP send (run in executor)."""
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.sendmail(SENDGRID_FROM_EMAIL, [to_email], msg.as_string())


async def send_notification_email(to_email: str, subject: str, html_body: str) -> bool:
    """Try SendGrid first, fall back to SMTP."""
    if SENDGRID_ENABLED:
        return await send_email_sendgrid(to_email, subject, html_body)
    elif SMTP_ENABLED:
        return await send_email_smtp(to_email, subject, html_body)
    else:
        logger.info(f"Email notification (dry-run) → {to_email}: {subject}")
        return True  # Dry-run mode: log only


def build_incident_email(incident_id: str, title: str, severity: str,
                         service_name: str, assigned_to: str, event: str = "new") -> tuple:
    """Build HTML email for incident events. Returns (subject, html_body)."""
    color_map = {"critical": "#dc3545", "high": "#fd7e14", "medium": "#ffc107", "low": "#17a2b8"}
    color = color_map.get(severity, "#6c757d")
    event_label = {"new": "NEW INCIDENT", "escalation": "ESCALATION", "resolved": "RESOLVED"}.get(event, event.upper())

    subject = f"[{event_label}] {title} — {service_name}"
    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: {color}; color: white; padding: 16px; border-radius: 8px 8px 0 0;">
            <h2 style="margin: 0;">{event_label}</h2>
        </div>
        <div style="border: 1px solid #ddd; border-top: none; padding: 20px; border-radius: 0 0 8px 8px;">
            <table style="width: 100%; border-collapse: collapse;">
                <tr><td style="padding: 8px; font-weight: bold;">Incident ID</td><td style="padding: 8px;">{incident_id[:12]}...</td></tr>
                <tr><td style="padding: 8px; font-weight: bold;">Title</td><td style="padding: 8px;">{title}</td></tr>
                <tr><td style="padding: 8px; font-weight: bold;">Service</td><td style="padding: 8px;">{service_name}</td></tr>
                <tr><td style="padding: 8px; font-weight: bold;">Severity</td><td style="padding: 8px;"><span style="background: {color}; color: white; padding: 2px 8px; border-radius: 4px;">{severity.upper()}</span></td></tr>
                <tr><td style="padding: 8px; font-weight: bold;">Assigned To</td><td style="padding: 8px;">{assigned_to}</td></tr>
                <tr><td style="padding: 8px; font-weight: bold;">Time</td><td style="padding: 8px;">{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</td></tr>
            </table>
            <hr style="margin: 20px 0;">
            <p style="color: #666; font-size: 12px;">Dashboard: <a href="http://localhost:8080">http://localhost:8080</a></p>
        </div>
    </div>
    """
    return subject, html_body


# ======================== WEBHOOK NOTIFICATIONS ========================

# Webhook registry (in-memory + Redis-backed)
# Format: {"url": "https://...", "events": ["incident.new", "incident.resolved"], "secret": "..."}
_webhook_registry: List[Dict[str, Any]] = []

WEBHOOK_EVENTS = [
    "incident.new",
    "incident.acknowledged",
    "incident.resolved",
    "incident.escalated",
    "alert.new",
]


def register_webhook(url: str, events: List[str], secret: str = "") -> dict:
    """Register a webhook endpoint."""
    import hashlib
    webhook_id = hashlib.sha256(f"{url}:{','.join(events)}".encode()).hexdigest()[:16]
    entry = {
        "id": webhook_id,
        "url": url,
        "events": events,
        "secret": secret,
        "created_at": datetime.utcnow().isoformat(),
        "active": True,
    }
    # Deduplicate by URL
    _webhook_registry[:] = [w for w in _webhook_registry if w["url"] != url]
    _webhook_registry.append(entry)
    logger.info(f"Webhook registered: {webhook_id} → {url} for events {events}")
    return entry


def unregister_webhook(webhook_id: str) -> bool:
    """Remove a webhook by ID."""
    before = len(_webhook_registry)
    _webhook_registry[:] = [w for w in _webhook_registry if w["id"] != webhook_id]
    return len(_webhook_registry) < before


def list_webhooks() -> List[Dict]:
    """List all registered webhooks."""
    return list(_webhook_registry)


async def dispatch_webhook(event_type: str, payload: dict):
    """
    Dispatch webhook event to all registered endpoints matching this event type.
    Uses HMAC-SHA256 signature if a secret is configured.
    """
    import aiohttp
    import hashlib
    import hmac

    matching = [w for w in _webhook_registry if w["active"] and event_type in w["events"]]
    if not matching:
        return

    body = json.dumps({
        "event": event_type,
        "timestamp": datetime.utcnow().isoformat(),
        "data": payload,
    }, default=str)

    async with aiohttp.ClientSession() as session:
        for webhook in matching:
            try:
                headers = {"Content-Type": "application/json", "X-Event-Type": event_type}
                if webhook.get("secret"):
                    sig = hmac.new(
                        webhook["secret"].encode(),
                        body.encode(),
                        hashlib.sha256,
                    ).hexdigest()
                    headers["X-Webhook-Signature"] = f"sha256={sig}"

                async with session.post(
                    webhook["url"],
                    data=body,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status < 300:
                        logger.info(f"Webhook delivered: {event_type} → {webhook['url']} ({resp.status})")
                    else:
                        logger.warning(f"Webhook failed: {webhook['url']} → {resp.status}")
            except Exception as e:
                logger.warning(f"Webhook dispatch error: {webhook['url']} → {e}")


async def load_webhooks_from_redis():
    """Load webhook registry from Redis on startup."""
    try:
        from shared.redis_client import cache_get
        data = await cache_get("webhooks:registry")
        if data and isinstance(data, list):
            _webhook_registry.clear()
            _webhook_registry.extend(data)
            logger.info(f"Loaded {len(data)} webhooks from Redis")
    except Exception:
        pass


async def save_webhooks_to_redis():
    """Persist webhook registry to Redis."""
    try:
        from shared.redis_client import cache_set
        await cache_set("webhooks:registry", _webhook_registry, ttl=86400)
    except Exception:
        pass
