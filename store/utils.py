import json
import logging
import hashlib
import secrets
import re
import time
from datetime import timedelta
from typing import Any

from django.db import OperationalError
from django.http import HttpRequest
from django.utils import timezone

from .models import HoneypotLog, LoginAttempt, Product

EVENT_LOGGER = logging.getLogger("honeytrap.events")

SQLI_PATTERN = re.compile(
    r"('\\s*or\\s*'1'='1|union\\s+select|drop\\s+table|information_schema|--|;\\s*shutdown)",
    re.IGNORECASE,
)
SCANNER_PATTERN = re.compile(r"(sqlmap|nikto|nmap|acunetix|burp|curl|wget|python-requests|masscan|dirbuster|gobuster)", re.IGNORECASE)
PROBING_PATH_PATTERN = re.compile(
    r"(wp-admin|phpmyadmin|grafana|jenkins|dashboard|cms|portal|internal|graphql|debug|phpinfo|\.env|\.git|backup|\.bak|\.zip|\.sql|config|shell|webshell|vendor|actuator|cpanel)",
    re.IGNORECASE,
)
COMMAND_PATTERN = re.compile(r"(whoami|uname\s+-a|pwd|ls|cat\s+/etc/passwd|ifconfig|netstat)", re.IGNORECASE)
API_SUSPICIOUS_KEYWORDS = ("admin", "password", "token", "database", "config", "dump")


def get_client_ip(request: HttpRequest) -> str:
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


def get_or_create_honey_session_id(request: HttpRequest) -> str:
    session = getattr(request, "session", None)
    if session is None:
        return secrets.token_hex(16)

    honey_session_id = session.get("honey_session_id")
    if not honey_session_id:
        honey_session_id = secrets.token_hex(16)
        session["honey_session_id"] = honey_session_id
        session.modified = True
    return str(honey_session_id)[:80]


def derive_session_id(*, ip_address: str = "", user_agent: str = "", accept_language: str = "", cookie_seed: str = "", path: str = "") -> str:
    """Derive a stable session-like identifier for correlating attacker activity.

    The identifier is intentionally deterministic for the same client fingerprint so
    that logs, alerts, and the timeline UI can be grouped without storing extra state.
    """
    if cookie_seed:
        return str(cookie_seed)[:80]
    seed = "|".join([ip_address, user_agent, accept_language, cookie_seed])
    digest = hashlib.sha256(seed.encode("utf-8", errors="ignore")).hexdigest()
    return digest[:24]


def request_payload_to_text(request: HttpRequest) -> str:
    if request.method in ["POST", "PUT", "PATCH"]:
        try:
            if request.content_type and "application/json" in request.content_type:
                body = request.body.decode("utf-8", errors="ignore")
                if body:
                    parsed: Any = json.loads(body)
                    return json.dumps(parsed)
            if request.POST:
                return json.dumps(request.POST.dict())
            body = request.body.decode("utf-8", errors="ignore")
            return body[:4000]
        except Exception:
            return "<unparseable-payload>"
    return ""


def emit_structured_event(event_name: str, **fields: Any) -> None:
    payload = {"event": event_name, "timestamp": timezone.now().isoformat(), **fields}
    EVENT_LOGGER.info(json.dumps(payload, default=str))


def detect_suspicion(request: HttpRequest, payload: str) -> tuple[bool, str]:
    combined = f"{request.path} {request.META.get('QUERY_STRING', '')} {payload}"
    user_agent = request.META.get("HTTP_USER_AGENT", "")

    if SQLI_PATTERN.search(combined):
        return True, "Potential SQL injection payload"
    if SCANNER_PATTERN.search(user_agent):
        return True, "Automated scanner or scripted client detected"
    if COMMAND_PATTERN.search(combined):
        return True, "Command-emulation probe detected"
    if len(payload) > 800:
        return True, "Oversized payload submitted"

    ip = get_client_ip(request)
    recent_hits = HoneypotLog.objects.filter(
        ip_address=ip,
        requested_url=request.path,
        timestamp__gte=request._request_time_window,
    ).count()
    if recent_hits >= 10:
        return True, "Repeated requests to same endpoint (possible brute force)"

    return False, ""


def classify_attack(request: HttpRequest, payload: str, event_type: str) -> tuple[str, str]:
    combined = f"{request.path} {request.META.get('QUERY_STRING', '')} {payload}"
    user_agent = request.META.get("HTTP_USER_AGENT", "")
    ip = get_client_ip(request)

    if SQLI_PATTERN.search(combined):
        return "SQL_INJECTION_ATTEMPT", "Matched SQL injection pattern in URL/query/payload"

    login_related = (
        event_type == "LOGIN_ATTEMPT"
        or request.path.startswith("/login")
        or request.path.startswith("/api/login")
        or request.path.startswith("/api/admin/login")
    )
    if login_related:
        failed_login_count = LoginAttempt.objects.filter(
            ip_address=ip,
            success=False,
            timestamp__gte=timezone.now() - timedelta(minutes=5),
        ).count()
        if failed_login_count >= 5:
            return "BRUTE_FORCE_ATTACK", "5+ failed login attempts from same IP within 5 minutes"

    recent_window = timezone.now() - timedelta(minutes=2)
    recent_logs = HoneypotLog.objects.filter(ip_address=ip, timestamp__gte=recent_window)
    unique_endpoints = recent_logs.values("requested_url").distinct().count()
    rapid_request_count = recent_logs.count()
    if SCANNER_PATTERN.search(user_agent) or PROBING_PATH_PATTERN.search(combined) or unique_endpoints >= 6 or rapid_request_count >= 15:
        return "SCANNER_BOT_ACTIVITY", "Rapid endpoint probing or scanner signature detected"

    return "NORMAL_TRAFFIC", "No attack signature matched"


def detect_api_probe_suspicion(request: HttpRequest, payload: str) -> tuple[bool, str, list[str], str]:
    combined = f"{request.path} {request.META.get('QUERY_STRING', '')} {payload}".lower()
    suspicious_keywords = sorted({keyword for keyword in API_SUSPICIOUS_KEYWORDS if keyword in combined})

    ip = get_client_ip(request)
    recent_window = timezone.now() - timedelta(minutes=2)
    recent_logs = HoneypotLog.objects.filter(ip_address=ip, timestamp__gte=recent_window)
    admin_hits = recent_logs.filter(requested_url__startswith="/api/admin").count()
    internal_hits = recent_logs.filter(requested_url__startswith="/api/internal").count()
    api_hits = recent_logs.filter(requested_url__startswith="/api/").count()

    repeated_admin_access = admin_hits >= 3 or internal_hits >= 3 or api_hits >= 6
    posted_sensitive_data = request.method == "POST" and request.path.startswith(("/api/admin", "/api/internal"))
    suspicious = bool(suspicious_keywords) or repeated_admin_access or posted_sensitive_data

    if suspicious_keywords:
        severity = "high" if any(keyword in {"password", "token", "database", "dump"} for keyword in suspicious_keywords) else "medium"
        reason = f"Sensitive keyword probe detected: {', '.join(suspicious_keywords)}"
    elif repeated_admin_access:
        severity = "medium"
        reason = "Multiple administrative API requests from the same IP in a short window"
    elif posted_sensitive_data:
        severity = "medium"
        reason = "Sensitive administrative POST request"
    else:
        severity = "low"
        reason = "Decoy API interaction"

    return suspicious, reason, suspicious_keywords, severity


def log_event(
    request: HttpRequest,
    *,
    event_type: str,
    payload: str = "",
    username: str = "",
    is_suspicious: bool = False,
    suspicion_reason: str = "",
    status_code: int = 200,
    trigger_detection: bool = False,
) -> None:
    session_id = get_or_create_honey_session_id(request)
    attack_classification, classification_reason = classify_attack(request, payload, event_type)
    derived_suspicious = is_suspicious or attack_classification != "NORMAL_TRAFFIC"
    final_reason = suspicion_reason if suspicion_reason else (classification_reason if derived_suspicious else "")

    emit_structured_event(
        "honeypot_log",
        ip_address=get_client_ip(request),
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
        requested_url=request.get_full_path()[:1000],
        method=request.method,
        query_params=request.META.get("QUERY_STRING", "")[:2000],
        session_id=session_id,
        event_type=event_type,
        attack_classification=attack_classification,
        is_suspicious=derived_suspicious,
        suspicion_reason=final_reason[:300],
        status_code=status_code,
    )

    for attempt in range(3):
        try:
            created_log = HoneypotLog.objects.create(
                ip_address=get_client_ip(request),
                session_id=session_id,
                user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
                requested_url=request.get_full_path()[:1000],
                method=request.method,
                query_params=request.META.get("QUERY_STRING", "")[:2000],
                payload=payload[:4000],
                username=username[:150],
                event_type=event_type,
                attack_classification=attack_classification,
                is_suspicious=derived_suspicious,
                suspicion_reason=final_reason[:300],
                status_code=status_code,
            )
            should_run_detection = bool(trigger_detection or derived_suspicious)
            if should_run_detection:
                try:
                    from .deception import persist_fake_iocs

                    persist_fake_iocs(
                        session_id=session_id,
                        source_event="HoneypotLog",
                        source_model="HoneypotLog",
                        source_object_id=created_log.id if created_log else None,
                        text=" ".join(
                            [
                                request.get_full_path(),
                                request.META.get("QUERY_STRING", ""),
                                payload,
                                username,
                                request.META.get("HTTP_USER_AGENT", ""),
                            ]
                        ),
                        metadata={"event_type": event_type, "attack_classification": attack_classification},
                        evidence_summary=f"{event_type} on {request.get_full_path()[:120]}",
                    )
                    from .detection import run_detection_pipeline

                    run_detection_pipeline(
                        session_id,
                        trigger={
                            "source_model": "HoneypotLog",
                            "source_object_id": created_log.id if created_log else None,
                            "source_event": event_type,
                            "ip_address": get_client_ip(request),
                            "request_path": request.path,
                            "payload": payload,
                        },
                    )
                except Exception:
                    pass
            break
        except OperationalError:
            if attempt == 2:
                break
            time.sleep(0.2)

    # Ensure the flag is always defined even if DB writes failed repeatedly
    try:
        should_run_detection
    except UnboundLocalError:
        should_run_detection = False

    if not should_run_detection:
        return

    if request.path.rstrip("/") != "/api/upload/trap":
        try:
            from .asg import update_attacker_state

            update_attacker_state(
                session_id=session_id,
                event_type=event_type,
                path=request.path,
                request=request,
                source_model="HoneypotLog",
                payload=payload,
            )
        except Exception:
            pass

    # Queue background job to update an AttackJourney record for this session.
    try:
        # Prefer debounce via Redis to batch session ids
        from . import debounce
        queued = debounce.add_session(session_id)
        if queued:
            return
    except Exception:
        queued = False

    # If debounce unavailable or failed, fall back to enqueueing a per-session task
    try:
        from . import tasks as bg_tasks
        try:
            bg_tasks.update_attack_journey_task.delay(session_id, request.path)
            return
        except Exception:
            # synchronous fallback
            bg_tasks.update_attack_journey_task(session_id, request.path)
            return
    except Exception:
        # last-resort synchronous upsert
        try:
            from .deception import upsert_attack_journey
            upsert_attack_journey(session_id=session_id, entry_point=request.path)
        except Exception:
            pass


def seed_products_if_empty() -> None:
    if Product.objects.exists():
        return

    products = [
        {
            "name": "Wildflower Raw Honey",
            "slug": "wildflower-raw-honey",
            "short_description": "Floral notes with a smooth golden finish.",
            "description": "Single-origin wildflower honey harvested from pesticide-free meadows. Ideal for tea, toast, and artisan desserts.",
            "price": 18.50,
            "image_url": "https://images.unsplash.com/photo-1471943311424-646960669fbc?auto=format&fit=crop&w=1200&q=80",
            "featured": True,
        },
        {
            "name": "Forest Amber Honey",
            "slug": "forest-amber-honey",
            "short_description": "Rich and deep, perfect for baking.",
            "description": "Dark amber honey with caramelized undertones sourced from forest blossoms. Pair with pastries and roasted nuts.",
            "price": 22.00,
            "image_url": "https://images.unsplash.com/photo-1523983302122-73e869e1f850?auto=format&fit=crop&w=1200&q=80",
            "featured": True,
        },
        {
            "name": "Organic Acacia Honey",
            "slug": "organic-acacia-honey",
            "short_description": "Light, delicate, and naturally sweet.",
            "description": "Crystal-clear acacia honey with a gentle sweetness. A premium choice for yogurts, smoothies, and breakfast bowls.",
            "price": 19.90,
            "image_url": "https://images.unsplash.com/photo-1587049352851-8d4e89133924?auto=format&fit=crop&w=1200&q=80",
            "featured": False,
        },
        {
            "name": "Cinnamon Infused Honey",
            "slug": "cinnamon-infused-honey",
            "short_description": "Warm spice infusion for cozy drinks.",
            "description": "Small-batch honey infused with organic cinnamon sticks for a warm and aromatic profile. Excellent in coffee and oatmeal.",
            "price": 24.90,
            "image_url": "https://images.unsplash.com/photo-1470549813517-2fa741d25c92?auto=format&fit=crop&w=1200&q=80",
            "featured": False,
        },
    ]

    for item in products:
        Product.objects.create(**item)
