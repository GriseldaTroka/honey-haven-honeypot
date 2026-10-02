
from datetime import timedelta
from typing import Any
import csv
import json
import secrets
import hashlib
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Count, Q
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.db import connection
import time
import logging

from .forms import CheckoutForm, RegisterForm
from .deception import (
    build_fake_runtime_profile,
    fake_geoip_profile,
    fake_payment_payload,
    fake_support_ticket,
    decoy_headers,
    emit_external_alerts,
    fake_attack_research_report,
    extract_fake_iocs,
    persist_fake_iocs,
    generate_noise_batch,
    fake_command_output,
    fake_export_csv,
    fake_file_response,
    fake_graphql_response,
    fake_json_response,
    fake_panel_response,
    log_decoy_access,
    record_telemetry_event,
    _journey_intent_label,
    upload_trap_report,
    upsert_attack_journey,
)
from .asg import build_explanation_summary, get_attacker_state, update_attacker_state
from .analytics import build_attack_flow_analytics
from .detection import (
    build_detection_alert_detail,
    build_detection_alert_list_payload,
    build_detection_dashboard,
    build_detection_overview_payload,
    get_detection_alert,
    run_detection_pipeline,
    serialize_detection_alert,
    update_detection_alert_status,
)
from .investigation import (
    build_campaign_journeys,
    build_campaign_summaries,
    build_investigation_graph,
    build_ioc_index,
    build_journey_similarity_pairs,
    build_investigation_timeline,
    get_ioc_evidence_bundle,
    get_campaign_summary,
    get_journey_investigation_view,
    get_ioc_detail,
    get_ioc_relationships,
)
from .models import AlertEvent, AnalystNote, AttackJourney, AttackerState, BlogPost, CanaryToken, DetectionAlert, HoneypotLog, IOCIndicator, InvestigationBookmark, LoginAttempt, NoiseEvent, PaymentRecord, Product, SupportTicket, TelemetryEvent, ThreatIntelSnapshot, UploadArtifact
from .utils import derive_session_id, detect_api_probe_suspicion, detect_suspicion, get_client_ip, get_or_create_honey_session_id, log_event, request_payload_to_text, seed_products_if_empty, emit_structured_event
from .deception import build_attack_journeys
from django.contrib.auth.decorators import user_passes_test


def dashboard_overview_view(request: HttpRequest) -> JsonResponse:
    """Staff-only dashboard overview for the SOC UI.

    This returns the real analytics blocks the frontend expects instead of a
    zero-filled partial payload. It is intentionally bounded by limit and keeps
    the response shape stable for the dashboard widgets.
    """
    if not _has_staff_access(request):
        return JsonResponse({"detail": "Authentication required"}, status=401)

    from .analytics import build_attack_flow_analytics, build_campaign_dashboard_aggregates, build_session_inventory

    limit = int(request.GET.get("limit", 20) or 20)
    overview: dict[str, Any] = {
        "generated_at": None,
        "summary": {},
        "attack_flow": {},
        "detection": {},
        "campaign_intelligence": {},
        "recent_sessions": [],
        "recent_campaigns": [],
        "recent_notes": [],
        "recent_bookmarks": [],
    }

    try:
        from .models import AnalystNote, InvestigationBookmark

        campaign_summaries = build_campaign_summaries(limit=limit)
        overview["detection"] = build_detection_overview_payload()
        overview["attack_flow"] = build_attack_flow_analytics(limit=limit)
        overview["campaign_intelligence"] = build_campaign_dashboard_aggregates(limit=limit, campaign_summaries=campaign_summaries)
        overview["recent_sessions"] = build_session_inventory(limit=limit)
        overview["recent_campaigns"] = campaign_summaries

        overview["summary"] = {
            "session_count": AttackerState.objects.count(),
            "journey_count": AttackJourney.objects.count(),
            "alert_count": DetectionAlert.objects.count(),
            "campaign_count": AttackJourney.objects.exclude(campaign_id="").values("campaign_id").distinct().count(),
            "note_count": AnalystNote.objects.count(),
            "bookmark_count": InvestigationBookmark.objects.count(),
        }

        overview["recent_notes"] = [
            {
                "id": note.id,
                "title": note.title,
                "session_id": note.session_id,
                "campaign_id": note.campaign_id,
                "pinned": note.pinned,
                "updated_at": note.updated_at.isoformat() if note.updated_at else None,
            }
            for note in AnalystNote.objects.select_related("author").order_by("-pinned", "-updated_at")[:limit]
        ]
        overview["recent_bookmarks"] = [
            {
                "id": bookmark.id,
                "label": bookmark.label,
                "session_id": bookmark.session_id,
                "campaign_id": bookmark.campaign_id,
                "alert_id": bookmark.alert_id,
                "ioc_id": bookmark.ioc_id,
                "created_at": bookmark.created_at.isoformat() if bookmark.created_at else None,
            }
            for bookmark in InvestigationBookmark.objects.select_related("user").order_by("-created_at")[:limit]
        ]
        overview["generated_at"] = timezone.now().isoformat()
    except Exception:
        # Return a stable fallback when one of the analytics pieces fails,
        # rather than a broken zero-filled payload that triggers the UI warning.
        overview["generated_at"] = timezone.now().isoformat()
        overview["summary"] = {
            "session_count": AttackerState.objects.count() if AttackerState is not None else 0,
            "journey_count": AttackJourney.objects.count() if AttackJourney is not None else 0,
            "alert_count": DetectionAlert.objects.count() if DetectionAlert is not None else 0,
            "campaign_count": AttackJourney.objects.exclude(campaign_id="").values("campaign_id").distinct().count() if AttackJourney is not None else 0,
            "note_count": AnalystNote.objects.count() if AnalystNote is not None else 0,
            "bookmark_count": InvestigationBookmark.objects.count() if InvestigationBookmark is not None else 0,
        }

    return JsonResponse(overview, status=200)

def csrf_failure_view(request: HttpRequest, reason: str = "") -> HttpResponse:
    is_login_post = request.method == "POST" and request.path.rstrip("/") == "/login"
    if is_login_post:
        return render(request, "login.html", {"csrf_expired": True}, status=403)

    return HttpResponse("Forbidden (CSRF verification failed).", status=403)


def _has_staff_access(request: HttpRequest) -> bool:
    user = getattr(request, "user", None)
    return bool(user and getattr(user, "is_authenticated", False) and getattr(user, "is_staff", False))


def _metadata_session_id(metadata: dict | None) -> str:
    if isinstance(metadata, dict):
        return str(metadata.get("session_id", ""))[:80]
    return ""


def home(request: HttpRequest) -> HttpResponse:
    seed_products_if_empty()
    featured_products = Product.objects.filter(featured=True)[:3]
    return render(request, "home.html", {"featured_products": featured_products})


def blog(request: HttpRequest) -> HttpResponse:
    posts = BlogPost.objects.filter(is_published=True)
    return render(request, "blog.html", {"posts": posts})


def blog_detail(request: HttpRequest, slug: str) -> HttpResponse:
    post = get_object_or_404(BlogPost, slug=slug, is_published=True)
    return render(request, "blog_detail.html", {"post": post})


def shop(request: HttpRequest) -> HttpResponse:
    products = Product.objects.all()
    return render(request, "shop.html", {"products": products})


def product_detail(request: HttpRequest, slug: str) -> HttpResponse:
    product = get_object_or_404(Product, slug=slug)
    return render(request, "product_detail.html", {"product": product})


def register_view(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, "Welcome to Honey Haven. Your account is ready.")
            return redirect("home")
        messages.error(request, "Please review the form fields and try again.")
    else:
        form = RegisterForm()
    return render(request, "register.html", {"form": form})


def _safe_post_login_redirect(request: HttpRequest, fallback_name: str = "home") -> HttpResponse:
    target = request.POST.get("next") or request.GET.get("next")
    if not target:
        return redirect(fallback_name)

    if target.startswith("/"):
        if target.startswith("/soc"):
            return redirect("http://127.0.0.1:5173/soc")
        return redirect(target)

    from urllib.parse import urlparse

    parsed = urlparse(target)
    if parsed.scheme and parsed.netloc:
        hostname = (parsed.hostname or "").lower()
        valid_hosts = {"127.0.0.1", "localhost"}
        if hostname in valid_hosts:
            if parsed.path.startswith("/soc"):
                return redirect("http://127.0.0.1:5173/soc")
            return redirect(target)

    return redirect(fallback_name)


def login_view(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")

        user = authenticate(request, username=username, password=password)
        success = user is not None

        login_attempt = LoginAttempt.objects.create(
            username=username,
            password_submitted=password[:256],
            ip_address=get_client_ip(request),
            session_id=get_or_create_honey_session_id(request),
            user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
            requested_url=request.get_full_path()[:1000],
            success=success,
        )
        payload = request_payload_to_text(request)
        is_suspicious, reason = detect_suspicion(request, payload)
        recent_failed_attempts = LoginAttempt.objects.filter(
            ip_address=get_client_ip(request),
            username=username,
            success=False,
            timestamp__gte=timezone.now() - timedelta(minutes=5),
        ).count()
        brute_force_detected = recent_failed_attempts >= 5 and not success
        should_run_auth_detection = bool((not success) or is_suspicious or brute_force_detected)

        if should_run_auth_detection:
            try:
                persist_fake_iocs(
                    session_id=get_or_create_honey_session_id(request),
                    source_event="LoginAttempt",
                    source_model="LoginAttempt",
                    source_object_id=login_attempt.id if login_attempt else None,
                    text=" ".join([username, password, request.get_full_path(), request.META.get("HTTP_USER_AGENT", "")]),
                    evidence_summary=f"Login attempt for {username or 'anonymous'}",
                )
            except Exception:
                pass

        log_event(
            request,
            event_type="LOGIN_ATTEMPT",
            payload=payload,
            username=username,
            is_suspicious=is_suspicious or brute_force_detected or not success,
            suspicion_reason=reason if reason else ("Repeated failed login attempts" if brute_force_detected else ("Failed login attempt" if not success else "")),
            status_code=200,
            trigger_detection=should_run_auth_detection,
        )

        if success:
            login(request, user)
            get_or_create_honey_session_id(request)
            messages.success(request, "Login successful.")
            return _safe_post_login_redirect(request, "home")

        messages.error(request, "Invalid credentials. Please try again.")

    return render(request, "login.html", {"next": request.GET.get("next", "")})


def logout_view(request: HttpRequest) -> HttpResponse:
    logout(request)
    messages.info(request, "You have been logged out.")
    return redirect("home")


@login_required
def checkout(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        form = CheckoutForm(request.POST)
        if form.is_valid():
            payload = request_payload_to_text(request)
            is_suspicious, reason = detect_suspicion(request, payload)
            log_event(
                request,
                event_type="FORM_SUBMISSION",
                payload=payload,
                username=request.user.username,
                is_suspicious=is_suspicious,
                suspicion_reason=reason,
                status_code=200,
            )
            return redirect("order_loading")
        messages.error(request, "Please complete the checkout form.")
    else:
        form = CheckoutForm()

    return render(request, "checkout.html", {"form": form})


@login_required
def order_loading(request: HttpRequest) -> HttpResponse:
    return render(request, "order_loading.html")


@login_required
def order_confirmation(request: HttpRequest) -> HttpResponse:
    return render(request, "order_confirmation.html")


def fake_admin_dashboard(request: HttpRequest) -> HttpResponse:
    recent_activity = LoginAttempt.objects.all()[:12]
    return render(request, "fake_admin.html", {"recent_activity": recent_activity})


def fake_panel_view(request: HttpRequest, panel_key: str) -> HttpResponse:
    return fake_panel_response(request, panel_key)


def decoy_file_view(request: HttpRequest, artifact: str) -> HttpResponse:
    return fake_file_response(request, artifact)


def decoy_env_view(request: HttpRequest) -> HttpResponse:
    return fake_file_response(request, ".env")


def decoy_phpinfo_view(request: HttpRequest) -> HttpResponse:
    return fake_file_response(request, "phpinfo.php")


def decoy_git_view(request: HttpRequest, artifact: str) -> HttpResponse:
    return fake_file_response(request, f".git/{artifact}")


def _api_decoy_json(
    request: HttpRequest,
    endpoint: str,
    payload: dict[str, Any],
    *,
    label: str | None = None,
    status_code: int = 200,
) -> JsonResponse:
    request_body = request_payload_to_text(request)
    suspicious, reason, keywords, severity = detect_api_probe_suspicion(request, request_body)
    return fake_json_response(
        request,
        payload,
        label=label or endpoint.lstrip("/"),
        status_code=status_code,
        endpoint=endpoint,
        request_body=request_body,
        suspicious_keywords=keywords,
        severity=severity,
        suspicion_reason=reason if suspicious else "Decoy surface interaction",
        allow_error_injection=False,
    )


def api_decoy_view(request: HttpRequest) -> JsonResponse:
    payload = {
        "status": "success",
        "api": "Honey Haven Hidden Decoy API",
        "version": "1.0.0",
        "message": "Restricted internal endpoint",
        "scope": "hidden",
    }
    return _api_decoy_json(request, "/api/decoy", payload)
def api_users_view(request: HttpRequest) -> JsonResponse:
    payload = {
        "users": [
            {"id": 1, "username": "admin", "email": "admin@honeyhaven.local", "role": "administrator"},
            {"id": 2, "username": "linda", "email": "linda@honeyhaven.local", "role": "support"},
            {"id": 3, "username": "marco", "email": "marco@honeyhaven.local", "role": "finance"},
        ]
    }
    return fake_json_response(request, payload, label="api/v1/users", endpoint="/api/v1/users")


def api_orders_view(request: HttpRequest) -> JsonResponse:
    payload = {
        "orders": [
            {"order_id": "ORD-10421", "status": "pending", "total": 186.2, "currency": "USD"},
            {"order_id": "ORD-10422", "status": "paid", "total": 74.9, "currency": "USD"},
            {"order_id": "ORD-10423", "status": "refunded", "total": 23.0, "currency": "USD"},
        ]
    }
    return fake_json_response(request, payload, label="api/v1/orders", endpoint="/api/v1/orders")


@csrf_exempt
def api_admin_root_view(request: HttpRequest) -> JsonResponse:
    payload = {
        "status": "success",
        "panel": "Honey Haven Admin API",
        "version": "2.4.1",
        "environment": "production",
        "message": "Authenticated administrator session required",
    }
    return _api_decoy_json(request, "/api/admin", payload)


def api_admin_users_view(request: HttpRequest) -> JsonResponse:
    payload = {
        "users": [
            {"id": 1, "username": "admin", "role": "administrator", "last_login": "2026-07-20T10:30:00"},
            {"id": 2, "username": "operator", "role": "staff"},
            {"id": 3, "username": "audit", "role": "read_only"},
        ],
        "total": 3,
    }
    return _api_decoy_json(request, "/api/admin/users", payload)


def api_admin_settings_view(request: HttpRequest) -> JsonResponse:
    payload = {
        "settings": {
            "mfa_required": True,
            "password_rotation_days": 30,
            "session_timeout_minutes": 45,
            "audit_logging": True,
            "export_enabled": True,
        }
    }
    return _api_decoy_json(request, "/api/admin/settings", payload)


def api_internal_status_view(request: HttpRequest) -> JsonResponse:
    payload = {
        "service": "honeyhaven-internal",
        "status": "ok",
        "uptime_seconds": 482913,
        "version": "2.4.1",
        "maintenance": False,
    }
    return _api_decoy_json(request, "/api/internal/status", payload)


def api_internal_config_view(request: HttpRequest) -> JsonResponse:
    payload = {
        "database": "honey_prod",
        "debug": False,
        "storage": "s3",
        "maintenance": False,
        "feature_flags": {"exports": True, "telemetry": True, "canary_traps": True},
    }
    return _api_decoy_json(request, "/api/internal/config", payload)


@csrf_exempt
def api_admin_login_view(request: HttpRequest) -> JsonResponse:
    if request.method != "POST":
        return _api_decoy_json(request, "/api/admin/login", {"status": "error", "message": "POST required"}, status_code=405)

    payload = request_payload_to_text(request)
    username = request.POST.get("username", "") or request.GET.get("username", "")
    log_event(
        request,
        event_type="LOGIN_ATTEMPT",
        payload=payload,
        username=username,
        is_suspicious=True,
        suspicion_reason="Admin API login probe",
        status_code=401,
    )
    return _api_decoy_json(
        request,
        "/api/admin/login",
        {
            "status": "failure",
            "message": "MFA challenge required",
            "challenge": "totp",
            "session_scope": "admin-console",
            "locked": True,
        },
        status_code=401,
    )


def api_internal_auth_view(request: HttpRequest) -> JsonResponse:
    profile = build_fake_runtime_profile(request, "api/internal/auth")
    payload = {
        "status": "ok",
        "token_type": "Bearer",
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake.internal.token",
        "expires_in": 3600,
        "scopes": ["orders:read", "customers:read", "exports:download"],
        "meta": {"session_id": profile["identity"], "cluster": profile["cluster"], "backend": profile["backend"]},
    }
    log_decoy_access(
        request,
        event_type="API_HIT",
        payload=request_payload_to_text(request),
        status_code=200,
        suspicion_reason="Attempted internal token flow",
        endpoint="/api/internal/auth",
        request_body=request_payload_to_text(request),
    )
    return decoy_headers(JsonResponse(payload), "api/internal/auth", profile)


def staff_status_view(request: HttpRequest) -> JsonResponse:
    # Lightweight staff/status endpoint — keep minimal and cache briefly to
    # avoid repeated DB/user lookups from frequent frontend polling.
    try:
        from django.core.cache import cache
    except Exception:
        cache = None

    session_key = None
    try:
        session_key = getattr(request, "session", None) and request.session.session_key
    except Exception:
        session_key = None

    cache_key = f"staff_status:{session_key or request.COOKIES.get('sessionid') or get_client_ip(request)}"
    if cache:
        cached = cache.get(cache_key)
        if isinstance(cached, dict):
            return JsonResponse(cached)

    user = getattr(request, "user", None)
    authenticated = bool(user and getattr(user, "is_authenticated", False))
    staff = bool(user and getattr(user, "is_staff", False))
    result = {"authenticated": authenticated, "staff": staff}

    try:
        if cache:
            # very short TTL to keep UI snappy while reflecting login changes
            cache.set(cache_key, result, timeout=2)
    except Exception:
        pass

    return JsonResponse(result)


def api_docs_page_view(request: HttpRequest) -> HttpResponse:
    return render(
        request,
        "api_docs_page.html",
        {
            "page_title": "API Docs",
            "api_endpoint": "/api/docs/",
        },
    )


@csrf_exempt
def api_admin_export_view(request: HttpRequest) -> HttpResponse:
    export_type = request.GET.get("type", "customers")
    request_body = request_payload_to_text(request)
    if request.method == "POST":
        return _api_decoy_json(
            request,
            "/api/admin/export",
            {
                "status": "queued",
                "export_id": f"exp-{timezone.now().strftime('%Y%m%d%H%M%S')}",
                "format": request.POST.get("format", "csv"),
                "export_type": request.POST.get("type", export_type),
                "estimated_rows": 12482,
                "message": "Administrative export queued for background processing",
            },
            status_code=202,
        )

    csv_text, filename = fake_export_csv(export_type)
    response = HttpResponse(csv_text, content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    log_decoy_access(
        request,
        event_type="API_HIT",
        payload=request_body,
        status_code=200,
        suspicion_reason=f"Requested administrative export: {export_type}",
        endpoint="/api/admin/export",
        request_body=request_body,
    )
    return decoy_headers(response, "api/admin/export", build_fake_runtime_profile(request, f"api/admin/export:{export_type}"))


def graphql_view(request: HttpRequest) -> JsonResponse:
    payload_text = request_payload_to_text(request)
    query_text = request.GET.get("query", "") or request.POST.get("query", "") or payload_text
    payload = fake_graphql_response(query_text)
    return fake_json_response(request, payload, label="graphql")


def debug_view(request: HttpRequest) -> HttpResponse:
    profile = build_fake_runtime_profile(request, "debug")
    trace = "Traceback (most recent call last):\n  File \"/var/www/html/app.py\", line 214, in resolve_request\n    raise RuntimeError('Unexpected edge-case in debug handler')\nRuntimeError: Unexpected edge-case in debug handler\n"
    response = HttpResponse(trace, content_type="text/plain; charset=utf-8", status=500)
    log_decoy_access(
        request,
        event_type="SUSPICIOUS",
        payload=request_payload_to_text(request),
        status_code=500,
        suspicion_reason="Triggered fake debug stack trace",
    )
    return decoy_headers(response, "debug", profile)


def command_emulator_view(request: HttpRequest) -> JsonResponse:
    profile = build_fake_runtime_profile(request, "api/internal/exec")
    command = request.GET.get("cmd", "") or request.POST.get("cmd", "")
    payload = fake_command_output(command)
    log_decoy_access(
        request,
        event_type="API_HIT",
        payload=json.dumps(payload),
        status_code=200,
        suspicion_reason=f"Command emulation requested: {command}",
    )
    return decoy_headers(JsonResponse(payload), "command-emulator", profile)


@csrf_exempt
def behavior_telemetry_view(request: HttpRequest) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"status": "ok"})

    payload = request_payload_to_text(request)
    try:
        body = json.loads(payload or "{}")
    except json.JSONDecodeError:
        body = {"raw": payload}

    event_type = body.get("event_type", "BEHAVIOR_SIGNAL")
    if body.get("kind") == "fingerprint":
        event_type = "FINGERPRINT_SIGNAL"

    session_id = get_or_create_honey_session_id(request)
    record_telemetry_event(session_id, event_type, request.path, body, request)
    try:
        update_attacker_state(
            session_id=session_id,
            event_type=event_type,
            path=request.path,
            request=request,
            source_model="TelemetryEvent",
            payload=body,
        )
    except Exception:
        pass
    journey = upsert_attack_journey(
        session_id=session_id,
        entry_point=body.get("referrer") or body.get("url") or request.META.get("HTTP_REFERER", ""),
        recon_path=(body.get("events") or [])[-10:],
        payload_evolution=(body.get("events") or [])[:10],
        escalation_attempts=body.get("escalation_attempts", []),
        tools_used=body.get("tools_used", []),
        seconds_spent=int(body.get("seconds_spent", 0) or 0),
        notes=str(body.get("notes", ""))[:1000],
    )

    log_decoy_access(
        request,
        event_type=event_type,
        payload=json.dumps(body)[:4000],
        status_code=202,
        suspicion_reason="Browser fingerprint or behavior telemetry received",
    )
    return JsonResponse({"status": "ok", "received": body.get("event_type", "signal"), "session_id": journey.session_id}, status=202)


def canary_view(request: HttpRequest, token: str) -> HttpResponse:
    profile = build_fake_runtime_profile(request, f"canary:{token}")
    pixel = (
        b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
    )
    response = HttpResponse(pixel, content_type="image/gif")
    canary = CanaryToken.objects.filter(token=token).first()
    if canary:
        canary.hit_count += 1
        canary.last_hit_at = timezone.now()
        canary.metadata = {**(canary.metadata or {}), "last_hit_ip": get_client_ip(request), "last_hit_user_agent": request.META.get("HTTP_USER_AGENT", "")[:1000]}
        canary.save(update_fields=["hit_count", "last_hit_at", "metadata", "updated_at"])
        # enqueue an alert event for the canary hit with token context
        try:
            from .deception import enqueue_alert_event

            channels = {
                "discord": "",
                "telegram": "",
                "email": "",
            }
            # prefer configured webhooks from env if present (deception.enqueue_alert_event will include them again)
            event = enqueue_alert_event(
                request,
                alert_type="CANARY_HIT",
                detail=f"Canary token hit: {canary.token} (id={canary.id})",
                channels=channels,
            )
            # attach token metadata to the alert for richer downstream context
            try:
                event.metadata = {**(event.metadata or {}), "canary_id": canary.id, "canary_token": canary.token, "canary_label": canary.label, "destination_url": canary.destination_url, "session_id": profile["identity"]}
                event.save(update_fields=["metadata"])
            except Exception:
                pass
        except Exception:
            # best-effort: don't break the pixel response
            pass
    log_decoy_access(
        request,
        event_type="SUSPICIOUS",
        payload=token,
        status_code=200,
        suspicion_reason=f"Canary token triggered: {token}",
    )
    return decoy_headers(response, "canary", profile)


@csrf_exempt
def honeypot_webhook_view(request: HttpRequest) -> JsonResponse:
    """Receive JSON webhooks from external honeypot containers (cowrie/dionaea/conpot).

    Expected JSON: {"source": "cowrie", "event": "login_attempt", "data": {...}}
    Will create an AlertEvent for suspicious events or a NoiseEvent otherwise.
    """
    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "POST required"}, status=405)

    try:
        payload = json.loads(request.body.decode("utf-8") or "{}")
    except Exception:
        payload = {"raw": request.body.decode("utf-8", errors="ignore")}

    source = payload.get("source", "honeypot")
    event = payload.get("event", "event")
    data = payload.get("data", {}) or {}
    session_id = get_or_create_honey_session_id(request)

    # heuristics: treat events labeled 'login_success', 'command_exec', 'upload' as suspicious
    suspicious_markers = {"login_success", "command_exec", "upload", "exploit_detected", "shell"}
    is_suspicious = event in suspicious_markers or data.get("verdict") in {"webshell-suspected", "high-entropy"}

    if is_suspicious:
        AlertEvent.objects.create(
            alert_type="HONEYPOT_EVENT",
            detail=f"{source}:{event}",
            ip_address=data.get("ip") or get_client_ip(request),
            user_agent=data.get("user_agent", request.META.get("HTTP_USER_AGENT", ""))[:1000],
            requested_url=data.get("url", ""),
            metadata={"source": source, "event": event, "details": data, "session_id": session_id},
            dispatch_status="pending",
        )
        emit_structured_event("honeypot_webhook", source=source, event=event, details=data)
        return JsonResponse({"status": "ok", "queued": True}, status=202)

    # non-suspicious: log as noise
    NoiseEvent.objects.create(event_type=f"{source}:{event}", payload=data)
    emit_structured_event("honeypot_noise", source=source, event=event, details=data)
    return JsonResponse({"status": "ok", "queued": False}, status=200)


@user_passes_test(lambda user: user.is_staff)
def canary_tokens_view(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        action = request.POST.get("action", "create")
        token_id = request.POST.get("token_id", "")

        if action == "create":
            label = (request.POST.get("label", "").strip() or "Canary Token")[:120]
            destination_url = request.POST.get("destination_url", "").strip()
            notes = request.POST.get("notes", "").strip()
            token_value = f"beacon-{secrets.token_hex(8)}"
            CanaryToken.objects.create(
                label=label,
                token=token_value,
                destination_url=destination_url,
                notes=notes,
                metadata={"created_by": request.user.username},
            )
            messages.success(request, f"Created canary token {token_value}.")
        elif action == "revoke":
            token_obj = CanaryToken.objects.filter(id=token_id).first()
            if token_obj:
                token_obj.is_active = False
                token_obj.revoked_at = timezone.now()
                token_obj.save(update_fields=["is_active", "revoked_at", "updated_at"])
                messages.success(request, f"Revoked canary token {token_obj.token}.")
            else:
                messages.error(request, "Canary token not found.")
        elif action == "rotate":
            token_obj = CanaryToken.objects.filter(id=token_id).first()
            if token_obj:
                old_token = token_obj.token
                token_obj.token = f"beacon-{secrets.token_hex(8)}"
                token_obj.is_active = True
                token_obj.revoked_at = None
                token_obj.last_hit_at = None
                token_obj.hit_count = 0
                token_obj.save(update_fields=["token", "is_active", "revoked_at", "last_hit_at", "hit_count", "updated_at"])
                messages.success(request, f"Rotated canary token {old_token}.")
            else:
                messages.error(request, "Canary token not found.")
        else:
            messages.error(request, "Unknown action requested.")

        return redirect("canary_tokens")

    tokens = CanaryToken.objects.all()[:100]
    active_count = CanaryToken.objects.filter(is_active=True).count()
    revoked_count = CanaryToken.objects.filter(is_active=False).count()
    hit_count = sum(token.hit_count for token in tokens)
    return render(
        request,
        "canary_tokens.html",
        {
            "tokens": tokens,
            "active_count": active_count,
            "revoked_count": revoked_count,
            "hit_count": hit_count,
            "beacon_base": request.build_absolute_uri("/beacon/")[:-8],
        },
    )


def api_login(request: HttpRequest) -> JsonResponse:
    payload = request_payload_to_text(request)
    is_suspicious, reason = detect_suspicion(request, payload)
    username = request.POST.get("username", "") or request.GET.get("username", "")

    log_event(
        request,
        event_type="API_HIT",
        payload=payload,
        username=username,
        is_suspicious=True if is_suspicious else True,
        suspicion_reason=reason if reason else "Credential stuffing or scripted API probe",
        status_code=401,
    )

    return JsonResponse(
        {
            "status": "error",
            "message": "Invalid API credentials",
            "hint": "Use OAuth2 token flow",
        },
        status=401,
    )


def api_docs_view(request: HttpRequest) -> JsonResponse:
    payload = {
        "openapi": "3.0.3",
        "info": {"title": "Honey Haven Internal API", "version": "1.4.2"},
        "paths": {
            "/api/admin": {"get": {"summary": "Administrative API landing"}},
            "/api/admin/users": {"get": {"summary": "List administrative users"}},
            "/api/admin/settings": {"get": {"summary": "Read administrative settings"}},
            "/api/admin/login": {"post": {"summary": "Submit administrative credentials"}},
            "/api/admin/export": {
                "get": {"summary": "Export administrative records"},
                "post": {"summary": "Queue administrative export"},
            },
            "/api/internal/status": {"get": {"summary": "Read service status"}},
            "/api/internal/config": {"get": {"summary": "Read service configuration"}},
            "/api/v1/users": {"get": {"summary": "List users"}},
            "/api/v1/orders": {"get": {"summary": "List orders"}},
            "/api/internal/auth": {"post": {"summary": "Issue internal token"}},
            "/graphql": {"post": {"summary": "GraphQL endpoint"}},
            "/debug": {"get": {"summary": "Debug diagnostics"}},
        },
    }
    # Always allow API docs, but for non-staff return a redacted decoy
    if not _has_staff_access(request):
        redacted = {"openapi": "3.0.3", "info": {"title": "Honey Haven Public API (redacted)", "version": "1.0"}, "paths": {"/graphql": {"post": {"summary": "GraphQL endpoint"}}}}
        return fake_json_response(request, redacted, label="api/docs")

    return fake_json_response(request, payload, label="api/docs")


def api_gateway_view(request: HttpRequest) -> JsonResponse:
    payload = {
        "status": "ok",
        "service": "Honey Haven API Gateway",
        "version": "3.8.0",
        "environment": "production",
        "routes": [
            "/api/health",
            "/api/decoy",
            "/api/admin",
            "/api/admin/users",
            "/api/admin/settings",
            "/api/internal/status",
            "/api/internal/config",
        ],
    }
    return _api_decoy_json(request, "/api", payload)


def api_health_view(request: HttpRequest) -> JsonResponse:
    payload = {
        "status": "healthy",
        "service": "honeyhaven-api",
        "environment": "production",
        "uptime_seconds": 893211,
        "database": {"status": "up", "replicas": 2, "lag_ms": 12},
        "cache": {"status": "up", "hit_ratio": 0.97},
    }
    return _api_decoy_json(request, "/api/health", payload)


def hidden_status_view(request: HttpRequest) -> JsonResponse:
    payload = {
        "status": "restricted",
        "component": "Honey Haven Monitoring",
        "message": "This endpoint is reserved for internal observability staff",
        "checks": [
            {"name": "ingest", "status": "ok"},
            {"name": "alert-routing", "status": "degraded"},
            {"name": "heartbeat", "status": "ok"},
        ],
    }
    return _api_decoy_json(request, "/hidden/status", payload)


@csrf_exempt
def upload_trap_view(request: HttpRequest) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "POST required"}, status=405)

    uploaded = request.FILES.get("file")
    if not uploaded:
        return JsonResponse({"status": "error", "message": "No file supplied"}, status=400)
    # Basic hardening checks
    MAX_UPLOAD_BYTES = 200 * 1024  # 200 KB
    forbidden_exts = (".php", ".phtml", ".asp", ".aspx", ".jsp", ".sh", ".exe")

    content = uploaded.read()
    honey_session_id = get_or_create_honey_session_id(request)
    if len(content) > MAX_UPLOAD_BYTES:
        report = upload_trap_report(uploaded.name, content, get_client_ip(request), request.META.get("HTTP_USER_AGENT", ""), session_id=honey_session_id)
        # mark oversized as suspicious and create alert
        AlertEvent.objects.create(
            alert_type="SUSPICIOUS_UPLOAD",
            detail=f"Oversized upload: {uploaded.name}",
            ip_address=get_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
            requested_url=request.get_full_path(),
            metadata={"size": len(content), "sha256": report.get("sha256"), "session_id": honey_session_id},
        )
        try:
            import store.middleware as _mw

            _mw.DENYLIST.add(get_client_ip(request))
        except Exception:
            pass
        try:
            update_attacker_state(
                session_id=honey_session_id,
                event_type="UPLOAD_TRAP",
                path=request.path,
                request=request,
                source_model="UploadArtifact",
                payload={"filename": uploaded.name, "verdict": report.get("verdict"), "reason": "oversized"},
            )
        except Exception:
            pass
        return JsonResponse({"status": "quarantined", "reason": "oversized", "report": report}, status=202)

    # Suspicious extension immediate flag
    if uploaded.name.lower().endswith(forbidden_exts):
        report = upload_trap_report(uploaded.name, content, get_client_ip(request), request.META.get("HTTP_USER_AGENT", ""), session_id=honey_session_id)
        AlertEvent.objects.create(
            alert_type="SUSPICIOUS_UPLOAD",
            detail=f"Suspicious extension upload: {uploaded.name}",
            ip_address=get_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
            requested_url=request.get_full_path(),
            metadata={"size": len(content), "sha256": report.get("sha256"), "session_id": honey_session_id},
        )
        try:
            import store.middleware as _mw

            _mw.DENYLIST.add(get_client_ip(request))
        except Exception:
            pass
        try:
            update_attacker_state(
                session_id=honey_session_id,
                event_type="UPLOAD_TRAP",
                path=request.path,
                request=request,
                source_model="UploadArtifact",
                payload={"filename": uploaded.name, "verdict": report.get("verdict"), "reason": "suspicious-extension"},
            )
        except Exception:
            pass
        return JsonResponse({"status": "quarantined", "reason": "suspicious-extension", "report": report}, status=202)

    # Default processing: call existing analyzer which records artifact and entropy
    report = upload_trap_report(uploaded.name, content, get_client_ip(request), request.META.get("HTTP_USER_AGENT", ""), session_id=honey_session_id)

    # If analyzer marked suspicious, create an alert and optionally denylist the IP in-memory
    if report.get("verdict") and report.get("verdict") != "clean":
        AlertEvent.objects.create(
            alert_type="SUSPICIOUS_UPLOAD",
            detail=f"Upload flagged: {uploaded.name} ({report.get('verdict')})",
            ip_address=get_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
            requested_url=request.get_full_path(),
            metadata={"size": len(content), "sha256": report.get("sha256"), "verdict": report.get("verdict"), "session_id": honey_session_id},
        )
        try:
            import store.middleware as _mw

            _mw.DENYLIST.add(get_client_ip(request))
        except Exception:
            pass

    try:
        update_attacker_state(
            session_id=honey_session_id,
            event_type="UPLOAD_TRAP",
            path=request.path,
            request=request,
            source_model="UploadArtifact",
            payload={"filename": uploaded.name, "verdict": report.get("verdict"), "sha256": report.get("sha256")},
        )
    except Exception:
        pass

    log_decoy_access(
        request,
        event_type="SUSPICIOUS",
        payload=uploaded.name,
        status_code=202,
        suspicion_reason=f"Uploaded payload trapped: {uploaded.name}",
    )
    return JsonResponse({"status": "quarantined", "report": report}, status=202)


def threat_intel_view(request: HttpRequest, ip_address: str) -> JsonResponse:
    profile = fake_geoip_profile(ip_address)
    return fake_json_response(request, profile, label=f"threat-intel/{ip_address}")


def live_feed_view(request: HttpRequest) -> JsonResponse:
    # Provide a limited public live feed to non-staff users; full feed for staff
    if not _has_staff_access(request):
        payload = {"alerts": [], "telemetry": [], "message": "Live feed limited. Log in as staff for full view."}
        return fake_json_response(request, payload, label="live-feed")

    honey_session_id = get_or_create_honey_session_id(request)

    alerts = [
        {"timestamp": item.timestamp, "alert_type": item.alert_type, "detail": item.detail}
        for item in AlertEvent.objects.all()[:50]
        if _metadata_session_id(item.metadata) == honey_session_id
    ][:10]
    telemetry = list(TelemetryEvent.objects.filter(session_id=honey_session_id).values("timestamp", "session_id", "event_type", "path")[:20])
    uploads = [
        {"timestamp": item.timestamp, "filename": item.filename, "verdict": item.verdict, "entropy": item.entropy}
        for item in UploadArtifact.objects.all()[:50]
        if _metadata_session_id(item.metadata) == honey_session_id
    ][:10]
    payments = [
        {"timestamp": item.timestamp, "payment_id": item.payment_id, "status": item.status, "amount": item.amount}
        for item in PaymentRecord.objects.all()[:50]
        if _metadata_session_id(item.metadata) == honey_session_id
    ][:10]
    tickets = [
        {"timestamp": item.timestamp, "ticket_id": item.ticket_id, "status": item.status, "priority": item.priority}
        for item in SupportTicket.objects.all()[:50]
        if _metadata_session_id(item.metadata) == honey_session_id
    ][:10]

    payload = {
        "alerts": alerts,
        "telemetry": telemetry,
        "uploads": uploads,
        "payments": payments,
        "tickets": tickets,
    }
    return fake_json_response(request, payload, label="live-feed")


def alerts_view(request: HttpRequest) -> JsonResponse:
    # For API consumers, return JSON 401 when unauthenticated instead of
    # redirecting to an HTML login page. Authenticated staff continue to
    # receive the standard JSON payload.
    if not _has_staff_access(request):
        return JsonResponse({"detail": "Authentication required"}, status=401)

    # Support optional status/severity filters coming from the UI query string
    status = (request.GET.get("status") or "").strip().upper() or None
    severity = (request.GET.get("severity") or "").strip().upper() or None
    try:
        payload = build_detection_alert_list_payload(status=status, severity=severity)
    except TypeError:
        # Fallback for older signature: call without filters
        payload = build_detection_alert_list_payload()
    return JsonResponse(payload, status=200)


@user_passes_test(lambda user: user.is_staff)
def detection_dashboard_view(request: HttpRequest) -> JsonResponse:
    limit = max(1, min(int(request.GET.get("limit", 100) or 100), 500))
    return JsonResponse(build_detection_dashboard(limit=limit), status=200)


@user_passes_test(lambda user: user.is_staff)
def alert_detail_api_view(request: HttpRequest, alert_id: int) -> JsonResponse:
    alert = get_detection_alert(alert_id)
    if not alert:
        return JsonResponse({"status": "not_found", "alert_id": alert_id}, status=404)

    if request.method == "PATCH":
        try:
            body = json.loads(request.body.decode("utf-8") or "{}")
        except Exception:
            body = {}
        status = str(body.get("status", "") or "").upper()
        if status not in {"OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}:
            return JsonResponse({"status": "error", "message": "Invalid status"}, status=400)
        alert = update_detection_alert_status(alert, status, changed_by=getattr(request.user, "username", ""))

    detail = build_detection_alert_detail(alert)
    return JsonResponse(detail, status=200)


def session_journey_view(request: HttpRequest, session_id: str) -> JsonResponse:
    # Return JSON 401/403 for API clients instead of redirecting.
    if not _has_staff_access(request):
        user = getattr(request, "user", None)
        if user and getattr(user, "is_authenticated", False):
            return JsonResponse({"detail": "Forbidden"}, status=403)
        return JsonResponse({"detail": "Authentication required"}, status=401)

    journey = AttackJourney.objects.filter(session_id=session_id).first()
    if not journey:
        return JsonResponse({"status": "not_found", "session_id": session_id}, status=404)
    payload = {
        "session_id": journey.session_id,
        "entry_point": journey.entry_point,
        "recon_path": journey.recon_path,
        "payload_evolution": journey.payload_evolution,
        "escalation_attempts": journey.escalation_attempts,
        "tools_used": journey.tools_used,
        "phases": journey.phases,
        "seconds_spent": journey.seconds_spent,
        "risk_score": journey.risk_score,
        "confidence_score": journey.confidence_score,
        "intent_score": journey.intent_score,
        "intent_label": _journey_intent_label(journey.phases or [], journey.tools_used or [], journey.escalation_attempts or []),
        "campaign_id": journey.campaign_id,
        "notes": journey.notes,
        "first_seen": journey.first_seen.isoformat() if journey.first_seen else None,
        "last_seen": journey.last_seen.isoformat() if journey.last_seen else None,
    }
    return fake_json_response(request, payload, label=f"session/{session_id}")


def sessions_view(request: HttpRequest) -> JsonResponse:
    limit = max(1, min(int(request.GET.get("limit", 250) or 250), 2000))
    # Return JSON 401/403 for API clients instead of redirecting.
    if not _has_staff_access(request):
        user = getattr(request, "user", None)
        if user and getattr(user, "is_authenticated", False):
            return JsonResponse({"detail": "Forbidden"}, status=403)
        return JsonResponse({"detail": "Authentication required"}, status=401)
    sessions = list(
        AttackerState.objects.order_by("-updated_at").values(
            "session_id",
            "risk_score",
            "current_phase",
            "campaign_id",
            "first_seen_at",
            "alert_count",
            "updated_at",
        )[:limit]
    )
    # If the AttackerState rows lack a campaign_id, prefer the authoritative
    # AttackJourney mapping so the UI can consistently display campaign linkage.
    session_ids = [item["session_id"] for item in sessions if item.get("session_id")]
    journey_map: dict[str, str] = {}
    if session_ids:
        from .models import AttackJourney

        for j in AttackJourney.objects.filter(session_id__in=session_ids).values_list("session_id", "campaign_id"):
            journey_map[str(j[0])] = str(j[1] or "")

    payload = {
        "sessions": [
            {
                "session_id": item["session_id"],
                "current_risk_score": round(float(item.get("risk_score") or 0.0), 2),
                "current_attack_phase": item.get("current_phase") or "",
                "campaign_id": item.get("campaign_id") or journey_map.get(item.get("session_id") or "", ""),
                "start_time": item.get("first_seen_at").isoformat() if item.get("first_seen_at") else None,
                "alert_count": int(item.get("alert_count") or 0),
                "updated_at": item.get("updated_at").isoformat() if item.get("updated_at") else None,
                # Duration in seconds when available: prefer stored value else compute from timestamps
                "duration_seconds": int((item.get("updated_at") - item.get("first_seen_at")).total_seconds()) if item.get("updated_at") and item.get("first_seen_at") else None,
            }
            for item in sessions
        ]
    }
    return JsonResponse(payload, status=200)


def _parse_json_body(request: HttpRequest) -> dict[str, Any]:
    try:
        return json.loads(request.body.decode("utf-8") or "{}")
    except Exception:
        return {}


def _serialize_note(note: AnalystNote) -> dict[str, Any]:
    return {
        "id": note.id,
        "session_id": note.session_id,
        "campaign_id": note.campaign_id,
        "alert_id": note.alert_id,
        "title": note.title,
        "body": note.body,
        "pinned": note.pinned,
        "tags": note.tags or [],
        "author": getattr(note.author, "username", ""),
        "created_at": note.created_at.isoformat() if note.created_at else None,
        "updated_at": note.updated_at.isoformat() if note.updated_at else None,
    }


def _serialize_bookmark(bookmark: InvestigationBookmark) -> dict[str, Any]:
    return {
        "id": bookmark.id,
        "session_id": bookmark.session_id,
        "campaign_id": bookmark.campaign_id,
        "alert_id": bookmark.alert_id,
        "ioc_id": bookmark.ioc_id,
        "label": bookmark.label,
        "note": bookmark.note,
        "user": getattr(bookmark.user, "username", ""),
        "created_at": bookmark.created_at.isoformat() if bookmark.created_at else None,
    }


def notes_feed_view(request: HttpRequest) -> JsonResponse:
    # Return JSON 401/403 for API clients instead of redirecting.
    if not _has_staff_access(request):
        user = getattr(request, "user", None)
        if user and getattr(user, "is_authenticated", False):
            return JsonResponse({"detail": "Forbidden"}, status=403)
        return JsonResponse({"detail": "Authentication required"}, status=401)

    if request.method == "GET":
        limit = max(1, min(int(request.GET.get("limit", 200) or 200), 1000))
        notes = AnalystNote.objects.select_related("author").order_by("-pinned", "-updated_at")
        session_id = (request.GET.get("session_id") or "").strip()
        campaign_id = (request.GET.get("campaign_id") or "").strip()
        alert_id = (request.GET.get("alert_id") or "").strip()
        if session_id:
            notes = notes.filter(session_id=session_id)
        if campaign_id:
            notes = notes.filter(campaign_id=campaign_id)
        if alert_id.isdigit():
            notes = notes.filter(alert_id=int(alert_id))
        return JsonResponse({"notes": [_serialize_note(item) for item in notes[:limit]]}, status=200)

    if request.method == "POST":
        body = _parse_json_body(request)
        title = str(body.get("title", "")).strip()
        note_body = str(body.get("body", "")).strip()
        if not title or not note_body:
            return JsonResponse({"status": "error", "message": "title and body are required"}, status=400)
        note = AnalystNote.objects.create(
            session_id=str(body.get("session_id", ""))[:80],
            campaign_id=str(body.get("campaign_id", ""))[:120],
            alert_id=body.get("alert_id") if isinstance(body.get("alert_id"), int) else None,
            title=title[:180],
            body=note_body,
            pinned=bool(body.get("pinned", False)),
            tags=body.get("tags") if isinstance(body.get("tags"), list) else [],
            author=request.user,
        )
        return JsonResponse({"note": _serialize_note(note)}, status=201)

    return JsonResponse({"status": "error", "message": "Method not allowed"}, status=405)


@user_passes_test(lambda user: user.is_staff)
def note_detail_view(request: HttpRequest, note_id: int) -> JsonResponse:
    note = AnalystNote.objects.filter(id=note_id).select_related("author").first()
    if not note:
        return JsonResponse({"status": "not_found", "note_id": note_id}, status=404)

    if request.method == "PATCH":
        body = _parse_json_body(request)
        changed = False
        if "title" in body:
            note.title = str(body.get("title", "")).strip()[:180]
            changed = True
        if "body" in body:
            note.body = str(body.get("body", ""))
            changed = True
        if "pinned" in body:
            note.pinned = bool(body.get("pinned"))
            changed = True
        if "tags" in body and isinstance(body.get("tags"), list):
            note.tags = body.get("tags")
            changed = True
        if changed:
            note.save()
        return JsonResponse({"note": _serialize_note(note)}, status=200)

    if request.method == "DELETE":
        note.delete()
        return JsonResponse({"deleted": True, "note_id": note_id}, status=200)

    if request.method == "GET":
        return JsonResponse({"note": _serialize_note(note)}, status=200)

    return JsonResponse({"status": "error", "message": "Method not allowed"}, status=405)


def bookmarks_feed_view(request: HttpRequest) -> JsonResponse:
    # Return JSON 401/403 for fetch clients instead of HTML redirect.
    user = getattr(request, "user", None)
    if not _has_staff_access(request):
        if user and getattr(user, "is_authenticated", False):
            return JsonResponse({"detail": "Forbidden"}, status=403)
        return JsonResponse({"detail": "Authentication required"}, status=401)

    if request.method == "GET":
        limit = max(1, min(int(request.GET.get("limit", 200) or 200), 1000))
        bookmarks = InvestigationBookmark.objects.select_related("user").order_by("-created_at")
        session_id = (request.GET.get("session_id") or "").strip()
        campaign_id = (request.GET.get("campaign_id") or "").strip()
        if session_id:
            bookmarks = bookmarks.filter(session_id=session_id)
        if campaign_id:
            bookmarks = bookmarks.filter(campaign_id=campaign_id)
        return JsonResponse({"bookmarks": [_serialize_bookmark(item) for item in bookmarks[:limit]]}, status=200)

    if request.method == "POST":
        body = _parse_json_body(request)
        label = str(body.get("label", "")).strip()
        if not label:
            return JsonResponse({"status": "error", "message": "label is required"}, status=400)

        bookmark = InvestigationBookmark.objects.create(
            session_id=str(body.get("session_id", ""))[:80],
            campaign_id=str(body.get("campaign_id", ""))[:120],
            alert_id=body.get("alert_id") if isinstance(body.get("alert_id"), int) else None,
            ioc_id=body.get("ioc_id") if isinstance(body.get("ioc_id"), int) else None,
            label=label[:180],
            note=str(body.get("note", ""))[:300],
            user=request.user,
        )
        return JsonResponse({"bookmark": _serialize_bookmark(bookmark)}, status=201)

    return JsonResponse({"status": "error", "message": "Method not allowed"}, status=405)


@user_passes_test(lambda user: user.is_staff)
def bookmark_detail_view(request: HttpRequest, bookmark_id: int) -> JsonResponse:
    bookmark = InvestigationBookmark.objects.filter(id=bookmark_id).select_related("user").first()
    if not bookmark:
        return JsonResponse({"status": "not_found", "bookmark_id": bookmark_id}, status=404)

    if request.method == "DELETE":
        bookmark.delete()
        return JsonResponse({"deleted": True, "bookmark_id": bookmark_id}, status=200)

    if request.method == "GET":
        return JsonResponse({"bookmark": _serialize_bookmark(bookmark)}, status=200)

    return JsonResponse({"status": "error", "message": "Method not allowed"}, status=405)


@user_passes_test(lambda user: user.is_staff)
def soc_search_view(request: HttpRequest) -> JsonResponse:
    query = (request.GET.get("q") or "").strip()
    if len(query) < 2:
        return JsonResponse({"sessions": [], "campaigns": [], "iocs": [], "alerts": [], "notes": []}, status=200)

    state_sessions = list(
        AttackerState.objects.filter(
            Q(session_id__icontains=query)
            | Q(campaign_id__icontains=query)
            | Q(current_phase__icontains=query)
        )
        .order_by("-updated_at")
        .values("session_id", "campaign_id", "current_phase", "risk_score")[:12]
    )

    journey_sessions = list(
        AttackJourney.objects.filter(
            Q(session_id__icontains=query)
            | Q(campaign_id__icontains=query)
            | Q(entry_point__icontains=query)
        )
        .order_by("-last_seen")
        .values("session_id", "campaign_id", "risk_score")[:12]
    )

    sessions_map: dict[str, dict[str, Any]] = {}
    for item in state_sessions:
        key = str(item.get("session_id") or "")
        if key:
            sessions_map[key] = {
                "session_id": key,
                "campaign_id": item.get("campaign_id") or "",
                "current_phase": item.get("current_phase") or "",
                "risk_score": item.get("risk_score") or 0.0,
            }
    for item in journey_sessions:
        key = str(item.get("session_id") or "")
        if key and key not in sessions_map:
            sessions_map[key] = {
                "session_id": key,
                "campaign_id": item.get("campaign_id") or "",
                "current_phase": "",
                "risk_score": item.get("risk_score") or 0.0,
            }
    sessions = list(sessions_map.values())[:12]

    campaigns = list(
        AttackJourney.objects.filter(campaign_id__icontains=query)
        .exclude(campaign_id="")
        .values("campaign_id")
        .distinct()[:12]
    )

    iocs = list(
        IOCIndicator.objects.filter(
            Q(ioc_value__icontains=query)
            | Q(ioc_type__icontains=query)
            | Q(session_id__icontains=query)
            | Q(attack_journey__campaign_id__icontains=query)
            | Q(evidence_summary__icontains=query)
        )
        .order_by("-last_seen")
        .values("id", "ioc_type", "ioc_value", "session_id", "confidence_score")[:12]
    )

    alerts = list(
        DetectionAlert.objects.filter(
            Q(rule_name__icontains=query)
            | Q(description__icontains=query)
            | Q(session_id__icontains=query)
            | Q(campaign_id__icontains=query)
        )
        .order_by("-created_at")
        .values("id", "rule_name", "severity", "status", "session_id", "campaign_id")[:12]
    )

    notes = list(
        AnalystNote.objects.filter(
            Q(title__icontains=query)
            | Q(body__icontains=query)
            | Q(session_id__icontains=query)
            | Q(campaign_id__icontains=query)
        )
        .order_by("-updated_at")
        .values("id", "title", "session_id", "campaign_id")[:12]
    )

    return JsonResponse(
        {
            "sessions": sessions,
            "campaigns": campaigns,
            "iocs": iocs,
            "alerts": alerts,
            "notes": notes,
        },
        status=200,
    )


@csrf_exempt
def payment_webhook_view(request: HttpRequest) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "POST required"}, status=405)
    payload = request_payload_to_text(request)
    body = json.loads(payload or "{}") if payload else {}
    payment = fake_payment_payload(body.get("id"), session_id=get_or_create_honey_session_id(request))
    return fake_json_response(request, {"received": True, "payment": payment}, label="payments/webhook", status_code=202)


def merchant_dashboard_view(request: HttpRequest) -> HttpResponse:
    payments = PaymentRecord.objects.all()[:10]
    tickets = SupportTicket.objects.all()[:10]
    return render(request, "merchant_dashboard.html", {"payments": payments, "tickets": tickets})


def support_chat_view(request: HttpRequest) -> JsonResponse:
    if request.method == "POST":
        payload = request_payload_to_text(request)
        body = json.loads(payload or "{}") if payload else {}
        ticket = fake_support_ticket(
            body.get("subject", "Support request"),
            body.get("message", ""),
            body.get("email", ""),
            session_id=get_or_create_honey_session_id(request),
        )
        return fake_json_response(request, {"status": "queued", "ticket": ticket}, label="support/chat", status_code=202)

    transcript = [
        {"speaker": "agent", "message": "Thanks for contacting support. How can we help?"},
        {"speaker": "customer", "message": "I need help with an invoice export."},
        {"speaker": "agent", "message": "Please wait while we check the merchant portal."},
    ]
    return fake_json_response(request, {"transcript": transcript}, label="support/chat")


def noise_generator_view(request: HttpRequest) -> JsonResponse:
    batch = generate_noise_batch()
    return fake_json_response(request, {"generated": len(batch), "events": batch}, label="noise-generator")


def attack_research_report_view(request: HttpRequest) -> JsonResponse:
    # Provide a limited decoy report to non-staff users, full report for staff
    if not _has_staff_access(request):
        # minimal decoy summary to avoid leaking internal details
        try:
            update_attacker_state(
                session_id=get_or_create_honey_session_id(request),
                event_type="REPORT_VIEW",
                path=request.path,
                request=request,
                source_model="HoneypotLog",
                payload={"staff": False, "surface": "research_report"},
            )
        except Exception:
            pass
        return fake_json_response(request, {"summary": "Research summary unavailable. Contact support."}, label="research/report", status_code=200)

    observations = list(HoneypotLog.objects.values("id", "session_id", "requested_url", "payload", "user_agent", "attack_classification")[:25])
    for observation in observations:
        persist_fake_iocs(
            session_id=str(observation.get("session_id", ""))[:80],
            source_event="HoneypotLog",
            source_model="HoneypotLog",
            source_object_id=observation.get("id"),
            text=" ".join(
                [
                    str(observation.get("requested_url", "")),
                    str(observation.get("payload", "")),
                    str(observation.get("user_agent", "")),
                    str(observation.get("attack_classification", "")),
                ]
            ),
            metadata={"attack_classification": observation.get("attack_classification", "")},
            evidence_summary=f"Research report observation from HoneypotLog #{observation.get('id')}",
        )
    report = fake_attack_research_report(observations)
    try:
        update_attacker_state(
            session_id=get_or_create_honey_session_id(request),
            event_type="REPORT_VIEW",
            path=request.path,
            request=request,
            source_model="HoneypotLog",
            payload={"staff": True, "surface": "research_report", "observations": len(observations)},
        )
    except Exception:
        pass
    return fake_json_response(request, report, label="research/report")


@user_passes_test(lambda user: user.is_staff)
def attacker_state_current_view(request: HttpRequest) -> JsonResponse:
    session_id = get_or_create_honey_session_id(request)
    state = get_attacker_state(session_id)
    if not state:
        return JsonResponse({"status": "not_found", "session_id": session_id}, status=404)
    recent_transitions = list(
        state.transitions.values(
            "from_phase",
            "to_phase",
            "trigger_event_type",
            "trigger_path",
            "trigger_reason",
            "risk_delta",
            "confidence_delta",
            "created_at",
        )[:10]
    )
    return JsonResponse(
        {
            "session_id": state.session_id,
            "current_phase": state.current_phase,
            "previous_phase": state.previous_phase,
            "phase_confidence": state.phase_confidence,
            "risk_score": state.risk_score,
            "intent_score": state.intent_score,
            "last_event_type": state.last_event_type,
            "last_observed_path": state.last_observed_path,
            "last_observed_at": state.last_observed_at.isoformat() if state.last_observed_at else None,
            "event_count": state.event_count,
            "suspicious_event_count": state.suspicious_event_count,
            "alert_count": state.alert_count,
            "unique_ips_count": state.unique_ips_count,
            "unique_user_agents_count": state.unique_user_agents_count,
            "primary_ip": state.primary_ip,
            "primary_user_agent": state.primary_user_agent,
            "geo_country": state.geo_country,
            "asn": state.asn,
            "campaign_id": state.campaign_id,
            "last_signals": state.last_signals,
            "state_snapshot": state.state_snapshot,
            "meta": state.meta,
            "recent_transitions": recent_transitions,
        }
    )


@user_passes_test(lambda user: user.is_staff)
def attacker_state_detail_view(request: HttpRequest, session_id: str) -> JsonResponse:
    state = get_attacker_state(session_id)
    if not state:
        return JsonResponse({"status": "not_found", "session_id": session_id}, status=404)
    recent_transitions = list(
        state.transitions.values(
            "from_phase",
            "to_phase",
            "trigger_event_type",
            "trigger_path",
            "trigger_reason",
            "risk_delta",
            "confidence_delta",
            "created_at",
        )[:25]
    )
    return JsonResponse(
        {
            "session_id": state.session_id,
            "current_phase": state.current_phase,
            "previous_phase": state.previous_phase,
            "phase_confidence": state.phase_confidence,
            "risk_score": state.risk_score,
            "intent_score": state.intent_score,
            "last_event_type": state.last_event_type,
            "last_observed_path": state.last_observed_path,
            "last_observed_at": state.last_observed_at.isoformat() if state.last_observed_at else None,
            "event_count": state.event_count,
            "suspicious_event_count": state.suspicious_event_count,
            "alert_count": state.alert_count,
            "unique_ips_count": state.unique_ips_count,
            "unique_user_agents_count": state.unique_user_agents_count,
            "primary_ip": state.primary_ip,
            "primary_user_agent": state.primary_user_agent,
            "geo_country": state.geo_country,
            "asn": state.asn,
            "campaign_id": state.campaign_id,
            "last_signals": state.last_signals,
            "state_snapshot": state.state_snapshot,
            "meta": state.meta,
            "recent_transitions": recent_transitions,
        }
    )


@user_passes_test(lambda user: user.is_staff)
def attacker_state_explain_view(request: HttpRequest, session_id: str) -> JsonResponse:
    state = get_attacker_state(session_id)
    if not state:
        return JsonResponse({"status": "not_found", "session_id": session_id}, status=404)

    top_signals, explanation_summary = build_explanation_summary(state)
    return JsonResponse(
        {
            "session_id": state.session_id,
            "phase": state.current_phase,
            "risk_score": round(state.risk_score, 2),
            "confidence": round(state.phase_confidence, 2),
            "top_signals": top_signals,
            "last_event": state.last_event_type,
            "last_signals": state.last_signals,
            "explanation_summary": explanation_summary,
        }
    )


@user_passes_test(lambda user: user.is_staff)
def attack_flow_analytics_api(request: HttpRequest) -> JsonResponse:
    return JsonResponse(build_attack_flow_analytics())


@user_passes_test(lambda user: user.is_staff)
def ioc_extraction_view(request: HttpRequest) -> JsonResponse:
    payload = request_payload_to_text(request)
    report = extract_fake_iocs(payload or request.get_full_path())
    return fake_json_response(request, report, label="research/ioc", allow_error_injection=False)


def session_iocs_view(request: HttpRequest, session_id: str) -> JsonResponse:
    # Return JSON 401/403 for API clients instead of redirecting.
    if not _has_staff_access(request):
        user = getattr(request, "user", None)
        if user and getattr(user, "is_authenticated", False):
            return JsonResponse({"detail": "Forbidden"}, status=403)
        return JsonResponse({"detail": "Authentication required"}, status=401)
    indicators = IOCIndicator.objects.filter(session_id=session_id).order_by("-last_seen")
    payload = {
        "session_id": session_id,
        "iocs": [
            {
                "ioc_type": item.ioc_type,
                "ioc_value": item.ioc_value,
                "confidence_score": item.confidence_score,
                "source_model": item.source_model,
                "source_object_id": item.source_object_id,
                "evidence_summary": item.evidence_summary,
                "attack_phase": item.attack_phase,
                "asg_risk_score": item.asg_risk_score,
                "asg_confidence": item.asg_confidence,
                "source_event": item.source_event,
                "first_seen": item.first_seen.isoformat() if item.first_seen else None,
                "last_seen": item.last_seen.isoformat() if item.last_seen else None,
                "attack_journey": item.attack_journey.session_id if item.attack_journey else None,
            }
            for item in indicators
        ],
    }
    return JsonResponse(payload)


@user_passes_test(lambda user: user.is_staff)
def ioc_index_view(request: HttpRequest) -> JsonResponse:
    limit = max(1, min(int(request.GET.get("limit", 250) or 250), 1000))
    return JsonResponse({"iocs": build_ioc_index(limit=limit)}, status=200)


@user_passes_test(lambda user: user.is_staff)
def ioc_detail_view(request: HttpRequest, ioc_id: int) -> JsonResponse:
    detail = get_ioc_detail(ioc_id)
    if not detail:
        return JsonResponse({"status": "not_found", "ioc_id": ioc_id}, status=404)
    return JsonResponse(detail, status=200)


@user_passes_test(lambda user: user.is_staff)
def ioc_relationships_view(request: HttpRequest, ioc_id: int) -> JsonResponse:
    relationships = get_ioc_relationships(ioc_id)
    if not relationships:
        return JsonResponse({"status": "not_found", "ioc_id": ioc_id}, status=404)
    return JsonResponse(relationships, status=200)


@user_passes_test(lambda user: user.is_staff)
def ioc_evidence_view(request: HttpRequest, ioc_id: int) -> JsonResponse:
    evidence = get_ioc_evidence_bundle(ioc_id)
    if not evidence:
        return JsonResponse({"status": "not_found", "ioc_id": ioc_id}, status=404)
    return JsonResponse(evidence, status=200)


def campaign_list_view(request: HttpRequest) -> JsonResponse:
    # For AJAX/API consumers, respond with a JSON 401 when unauthenticated
    # instead of redirecting to the login page. Preserve behavior for
    # authenticated staff users.
    from django.http import HttpResponse

    if not _has_staff_access(request):
        return JsonResponse({"detail": "Authentication required"}, status=401)

    limit = max(1, min(int(request.GET.get("limit", 250) or 250), 1000))
    return JsonResponse({"campaigns": build_campaign_summaries(limit=limit)}, status=200)


def campaign_detail_view(request: HttpRequest, campaign_id: str) -> JsonResponse:
    # Ensure API clients receive JSON 401/403 rather than an HTML redirect.
    user = getattr(request, "user", None)
    if not _has_staff_access(request):
        if user and getattr(user, "is_authenticated", False):
            return JsonResponse({"detail": "Forbidden"}, status=403)
        return JsonResponse({"detail": "Authentication required"}, status=401)

    detail = get_campaign_summary(campaign_id)
    if not detail:
        return JsonResponse({"status": "not_found", "campaign_id": campaign_id}, status=404)
    return JsonResponse(detail, status=200)


def campaign_journeys_view(request: HttpRequest, campaign_id: str) -> JsonResponse:
    # Return JSON 401/403 for API clients instead of redirecting.
    if not _has_staff_access(request):
        user = getattr(request, "user", None)
        if user and getattr(user, "is_authenticated", False):
            return JsonResponse({"detail": "Forbidden"}, status=403)
        return JsonResponse({"detail": "Authentication required"}, status=401)

    journeys = build_campaign_journeys(campaign_id)
    if not journeys:
        return JsonResponse({"status": "not_found", "campaign_id": campaign_id}, status=404)
    return JsonResponse({"campaign_id": campaign_id, "journeys": journeys}, status=200)


@user_passes_test(lambda user: user.is_staff)
def journey_detail_view(request: HttpRequest, journey_id: int) -> JsonResponse:
    detail = get_journey_investigation_view(journey_id)
    if not detail:
        return JsonResponse({"status": "not_found", "journey_id": journey_id}, status=404)
    return JsonResponse(detail, status=200)


def investigation_graph_view(request: HttpRequest) -> JsonResponse:
    # Return JSON 401/403 for API clients instead of redirecting.
    if not _has_staff_access(request):
        user = getattr(request, "user", None)
        if user and getattr(user, "is_authenticated", False):
            return JsonResponse({"detail": "Forbidden"}, status=403)
        return JsonResponse({"detail": "Authentication required"}, status=401)

    limit = max(1, min(int(request.GET.get("limit", 250) or 250), 1000))
    session_id = (request.GET.get("session_id") or "").strip()
    return JsonResponse(build_investigation_graph(limit=limit, session_id=session_id), status=200)


@user_passes_test(lambda user: user.is_staff)
def attack_cluster_view(request: HttpRequest) -> JsonResponse:
    report = fake_attack_research_report()
    return fake_json_response(request, {"clusters": report["clusters"], "classification": report["classification"]}, label="research/cluster")


@user_passes_test(lambda user: user.is_staff)
def mitre_mapping_view(request: HttpRequest) -> JsonResponse:
    report = fake_attack_research_report()
    return fake_json_response(request, {"mitre_attack": report["mitre_attack"], "classification": report["classification"]}, label="research/mitre")


@user_passes_test(lambda user: user.is_staff)
def attacker_timeline_json(request: HttpRequest) -> JsonResponse:
    """Return timeline events as JSON for UI replay controls."""
    selected_ip = request.GET.get("ip", "").strip()
    selected_session = request.GET.get("session", "").strip()
    limit = max(25, min(int(request.GET.get("limit", 160) or 160), 1000))

    events: list[dict[str, object]] = []
    logger = logging.getLogger("honeytrap.timeline")
    start_time = time.perf_counter()
    start_queries = len(connection.queries) if connection is not None else None

    def add_event(*, timestamp, kind: str, label: str, detail: str, ip_address: str = "", user_agent: str = "", attack_type: str = "", response: str = "", payload: str = "", source: str = "", session_id_value: str = "") -> None:
        session_id = session_id_value or derive_session_id(ip_address=ip_address or "", user_agent=user_agent or "")
        session_id_is_canonical = bool(session_id_value)
        entry = {
            "timestamp": timestamp.isoformat() if hasattr(timestamp, "isoformat") else str(timestamp),
            "kind": kind,
            "label": label,
            "detail": detail,
            "ip_address": ip_address,
            "session_id": session_id,
            "attack_type": attack_type,
            "response": response,
            "payload": payload,
            "source": source,
            "session_id_is_canonical": session_id_is_canonical,
        }
        if selected_ip and entry["ip_address"] != selected_ip:
            return
        if selected_session and selected_session not in {entry["session_id"], session_id_value}:
            return
        events.append(entry)

    hp_qs = HoneypotLog.objects.order_by("-timestamp")
    if selected_ip:
        hp_qs = hp_qs.filter(ip_address=selected_ip)
    if selected_session:
        hp_qs = hp_qs.filter(session_id=selected_session)
    hp_vals = hp_qs.values(
        "timestamp",
        "event_type",
        "requested_url",
        "ip_address",
        "user_agent",
        "attack_classification",
        "status_code",
        "payload",
        "session_id",
    )[:limit]
    for item in hp_vals:
        payload = item.get("payload") or ""
        add_event(
            timestamp=item["timestamp"],
            kind="page_visit",
            label=item.get("event_type", ""),
            detail=item.get("requested_url", ""),
            ip_address=item.get("ip_address") or "",
            user_agent=item.get("user_agent", ""),
            attack_type=item.get("attack_classification", ""),
            response=str(item.get("status_code", "")),
            payload=(payload[:400] + "…") if payload and len(payload) > 400 else payload,
            source="web",
            session_id_value=item.get("session_id", ""),
        )

    la_qs = LoginAttempt.objects.order_by("-timestamp")
    if selected_ip:
        la_qs = la_qs.filter(ip_address=selected_ip)
    if selected_session:
        la_qs = la_qs.filter(session_id=selected_session)
    la_vals = la_qs.values("timestamp", "username", "requested_url", "ip_address", "user_agent", "success", "password_submitted", "session_id")[:limit]
    for item in la_vals:
        pw = item.get("password_submitted") or ""
        add_event(
            timestamp=item["timestamp"],
            kind="login_attempt",
            label=item.get("username") or "anonymous",
            detail=item.get("requested_url") or "/login",
            ip_address=item.get("ip_address") or "",
            user_agent=item.get("user_agent", ""),
            attack_type=("brute_force" if not item.get("success") else "login"),
            response=("success" if item.get("success") else "failed"),
            payload=(pw[:64] + "…") if pw else "",
            source="auth",
            session_id_value=item.get("session_id", ""),
        )

    from django.db.utils import NotSupportedError

    ae_qs = AlertEvent.objects.order_by("-timestamp")
    if selected_ip:
        ae_qs = ae_qs.filter(ip_address=selected_ip)

    # Some DB backends (SQLite) do not support JSONField __contains lookups.
    # Use a fast DB-side filter on Postgres, otherwise fetch a bounded window
    # and filter in Python to preserve behavior without raising NotSupportedError.

    ae_vals = []
    if selected_session:
        if connection.vendor == 'sqlite':
            window = max(limit * 10, 1000)
            raw = list(ae_qs.values("timestamp", "alert_type", "detail", "ip_address", "user_agent", "metadata", "dispatch_status")[:window])
            for item in raw:
                metadata = item.get("metadata") or {}
                if str(metadata.get("session_id", "")) == str(selected_session):
                    ae_vals.append(item)
                    if len(ae_vals) >= limit:
                        break
        else:
            ae_filtered = ae_qs.filter(metadata__contains={"session_id": selected_session})
            ae_vals = list(ae_filtered.values("timestamp", "alert_type", "detail", "ip_address", "user_agent", "metadata", "dispatch_status")[:limit])
    else:
        ae_vals = list(ae_qs.values("timestamp", "alert_type", "detail", "ip_address", "user_agent", "metadata", "dispatch_status")[:limit])

    for item in ae_vals:
        metadata = item.get("metadata") or {}
        add_event(
            timestamp=item["timestamp"],
            kind="alert",
            label=item.get("alert_type", ""),
            detail=item.get("detail", ""),
            ip_address=item.get("ip_address") or "",
            user_agent=item.get("user_agent", ""),
            attack_type=str(metadata.get("source", item.get("alert_type", ""))).lower(),
            response=item.get("dispatch_status", ""),
            payload=json.dumps(metadata)[:400],
            source="alert-worker",
            session_id_value=str(metadata.get("session_id", "")) if metadata.get("session_id") else "",
        )

    te_qs = TelemetryEvent.objects.order_by("-timestamp")
    if selected_ip:
        te_qs = te_qs.filter(ip_address=selected_ip)
    if selected_session:
        te_qs = te_qs.filter(session_id=selected_session)
    te_vals = te_qs.values("timestamp", "event_type", "path", "ip_address", "user_agent", "details", "session_id")[:limit]
    for item in te_vals:
        details = item.get("details") or {}
        add_event(
            timestamp=item["timestamp"],
            kind="telemetry",
            label=item.get("event_type", ""),
            detail=item.get("path", ""),
            ip_address=item.get("ip_address") or "",
            user_agent=item.get("user_agent", ""),
            attack_type="telemetry",
            response="observed",
            payload=json.dumps(details)[:400],
            source="browser",
            session_id_value=item.get("session_id", ""),
        )

    aj_qs = AttackJourney.objects.order_by("-last_seen")
    if selected_session:
        aj_qs = aj_qs.filter(session_id=selected_session)
    aj_vals = aj_qs.values("last_seen", "session_id", "entry_point", "recon_path", "tools_used", "notes")[:limit]
    for item in aj_vals:
        recon = item.get("recon_path") or []
        tools = item.get("tools_used") or []
        add_event(
            timestamp=item.get("last_seen"),
            kind="journey",
            label=item.get("session_id", ""),
            detail=item.get("entry_point") or "Unknown entry point",
            attack_type="journey",
            response=f"{len(recon)} recon steps",
            payload=json.dumps({"tools": tools, "notes": item.get("notes")})[:400],
            source="journey",
            session_id_value=item.get("session_id", ""),
        )

    events.sort(key=lambda e: e["timestamp"])  # chronological
    events = events[:limit]
    elapsed = time.perf_counter() - start_time
    end_queries = len(connection.queries) if connection is not None else None
    try:
        logger.info(
            json.dumps({"timeline_limit": limit, "events_returned": len(events), "elapsed_sec": elapsed, "queries_before": start_queries, "queries_after": end_queries})
        )
    except Exception:
        pass
    return JsonResponse({"events": events}, status=200)


@user_passes_test(lambda user: user.is_staff)
def attack_journeys_view(request: HttpRequest) -> HttpResponse:
    # render journeys UI
    return render(request, "journeys.html", {})


@user_passes_test(lambda user: user.is_staff)
def attack_journeys_json(request: HttpRequest) -> JsonResponse:
    lookback = int(request.GET.get("hours", 24))
    proximity = int(request.GET.get("proximity", 900))
    limit = int(request.GET.get("limit", 200))
    journeys = build_attack_journeys(lookback_hours=lookback, proximity_seconds=proximity, limit=limit)
    return JsonResponse({"journeys": journeys}, status=200)


@user_passes_test(lambda user: user.is_staff)
def export_logs_csv(request: HttpRequest) -> HttpResponse:
    export_type = request.GET.get("type", "honeypot")

    if export_type == "login_attempts":
        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = 'attachment; filename="login_attempts_export.csv"'

        writer = csv.writer(response)
        writer.writerow(
            [
                "timestamp",
                "username",
                "password_submitted",
                "ip_address",
                "user_agent",
                "requested_url",
                "success",
            ]
        )

        for item in LoginAttempt.objects.all().order_by("-timestamp"):
            writer.writerow(
                [
                    item.timestamp.isoformat() if item.timestamp else "",
                    item.username,
                    item.password_submitted,
                    item.ip_address,
                    item.user_agent,
                    item.requested_url,
                    item.success,
                ]
            )

        return response

    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="honeypot_logs_export.csv"'

    writer = csv.writer(response)
    writer.writerow(
        [
            "timestamp",
            "event_type",
            "attack_classification",
            "ip_address",
            "username",
            "method",
            "requested_url",
            "query_params",
            "payload",
            "user_agent",
            "is_suspicious",
            "suspicion_reason",
            "status_code",
        ]
    )

    for item in HoneypotLog.objects.all().order_by("-timestamp"):
        writer.writerow(
            [
                item.timestamp.isoformat() if item.timestamp else "",
                item.event_type,
                item.attack_classification,
                item.ip_address,
                item.username,
                item.method,
                item.requested_url,
                item.query_params,
                item.payload,
                item.user_agent,
                item.is_suspicious,
                item.suspicion_reason,
                item.status_code,
            ]
        )

    return response
