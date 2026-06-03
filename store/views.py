from datetime import timedelta
import csv
import json
import secrets
import hashlib

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Count, Q
from django.db.models.functions import TruncDate, TruncHour, TruncMinute
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

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
    generate_noise_batch,
    fake_command_output,
    fake_export_csv,
    fake_file_response,
    fake_graphql_response,
    fake_json_response,
    fake_panel_response,
    log_decoy_access,
    record_telemetry_event,
    upload_trap_report,
    upsert_attack_journey,
)
from .models import AlertEvent, AttackJourney, BlogPost, CanaryToken, HoneypotLog, LoginAttempt, NoiseEvent, PaymentRecord, Product, SupportTicket, TelemetryEvent, ThreatIntelSnapshot, UploadArtifact
from .utils import derive_session_id, detect_suspicion, get_client_ip, log_event, request_payload_to_text, seed_products_if_empty, emit_structured_event
from .deception import build_attack_journeys


def _has_staff_access(request: HttpRequest) -> bool:
    user = getattr(request, "user", None)
    return bool(user and getattr(user, "is_authenticated", False) and getattr(user, "is_staff", False))


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


def login_view(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")

        user = authenticate(request, username=username, password=password)
        success = user is not None

        LoginAttempt.objects.create(
            username=username,
            password_submitted=password[:256],
            ip_address=get_client_ip(request),
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

        log_event(
            request,
            event_type="LOGIN_ATTEMPT",
            payload=payload,
            username=username,
            is_suspicious=is_suspicious or brute_force_detected or not success,
            suspicion_reason=reason if reason else ("Repeated failed login attempts" if brute_force_detected else ("Failed login attempt" if not success else "")),
            status_code=200,
        )

        if success:
            login(request, user)
            messages.success(request, "Login successful.")
            return redirect("home")

        messages.error(request, "Invalid credentials. Please try again.")

    return render(request, "login.html")


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


def api_users_view(request: HttpRequest) -> JsonResponse:
    payload = {
        "users": [
            {"id": 1, "username": "admin", "email": "admin@honeyhaven.local", "role": "administrator"},
            {"id": 2, "username": "linda", "email": "linda@honeyhaven.local", "role": "support"},
            {"id": 3, "username": "marco", "email": "marco@honeyhaven.local", "role": "finance"},
        ]
    }
    return fake_json_response(request, payload, label="api/v1/users")


def api_orders_view(request: HttpRequest) -> JsonResponse:
    payload = {
        "orders": [
            {"order_id": "ORD-10421", "status": "pending", "total": 186.2, "currency": "USD"},
            {"order_id": "ORD-10422", "status": "paid", "total": 74.9, "currency": "USD"},
            {"order_id": "ORD-10423", "status": "refunded", "total": 23.0, "currency": "USD"},
        ]
    }
    return fake_json_response(request, payload, label="api/v1/orders")


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
    )
    return decoy_headers(JsonResponse(payload), "api/internal/auth", profile)


def api_admin_export_view(request: HttpRequest) -> HttpResponse:
    export_type = request.GET.get("type", "customers")
    csv_text, filename = fake_export_csv(export_type)
    response = HttpResponse(csv_text, content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    log_decoy_access(
        request,
        event_type="API_HIT",
        payload=request_payload_to_text(request),
        status_code=200,
        suspicion_reason=f"Requested administrative export: {export_type}",
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

    session_id = str(body.get("session_id", "")) or derive_session_id(
        ip_address=get_client_ip(request),
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
        accept_language=request.META.get("HTTP_ACCEPT_LANGUAGE", "")[:200],
        cookie_seed=request.COOKIES.get("sessionid", "")[:80],
    )
    record_telemetry_event(session_id, event_type, request.path, body, request)
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
    session_id = derive_session_id(
        ip_address=get_client_ip(request),
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
        accept_language=request.META.get("HTTP_ACCEPT_LANGUAGE", "")[:200],
        cookie_seed=request.COOKIES.get("sessionid", "")[:80],
        path=request.path,
    )

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
            "/api/v1/users": {"get": {"summary": "List users"}},
            "/api/v1/orders": {"get": {"summary": "List orders"}},
            "/api/internal/auth": {"post": {"summary": "Issue internal token"}},
            "/api/admin/export": {"get": {"summary": "Export administrative records"}},
            "/graphql": {"post": {"summary": "GraphQL endpoint"}},
            "/debug": {"get": {"summary": "Debug diagnostics"}},
        },
    }
    # Always allow API docs, but for non-staff return a redacted decoy
    if not _has_staff_access(request):
        redacted = {"openapi": "3.0.3", "info": {"title": "Honey Haven Public API (redacted)", "version": "1.0"}, "paths": {"/graphql": {"post": {"summary": "GraphQL endpoint"}}}}
        return fake_json_response(request, redacted, label="api/docs")

    return fake_json_response(request, payload, label="api/docs")


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
    if len(content) > MAX_UPLOAD_BYTES:
        report = upload_trap_report(uploaded.name, content, get_client_ip(request), request.META.get("HTTP_USER_AGENT", ""))
        # mark oversized as suspicious and create alert
        AlertEvent.objects.create(
            alert_type="SUSPICIOUS_UPLOAD",
            detail=f"Oversized upload: {uploaded.name}",
            ip_address=get_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
            requested_url=request.get_full_path(),
            metadata={"size": len(content), "sha256": report.get("sha256")},
        )
        try:
            import store.middleware as _mw

            _mw.DENYLIST.add(get_client_ip(request))
        except Exception:
            pass
        return JsonResponse({"status": "quarantined", "reason": "oversized", "report": report}, status=202)

    # Suspicious extension immediate flag
    if uploaded.name.lower().endswith(forbidden_exts):
        report = upload_trap_report(uploaded.name, content, get_client_ip(request), request.META.get("HTTP_USER_AGENT", ""))
        AlertEvent.objects.create(
            alert_type="SUSPICIOUS_UPLOAD",
            detail=f"Suspicious extension upload: {uploaded.name}",
            ip_address=get_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
            requested_url=request.get_full_path(),
            metadata={"size": len(content), "sha256": report.get("sha256")},
        )
        try:
            import store.middleware as _mw

            _mw.DENYLIST.add(get_client_ip(request))
        except Exception:
            pass
        return JsonResponse({"status": "quarantined", "reason": "suspicious-extension", "report": report}, status=202)

    # Default processing: call existing analyzer which records artifact and entropy
    report = upload_trap_report(uploaded.name, content, get_client_ip(request), request.META.get("HTTP_USER_AGENT", ""))

    # If analyzer marked suspicious, create an alert and optionally denylist the IP in-memory
    if report.get("verdict") and report.get("verdict") != "clean":
        AlertEvent.objects.create(
            alert_type="SUSPICIOUS_UPLOAD",
            detail=f"Upload flagged: {uploaded.name} ({report.get('verdict')})",
            ip_address=get_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
            requested_url=request.get_full_path(),
            metadata={"size": len(content), "sha256": report.get("sha256"), "verdict": report.get("verdict")},
        )
        try:
            import store.middleware as _mw

            _mw.DENYLIST.add(get_client_ip(request))
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

    payload = {
        "alerts": list(AlertEvent.objects.values("timestamp", "alert_type", "detail")[:10]),
        "telemetry": list(TelemetryEvent.objects.values("timestamp", "session_id", "event_type", "path")[:20]),
        "uploads": list(UploadArtifact.objects.values("timestamp", "filename", "verdict", "entropy")[:10]),
        "payments": list(PaymentRecord.objects.values("timestamp", "payment_id", "status", "amount")[:10]),
        "tickets": list(SupportTicket.objects.values("timestamp", "ticket_id", "status", "priority")[:10]),
    }
    return fake_json_response(request, payload, label="live-feed")


@user_passes_test(lambda user: user.is_staff)
def alerts_view(request: HttpRequest) -> JsonResponse:
    payload = {"alerts": list(AlertEvent.objects.values("timestamp", "alert_type", "detail", "requested_url")[:50])}
    return fake_json_response(request, payload, label="alerts")


@user_passes_test(lambda user: user.is_staff)
def session_journey_view(request: HttpRequest, session_id: str) -> JsonResponse:
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
        "seconds_spent": journey.seconds_spent,
        "notes": journey.notes,
    }
    return fake_json_response(request, payload, label=f"session/{session_id}")


@csrf_exempt
def payment_webhook_view(request: HttpRequest) -> JsonResponse:
    if request.method != "POST":
        return JsonResponse({"status": "error", "message": "POST required"}, status=405)
    payload = request_payload_to_text(request)
    body = json.loads(payload or "{}") if payload else {}
    payment = fake_payment_payload(body.get("id"))
    return fake_json_response(request, {"received": True, "payment": payment}, label="payments/webhook", status_code=202)


def merchant_dashboard_view(request: HttpRequest) -> HttpResponse:
    payments = PaymentRecord.objects.all()[:10]
    tickets = SupportTicket.objects.all()[:10]
    return render(request, "merchant_dashboard.html", {"payments": payments, "tickets": tickets})


def support_chat_view(request: HttpRequest) -> JsonResponse:
    if request.method == "POST":
        payload = request_payload_to_text(request)
        body = json.loads(payload or "{}") if payload else {}
        ticket = fake_support_ticket(body.get("subject", "Support request"), body.get("message", ""), body.get("email", ""))
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


@user_passes_test(lambda user: user.is_staff)
def alert_review_view(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        alert_id = request.POST.get("alert_id", "")
        action = request.POST.get("action", "")
        alert = AlertEvent.objects.filter(id=alert_id).first()

        if alert:
            if action == "replay":
                alert.dispatch_status = "pending"
                alert.dispatched_at = None
                alert.metadata = {**(alert.metadata or {}), "replay_requested": True}
                alert.save(update_fields=["dispatch_status", "dispatched_at", "metadata"])
                messages.success(request, f"Alert {alert.id} re-queued for dispatch.")
            elif action == "mark_reviewed":
                alert.dispatch_status = "reviewed"
                alert.dispatched_at = alert.dispatched_at or timezone.now()
                alert.metadata = {**(alert.metadata or {}), "reviewed_by": request.user.username}
                alert.save(update_fields=["dispatch_status", "dispatched_at", "metadata"])
                messages.success(request, f"Alert {alert.id} marked reviewed.")
            else:
                messages.error(request, "Unknown action requested.")
        else:
            messages.error(request, "Alert not found.")

        return redirect("alert_review")

    alerts = AlertEvent.objects.all()[:50]
    pending_count = AlertEvent.objects.filter(dispatch_status="pending").count()
    sent_count = AlertEvent.objects.filter(dispatch_status="sent").count()
    reviewed_count = AlertEvent.objects.filter(dispatch_status="reviewed").count()
    return render(
        request,
        "alert_review.html",
        {
            "alerts": alerts,
            "pending_count": pending_count,
            "sent_count": sent_count,
            "reviewed_count": reviewed_count,
        },
    )


def attack_research_report_view(request: HttpRequest) -> JsonResponse:
    # Provide a limited decoy report to non-staff users, full report for staff
    if not _has_staff_access(request):
        # minimal decoy summary to avoid leaking internal details
        return fake_json_response(request, {"summary": "Research summary unavailable. Contact support."}, label="research/report", status_code=200)

    observations = list(HoneypotLog.objects.values("requested_url", "payload", "user_agent", "attack_classification")[:25])
    report = fake_attack_research_report(observations)
    return fake_json_response(request, report, label="research/report")


@user_passes_test(lambda user: user.is_staff)
def ioc_extraction_view(request: HttpRequest) -> JsonResponse:
    payload = request_payload_to_text(request)
    report = extract_fake_iocs(payload or request.get_full_path())
    return fake_json_response(request, report, label="research/ioc")


@user_passes_test(lambda user: user.is_staff)
def attack_cluster_view(request: HttpRequest) -> JsonResponse:
    report = fake_attack_research_report()
    return fake_json_response(request, {"clusters": report["clusters"], "classification": report["classification"]}, label="research/cluster")


@user_passes_test(lambda user: user.is_staff)
def mitre_mapping_view(request: HttpRequest) -> JsonResponse:
    report = fake_attack_research_report()
    return fake_json_response(request, {"mitre_attack": report["mitre_attack"], "classification": report["classification"]}, label="research/mitre")


@user_passes_test(lambda user: user.is_staff)
def research_analytics(request: HttpRequest) -> HttpResponse:
    logs = HoneypotLog.objects.all()
    selected_interval = request.GET.get("interval", "hour")
    if selected_interval not in {"minute", "hour", "day"}:
        selected_interval = "hour"

    if selected_interval == "minute":
        trunc_function = TruncMinute("timestamp")
        timeline_format = "%Y-%m-%d %H:%M"
    elif selected_interval == "day":
        trunc_function = TruncDate("timestamp")
        timeline_format = "%Y-%m-%d"
    else:
        trunc_function = TruncHour("timestamp")
        timeline_format = "%Y-%m-%d %H:00"

    total_requests = logs.count()
    suspicious_requests = logs.filter(is_suspicious=True).count()
    login_attempts = LoginAttempt.objects.count()
    failed_logins = LoginAttempt.objects.filter(success=False).count()
    brute_force_count = logs.filter(attack_classification="BRUTE_FORCE_ATTACK").count()
    sqli_count = logs.filter(attack_classification="SQL_INJECTION_ATTEMPT").count()
    scanner_count = logs.filter(attack_classification="SCANNER_BOT_ACTIVITY").count()
    normal_count = logs.filter(attack_classification="NORMAL_TRAFFIC").count()

    top_ips = (
        logs.exclude(ip_address__isnull=True)
        .exclude(ip_address="")
        .values("ip_address")
        .annotate(total=Count("id"))
        .order_by("-total")[:10]
    )

    top_endpoints = logs.values("requested_url").annotate(total=Count("id")).order_by("-total")[:10]

    suspicious_reasons = (
        logs.filter(is_suspicious=True)
        .exclude(suspicion_reason="")
        .values("suspicion_reason")
        .annotate(total=Count("id"))
        .order_by("-total")[:8]
    )

    timeline_data = (
        logs.annotate(slot=trunc_function)
        .values("slot")
        .annotate(total=Count("id"), suspicious=Count("id", filter=Q(is_suspicious=True)))
        .order_by("slot")
    )

    category_data = (
        logs.values("attack_classification")
        .annotate(total=Count("id"))
        .order_by("-total")
    )

    daily_failures = (
        LoginAttempt.objects.filter(success=False)
        .annotate(day=TruncDate("timestamp"))
        .values("day")
        .annotate(total=Count("id"))
        .order_by("day")
    )

    daily_labels = [entry["day"].isoformat() for entry in daily_failures if entry["day"]]
    daily_values = [entry["total"] for entry in daily_failures]
    endpoint_labels = [entry["requested_url"][:45] for entry in top_endpoints]
    endpoint_values = [entry["total"] for entry in top_endpoints]
    timeline_labels = [entry["slot"].strftime(timeline_format) for entry in timeline_data if entry["slot"]]
    timeline_values = [entry["total"] for entry in timeline_data]
    suspicious_timeline_values = [entry["suspicious"] for entry in timeline_data]

    classification_display = {
        "BRUTE_FORCE_ATTACK": "Brute Force Attack",
        "SQL_INJECTION_ATTEMPT": "SQL Injection Attempt",
        "SCANNER_BOT_ACTIVITY": "Scanner/Bot Activity",
        "NORMAL_TRAFFIC": "Normal Traffic",
    }
    category_labels = [classification_display.get(entry["attack_classification"], entry["attack_classification"]) for entry in category_data]
    category_values = [entry["total"] for entry in category_data]

    latest_alerts = AlertEvent.objects.values("timestamp", "alert_type", "detail")[:8]
    latest_uploads = UploadArtifact.objects.values("timestamp", "filename", "verdict", "entropy")[:8]
    latest_payments = PaymentRecord.objects.values("timestamp", "payment_id", "status", "amount", "currency")[:8]
    latest_tickets = SupportTicket.objects.values("timestamp", "ticket_id", "status", "priority")[:8]
    latest_sessions = TelemetryEvent.objects.values("timestamp", "session_id", "event_type", "path")[:12]
    top_countries = (
        ThreatIntelSnapshot.objects.exclude(country="")
        .values("country")
        .annotate(total=Count("id"))
        .order_by("-total")[:8]
    )

    context = {
        "total_requests": total_requests,
        "suspicious_requests": suspicious_requests,
        "login_attempts": login_attempts,
        "failed_logins": failed_logins,
        "selected_interval": selected_interval,
        "suspicious_rate": round((suspicious_requests / total_requests) * 100, 2) if total_requests else 0,
        "brute_force_count": brute_force_count,
        "sqli_count": sqli_count,
        "scanner_count": scanner_count,
        "normal_count": normal_count,
        "top_ips": top_ips,
        "top_endpoints": top_endpoints,
        "suspicious_reasons": suspicious_reasons,
        "daily_labels": daily_labels,
        "daily_values": daily_values,
        "endpoint_labels": endpoint_labels,
        "endpoint_values": endpoint_values,
        "timeline_labels": timeline_labels,
        "timeline_values": timeline_values,
        "suspicious_timeline_values": suspicious_timeline_values,
        "category_labels": category_labels,
        "category_values": category_values,
        "latest_alerts": latest_alerts,
        "latest_uploads": latest_uploads,
        "latest_payments": latest_payments,
        "latest_tickets": latest_tickets,
        "latest_sessions": latest_sessions,
        "top_countries": top_countries,
    }
    return render(request, "research_analytics.html", context)


def _timeline_attack_match(selected_attack_type: str, entry: dict[str, str]) -> bool:
    if not selected_attack_type or selected_attack_type == "all":
        return True

    haystack = " ".join(
        str(value) for value in [entry.get("kind"), entry.get("label"), entry.get("detail"), entry.get("attack_type"), entry.get("response"), entry.get("source")] if value
    ).lower()
    normalized = selected_attack_type.lower().strip()
    aliases = {
        "sqli": ["sql", "injection"],
        "sql_injection": ["sql", "injection"],
        "scanner": ["scanner", "bot"],
        "bot": ["scanner", "bot"],
        "brute_force": ["brute", "login"],
        "login": ["login"],
        "alert": ["alert"],
        "telemetry": ["telemetry", "fingerprint"],
        "page_visit": ["page", "visit", "request"],
        "journey": ["journey", "session"],
    }
    terms = aliases.get(normalized, [normalized])
    return any(term in haystack for term in terms)


@user_passes_test(lambda user: user.is_staff)
def attacker_timeline_view(request: HttpRequest) -> HttpResponse:
    selected_ip = request.GET.get("ip", "").strip()
    selected_session = request.GET.get("session", "").strip()
    selected_attack_type = request.GET.get("attack_type", "all").strip() or "all"
    limit = max(25, min(int(request.GET.get("limit", 160) or 160), 400))

    events: list[dict[str, object]] = []

    def add_event(*, timestamp, kind: str, label: str, detail: str, ip_address: str = "", user_agent: str = "", attack_type: str = "", response: str = "", payload: str = "", source: str = "", session_id_value: str = "") -> None:
        session_id = session_id_value or derive_session_id(ip_address=ip_address or "", user_agent=user_agent or "")
        entry = {
            "timestamp": timestamp,
            "kind": kind,
            "label": label,
            "detail": detail,
            "ip_address": ip_address,
            "session_id": session_id,
            "attack_type": attack_type,
            "response": response,
            "payload": payload,
            "source": source,
        }
        if selected_ip and entry["ip_address"] != selected_ip:
            return
        if selected_session and selected_session not in {entry["session_id"], session_id_value}:
            return
        if not _timeline_attack_match(selected_attack_type, entry):
            return
        events.append(entry)

    for item in HoneypotLog.objects.all().order_by("-timestamp")[:limit]:
        add_event(
            timestamp=item.timestamp,
            kind="page_visit",
            label=item.event_type,
            detail=item.requested_url,
            ip_address=item.ip_address or "",
            user_agent=item.user_agent,
            attack_type=item.attack_classification,
            response=str(item.status_code),
            payload=(item.payload[:180] + "…") if item.payload and len(item.payload) > 180 else item.payload,
            source="web",
        )

    for item in LoginAttempt.objects.all().order_by("-timestamp")[:limit]:
        add_event(
            timestamp=item.timestamp,
            kind="login_attempt",
            label=item.username or "anonymous",
            detail=item.requested_url or "/login",
            ip_address=item.ip_address or "",
            user_agent=item.user_agent,
            attack_type="brute_force" if not item.success else "login",
            response="success" if item.success else "failed",
            payload=(item.password_submitted[:24] + "…") if item.password_submitted else "",
            source="auth",
        )

    for item in AlertEvent.objects.all().order_by("-timestamp")[:limit]:
        metadata = item.metadata or {}
        add_event(
            timestamp=item.timestamp,
            kind="alert",
            label=item.alert_type,
            detail=item.detail,
            ip_address=item.ip_address or "",
            user_agent=item.user_agent,
            attack_type=str(metadata.get("source", item.alert_type)).lower(),
            response=item.dispatch_status,
            payload=json.dumps(metadata)[:240],
            source="alert-worker",
        )

    for item in TelemetryEvent.objects.all().order_by("-timestamp")[:limit]:
        add_event(
            timestamp=item.timestamp,
            kind="telemetry",
            label=item.event_type,
            detail=item.path,
            ip_address=item.ip_address or "",
            user_agent=item.user_agent,
            attack_type="telemetry",
            response="observed",
            payload=json.dumps(item.details)[:240],
            source="browser",
            session_id_value=item.session_id,
        )

    for item in AttackJourney.objects.all().order_by("-last_seen")[:limit]:
        add_event(
            timestamp=item.last_seen,
            kind="journey",
            label=item.session_id,
            detail=item.entry_point or "Unknown entry point",
            attack_type="journey",
            response=f"{len(item.recon_path or [])} recon steps",
            payload=json.dumps({"tools": item.tools_used, "notes": item.notes})[:240],
            source="journey",
            session_id_value=item.session_id,
        )

    events.sort(key=lambda entry: entry["timestamp"] or timezone.now())
    story_events = events[-80:]
    story_summary = {
        "total": len(story_events),
        "pages": sum(1 for entry in story_events if entry["kind"] == "page_visit"),
        "logins": sum(1 for entry in story_events if entry["kind"] == "login_attempt"),
        "alerts": sum(1 for entry in story_events if entry["kind"] == "alert"),
        "telemetry": sum(1 for entry in story_events if entry["kind"] == "telemetry"),
        "journeys": sum(1 for entry in story_events if entry["kind"] == "journey"),
    }
    selected_story = story_events[-1] if story_events else None

    top_sessions = {}
    for entry in story_events:
        top_sessions.setdefault(entry["session_id"], 0)
        top_sessions[entry["session_id"]] += 1

    session_options = [
        {"session_id": session_id, "total": total}
        for session_id, total in sorted(top_sessions.items(), key=lambda item: item[1], reverse=True)[:12]
    ]

    return render(
        request,
        "attacker_timeline.html",
        {
            "events": story_events,
            "story_summary": story_summary,
            "selected_ip": selected_ip,
            "selected_session": selected_session,
            "selected_attack_type": selected_attack_type,
            "session_options": session_options,
            "selected_story": selected_story,
            "attack_type_choices": [
                ("all", "All Events"),
                ("page_visit", "Page Visits"),
                ("login", "Login Attempts"),
                ("alert", "Alerts"),
                ("telemetry", "Telemetry"),
                ("journey", "Journey Records"),
                ("brute_force", "Brute Force"),
                ("sqli", "SQL Injection"),
                ("scanner", "Scanner / Bot"),
                ("canary_hit", "Canary Hits"),
            ],
            "limit_choices": [80, 120, 160, 240, 320],
        },
    )


@user_passes_test(lambda user: user.is_staff)
def attacker_timeline_json(request: HttpRequest) -> JsonResponse:
    """Return timeline events as JSON for UI replay controls."""
    selected_ip = request.GET.get("ip", "").strip()
    selected_session = request.GET.get("session", "").strip()
    limit = max(25, min(int(request.GET.get("limit", 160) or 160), 1000))

    events: list[dict[str, object]] = []

    def add_event(*, timestamp, kind: str, label: str, detail: str, ip_address: str = "", user_agent: str = "", attack_type: str = "", response: str = "", payload: str = "", source: str = "", session_id_value: str = "") -> None:
        session_id = session_id_value or derive_session_id(ip_address=ip_address or "", user_agent=user_agent or "")
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
        }
        if selected_ip and entry["ip_address"] != selected_ip:
            return
        if selected_session and selected_session not in {entry["session_id"], session_id_value}:
            return
        events.append(entry)

    for item in HoneypotLog.objects.all().order_by("-timestamp")[:limit]:
        add_event(
            timestamp=item.timestamp,
            kind="page_visit",
            label=item.event_type,
            detail=item.requested_url,
            ip_address=item.ip_address or "",
            user_agent=item.user_agent,
            attack_type=item.attack_classification,
            response=str(item.status_code),
            payload=(item.payload[:400] + "…") if item.payload and len(item.payload) > 400 else item.payload,
            source="web",
        )

    for item in LoginAttempt.objects.all().order_by("-timestamp")[:limit]:
        add_event(
            timestamp=item.timestamp,
            kind="login_attempt",
            label=item.username or "anonymous",
            detail=item.requested_url or "/login",
            ip_address=item.ip_address or "",
            user_agent=item.user_agent,
            attack_type="brute_force" if not item.success else "login",
            response="success" if item.success else "failed",
            payload=(item.password_submitted[:64] + "…") if item.password_submitted else "",
            source="auth",
        )

    for item in AlertEvent.objects.all().order_by("-timestamp")[:limit]:
        metadata = item.metadata or {}
        add_event(
            timestamp=item.timestamp,
            kind="alert",
            label=item.alert_type,
            detail=item.detail,
            ip_address=item.ip_address or "",
            user_agent=item.user_agent,
            attack_type=str(metadata.get("source", item.alert_type)).lower(),
            response=item.dispatch_status,
            payload=json.dumps(metadata)[:400],
            source="alert-worker",
        )

    for item in TelemetryEvent.objects.all().order_by("-timestamp")[:limit]:
        add_event(
            timestamp=item.timestamp,
            kind="telemetry",
            label=item.event_type,
            detail=item.path,
            ip_address=item.ip_address or "",
            user_agent=item.user_agent,
            attack_type="telemetry",
            response="observed",
            payload=json.dumps(item.details)[:400],
            source="browser",
            session_id_value=item.session_id,
        )

    for item in AttackJourney.objects.all().order_by("-last_seen")[:limit]:
        add_event(
            timestamp=item.last_seen,
            kind="journey",
            label=item.session_id,
            detail=item.entry_point or "Unknown entry point",
            attack_type="journey",
            response=f"{len(item.recon_path or [])} recon steps",
            payload=json.dumps({"tools": item.tools_used, "notes": item.notes})[:400],
            source="journey",
            session_id_value=item.session_id,
        )

    events.sort(key=lambda e: e["timestamp"])  # chronological
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
