from __future__ import annotations

import csv
import io
import json
import logging
import os
import hashlib
import random
import string
import textwrap
from typing import Any

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils import timezone
from . import fake_registry
from .utils import SQLI_PATTERN, PROBING_PATH_PATTERN, COMMAND_PATTERN, SCANNER_PATTERN
from django.conf import settings

from .models import AlertEvent, AttackJourney, NoiseEvent, PaymentRecord, SupportTicket, TelemetryEvent, ThreatIntelSnapshot, UploadArtifact
from .utils import derive_session_id, emit_structured_event, get_client_ip, log_event, request_payload_to_text

EVENT_LOGGER = logging.getLogger("honeytrap.events")


FAKE_FILE_CONTENTS: dict[str, str] = {
    ".env": textwrap.dedent(
        """
        APP_ENV=production
        APP_DEBUG=false
        DB_HOST=127.0.0.1
        DB_PORT=5432
        DB_NAME=honey_prod
        DB_USER=honey_readonly
        DB_PASSWORD=Honey!ReadOnly_2026
        STRIPE_SECRET_KEY=stripe_secret_key_redacted_demo_value
        STRIPE_WEBHOOK_SECRET=whsec_fake_honeytrap_2026
        AWS_ACCESS_KEY_ID=AKIAFAKEHONEYTRAP0000
        AWS_SECRET_ACCESS_KEY=QmFzZTY0RmFrZVNlY3JldEhvbmV5VHJhcA==
        INTERNAL_API_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake.honeytrap
        """
    ).strip(),
    "config.php": textwrap.dedent(
        """
        <?php
        return [
            'app_name' => 'Honey Haven Admin',
            'db_host' => '127.0.0.1',
            'db_name' => 'honey_prod',
            'feature_flags' => ['analytics' => true, 'exports' => true],
        ];
                # compute sequence-based phases with confidences
                seq_phases = _sequence_detect_phases(all_events)
                # store ordered phases and a short narrative
                journey.first_seen = journey.first_seen or first_seen
                journey.last_seen = last_seen
                journey.seconds_spent = seconds_spent
                journey.event_count = len(all_events)
                journey.ips = ips
                journey.user_agents = uas
                journey.phases = seq_phases
                # build a short narrative summary
                try:
                    top_phases = ", ".join([f"{p['phase']}({int(p['confidence']*100)}%)" for p in seq_phases[:3]])
                    journey.notes = f"Detected phases: {top_phases}. Events: {len(all_events)}. Duration: {seconds_spent}s."
                except Exception:
                    journey.notes = journey.notes or ""
            <table>
              <tr><td>Server API</td><td>FPM/FastCGI</td></tr>
              <tr><td>Loaded Configuration File</td><td>/etc/php/8.2/fpm/php.ini</td></tr>
              <tr><td>Document Root</td><td>/var/www/html</td></tr>
            </table>
          </body>
        </html>
        """
    ).strip(),
    "backup.sql": textwrap.dedent(
        """
        -- MySQL dump 10.13  Distrib 8.0.36
        -- Host: localhost    Database: honey_prod
        CREATE TABLE users (id int, username varchar(64), password varchar(255));
        INSERT INTO users VALUES (1,'admin','$2y$10$fakehash');
        INSERT INTO users VALUES (2,'ops','password123');
        INSERT INTO api_keys VALUES (1,'stripe_live_fake','stripe_secret_key_redacted_demo_value');
        """
    ).strip(),
    "backup.bak": "FAKE BACKUP ARCHIVE - RESTORE USING INTERNAL TOOL ONLY\n",
    "backup.zip": "PK\x03\x04 honeyhaven_fake_backup.zip contains customers.csv and invoices.csv\n",
    "employee.csv": textwrap.dedent(
        """
        employee_id,name,email,department,manager,notes
        101,Ada Ellis,ada.ellis@honeyhaven.local,Finance,Marcus Bell,Pending travel reimbursement
        102,Noah Patel,noah.patel@honeyhaven.local,Operations,Marcus Bell,Access to invoicing portal
        103,Maya Chen,maya.chen@honeyhaven.local,Customer Support,Leah Moss,Handles escalations
        """
    ).strip(),
    ".git/HEAD": "ref: refs/heads/main\n",
    ".git/config": textwrap.dedent(
        """
        [core]
            repositoryformatversion = 0
            filemode = true
            bare = false
        [remote "origin"]
            url = git@internal.example.local:honeyhaven/site.git
        """
    ).strip(),
}


FAKE_PANEL_CATALOG: dict[str, dict[str, Any]] = {
    "wp-admin": {
        "title": "WordPress Admin",
        "subtitle": "Content management and plugin maintenance",
        "status": "Locked pending SSO",
        "metrics": [
            {"label": "Pending plugin updates", "value": "12"},
            {"label": "Editorial drafts", "value": "27"},
            {"label": "Failed logins (24h)", "value": "84"},
        ],
        "notes": ["Two-factor reset requested", "Backup scheduled at 02:30 UTC"],
    },
    "cpanel": {
        "title": "cPanel Hosting Center",
        "subtitle": "Domain, mail, and backup administration",
        "status": "Support session required",
        "metrics": [
            {"label": "Mailboxes", "value": "118"},
            {"label": "Scheduled backups", "value": "9"},
            {"label": "Resource warnings", "value": "3"},
        ],
        "notes": ["Quota nearing limit", "DNS change pending approval"],
    },
    "phpmyadmin": {
        "title": "phpMyAdmin",
        "subtitle": "Database access console",
        "status": "Read-only mode active",
        "metrics": [
            {"label": "Databases", "value": "6"},
            {"label": "Slow queries", "value": "14"},
            {"label": "Dump jobs", "value": "2"},
        ],
        "notes": ["Replication lag detected", "Export history preserved for 90 days"],
    },
    "grafana": {
        "title": "Grafana",
        "subtitle": "Service observability dashboard",
        "status": "Live metrics streaming",
        "metrics": [
            {"label": "CPU alerts", "value": "7"},
            {"label": "Active dashboards", "value": "24"},
            {"label": "SLO breaches", "value": "1"},
        ],
        "notes": ["Red line on auth latency", "Tracing enabled for high risk hosts"],
    },
    "jenkins": {
        "title": "Jenkins",
        "subtitle": "Build and deployment orchestration",
        "status": "Pipeline paused",
        "metrics": [
            {"label": "Queued builds", "value": "5"},
            {"label": "Credential stores", "value": "11"},
            {"label": "Failed jobs", "value": "2"},
        ],
        "notes": ["Webhook token rotated", "Release candidate blocked by QA"],
    },
    "dashboard": {
        "title": "Executive Dashboard",
        "subtitle": "Internal KPIs and operational summaries",
        "status": "Stale cache refreshed 2m ago",
        "metrics": [
            {"label": "Monthly orders", "value": "$482k"},
            {"label": "Refund rate", "value": "0.8%"},
            {"label": "VIP customers", "value": "146"},
        ],
        "notes": ["Marketing campaign review scheduled", "Abandoned cart cohort rising"],
    },
    "cms": {
        "title": "CMS Control Room",
        "subtitle": "Pages, assets, and editorial workflows",
        "status": "Authoring mode",
        "metrics": [
            {"label": "Published pages", "value": "73"},
            {"label": "Media assets", "value": "3,281"},
            {"label": "Draft reviews", "value": "8"},
        ],
        "notes": ["One article flagged for sensitive wording", "Asset cache warm"],
    },
    "portal": {
        "title": "Internal Portal",
        "subtitle": "Employee self-service and approvals",
        "status": "Identity verified",
        "metrics": [
            {"label": "Open tickets", "value": "21"},
            {"label": "HR approvals", "value": "4"},
            {"label": "Policy acknowledgements", "value": "91%"},
        ],
        "notes": ["Travel reimbursement queue growing", "Remote access policy updated"],
    },
    "internal": {
        "title": "Internal Operations",
        "subtitle": "Restricted staff-only systems",
        "status": "Multi-factor challenge required",
        "metrics": [
            {"label": "Support tickets", "value": "37"},
            {"label": "Warehouse sync errors", "value": "2"},
            {"label": "Admin sessions", "value": "15"},
        ],
        "notes": ["Invoice export delayed", "Customer record audit complete"],
    },
}


FAKE_API_USERS = [
    {"id": 1, "username": "admin", "role": "administrator", "status": "active"},
    {"id": 2, "username": "linda", "role": "support", "status": "active"},
    {"id": 3, "username": "marco", "role": "finance", "status": "locked"},
]

FAKE_API_ORDERS = [
    {"order_id": "ORD-10421", "status": "pending", "total": 186.2, "currency": "USD"},
    {"order_id": "ORD-10422", "status": "paid", "total": 74.9, "currency": "USD"},
    {"order_id": "ORD-10423", "status": "refunded", "total": 23.0, "currency": "USD"},
]


FAKE_COMMAND_OUTPUTS = {
    "whoami": "www-data\n",
    "uname -a": "Linux honeyhaven 6.1.0-27-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.116-1 (2025-11-10) x86_64 GNU/Linux\n",
    "pwd": "/var/www/html\n",
    "ls": "app\nstatic\ntemplates\nmedia\nlogs\n",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
    "ifconfig": "eth0: inet 10.12.4.18  netmask 255.255.255.0  broadcast 10.12.4.255\n",
    "netstat": "tcp        0      0 0.0.0.0:22         0.0.0.0:*         LISTEN\n",
}

FAKE_ORG_PROFILE = {
    "name": "Honey Haven Retail Group",
    "backend": "honey-core",
    "region": "eu-west-2",
    "release_track": "stable-2026.05",
    "surfaces": ["merchant-admin", "api-gateway", "cms", "ops-portal"],
}

FAKE_PERSONAS = [
    {"name": "Ava Stone", "role": "operations", "team": "storefront"},
    {"name": "Noah Patel", "role": "finance", "team": "billing"},
    {"name": "Maya Chen", "role": "support", "team": "customer-success"},
    {"name": "Leah Moss", "role": "platform", "team": "site-reliability"},
]


_PUBLIC_DECOY_SEED = int(
    hashlib.sha256(f"{FAKE_ORG_PROFILE['name']}|{FAKE_ORG_PROFILE['release_track']}".encode("utf-8")).hexdigest()[:16],
    16,
)
_PUBLIC_DECOY_RNG = random.Random(_PUBLIC_DECOY_SEED)
_PUBLIC_DECOY_PERSONA = FAKE_PERSONAS[_PUBLIC_DECOY_SEED % len(FAKE_PERSONAS)]
_PUBLIC_DECOY_BACKEND = ["nginx", "apache", "gunicorn", "php-fpm"][_PUBLIC_DECOY_SEED % 4]
_PUBLIC_DECOY_CLUSTER = f"cluster-{(_PUBLIC_DECOY_SEED % 4) + 1}"
_PUBLIC_DECOY_SESSION = f"{_PUBLIC_DECOY_SEED % 10**16:016d}"


def _short_delay() -> None:
    import time

    time.sleep(random.uniform(0.08, 0.28))


def _stable_seed(*parts: Any) -> int:
    raw = "::".join(str(part) for part in parts if part is not None)
    digest = hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()
    return int(digest[:16], 16)


def build_fake_runtime_profile(request: HttpRequest, surface: str) -> dict[str, Any]:
    """Build a stable decoy profile for the current visitor.

    The profile is keyed to the request fingerprint only, not the individual surface,
    so that live feed / API docs / research report share the same backend, cluster,
    and persona for a given visitor session.
    """
    identity = derive_session_id(
        ip_address=get_client_ip(request),
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
        accept_language=request.META.get("HTTP_ACCEPT_LANGUAGE", "")[:200],
        cookie_seed=request.COOKIES.get("sessionid", "")[:80],
        path="",
    )

    cached = getattr(request, "_honeytrap_runtime_profile", None)
    if isinstance(cached, dict) and cached.get("identity") == identity:
        cached.setdefault("surface", surface)
        return cached

    # Keep the public decoy fabric stable across all public surfaces.
    # Request fingerprint only affects per-request identifiers and timing.
    seed = _stable_seed(
        identity,
        request.META.get("HTTP_USER_AGENT", "")[:1000],
        request.META.get("HTTP_ACCEPT_LANGUAGE", "")[:200],
    )
    rng = random.Random(seed)
    persona = _PUBLIC_DECOY_PERSONA
    delay_seconds = rng.uniform(0.05, 0.22)
    if rng.random() < 0.12:
        delay_seconds += rng.uniform(0.25, 0.85)

    profile = {
        "identity": identity,
        "request_id": f"req-{seed % 10**10:010d}",
        "session_cookie": f"sess-{identity[:16]}",
        "persona": persona,
        "cluster": _PUBLIC_DECOY_CLUSTER,
        "backend": _PUBLIC_DECOY_BACKEND,
        "release_track": FAKE_ORG_PROFILE["release_track"],
        "delay_seconds": round(delay_seconds, 3),
        "surface": surface,
        "org_name": FAKE_ORG_PROFILE["name"],
        "region": FAKE_ORG_PROFILE["region"],
        "public_session": _PUBLIC_DECOY_SESSION,
    }
    setattr(request, "_honeytrap_runtime_profile", profile)
    return profile


def _apply_decoy_timing(profile: dict[str, Any]) -> None:
    import time

    time.sleep(profile.get("delay_seconds", 0.1))


def _maybe_inject_error(profile: dict[str, Any], label: str | None = None) -> dict[str, Any] | None:
    """Return an error dict {status, body, message} or None. Small probabilities based on backend and random seed."""
    import random

    backend = profile.get("backend", "nginx")
    # base probabilities
    p_502 = 0.02
    p_504 = 0.01
    p_429 = 0.01

    if backend in ("php-fpm", "apache"):
        p_502 += 0.02
        p_504 += 0.01

    # lower chance for staff-facing surfaces (detect via label)
    if label and str(label).lower().startswith("panel"):
        p_502 *= 0.2

    r = random.random()
    if r < p_502:
        return {"status": 502, "body": "502 Bad Gateway\nUpstream server error.", "message": "Bad Gateway"}
    if r < p_502 + p_504:
        return {"status": 504, "body": "504 Gateway Timeout\nUpstream timed out.", "message": "Gateway Timeout"}
    if r < p_502 + p_504 + p_429:
        return {"status": 429, "body": "429 Too Many Requests\nSlow down.", "message": "Too Many Requests"}
    return None


def _decorate_json_payload(payload: Any, profile: dict[str, Any]) -> Any:
    if not isinstance(payload, dict):
        return payload
    data = dict(payload)
    data.setdefault(
        "meta",
        {
            "organization": profile["org_name"],
            "backend": profile["backend"],
            "release_track": profile["release_track"],
            "cluster": profile["cluster"],
            "session_id": profile.get("public_session", profile["identity"]),
        },
    )
    return data


def decoy_headers(response: HttpResponse, label: str, profile: dict[str, Any] | None = None) -> HttpResponse:
    profile = profile or {
        "request_id": f"req-{random.randint(1000000000, 9999999999)}",
        "session_cookie": f"sess-{random.randint(10000000, 99999999)}",
        "persona": random.choice(FAKE_PERSONAS),
        "cluster": "cluster-1",
        "backend": "nginx",
        "release_track": FAKE_ORG_PROFILE["release_track"],
        "identity": f"session-{random.randint(10000000, 99999999)}",
        "org_name": FAKE_ORG_PROFILE["name"],
        "region": FAKE_ORG_PROFILE["region"],
    }
    response["Cache-Control"] = "no-store, max-age=0"
    response["Pragma"] = "no-cache"
    response["X-Content-Type-Options"] = "nosniff"
    response["X-Frame-Options"] = "SAMEORIGIN"
    response["X-Powered-By"] = "PHP/8.2.12" if label in {"phpinfo", "phpmyadmin", "wp-admin", "cpanel"} else profile["backend"].title()
    response["X-Honeypot-Org"] = profile["org_name"]
    response["X-Honeypot-Session"] = profile.get("public_session", profile["identity"])
    response["X-Honeypot-Cluster"] = profile["cluster"]
    response["X-Request-ID"] = profile["request_id"]
    response["Set-Cookie"] = f"sessionid={profile['session_cookie']}; Path=/; HttpOnly; SameSite=Lax"
    return response


def log_decoy_access(
    request: HttpRequest,
    *,
    event_type: str,
    payload: str = "",
    username: str = "",
    status_code: int = 200,
    suspicion_reason: str = "Decoy surface interaction",
) -> None:
    emit_structured_event(
        "decoy_access",
        event_type=event_type,
        ip_address=get_client_ip(request),
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
        requested_url=request.get_full_path()[:1000],
        payload=payload[:4000],
        username=username[:150],
        status_code=status_code,
        suspicion_reason=suspicion_reason,
    )
    log_event(
        request,
        event_type=event_type,
        payload=payload,
        username=username,
        is_suspicious=True,
        suspicion_reason=suspicion_reason,
        status_code=status_code,
    )

    if event_type in {"SUSPICIOUS", "ADMIN_ACCESS"}:
        enqueue_alert_event(
            request,
            alert_type=event_type,
            detail=suspicion_reason,
            channels={
                "discord": os.environ.get("HONEYPOT_DISCORD_WEBHOOK_URL", "").strip(),
                "telegram": os.environ.get("HONEYPOT_TELEGRAM_WEBHOOK_URL", "").strip(),
                "email": os.environ.get("HONEYPOT_ALERT_EMAIL", "").strip(),
            },
        )


def fake_panel_context(panel_key: str) -> dict[str, Any]:
    base = FAKE_PANEL_CATALOG.get(panel_key, {})
    recent_items = [
        {"label": "Last admin access", "value": "2 minutes ago"},
        {"label": "Export queue", "value": "4 pending"},
        {"label": "Suspicious logins", "value": "11 today"},
    ]
    return {
        "panel_key": panel_key,
        "panel_title": base.get("title", panel_key.title()),
        "panel_subtitle": base.get("subtitle", "Restricted internal surface"),
        "panel_status": base.get("status", "Access restricted"),
        "metrics": base.get("metrics", []),
        "notes": base.get("notes", []),
        "recent_items": recent_items,
    }


def build_fake_system_state(request: HttpRequest, surface: str) -> dict[str, Any]:
    profile = build_fake_runtime_profile(request, surface)
    return {
        **profile,
        "org": FAKE_ORG_PROFILE,
        "persona_name": profile["persona"]["name"],
        "persona_role": profile["persona"]["role"],
        "persona_team": profile["persona"]["team"],
    }


def fake_file_response(request: HttpRequest, artifact: str) -> HttpResponse:
    profile = build_fake_runtime_profile(request, f"file:{artifact}")
    _apply_decoy_timing(profile)
    # small chance to simulate upstream gateway errors for realism
    err = _maybe_inject_error(profile, artifact)
    if err is not None:
        return decoy_headers(HttpResponse(err["body"], status=err["status"], content_type="text/plain; charset=utf-8"), artifact, profile)
    body = FAKE_FILE_CONTENTS.get(artifact, f"404 Not Found: {artifact}\n")
    content_type = "text/plain; charset=utf-8"
    if artifact.endswith(".php"):
        content_type = "text/html; charset=utf-8"
    elif artifact.endswith(".csv"):
        content_type = "text/csv; charset=utf-8"
    elif artifact.endswith(".zip"):
        content_type = "application/zip"

    response_body = body.encode("utf-8") if content_type == "application/zip" else body
    response = HttpResponse(response_body, content_type=content_type, status=200)
    response["Content-Disposition"] = f'attachment; filename="{artifact.split("/")[-1]}"'
    log_decoy_access(
        request,
        event_type="SUSPICIOUS",
        payload=request_payload_to_text(request),
        status_code=200,
        suspicion_reason=f"Requested exposed file artifact: {artifact}",
    )
    return decoy_headers(response, artifact, profile)


def fake_panel_response(request: HttpRequest, panel_key: str) -> HttpResponse:
    profile = build_fake_runtime_profile(request, f"panel:{panel_key}")
    _apply_decoy_timing(profile)
    err = _maybe_inject_error(profile, panel_key)
    if err is not None:
        return decoy_headers(HttpResponse(err["body"], status=err["status"], content_type="text/html; charset=utf-8"), panel_key, profile)
    context = fake_panel_context(panel_key)
    from django.shortcuts import render

    context.update(build_fake_system_state(request, f"panel:{panel_key}"))
    response = render(request, "fake_panel.html", context)
    log_decoy_access(
        request,
        event_type="ADMIN_ACCESS",
        payload=request_payload_to_text(request),
        status_code=200,
        suspicion_reason=f"Accessed decoy panel: {panel_key}",
    )
    return decoy_headers(response, panel_key, profile)


def fake_json_response(request: HttpRequest, payload: dict[str, Any], *, label: str, status_code: int = 200) -> JsonResponse:
    profile = build_fake_runtime_profile(request, f"json:{label}")
    _apply_decoy_timing(profile)
    # probabilistically inject transient errors for non-staff surfaces
    err = _maybe_inject_error(profile, label)
    if err is not None:
        response = JsonResponse({"error": err.get("message", "Upstream error")}, status=err["status"])
    else:
        response = JsonResponse(_decorate_json_payload(payload, profile), status=status_code)
    log_decoy_access(
        request,
        event_type="API_HIT",
        payload=request_payload_to_text(request),
        status_code=status_code,
        suspicion_reason=f"Accessed decoy API: {label}",
    )
    return decoy_headers(response, label, profile)


def fake_command_output(command: str) -> dict[str, Any]:
    normalized = command.strip().lower()
    stdout = FAKE_COMMAND_OUTPUTS.get(normalized)
    if stdout is None:
        stdout = f"bash: {command}: command not found\n"
        exit_code = 127
    else:
        exit_code = 0
    return {"command": command, "stdout": stdout, "stderr": "", "exit_code": exit_code, "timestamp": timezone.now().isoformat()}


def fake_graphql_response(query_text: str) -> dict[str, Any]:
    lowered = query_text.lower()
    if "__schema" in lowered:
        return {"errors": [{"message": "Introspection is disabled on this environment"}]}
    if "users" in lowered:
        return {"data": {"users": FAKE_API_USERS}}
    if "orders" in lowered:
        return {"data": {"orders": FAKE_API_ORDERS}}
    return {"errors": [{"message": "Unknown field on type Query"}]}


def fake_export_csv(export_type: str) -> tuple[str, str]:
    buffer = io.StringIO()
    writer = csv.writer(buffer)

    if export_type == "invoices":
        rows = [
            ["invoice_id", "customer", "amount", "status"],
            ["INV-3301", "Ada Ellis", "128.00", "paid"],
            ["INV-3302", "Noah Patel", "42.50", "open"],
        ]
        filename = "invoice_export.csv"
    elif export_type == "payments":
        rows = [
            ["payment_id", "card_last4", "amount", "status"],
            ["PAY-901", "4242", "128.00", "captured"],
            ["PAY-902", "1111", "42.50", "reversed"],
        ]
        filename = "payment_export.csv"
    else:
        rows = [
            ["user_id", "name", "email", "role"],
            ["1", "Ada Ellis", "ada.ellis@honeyhaven.local", "finance"],
            ["2", "Noah Patel", "noah.patel@honeyhaven.local", "support"],
        ]
        filename = "customer_export.csv"

    for row in rows:
        writer.writerow(row)

    return buffer.getvalue(), filename


def emit_external_alerts(request: HttpRequest, *, alert_type: str, detail: str) -> None:
    candidate = {
        "alert_type": alert_type,
        "detail": detail,
        "ip_address": get_client_ip(request),
        "user_agent": request.META.get("HTTP_USER_AGENT", "")[:1000],
        "requested_url": request.get_full_path()[:1000],
    }
    payload = json.dumps(candidate).encode("utf-8")

    discord_webhook = os.environ.get("HONEYPOT_DISCORD_WEBHOOK_URL", "").strip()
    telegram_webhook = os.environ.get("HONEYPOT_TELEGRAM_WEBHOOK_URL", "").strip()
    alert_email = os.environ.get("HONEYPOT_ALERT_EMAIL", "").strip()

    def post_json(url: str, body: bytes) -> None:
        from urllib import request as urlrequest

        req = urlrequest.Request(url, data=body, headers={"Content-Type": "application/json"})
        urlrequest.urlopen(req, timeout=2)  # noqa: S310 - controlled optional outbound alerting

    deliver_alert_payload(candidate, payload, discord_webhook, telegram_webhook, alert_email, post_json)


def deliver_alert_payload(
    candidate: dict[str, Any],
    payload: bytes,
    discord_webhook: str,
    telegram_webhook: str,
    alert_email: str,
    post_json,
) -> None:
    try:
        if discord_webhook:
            post_json(discord_webhook, payload)
        if telegram_webhook:
            post_json(telegram_webhook, payload)
        if alert_email:
            from django.core.mail import send_mail
            from django.conf import settings

            send_mail(
                subject=f"Honey Haven alert: {candidate['alert_type']}",
                message=json.dumps(candidate, indent=2),
                from_email=getattr(settings, "DEFAULT_FROM_EMAIL", "alerts@honeyhaven.local"),
                recipient_list=[alert_email],
                fail_silently=True,
            )
    except Exception:
        pass


def enqueue_alert_event(request: HttpRequest, *, alert_type: str, detail: str, channels: dict[str, str]) -> AlertEvent:
    # deduplication / rate-limiting: avoid creating many identical alerts in short window
    ip = get_client_ip(request)
    session_id = derive_session_id(
        ip_address=ip or "",
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
        accept_language=request.META.get("HTTP_ACCEPT_LANGUAGE", "")[:200],
        cookie_seed=request.COOKIES.get("sessionid", "")[:80],
    )
    # Prefer centralized settings values (set in `honeytrap/settings.py`) so the
    # whole application uses a single source of truth. These are configurable
    # via environment variables described in settings.py.
    window_minutes = int(getattr(settings, "HONEYPOT_ALERT_DEDUP_WINDOW_MIN", 5))
    max_per_window = int(getattr(settings, "HONEYPOT_ALERT_MAX_PER_WINDOW", 10))

    cutoff = timezone.now() - timezone.timedelta(minutes=window_minutes)
    similar = (
        AlertEvent.objects.filter(alert_type=alert_type, detail=detail[:300], ip_address=ip, timestamp__gte=cutoff)
    )

    if similar.exists():
        # update existing alert rather than creating a new one
        existing = similar.order_by("-timestamp").first()
        meta = {**(existing.metadata or {}), "dedup_count": (existing.metadata or {}).get("dedup_count", 1) + 1}
        meta.setdefault("session_id", session_id)
        existing.metadata = meta
        existing.timestamp = timezone.now()
        existing.dispatch_status = "pending"
        existing.save(update_fields=["metadata", "timestamp", "dispatch_status"])
        emit_structured_event(
            "alert_queue",
            alert_type=alert_type,
            detail=detail[:300],
            ip_address=ip,
            requested_url=request.get_full_path()[:1000],
            dispatch_status="pending",
            deduped=True,
            session_id=session_id,
        )
        return existing

    # global rate check: count alerts in window
    recent_count = AlertEvent.objects.filter(timestamp__gte=cutoff).count()
    if recent_count >= max_per_window:
        # suppress creating new alerts to avoid flood; emit a noise_event instead
        NoiseEvent.objects.create(event_type="alert_suppressed", payload={"alert_type": alert_type, "detail": detail[:200], "ip": ip})
        emit_structured_event("alert_suppressed", alert_type=alert_type, detail=detail[:200], ip_address=ip, recent_count=recent_count)
        # return a pseudo-alert object by creating a suppressed AlertEvent with status suppressed
        suppressed = AlertEvent.objects.create(
            alert_type=alert_type,
            detail=(detail[:200] + " (suppressed)"),
            ip_address=ip,
            user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
            requested_url=request.get_full_path()[:1000],
            metadata={**channels, "suppressed": True, "session_id": session_id},
            dispatch_status="suppressed",
        )
        return suppressed

    event = AlertEvent.objects.create(
        alert_type=alert_type,
        detail=detail[:300],
        ip_address=ip,
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
        requested_url=request.get_full_path()[:1000],
        metadata={**channels, "session_id": session_id},
        dispatch_status="pending",
    )
    emit_structured_event(
        "alert_queue",
        alert_type=alert_type,
        detail=detail[:300],
        ip_address=ip,
        requested_url=request.get_full_path()[:1000],
        dispatch_status="pending",
        session_id=session_id,
    )
    return event


def fake_geoip_profile(ip_address: str) -> dict[str, Any]:
    seed = sum(ord(char) for char in ip_address if char.isdigit()) or 1
    countries = [
        ("United States", "US", "AS15169 Google LLC", "Google Cloud", False, False),
        ("Germany", "DE", "AS14061 DigitalOcean, LLC", "DigitalOcean", True, False),
        ("Singapore", "SG", "AS13335 Cloudflare, Inc.", "Cloudflare", False, False),
        ("Netherlands", "NL", "AS16276 OVH SAS", "OVHcloud", True, False),
        ("United Kingdom", "GB", "AS9009 M247 Europe SRL", "M247", False, True),
    ]
    country, code, asn, isp, vpn, tor = countries[seed % len(countries)]
    reputation = max(1, 95 - (seed % 53))
    cluster = f"cluster-{(seed % 7) + 1}"
    campaign = f"cmp-{(seed % 4) + 10}"
    profile = {
        "ip_address": ip_address,
        "country": country,
        "country_code": code,
        "asn": asn,
        "isp": isp,
        "hosting_provider": isp,
        "vpn": vpn,
        "tor": tor,
        "reputation_score": reputation,
        "cluster_id": cluster,
        "campaign_id": campaign,
    }
    ThreatIntelSnapshot.objects.create(**profile)
    emit_structured_event("threat_intel", **profile)
    return profile


def upload_trap_report(filename: str, payload: bytes, uploader_ip: str, user_agent: str) -> dict[str, Any]:
    digest = hashlib.sha256(payload).hexdigest()
    byte_counts = [payload.count(byte) for byte in set(payload)] or [1]
    entropy = 0.0
    total = len(payload) or 1
    for count in byte_counts:
        probability = count / total
        entropy -= probability * (0 if probability <= 0 else __import__("math").log2(probability))
    lowered = payload[:4000].decode("utf-8", errors="ignore").lower()
    verdict = "clean"
    if any(marker in lowered for marker in ["webshell", "eval(", "base64_decode", "cmd=", "system(", "passthru("]):
        verdict = "webshell-suspected"
    elif entropy > 6.5:
        verdict = "high-entropy"
    elif filename.lower().endswith((".php", ".phtml", ".aspx", ".jsp")):
        verdict = "suspicious-upload"

    UploadArtifact.objects.create(
        filename=filename[:255],
        sha256=digest,
        entropy=round(entropy, 4),
        verdict=verdict,
        uploader_ip=uploader_ip,
        user_agent=user_agent[:1000],
        metadata={"size": len(payload)},
    )
    emit_structured_event(
        "upload_trap",
        filename=filename,
        sha256=digest,
        entropy=round(entropy, 4),
        verdict=verdict,
        uploader_ip=uploader_ip,
        user_agent=user_agent[:1000],
        size=len(payload),
    )
    return {"filename": filename, "sha256": digest, "entropy": round(entropy, 4), "verdict": verdict}


def fake_payment_payload(reference: str | None = None) -> dict[str, Any]:
    # Use centralized fake registry to ensure consistency across surfaces
    if reference:
        order_ref = reference
    else:
        order_ref = None
    # pick a persona by session-like key if available
    persona = None
    try:
        persona = fake_registry.persona_for_session(reference or "payment")
    except Exception:
        persona = None
    order = fake_registry.order_for_persona(persona or {"username": "anon"}, order_ref)
    payment = fake_registry.payment_for_order(order["order_id"]) if order else fake_registry.payment_for_order("anon")
    record = {
        "payment_id": payment["payment_id"],
        "merchant_reference": order["order_id"],
        "card_last4": payment["card_last4"],
        "amount": order["amount"],
        "currency": payment.get("currency", "USD"),
        "status": payment.get("status", "pending"),
        "metadata": {"stripe_account": "acct_fake_honeyhaven", "customer": persona.get("username") if persona else None},
    }
    PaymentRecord.objects.create(**record)
    emit_structured_event("payment_record", **record)
    return record


def fake_support_ticket(subject: str, body: str, email: str = "") -> dict[str, Any]:
    ticket = fake_registry.ticket_for_subject(subject, email)
    # attach body and metadata
    ticket["body"] = body
    ticket.setdefault("metadata", {})
    ticket["metadata"]["channel"] = ticket["metadata"].get("channel", "portal")
    SupportTicket.objects.create(**{k: v for k, v in ticket.items() if k in ["ticket_id", "requester_email", "subject", "status", "priority", "body"]})
    emit_structured_event("support_ticket", **ticket)
    return ticket


def record_telemetry_event(session_id: str, event_type: str, path: str, details: dict[str, Any], request: HttpRequest) -> TelemetryEvent:
    event = TelemetryEvent.objects.create(
        session_id=session_id[:80],
        event_type=event_type[:80],
        path=path[:1000],
        ip_address=get_client_ip(request),
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
        details=details,
    )
    emit_structured_event(
        "telemetry",
        session_id=session_id[:80],
        event_type=event_type[:80],
        path=path[:1000],
        ip_address=get_client_ip(request),
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
        details=details,
    )
    return event


def upsert_attack_journey(session_id: str, **fields: Any) -> AttackJourney:
    # Create or update AttackJourney with aggregated summary fields.
    journey, created = AttackJourney.objects.get_or_create(session_id=session_id[:80], defaults={"entry_point": fields.get("entry_point", "")})

    # Update basic fields from provided inputs
    for key, value in fields.items():
        setattr(journey, key, value)

    # Recompute summary metrics from stored event tables to keep persisted journey consistent
    try:
        cutoff = timezone.now() - timezone.timedelta(days=30)
        # count related events by deriving session matching logic
        logs_qs = HoneypotLog.objects.filter(requested_url__isnull=False)
        # match by session-derived fingerprint: we approximate by matching on session_id via derived value
        # For correctness, we recompute derive_session_id per log entry and match to provided session_id
        related_logs = [l for l in HoneypotLog.objects.all() if derive_session_id(ip_address=l.ip_address or "", user_agent=l.user_agent or "", accept_language="", cookie_seed="", path=l.requested_url)[:80] == session_id[:80]]
        related_teles = [t for t in TelemetryEvent.objects.all() if (t.session_id or derive_session_id(ip_address=t.ip_address or "", user_agent=t.user_agent or "", accept_language="", cookie_seed="", path=t.path))[:80] == session_id[:80]]
        related_logins = [li for li in LoginAttempt.objects.all() if derive_session_id(ip_address=li.ip_address or "", user_agent=li.user_agent or "", accept_language="", cookie_seed="", path=li.requested_url)[:80] == session_id[:80]]
        related_alerts = [a for a in AlertEvent.objects.all() if derive_session_id(ip_address=a.ip_address or "", user_agent=a.user_agent or "", accept_language="", cookie_seed="", path=a.requested_url)[:80] == session_id[:80]]

        all_events = []
        all_events.extend([{"ts": l.timestamp, "kind": "request", "detail": l.requested_url, "attack_class": l.attack_classification, "ip": l.ip_address, "ua": l.user_agent} for l in related_logs])
        all_events.extend([{"ts": t.timestamp, "kind": "telemetry", "detail": t.path, "attack_class": "telemetry", "ip": t.ip_address, "ua": t.user_agent} for t in related_teles])
        all_events.extend([{"ts": li.timestamp, "kind": "login", "detail": li.requested_url, "attack_class": ("brute_force" if not li.success else "login"), "ip": li.ip_address, "ua": li.user_agent} for li in related_logins])
        all_events.extend([{"ts": a.timestamp, "kind": "alert", "detail": a.detail, "attack_class": a.alert_type, "ip": a.ip_address, "ua": a.user_agent} for a in related_alerts])

        if all_events:
            all_events.sort(key=lambda x: x["ts"])
            first_seen = all_events[0]["ts"]
            last_seen = all_events[-1]["ts"]
            seconds_spent = int((last_seen - first_seen).total_seconds())
            ips = list({e["ip"] for e in all_events if e.get("ip")})
            uas = list({(e.get("ua") or "")[:200] for e in all_events if e.get("ua")})
            phases = _detect_phases(all_events)
            journey.first_seen = journey.first_seen or first_seen
            journey.last_seen = last_seen
            journey.seconds_spent = seconds_spent
            journey.event_count = len(all_events)
            journey.ips = ips
            journey.user_agents = uas
            journey.phases = phases
    except Exception:
        # If any error occurs while aggregating, save whatever fields were provided
        pass

    journey.save()
    return journey


def generate_noise_batch() -> list[dict[str, Any]]:
    sources = ["purchase", "review", "login", "support_request", "browse_session"]
    noise = []
    for _ in range(5):
        event_type = random.choice(sources)
        payload = {
            "event_type": event_type,
            "user": f"user_{random.randint(1000, 9999)}",
            "product": random.choice(["wildflower", "forest amber", "acacia", "reserve"]),
            "amount": round(random.uniform(9.5, 88.0), 2),
            "rating": random.randint(3, 5),
        }
        NoiseEvent.objects.create(event_type=event_type, payload=payload)
        emit_structured_event("noise_event", event_type=event_type, payload=payload)
        noise.append(payload)
    return noise


def extract_fake_iocs(text: str) -> dict[str, list[str]]:
    import re

    # Match clean indicators instead of naive token splitting so URLs / UAs / quoted strings are not misclassified.
    ip_pattern = re.compile(r"(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w.])")
    url_pattern = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
    email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    hash_pattern = re.compile(r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b")

    ips = list(dict.fromkeys(ip_pattern.findall(text)))
    urls = list(dict.fromkeys(url_pattern.findall(text)))
    emails = list(dict.fromkeys(email_pattern.findall(text)))
    hashes = list(dict.fromkeys(hash_pattern.findall(text)))
    return {"ips": ips[:10], "urls": urls[:10], "emails": emails[:10], "hashes": hashes[:10]}


def build_attack_journeys(*, lookback_hours: int = 24, proximity_seconds: int = 900, limit: int = 200) -> list[dict[str, Any]]:
    """Aggregate events into attack journeys.

    Heuristics:
    - Primary grouping by `session_id` when available.
    - Fallback grouping by (ip_address, user_agent) for events without session_id.
    - Events within `proximity_seconds` are considered part of the same journey window.
    - Classify phases by event kinds and payload markers.
    Returns a list of journey summaries with metrics and sample events.
    """
    cutoff = timezone.now() - timezone.timedelta(hours=lookback_hours)
    # collect events
    logs = list(HoneypotLog.objects.filter(timestamp__gte=cutoff).order_by("timestamp")[:limit * 3])
    teles = list(TelemetryEvent.objects.filter(timestamp__gte=cutoff).order_by("timestamp")[:limit * 3])
    logins = list(LoginAttempt.objects.filter(timestamp__gte=cutoff).order_by("timestamp")[:limit * 3])
    alerts = list(AlertEvent.objects.filter(timestamp__gte=cutoff).order_by("timestamp")[:limit * 3])

    # normalize into unified events
    unified = []
    for e in logs:
        session = derive_session_id(ip_address=e.ip_address or "", user_agent=e.user_agent or "", accept_language="", cookie_seed="", path=e.requested_url)
        unified.append({"ts": e.timestamp, "kind": "request", "session_id": session, "ip": e.ip_address, "ua": e.user_agent, "detail": e.requested_url, "payload": e.payload, "attack_class": e.attack_classification, "ref": getattr(e, 'id', None)})
    for t in teles:
        unified.append({"ts": t.timestamp, "kind": "telemetry", "session_id": t.session_id or derive_session_id(ip_address=t.ip_address or "", user_agent=t.user_agent or "", accept_language="", cookie_seed="", path=t.path), "ip": t.ip_address, "ua": t.user_agent, "detail": t.path, "payload": json.dumps(t.details) if t.details else "", "attack_class": "telemetry", "ref": getattr(t, 'id', None)})
    for l in logins:
        session = derive_session_id(ip_address=l.ip_address or "", user_agent=l.user_agent or "", accept_language="", cookie_seed="", path=l.requested_url)
        unified.append({"ts": l.timestamp, "kind": "login", "session_id": session, "ip": l.ip_address, "ua": l.user_agent, "detail": l.requested_url, "payload": l.password_submitted[:400], "attack_class": ("brute_force" if not l.success else "login"), "ref": getattr(l, 'id', None)})
    for a in alerts:
        session = derive_session_id(ip_address=a.ip_address or "", user_agent=a.user_agent or "", accept_language="", cookie_seed="", path=a.requested_url)
        unified.append({"ts": a.timestamp, "kind": "alert", "session_id": session, "ip": a.ip_address, "ua": a.user_agent, "detail": a.detail, "payload": json.dumps(a.metadata)[:400], "attack_class": a.alert_type, "ref": getattr(a, 'id', None)})

    unified.sort(key=lambda x: x["ts"])

    # group by session_id first
    journeys = {}
    for ev in unified:
        sid = ev.get("session_id") or f"ip:{ev.get('ip') or 'unknown'}|ua:{(ev.get('ua') or '')[:80]}"
        if sid not in journeys:
            journeys[sid] = {"session_id": sid, "events": [], "ips": set(), "uas": set(), "first_seen": ev["ts"], "last_seen": ev["ts"]}
        j = journeys[sid]
        j["events"].append(ev)
        if ev.get("ip"):
            j["ips"].add(ev["ip"])
        if ev.get("ua"):
            j["uas"].add(ev["ua"])
        if ev["ts"] < j["first_seen"]:
            j["first_seen"] = ev["ts"]
        if ev["ts"] > j["last_seen"]:
            j["last_seen"] = ev["ts"]

    # now compress journeys by time proximity: if two journeys from same ip/ua overlap within proximity_seconds, merge
    merged = []
    for sid, j in journeys.items():
        # compute seconds_spent and phases
        secs = int((j["last_seen"] - j["first_seen"]).total_seconds()) if j["last_seen"] and j["first_seen"] else 0
        phases = _detect_phases(j["events"])
        summary = {
            "session_id": j["session_id"],
            "first_seen": j["first_seen"].isoformat(),
            "last_seen": j["last_seen"].isoformat(),
            "seconds_spent": secs,
            "event_count": len(j["events"]),
            "ips": list(j["ips"])[:3],
            "uas": list(j["uas"])[:3],
            "phases": phases,
            "sample_events": [{"ts": ev["ts"].isoformat(), "kind": ev["kind"], "detail": ev["detail"], "attack_class": ev.get("attack_class") } for ev in j["events"][:10]],
        }
        merged.append(summary)

    # sort by most recent activity
    merged.sort(key=lambda x: x["last_seen"], reverse=True)
    return merged


def _detect_phases(events: list[dict[str, Any]]) -> list[str]:
    # Backwards-compatible simple detector kept for callers that expect a list of phase names.
    seq = _sequence_detect_phases(events)
    return [p["phase"] for p in seq]


def _sequence_detect_phases(events: list[dict[str, Any]], *, max_events: int = 800) -> list[dict[str, Any]]:
    """Sequence-based phase detection.

    Returns an ordered list of phase dicts: {phase: str, confidence: float, start: iso, end: iso, count: int}

    Heuristics used:
    - Recon: many distinct endpoints, scanning user-agent signatures, probing paths.
    - Credential access: concentrated series of failed `login` events within short window.
    - Configuration discovery: hits to .env/.git/backup/admin/dashboard pages.
    - Injection attempts: presence of SQLi payloads or command-like tokens in sequence.
    - Execution/exploitation: suspicious uploads, requests for webshells, or command execution patterns.
    - Data exfiltration: repeated GETs of product/download endpoints or high-volume scraping.
    - Persistence/escalation: repeated admin access attempts and privilege probing.
    - Noise/observation: low-signal activity.

    The detector analyzes ordered events, counts, timing gaps, and repeated patterns.
    """
    if not events:
        return [{"phase": "noise_or_observation", "confidence": 0.5, "start": None, "end": None, "count": 0}]

    events = events[-max_events:] if len(events) > max_events else events
    events_sorted = sorted(events, key=lambda x: x["ts"]) if isinstance(events[0]["ts"], type(timezone.now())) else sorted(events, key=lambda x: x["ts"])

    # Rolling window metrics
    total = len(events_sorted)
    distinct_paths = len({(e.get("detail") or "") for e in events_sorted})
    kinds_seq = [e.get("kind") for e in events_sorted]
    ts_seq = [e.get("ts") for e in events_sorted]

    # timing analysis: average inter-event interval
    intervals = []
    for i in range(1, len(ts_seq)):
        try:
            intervals.append((ts_seq[i] - ts_seq[i - 1]).total_seconds())
        except Exception:
            pass
    avg_interval = sum(intervals) / len(intervals) if intervals else 0

    phases: list[dict[str, Any]] = []

    # Recon detection
    recon_score = 0.0
    if distinct_paths >= max(8, total * 0.25):
        recon_score += 0.5
    if any(SCANNER_PATTERN.search((e.get("ua") or "") or "") for e in events_sorted[:20]):
        recon_score += 0.3
    if any(PROBING_PATH_PATTERN.search((e.get("detail") or "")) for e in events_sorted):
        recon_score += 0.4
    recon_score = min(1.0, recon_score)
    if recon_score > 0.25:
        phases.append({"phase": "reconnaissance", "confidence": round(recon_score, 2), "start": events_sorted[0]["ts"].isoformat() if events_sorted else None, "end": events_sorted[min(5, total)-1]["ts"].isoformat() if events_sorted else None, "count": total})

    # Credential access detection
    cred_score = 0.0
    # look for sequences of login events with many failures
    login_events = [e for e in events_sorted if e.get("kind") == "login"]
    failed_logins = sum(1 for e in login_events if (e.get("attack_class") or "").lower() in ("brute_force", "failed", "brute_force_attack"))
    if failed_logins >= 3:
        cred_score += min(1.0, 0.3 + (failed_logins / max(5, len(login_events))) * 0.7)
    # clustering of login attempts in short time
    if login_events and len(login_events) >= 3:
        span = (login_events[-1]["ts"] - login_events[0]["ts"]).total_seconds() if login_events[-1]["ts"] and login_events[0]["ts"] else 0
        if span < 300:
            cred_score = min(1.0, cred_score + 0.2)
    if cred_score > 0.2:
        phases.append({"phase": "credential_access", "confidence": round(cred_score, 2), "start": login_events[0]["ts"].isoformat() if login_events else None, "end": login_events[-1]["ts"].isoformat() if login_events else None, "count": len(login_events)})

    # Configuration discovery
    config_score = 0.0
    config_hits = [e for e in events_sorted if PROBING_PATH_PATTERN.search((e.get("detail") or ""))]
    if config_hits:
        config_score = min(1.0, 0.3 + len(config_hits) / max(5, total) )
        phases.append({"phase": "configuration_discovery", "confidence": round(config_score, 2), "start": config_hits[0]["ts"].isoformat(), "end": config_hits[-1]["ts"].isoformat(), "count": len(config_hits)})

    # Injection attempts
    inj_score = 0.0
    inj_hits = [e for e in events_sorted if SQLI_PATTERN.search((e.get("detail") or "")) or SQLI_PATTERN.search((e.get("payload") or ""))]
    if inj_hits:
        inj_score = min(1.0, 0.4 + len(inj_hits) / max(3, total))
        phases.append({"phase": "injection_attempts", "confidence": round(inj_score, 2), "start": inj_hits[0]["ts"].isoformat(), "end": inj_hits[-1]["ts"].isoformat(), "count": len(inj_hits)})

    # Execution / exploitation
    exec_score = 0.0
    exec_hits = [e for e in events_sorted if COMMAND_PATTERN.search((e.get("detail") or "")) or COMMAND_PATTERN.search((e.get("payload") or ""))]
    # also consider suspicious upload requests or payloads
    exec_hits += [e for e in events_sorted if ("upload" in (e.get("detail") or "").lower()) or ("webshell" in (e.get("detail") or "").lower())]
    if exec_hits:
        exec_score = min(1.0, 0.4 + len(exec_hits) / max(3, total))
        phases.append({"phase": "execution_or_exploitation", "confidence": round(exec_score, 2), "start": exec_hits[0]["ts"].isoformat(), "end": exec_hits[-1]["ts"].isoformat(), "count": len(exec_hits)})

    # Data exfiltration
    exf_score = 0.0
    # heuristics: many GETs to content endpoints, repeated downloads, scraping
    get_requests = [e for e in events_sorted if (e.get("kind") == "request" and isinstance(e.get("detail"), str) and e.get("detail", "").lower().startswith("/download"))]
    if len(get_requests) >= 3:
        exf_score = min(1.0, 0.5 + len(get_requests) / max(5, total))
        phases.append({"phase": "data_exfiltration", "confidence": round(exf_score, 2), "start": get_requests[0]["ts"].isoformat(), "end": get_requests[-1]["ts"].isoformat(), "count": len(get_requests)})

    # Persistence / escalation
    pers_score = 0.0
    admin_hits = [e for e in events_sorted if "/admin" in (e.get("detail") or "").lower() or "admin" in (e.get("detail") or "").lower()]
    if len(admin_hits) >= 2:
        pers_score = min(1.0, 0.3 + len(admin_hits) / max(4, total))
        phases.append({"phase": "persistence_or_escalation", "confidence": round(pers_score, 2), "start": admin_hits[0]["ts"].isoformat(), "end": admin_hits[-1]["ts"].isoformat(), "count": len(admin_hits)})

    # If no meaningful phase detected, label as noise/observation
    if not phases:
        phases.append({"phase": "noise_or_observation", "confidence": 0.6, "start": events_sorted[0]["ts"].isoformat(), "end": events_sorted[-1]["ts"].isoformat(), "count": total})

    # Order phases by start time
    try:
        phases.sort(key=lambda p: p["start"] or "")
    except Exception:
        pass

    # Consolidate overlapping/duplicate phases: merge same-phase entries
    merged: list[dict[str, Any]] = []
    for p in phases:
        if merged and merged[-1]["phase"] == p["phase"]:
            merged[-1]["confidence"] = round(max(merged[-1]["confidence"], p["confidence"]), 2)
            merged[-1]["end"] = p.get("end") or merged[-1].get("end")
            merged[-1]["count"] += p.get("count", 0)
        else:
            merged.append(p.copy())

    # Normalize confidences to 0..1 and return
    for m in merged:
        m["confidence"] = float(min(1.0, max(0.0, m.get("confidence", 0.5))))

    return merged


def fake_attack_research_report(observations: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    observations = observations or []
    combined_text = json.dumps(observations) if observations else "sqlmap union select whoami /var/www/html"
    iocs = extract_fake_iocs(combined_text)
    report = {
        "classification": random.choice(["Credential Stuffing", "SQL Injection Attempt", "Scanner/Bot Activity", "LFI Probe", "Webshell Upload Attempt"]),
        "confidence": round(random.uniform(0.72, 0.98), 2),
        "mitre_attack": ["T1190", "T1059", "T1003", "T1046"],
        "threat_actor_profile": {
            "behavior": random.choice(["Noisy automation", "Opportunistic reconnaissance", "Credential spray", "Exploit chaining"]),
            "tooling": ["curl", "python-requests", "sqlmap", "gobuster"],
            "infrastructure": ["residential_proxy", "cloud_vps", "tor_exit_node"],
        },
        "iocs": iocs,
        "campaign_timeline": [
            {"stage": "recon", "note": "Enumerated hidden panels and backup files"},
            {"stage": "payload", "note": "Tested injection and file inclusion primitives"},
            {"stage": "escalation", "note": "Attempted fake credential or command execution paths"},
        ],
        "clusters": [
            {"cluster_id": f"cluster-{random.randint(1, 5)}", "count": random.randint(2, 15)},
            {"cluster_id": f"cluster-{random.randint(6, 9)}", "count": random.randint(1, 8)},
        ],
        "autonomous_deception_paths": [
            "/wp-admin/",
            "/phpmyadmin/",
            "/backup.sql",
            "/api/internal/auth/",
            "/api/internal/exec/",
        ],
        "dynamic_environment": {
            "surface_rotation": True,
            "fake_asset_variants": random.randint(3, 9),
            "noise_rate": "medium",
        },
    }
    return report
