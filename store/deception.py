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

from .models import AlertEvent, AttackJourney, AttackerState, IOCIndicator, NoiseEvent, PaymentRecord, SupportTicket, TelemetryEvent, ThreatIntelSnapshot, UploadArtifact, HoneypotLog, LoginAttempt
from .utils import derive_session_id, emit_structured_event, get_client_ip, get_or_create_honey_session_id, log_event, request_payload_to_text

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
    identity = get_or_create_honey_session_id(request)

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
        "public_session": identity,
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
    endpoint: str = "",
    request_body: str = "",
    suspicious_keywords: list[str] | None = None,
    severity: str = "medium",
) -> None:
    api_endpoint = endpoint or ""
    if not api_endpoint and request.path.startswith("/api/"):
        api_endpoint = request.path
    keyword_list = [keyword for keyword in (suspicious_keywords or []) if keyword]
    emit_structured_event(
        "decoy_access",
        event_type=event_type,
        ip_address=get_client_ip(request),
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
        requested_url=request.get_full_path()[:1000],
        endpoint=api_endpoint,
        method=request.method,
        payload=payload[:4000],
        request_body=request_body[:4000],
        username=username[:150],
        status_code=status_code,
        suspicion_reason=suspicion_reason,
        severity=severity,
        suspicious_keywords=keyword_list,
    )
    if api_endpoint:
        emit_structured_event(
            "api_probe",
            event_type="api_probe",
            endpoint=api_endpoint,
            method=request.method,
            ip_address=get_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", "")[:1000],
            request_body=request_body[:4000],
            response_status=status_code,
            severity=severity,
            suspicious_keywords=keyword_list,
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


def fake_json_response(
    request: HttpRequest,
    payload: dict[str, Any],
    *,
    label: str,
    status_code: int = 200,
    endpoint: str = "",
    request_body: str = "",
    suspicious_keywords: list[str] | None = None,
    severity: str = "medium",
    suspicion_reason: str = "Decoy surface interaction",
    allow_error_injection: bool = True,
) -> JsonResponse:
    profile = build_fake_runtime_profile(request, f"json:{label}")
    _apply_decoy_timing(profile)
    # probabilistically inject transient errors for non-staff surfaces
    err = _maybe_inject_error(profile, label) if allow_error_injection else None
    if err is not None:
        response = JsonResponse({"error": err.get("message", "Upstream error")}, status=err["status"])
    else:
        response = JsonResponse(_decorate_json_payload(payload, profile), status=status_code)
    log_decoy_access(
        request,
        event_type="API_HIT",
        payload=request_body or request_payload_to_text(request),
        status_code=status_code,
        suspicion_reason=suspicion_reason,
        endpoint=endpoint or (f"/{label}" if label.startswith("api/") else ""),
        request_body=request_body or request_payload_to_text(request),
        suspicious_keywords=suspicious_keywords,
        severity=severity,
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
    session_id = get_or_create_honey_session_id(request)
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
    try:
        persist_fake_iocs(
            session_id=session_id,
            source_event="AlertEvent",
            source_model="AlertEvent",
            source_object_id=event.id,
            text=" ".join([detail, request.get_full_path(), request.META.get("HTTP_USER_AGENT", "")]),
            related_journey=AttackJourney.objects.filter(session_id=session_id).first(),
            metadata={"alert_type": alert_type},
            evidence_summary=f"Alert {alert_type}: {detail[:120]}",
        )
    except Exception:
        pass
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


def upload_trap_report(filename: str, payload: bytes, uploader_ip: str, user_agent: str, *, session_id: str = "") -> dict[str, Any]:
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

    artifact = UploadArtifact.objects.create(
        filename=filename[:255],
        sha256=digest,
        entropy=round(entropy, 4),
        verdict=verdict,
        uploader_ip=uploader_ip,
        user_agent=user_agent[:1000],
        metadata={"size": len(payload), "session_id": session_id},
    )
    try:
        persist_fake_iocs(
            session_id=session_id,
            source_event="UploadArtifact",
            source_model="UploadArtifact",
            source_object_id=artifact.id,
            text=" ".join([filename, lowered, digest, user_agent]),
            related_journey=AttackJourney.objects.filter(session_id=session_id).first(),
            metadata={"verdict": verdict, "entropy": round(entropy, 4)},
            evidence_summary=f"UploadArtifact {filename} flagged {verdict}",
        )
        from .detection import run_detection_pipeline

        run_detection_pipeline(
            session_id,
            trigger={
                "source_model": "UploadArtifact",
                "source_object_id": artifact.id,
                "source_event": "UploadArtifact",
                "ip_address": uploader_ip,
                "payload": filename,
            },
        )
    except Exception:
        pass
    emit_structured_event(
        "upload_trap",
        filename=filename,
        sha256=digest,
        entropy=round(entropy, 4),
        verdict=verdict,
        uploader_ip=uploader_ip,
        user_agent=user_agent[:1000],
        size=len(payload),
        session_id=session_id,
    )
    return {"filename": filename, "sha256": digest, "entropy": round(entropy, 4), "verdict": verdict}


def fake_payment_payload(reference: str | None = None, *, session_id: str = "") -> dict[str, Any]:
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
        "metadata": {"stripe_account": "acct_fake_honeyhaven", "customer": persona.get("username") if persona else None, "session_id": session_id},
    }
    payment_record = PaymentRecord.objects.create(**record)
    try:
        persist_fake_iocs(
            session_id=session_id,
            source_event="PaymentRecord",
            source_model="PaymentRecord",
            source_object_id=payment_record.id,
            text=" ".join([record["payment_id"], record["merchant_reference"], record["card_last4"], record["status"], json.dumps(record.get("metadata", {}), default=str)]),
            related_journey=AttackJourney.objects.filter(session_id=session_id).first(),
            metadata={"currency": record["currency"], "amount": str(record["amount"])},
            evidence_summary=f"PaymentRecord {record['payment_id']} status {record['status']}",
        )
        from .detection import run_detection_pipeline

        run_detection_pipeline(
            session_id,
            trigger={
                "source_model": "PaymentRecord",
                "source_object_id": payment_record.id,
                "source_event": "PaymentRecord",
                "payload": json.dumps(record, default=str),
            },
        )
    except Exception:
        pass
    emit_structured_event("payment_record", **record)
    return record


def fake_support_ticket(subject: str, body: str, email: str = "", *, session_id: str = "") -> dict[str, Any]:
    ticket = fake_registry.ticket_for_subject(subject, email)
    # attach body and metadata
    ticket["body"] = body
    ticket.setdefault("metadata", {})
    ticket["metadata"]["channel"] = ticket["metadata"].get("channel", "portal")
    ticket["metadata"]["session_id"] = session_id
    support_ticket = SupportTicket.objects.create(**{k: v for k, v in ticket.items() if k in ["ticket_id", "requester_email", "subject", "status", "priority", "body", "metadata"]})
    try:
        persist_fake_iocs(
            session_id=session_id,
            source_event="SupportTicket",
            source_model="SupportTicket",
            source_object_id=support_ticket.id,
            text=" ".join([ticket["ticket_id"], ticket.get("requester_email", ""), subject, body, json.dumps(ticket.get("metadata", {}), default=str)]),
            related_journey=AttackJourney.objects.filter(session_id=session_id).first(),
            metadata={"priority": ticket.get("priority", "normal"), "status": ticket.get("status", "open")},
            evidence_summary=f"SupportTicket {ticket['ticket_id']} subject {subject[:120]}",
        )
        from .detection import run_detection_pipeline

        run_detection_pipeline(
            session_id,
            trigger={
                "source_model": "SupportTicket",
                "source_object_id": support_ticket.id,
                "source_event": "SupportTicket",
                "payload": json.dumps(ticket, default=str),
            },
        )
    except Exception:
        pass
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
    try:
        persist_fake_iocs(
            session_id=session_id,
            source_event="TelemetryEvent",
            source_model="TelemetryEvent",
            source_object_id=event.id,
            text=" ".join([path, json.dumps(details, default=str), request.META.get("HTTP_USER_AGENT", "")]),
            related_journey=AttackJourney.objects.filter(session_id=session_id[:80]).first(),
            metadata={"event_type": event_type},
            evidence_summary=f"Telemetry event {event_type} on {path[:120]}",
        )
        from .detection import run_detection_pipeline

        run_detection_pipeline(
            session_id,
            trigger={
                "source_model": "TelemetryEvent",
                "source_object_id": event.id,
                "source_event": event_type,
                "ip_address": get_client_ip(request),
                "request_path": path,
                "payload": json.dumps(details, default=str),
            },
        )
    except Exception:
        pass
    return event


def upsert_attack_journey(session_id: str, **fields: Any) -> AttackJourney:
    # Create or update AttackJourney with aggregated summary fields.
    journey, created = AttackJourney.objects.get_or_create(session_id=session_id[:80], defaults={"entry_point": fields.get("entry_point", "")})

    # Update basic fields from provided inputs
    for key, value in fields.items():
        setattr(journey, key, value)

    # Recompute summary metrics from stored event tables to keep persisted journey consistent
    try:
        related_logs = HoneypotLog.objects.filter(session_id=session_id[:80])

        related_teles = TelemetryEvent.objects.filter(
            session_id=session_id[:80]
        ) | TelemetryEvent.objects.filter(
            details__session_id=session_id[:80]
        )

        related_logins = LoginAttempt.objects.filter(session_id=session_id[:80])
        related_alerts = AlertEvent.objects.filter(metadata__session_id=session_id[:80])
        related_uploads = UploadArtifact.objects.filter(metadata__session_id=session_id[:80])
        related_payments = PaymentRecord.objects.filter(metadata__session_id=session_id[:80])
        related_tickets = SupportTicket.objects.filter(metadata__session_id=session_id[:80])

        all_events = []
        all_events.extend([{"ts": l.timestamp, "kind": "request", "source": "HoneypotLog", "source_object_id": l.id, "detail": l.requested_url, "attack_class": l.attack_classification, "ip": l.ip_address, "ua": l.user_agent, "payload": l.payload[:400]} for l in related_logs])
        all_events.extend([{"ts": t.timestamp, "kind": "telemetry", "source": "TelemetryEvent", "source_object_id": t.id, "detail": t.path, "attack_class": "telemetry", "ip": t.ip_address, "ua": t.user_agent, "payload": json.dumps(t.details, default=str) if t.details else ""} for t in related_teles])
        all_events.extend([{"ts": li.timestamp, "kind": "login", "source": "LoginAttempt", "source_object_id": li.id, "detail": li.requested_url, "attack_class": ("brute_force" if not li.success else "login"), "ip": li.ip_address, "ua": li.user_agent, "payload": li.password_submitted[:400]} for li in related_logins])
        all_events.extend([{"ts": a.timestamp, "kind": "alert", "source": "AlertEvent", "source_object_id": a.id, "detail": a.detail, "attack_class": a.alert_type, "ip": a.ip_address, "ua": a.user_agent, "payload": json.dumps({"detail": a.detail, "requested_url": a.requested_url, "metadata": a.metadata}, default=str)[:400]} for a in related_alerts])
        all_events.extend([{"ts": u.timestamp, "kind": "upload", "source": "UploadArtifact", "source_object_id": u.id, "detail": u.filename, "attack_class": u.verdict, "ip": u.uploader_ip, "ua": u.user_agent, "payload": json.dumps({"filename": u.filename, "sha256": u.sha256, "entropy": u.entropy, "metadata": u.metadata}, default=str)[:400]} for u in related_uploads])
        all_events.extend([{"ts": p.timestamp, "kind": "payment", "source": "PaymentRecord", "source_object_id": p.id, "detail": p.payment_id, "attack_class": p.status, "ip": p.metadata.get("ip_address") if isinstance(p.metadata, dict) else None, "ua": p.metadata.get("user_agent", "") if isinstance(p.metadata, dict) else "", "payload": json.dumps({"merchant_reference": p.merchant_reference, "card_last4": p.card_last4, "metadata": p.metadata}, default=str)[:400]} for p in related_payments])
        all_events.extend([{"ts": s.timestamp, "kind": "support", "source": "SupportTicket", "source_object_id": s.id, "detail": s.ticket_id, "attack_class": s.status, "ip": s.metadata.get("ip_address") if isinstance(s.metadata, dict) else None, "ua": s.metadata.get("user_agent", "") if isinstance(s.metadata, dict) else "", "payload": json.dumps({"requester_email": s.requester_email, "subject": s.subject, "body": s.body, "metadata": s.metadata}, default=str)[:400]} for s in related_tickets])

        for event in all_events:
            source_text = " ".join(
                [
                    str(event.get("detail", "")),
                    str(event.get("payload", "")),
                    str(event.get("ua", "")),
                    str(event.get("attack_class", "")),
                ]
            )
            persist_fake_iocs(
                session_id=session_id,
                source_event=str(event.get("source", "")),
                source_model=str(event.get("source", "")),
                source_object_id=event.get("source_object_id"),
                text=source_text,
                related_journey=journey,
                metadata={"kind": event.get("kind", ""), "attack_class": event.get("attack_class", "")},
            )

        if all_events:
            all_events.sort(key=lambda x: x["ts"])
            first_seen = all_events[0]["ts"]
            last_seen = all_events[-1]["ts"]
            seconds_spent = min(
               int((last_seen - first_seen).total_seconds()),
                   86400
                )
            ips = list({e["ip"] for e in all_events if e.get("ip")})
            uas = list({(e.get("ua") or "")[:200] for e in all_events if e.get("ua")})
            phases = _sequence_detect_phases(all_events)
            tools_used = _journey_tools_used(all_events)
            escalation_attempts = _journey_escalation_attempts(all_events)
            risk_score, confidence_score, intent_score = _journey_scores(phases, escalation_attempts, tools_used, len(all_events))
            event_records = _journey_event_records(all_events)
            journey.recon_path = event_records
            journey.payload_evolution = event_records
            journey.first_seen = journey.first_seen or first_seen
            journey.last_seen = last_seen
            journey.seconds_spent = seconds_spent
            journey.event_count = len(all_events)
            journey.ips = ips
            journey.user_agents = uas
            journey.phases = phases
            journey.tools_used = tools_used
            journey.escalation_attempts = escalation_attempts
            journey.risk_score = risk_score
            journey.confidence_score = confidence_score
            journey.intent_score = intent_score
            journey.campaign_id = _journey_campaign_id(phases, tools_used, escalation_attempts)
    except Exception as e:
        print("AttackJourney aggregation error:", e)

    journey.save()
    try:
        from .detection import run_detection_pipeline

        run_detection_pipeline(
            session_id,
            trigger={
                "source_model": "AttackJourney",
                "source_object_id": journey.id,
                "source_event": "AttackJourney",
            },
        )
    except Exception:
        pass
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


def _ioc_confidence(ioc_type: str, source_event: str) -> float:
    base = {
        "ip": 0.72,
        "url": 0.82,
        "email": 0.88,
        "hash": 0.94,
    }.get(ioc_type, 0.75)
    if source_event in {"UploadArtifact", "PaymentRecord", "SupportTicket"}:
        base += 0.03
    if source_event == "IOCExtractionView":
        base -= 0.02
    return round(min(0.99, max(0.1, base)), 2)


def _ioc_attack_context(session_id: str, related_journey: AttackJourney | None) -> tuple[str, float | None, float | None]:
    attack_phase = ""
    asg_risk_score: float | None = None
    asg_confidence: float | None = None

    if related_journey:
        phases = related_journey.phases or []
        if phases and isinstance(phases[0], dict):
            attack_phase = str(phases[0].get("phase", ""))
        elif phases:
            attack_phase = str(phases[0])

        asg_risk_score = related_journey.risk_score
        asg_confidence = related_journey.confidence_score

    if not attack_phase:
        state = AttackerState.objects.filter(session_id=session_id[:80]).first() if session_id else None
        if state:
            attack_phase = state.current_phase or ""
            asg_risk_score = state.risk_score
            asg_confidence = state.phase_confidence

    return attack_phase, asg_risk_score, asg_confidence


def persist_fake_iocs(
    *,
    session_id: str,
    source_event: str,
    source_model: str = "",
    source_object_id: int | None = None,
    text: str,
    related_journey: AttackJourney | None = None,
    metadata: dict[str, Any] | None = None,
    evidence_summary: str = "",
) -> list[IOCIndicator]:
    extracted = extract_fake_iocs(text or "")
    # Avoid treating the session id itself as an IOC hash
    if session_id:
        hashes = extracted.get("hashes", [])
        extracted["hashes"] = [h for h in hashes if h != session_id]

    if not any(extracted.values()):
        return []

    ioc_type_map = {
        "ips": "ip",
        "urls": "url",
        "emails": "email",
        "hashes": "hash",
    }

    session_id = str(session_id or "")[:80]
    source_event = str(source_event or "")[:80]
    source_model = str(source_model or "")[:80]
    related_journey = related_journey or (AttackJourney.objects.filter(session_id=session_id).first() if session_id else None)
    attack_phase, asg_risk_score, asg_confidence = _ioc_attack_context(session_id, related_journey)
    now = timezone.now()
    persisted: list[IOCIndicator] = []

    for extracted_type, values in extracted.items():
        ioc_type = ioc_type_map.get(extracted_type, extracted_type)
        for value in values:
            value = str(value)[:512]
            confidence = _ioc_confidence(ioc_type, source_event)
            defaults = {
                "confidence_score": confidence,
                "attack_journey": related_journey,
                "source_model": source_model,
                "source_object_id": source_object_id,
                "evidence_summary": evidence_summary[:300],
                "attack_phase": attack_phase,
                "asg_risk_score": asg_risk_score,
                "asg_confidence": asg_confidence,
                "metadata": {
                    **(metadata or {}),
                    "discovered_from": [source_event] if source_event else [],
                },
            }
            indicator, created = IOCIndicator.objects.get_or_create(
                session_id=session_id,
                ioc_type=ioc_type,
                ioc_value=value,
                source_event=source_event,
                source_model=source_model,
                source_object_id=source_object_id,
                defaults=defaults,
            )
            if not created:
                merged_meta = dict(indicator.metadata or {})
                discovered_from = list(dict.fromkeys([*(merged_meta.get("discovered_from", []) or []), source_event]))
                merged_meta.update(metadata or {})
                merged_meta["discovered_from"] = discovered_from
                indicator.confidence_score = max(indicator.confidence_score, confidence)
                indicator.attack_journey = indicator.attack_journey or related_journey
                indicator.source_model = indicator.source_model or source_model
                indicator.source_object_id = indicator.source_object_id or source_object_id
                indicator.evidence_summary = indicator.evidence_summary or evidence_summary[:300]
                indicator.attack_phase = indicator.attack_phase or attack_phase
                indicator.asg_risk_score = indicator.asg_risk_score if indicator.asg_risk_score is not None else asg_risk_score
                indicator.asg_confidence = indicator.asg_confidence if indicator.asg_confidence is not None else asg_confidence
                indicator.metadata = merged_meta
                indicator.last_seen = now
                indicator.save(update_fields=["confidence_score", "attack_journey", "source_model", "source_object_id", "evidence_summary", "attack_phase", "asg_risk_score", "asg_confidence", "metadata", "last_seen"])
            elif metadata:
                indicator.metadata = {**indicator.metadata, **metadata}
                indicator.save(update_fields=["metadata"])
            persisted.append(indicator)

    return persisted


def _journey_session_id(*, session_id: str = "", ip_address: str = "", user_agent: str = "", path: str = "") -> str:
    session_id = str(session_id or "")[:80]
    if session_id:
        return session_id
    return derive_session_id(ip_address=ip_address or "", user_agent=user_agent or "", accept_language="", cookie_seed="", path=path or "")


def _journey_event(
    *,
    timestamp,
    kind: str,
    source: str,
    detail: str,
    attack_class: str,
    ip: str | None,
    ua: str,
    payload: str = "",
) -> dict[str, Any]:
    return {
        "timestamp": timestamp,
        "kind": kind,
        "source": source,
        "detail": detail,
        "attack_class": attack_class,
        "ip": ip,
        "ua": ua,
        "payload": payload,
    }


def _journey_event_records(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "timestamp": ev["ts"].isoformat(),
            "kind": ev["kind"],
            "source": ev["source"],
            "detail": ev["detail"],
            "attack_class": ev.get("attack_class"),
            "ip": ev.get("ip"),
            "ua": ev.get("ua", ""),
            "payload": ev.get("payload", ""),
        }
        for ev in events
    ]


def _journey_tools_used(events: list[dict[str, Any]]) -> list[str]:
    combined = " ".join(
        " ".join(
            [
                str(ev.get("source", "")),
                str(ev.get("detail", "")),
                str(ev.get("attack_class", "")),
                str(ev.get("payload", "")),
                str(ev.get("ua", "")),
            ]
        )
        for ev in events
    ).lower()

    tools: list[str] = []
    if "sqlmap" in combined:
        tools.append("sqlmap")
    if SCANNER_PATTERN.search(combined) or any(token in combined for token in ["nikto", "nmap", "gobuster", "dirbuster", "acunetix", "burp"]):
        tools.append("automated_scanner")
    if "curl" in combined:
        tools.append("curl")
    if "wget" in combined:
        tools.append("wget")
    if any(token in combined for token in ["python-requests", "requests/"]):
        tools.append("python-requests")
    if any(token in combined for token in ["mozilla/", "chrome/", "safari/", "firefox/", "edge/", "playwright", "puppeteer", "headlesschrome"]):
        tools.append("browser")
    if COMMAND_PATTERN.search(combined):
        tools.append("command_line")

    seen: set[str] = set()
    ordered: list[str] = []
    for tool in tools:
        if tool and tool not in seen:
            seen.add(tool)
            ordered.append(tool)
    return ordered


def _journey_escalation_attempts(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    attempts: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for ev in events:
        detail = str(ev.get("detail", ""))
        payload = str(ev.get("payload", ""))
        combined = f"{detail} {payload}"
        timestamp = ev["ts"].isoformat()
        attack_class = str(ev.get("attack_class", ""))

        candidates: list[dict[str, Any]] = []
        detail_lower = detail.lower()
        if any(token in detail_lower for token in ["/admin", "phpmyadmin", "grafana", "jenkins", "dashboard", "cms", "portal", "internal", "debug", "api/docs", "api/internal", "api/admin"]):
            candidates.append({"type": "admin_access_attempt", "path": detail, "timestamp": timestamp})
        if SQLI_PATTERN.search(combined) or attack_class == "SQL_INJECTION_ATTEMPT":
            candidates.append({"type": "sql_injection", "confidence": 0.93, "detail": detail, "timestamp": timestamp})
        if COMMAND_PATTERN.search(combined) or "webshell" in combined.lower() or attack_class in {"webshell-suspected", "high-entropy"}:
            candidates.append({"type": "command_execution", "confidence": 0.95, "detail": detail, "timestamp": timestamp})
        if ev.get("kind") == "upload" and attack_class not in {"clean", ""}:
            candidates.append({"type": "suspicious_upload", "verdict": attack_class, "timestamp": timestamp})
        if ev.get("kind") == "payment" and attack_class not in {"paid", "settled", "completed"}:
            candidates.append({"type": "payment_probe", "status": attack_class, "timestamp": timestamp})
        if ev.get("kind") == "support" and detail:
            candidates.append({"type": "support_discovery", "ticket_id": detail, "timestamp": timestamp})

        for candidate in candidates:
            key = (str(candidate.get("type", "")), str(candidate.get("timestamp", "")))
            if key in seen:
                continue
            seen.add(key)
            attempts.append(candidate)

    return attempts


def _journey_intent_label(phases: list[dict[str, Any]], tools_used: list[str], escalation_attempts: list[dict[str, Any]]) -> str:
    phase_names = {str(phase.get("phase", "")) for phase in phases}
    escalation_types = {str(item.get("type", "")) for item in escalation_attempts}

    if "credential_access" in phase_names or "brute_force" in escalation_types:
        return "Credential theft"
    if "data_exfiltration" in phase_names:
        return "Data exfiltration"
    if "execution_or_exploitation" in phase_names or "command_execution" in escalation_types:
        return "Code execution"
    if "injection_attempts" in phase_names or "sql_injection" in escalation_types:
        return "Injection testing"
    if "persistence_or_escalation" in phase_names or "admin_access_attempt" in escalation_types:
        return "Privilege escalation"
    if tools_used:
        return "Automated probing"
    return "Reconnaissance"


def _journey_scores(
    phases: list[dict[str, Any]],
    escalation_attempts: list[dict[str, Any]],
    tools_used: list[str],
    event_count: int,
) -> tuple[float, float, float]:
    risk_weights = {
        "noise_or_observation": 5.0,
        "reconnaissance": 12.0,
        "configuration_discovery": 28.0,
        "credential_access": 55.0,
        "injection_attempts": 65.0,
        "execution_or_exploitation": 85.0,
        "data_exfiltration": 78.0,
        "persistence_or_escalation": 70.0,
    }

    confidence_values = [float(phase.get("confidence", 0.0)) for phase in phases if isinstance(phase, dict)]
    phase_risk = 0.0
    for phase in phases:
        if not isinstance(phase, dict):
            continue
        phase_name = str(phase.get("phase", ""))
        phase_risk = max(phase_risk, risk_weights.get(phase_name, 15.0) + float(phase.get("confidence", 0.0)) * 10.0)

    risk_score = min(100.0, round(phase_risk + min(20.0, len(escalation_attempts) * 5.0) + min(10.0, len(tools_used) * 2.0) + min(10.0, event_count / 20.0), 2))
    confidence_score = round((sum(confidence_values) / len(confidence_values) * 100.0) if confidence_values else 0.0, 2)

    intent_score = 20.0
    if any(phase.get("phase") == "credential_access" for phase in phases):
        intent_score = max(intent_score, 80.0)
    if any(phase.get("phase") == "injection_attempts" for phase in phases):
        intent_score = max(intent_score, 75.0)
    if any(phase.get("phase") == "execution_or_exploitation" for phase in phases):
        intent_score = max(intent_score, 85.0)
    if any(phase.get("phase") == "data_exfiltration" for phase in phases):
        intent_score = max(intent_score, 90.0)
    if any(phase.get("phase") == "persistence_or_escalation" for phase in phases):
        intent_score = max(intent_score, 70.0)
    if tools_used and intent_score < 35.0:
        intent_score = 35.0

    return risk_score, confidence_score, round(intent_score, 2)


def _journey_campaign_id(phases: list[dict[str, Any]], tools_used: list[str], escalation_attempts: list[dict[str, Any]]) -> str:
    if "sqlmap" in tools_used:
        return "SQLMAP_CAMPAIGN_001"
    if "automated_scanner" in tools_used and any(phase.get("phase") in {"reconnaissance", "configuration_discovery", "credential_access"} for phase in phases):
        return "SCANNER_CAMPAIGN_001"
    if any(item.get("type") == "sql_injection" for item in escalation_attempts):
        return "SQLI_CAMPAIGN_001"

    signature = "|".join(
        [
            ",".join(sorted(tools_used)),
            ",".join(sorted({str(phase.get("phase", "")) for phase in phases if isinstance(phase, dict)})),
            ",".join(sorted({str(item.get("type", "")) for item in escalation_attempts if isinstance(item, dict)})),
        ]
    ).strip("|")
    if not signature:
        return ""
    digest = hashlib.sha1(signature.encode("utf-8", errors="ignore")).hexdigest()[:6].upper()
    return f"MIXED_CAMPAIGN_{digest}"


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
    uploads = list(UploadArtifact.objects.filter(timestamp__gte=cutoff).order_by("timestamp")[:limit * 3])
    payments = list(PaymentRecord.objects.filter(timestamp__gte=cutoff).order_by("timestamp")[:limit * 3])
    tickets = list(SupportTicket.objects.filter(timestamp__gte=cutoff).order_by("timestamp")[:limit * 3])

    # normalize into unified events
    unified = []
    for e in logs:
        session = _journey_session_id(session_id=e.session_id, ip_address=e.ip_address or "", user_agent=e.user_agent or "", path=e.requested_url)
        unified.append(
            {
                "ts": e.timestamp,
                "session_id": session,
                **_journey_event(
                    timestamp=e.timestamp,
                    kind="request",
                    source="HoneypotLog",
                    detail=e.requested_url,
                    attack_class=e.attack_classification,
                    ip=e.ip_address,
                    ua=e.user_agent or "",
                    payload=e.payload[:400],
                ),
            }
        )
    for t in teles:
        session = _journey_session_id(session_id=t.session_id, ip_address=t.ip_address or "", user_agent=t.user_agent or "", path=t.path)
        unified.append(
            {
                "ts": t.timestamp,
                "session_id": session,
                **_journey_event(
                    timestamp=t.timestamp,
                    kind="telemetry",
                    source="TelemetryEvent",
                    detail=t.path,
                    attack_class="telemetry",
                    ip=t.ip_address,
                    ua=t.user_agent or "",
                    payload=json.dumps(t.details, default=str) if t.details else "",
                ),
            }
        )
    for l in logins:
        session = _journey_session_id(session_id=l.session_id, ip_address=l.ip_address or "", user_agent=l.user_agent or "", path=l.requested_url)
        unified.append(
            {
                "ts": l.timestamp,
                "session_id": session,
                **_journey_event(
                    timestamp=l.timestamp,
                    kind="login",
                    source="LoginAttempt",
                    detail=l.requested_url,
                    attack_class=("brute_force" if not l.success else "login"),
                    ip=l.ip_address,
                    ua=l.user_agent or "",
                    payload=l.password_submitted[:400],
                ),
            }
        )
    for a in alerts:
        session = _journey_session_id(
            session_id=(a.metadata or {}).get("session_id", ""),
            ip_address=a.ip_address or "",
            user_agent=a.user_agent or "",
            path=a.requested_url,
        )
        unified.append(
            {
                "ts": a.timestamp,
                "session_id": session,
                **_journey_event(
                    timestamp=a.timestamp,
                    kind="alert",
                    source="AlertEvent",
                    detail=a.detail,
                    attack_class=a.alert_type,
                    ip=a.ip_address,
                    ua=a.user_agent or "",
                    payload=json.dumps(a.metadata, default=str)[:400],
                ),
            }
        )
    for u in uploads:
        metadata = u.metadata or {}
        session = _journey_session_id(session_id=metadata.get("session_id", ""), ip_address=u.uploader_ip or metadata.get("ip_address", ""), user_agent=u.user_agent or metadata.get("user_agent", ""), path=u.filename)
        unified.append(
            {
                "ts": u.timestamp,
                "session_id": session,
                **_journey_event(
                    timestamp=u.timestamp,
                    kind="upload",
                    source="UploadArtifact",
                    detail=u.filename,
                    attack_class=u.verdict,
                    ip=u.uploader_ip or metadata.get("ip_address"),
                    ua=u.user_agent or metadata.get("user_agent", ""),
                    payload=json.dumps(metadata, default=str)[:400],
                ),
            }
        )
    for p in payments:
        metadata = p.metadata or {}
        session = _journey_session_id(session_id=metadata.get("session_id", ""), ip_address=metadata.get("ip_address", ""), user_agent=metadata.get("user_agent", ""), path=p.payment_id)
        unified.append(
            {
                "ts": p.timestamp,
                "session_id": session,
                **_journey_event(
                    timestamp=p.timestamp,
                    kind="payment",
                    source="PaymentRecord",
                    detail=p.payment_id,
                    attack_class=p.status,
                    ip=metadata.get("ip_address"),
                    ua=metadata.get("user_agent", ""),
                    payload=json.dumps(metadata, default=str)[:400],
                ),
            }
        )
    for s in tickets:
        metadata = s.metadata or {}
        session = _journey_session_id(session_id=metadata.get("session_id", ""), ip_address=metadata.get("ip_address", ""), user_agent=metadata.get("user_agent", ""), path=s.ticket_id)
        unified.append(
            {
                "ts": s.timestamp,
                "session_id": session,
                **_journey_event(
                    timestamp=s.timestamp,
                    kind="support",
                    source="SupportTicket",
                    detail=s.ticket_id,
                    attack_class=s.status,
                    ip=metadata.get("ip_address"),
                    ua=metadata.get("user_agent", ""),
                    payload=json.dumps(metadata, default=str)[:400],
                ),
            }
        )

    unified.sort(key=lambda x: x["ts"])

    # group by canonical session_id first
    journeys = {}
    for ev in unified:
        sid = ev.get("session_id") or _journey_session_id(ip_address=ev.get("ip") or "", user_agent=ev.get("ua") or "", path=ev.get("detail") or "")
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
        phases = _sequence_detect_phases(j["events"])
        event_records = _journey_event_records(j["events"])
        tools_used = _journey_tools_used(j["events"])
        escalation_attempts = _journey_escalation_attempts(j["events"])
        risk_score, confidence_score, intent_score = _journey_scores(phases, escalation_attempts, tools_used, len(j["events"]))
        summary = {
            "session_id": j["session_id"],
            "first_seen": j["first_seen"].isoformat(),
            "last_seen": j["last_seen"].isoformat(),
            "seconds_spent": secs,
            "event_count": len(j["events"]),
            "ips": list(j["ips"])[:3],
            "uas": list(j["uas"])[:3],
            "phases": phases,
            "tools_used": tools_used,
            "escalation_attempts": escalation_attempts,
            "risk_score": risk_score,
            "confidence_score": confidence_score,
            "intent_score": intent_score,
            "intent_label": _journey_intent_label(phases, tools_used, escalation_attempts),
            "campaign_id": _journey_campaign_id(phases, tools_used, escalation_attempts),
            "sample_events": event_records[:10],
            "recon_path": event_records,
            "payload_evolution": event_records,
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
        except Exception as e:
           print("AttackJourney aggregation error:", e)
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
