from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from io import StringIO
from typing import Any, Callable

from django.contrib.auth.models import AnonymousUser
from django.contrib.sessions.backends.db import SessionStore
from django.test import RequestFactory
from django.utils import timezone

from store.asg import get_attacker_state, update_attacker_state
from store.models import AlertEvent, HoneypotLog, LoginAttempt, TelemetryEvent
from store.utils import get_client_ip, get_or_create_honey_session_id, log_event, request_payload_to_text


@dataclass
class SimulationResult:
    attack_type: str
    session_id: str
    expected_phase: str
    observed_phase: str
    asg_detected: bool
    first_event_at: datetime
    detected_at: datetime | None
    detection_time_seconds: float | None
    risk_peak: float
    risk_escalation_time_seconds: float | None
    alerts_triggered: int
    phase_correct: bool
    events_created: int
    notes: str = ""


@dataclass
class SimulationContext:
    attack_type: str
    expected_phase: str
    ip_address: str
    user_agent: str
    username_pool: list[str] = field(default_factory=list)
    password_pool: list[str] = field(default_factory=list)
    session: SessionStore = field(default_factory=SessionStore)
    first_event_at: datetime | None = None
    detected_at: datetime | None = None
    peak_risk: float = 0.0
    peak_at: datetime | None = None
    events_created: int = 0
    notes: str = ""

    def session_id(self) -> str:
        return str(self.session.get("honey_session_id", ""))


rf = RequestFactory()


def _base_request(path: str, *, method: str = "GET", data: dict[str, Any] | None = None, context: SimulationContext) -> Any:
    if method.upper() == "POST":
        request = rf.post(path, data=data or {})
    else:
        request = rf.get(path, data=data or {})
    request.META["REMOTE_ADDR"] = context.ip_address
    request.META["HTTP_USER_AGENT"] = context.user_agent
    request.session = context.session
    request.user = AnonymousUser()
    get_or_create_honey_session_id(request)
    context.session = request.session
    return request


def _mark_event(context: SimulationContext, request: Any) -> None:
    created_at = timezone.now()
    if context.first_event_at is None:
        context.first_event_at = created_at
    session_id = get_or_create_honey_session_id(request)
    state = get_attacker_state(session_id)
    if state and state.current_phase != "noise_or_observation" and context.detected_at is None:
        context.detected_at = state.last_observed_at or created_at
    if state and state.risk_score >= context.peak_risk:
        context.peak_risk = float(state.risk_score)
        context.peak_at = state.last_observed_at or created_at
    context.events_created += 1


def _record_request(context: SimulationContext, path: str, *, method: str = "GET", payload: str = "", username: str = "", status_code: int = 200, event_type: str = "REQUEST") -> Any:
    request = _base_request(path, method=method, context=context)
    log_event(
        request,
        event_type=event_type,
        payload=payload,
        username=username,
        is_suspicious=True if event_type != "REQUEST" else False,
        suspicion_reason="Simulated attack event" if event_type != "REQUEST" else "",
        status_code=status_code,
    )
    _mark_event(context, request)
    return request


def _record_telemetry(context: SimulationContext, path: str, *, event_type: str, details: dict[str, Any]) -> None:
    request = _base_request("/api/internal/telemetry/", method="POST", data={"event_type": event_type, **details}, context=context)
    TelemetryEvent.objects.create(
        session_id=get_or_create_honey_session_id(request),
        event_type=event_type,
        path=path,
        ip_address=context.ip_address,
        user_agent=context.user_agent,
        details=details,
    )
    update_attacker_state(
        session_id=get_or_create_honey_session_id(request),
        event_type=event_type,
        path=path,
        request=request,
        source_model="TelemetryEvent",
        payload=details,
    )
    _mark_event(context, request)


def _record_login_attempt(context: SimulationContext, *, username: str, password: str, success: bool, path: str = "/login/") -> Any:
    request = _base_request(path, method="POST", data={"username": username, "password": password}, context=context)
    LoginAttempt.objects.create(
        username=username,
        password_submitted=password[:256],
        ip_address=context.ip_address,
        session_id=get_or_create_honey_session_id(request),
        user_agent=context.user_agent,
        requested_url=path,
        success=success,
    )
    log_event(
        request,
        event_type="LOGIN_ATTEMPT",
        payload=request_payload_to_text(request),
        username=username,
        is_suspicious=not success,
        suspicion_reason="Failed login attempt" if not success else "",
        status_code=200 if success else 403,
    )
    _mark_event(context, request)
    return request


def _record_form_submission(context: SimulationContext, path: str, data: dict[str, Any], *, suspicious: bool = False) -> Any:
    request = _base_request(path, method="POST", data=data, context=context)
    log_event(
        request,
        event_type="FORM_SUBMISSION",
        payload=request_payload_to_text(request),
        username=data.get("username", ""),
        is_suspicious=suspicious,
        suspicion_reason="Suspicious form submission" if suspicious else "",
        status_code=200,
    )
    _mark_event(context, request)
    return request


def _run_scenario(context: SimulationContext, runner: Callable[[SimulationContext], None]) -> SimulationResult:
    runner(context)
    session_id = context.session_id()
    state = get_attacker_state(session_id)
    alerts_triggered = AlertEvent.objects.filter(metadata__asg__session_id=session_id).count()
    detected = bool(state and state.current_phase != "noise_or_observation")
    detection_time_seconds = None
    if detected and context.first_event_at and context.detected_at:
        detection_time_seconds = max(0.0, (context.detected_at - context.first_event_at).total_seconds())
    risk_escalation_time_seconds = None
    if context.first_event_at and context.peak_at:
        risk_escalation_time_seconds = max(0.0, (context.peak_at - context.first_event_at).total_seconds())
    return SimulationResult(
        attack_type=context.attack_type,
        session_id=session_id,
        expected_phase=context.expected_phase,
        observed_phase=state.current_phase if state else "unknown",
        asg_detected=detected,
        first_event_at=context.first_event_at or timezone.now(),
        detected_at=context.detected_at,
        detection_time_seconds=detection_time_seconds,
        risk_peak=context.peak_risk,
        risk_escalation_time_seconds=risk_escalation_time_seconds,
        alerts_triggered=alerts_triggered,
        phase_correct=bool(state and state.current_phase == context.expected_phase),
        events_created=context.events_created,
        notes=context.notes,
    )


def simulate_scanner_bot() -> SimulationResult:
    context = SimulationContext(
        attack_type="Scanner Bot Simulation",
        expected_phase="probing",
        ip_address="198.51.100.23",
        user_agent="sqlmap/1.7 (scanner bot)",
        notes="Rapid endpoint enumeration across protected and decoy surfaces.",
    )

    def runner(ctx: SimulationContext) -> None:
        paths = [
            "/admin/",
            "/login/",
            "/api/",
            "/backup.sql",
            "/phpmyadmin/",
            "/dashboard/",
            "/internal/",
            "/wp-admin/",
        ]
        for path in paths:
            _record_request(ctx, path, method="GET", event_type="API_HIT" if path.startswith("/api/") else "REQUEST")
            _record_telemetry(ctx, path, event_type="SCANNER_PROBE", details={"path": path, "kind": "scanner"})

    return _run_scenario(context, runner)


def simulate_credential_stuffing() -> SimulationResult:
    context = SimulationContext(
        attack_type="Credential Stuffing Simulation",
        expected_phase="credential_access",
        ip_address="198.51.100.42",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        username_pool=["admin", "test", "support", "billing"],
        password_pool=["Password123!", "Spring2026!", "Honey123!", "admin123", "letmein"],
        notes="High-failure login spray across multiple usernames and passwords.",
    )

    def runner(ctx: SimulationContext) -> None:
        for username in ctx.username_pool:
            for password in ctx.password_pool:
                _record_login_attempt(ctx, username=username, password=password, success=False)
                _record_telemetry(ctx, "/login/", event_type="LOGIN_FAILURE_SIGNAL", details={"username": username, "attempt": password})
        _record_login_attempt(ctx, username="admin", password="CorrectHorseBatteryStaple!", success=True)

    return _run_scenario(context, runner)


def simulate_sql_injection_probe() -> SimulationResult:
    context = SimulationContext(
        attack_type="SQL Injection Probe Simulation",
        expected_phase="authentication_bypass_attempt",
        ip_address="203.0.113.17",
        user_agent="Mozilla/5.0 sqlmap",
        notes="Injection payloads spread across forms and query parameters.",
    )

    payloads = [
        "' OR 1=1--",
        "UNION SELECT username, password FROM users",
        "DROP TABLE users;--",
        "admin'--",
    ]

    def runner(ctx: SimulationContext) -> None:
        for idx, payload in enumerate(payloads):
            path = "/api/v1/orders/" if idx % 2 else "/login/"
            _record_request(ctx, path, method="POST" if idx % 2 else "GET", payload=payload, username="probe", event_type="API_HIT")
            _record_form_submission(ctx, "/checkout/", {"query": payload, "notes": payload}, suspicious=True)
            _record_telemetry(ctx, path, event_type="SQLI_PAYLOAD", details={"payload": payload, "location": path})

    return _run_scenario(context, runner)


def simulate_reconnaissance() -> SimulationResult:
    context = SimulationContext(
        attack_type="Reconnaissance Simulation",
        expected_phase="reconnaissance",
        ip_address="192.0.2.91",
        user_agent="Mozilla/5.0 (compatible; ResearchBot/1.0)",
        notes="Slow browsing of public pages and low-volume telemetry.",
    )

    def runner(ctx: SimulationContext) -> None:
        pages = ["/", "/blog/", "/shop/", "/product/wildflower-raw-honey/", "/product/forest-amber-honey/"]
        for page in pages:
            _record_request(ctx, page, method="GET")
            _record_telemetry(ctx, page, event_type="PAGE_VIEW", details={"page": page, "intent": "browse"})
        _record_request(ctx, "/research/", method="GET")

    return _run_scenario(context, runner)


def simulate_normal_user_baseline() -> SimulationResult:
    context = SimulationContext(
        attack_type="Normal User Baseline",
        expected_phase="reconnaissance",
        ip_address="203.0.113.88",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        notes="Normal shopping flow with product browsing and checkout interaction.",
    )

    def runner(ctx: SimulationContext) -> None:
        for page in ["/", "/shop/", "/product/wildflower-raw-honey/", "/product/acacia-honey/"]:
            _record_request(ctx, page, method="GET")
            _record_telemetry(ctx, page, event_type="SHOP_VIEW", details={"page": page})
        _record_form_submission(
            ctx,
            "/checkout/",
            {"first_name": "Ava", "last_name": "Stone", "email": "ava@example.com", "address": "1 Market Street"},
            suspicious=False,
        )
        _record_telemetry(ctx, "/checkout/", event_type="CHECKOUT_FLOW", details={"step": "review"})

    return _run_scenario(context, runner)


def run_attack_evaluation_suite() -> list[SimulationResult]:
    return [
        simulate_scanner_bot(),
        simulate_credential_stuffing(),
        simulate_sql_injection_probe(),
        simulate_reconnaissance(),
        simulate_normal_user_baseline(),
    ]


def render_results_table(results: list[SimulationResult]) -> str:
    lines = ["| Attack Type | ASG Detected | Detection Time | Risk Peak | Alerts Triggered |", "| --- | --- | --- | ---: | ---: |"]
    for result in results:
        detection_time = "n/a" if result.detection_time_seconds is None else f"{result.detection_time_seconds:.1f}s"
        lines.append(
            f"| {result.attack_type} | {'Yes' if result.asg_detected else 'No'} | {detection_time} | {result.risk_peak:.1f} | {result.alerts_triggered} |"
        )
    return "\n".join(lines)
