from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from django.core.cache import cache
from django.db import transaction
from django.http import HttpRequest
from django.utils import timezone

from .models import AlertEvent, AttackerState, AttackJourney, LoginAttempt, StateTransition, TelemetryEvent, UploadArtifact
from .utils import COMMAND_PATTERN, PROBING_PATH_PATTERN, SCANNER_PATTERN, SQLI_PATTERN, emit_structured_event, get_client_ip, get_or_create_honey_session_id


PHASE_PRIORITY = {
    "noise_or_observation": 0,
    "reconnaissance": 1,
    "surface_mapping": 2,
    "probing": 3,
    "resource_enumeration": 4,
    "credential_access": 5,
    "authentication_bypass_attempt": 6,
    "data_access_attempt": 7,
    "exploitation_attempt": 8,
    "execution_attempt": 9,
    "persistence_attempt": 10,
    "exfiltration_attempt": 11,
    "defense_evasion": 12,
    "post_exploitation": 13,
}

SENSITIVE_PATHS = re.compile(r"(wp-admin|phpmyadmin|grafana|jenkins|dashboard|cms|portal|internal|debug|phpinfo|api/docs|api/live/feed|api/research/report|admin|reports|export|download|backup|config|token|secrets|sessions|users)", re.I)
XSS_PATTERN = re.compile(r"(<script|onerror\s*=|onload\s*=|javascript:|%3cscript)", re.I)
LFI_PATTERN = re.compile(r"(\.\./|/etc/passwd|file://|php://|\\..\\)", re.I)
SSRF_PATTERN = re.compile(r"(169\.254\.169\.254|localhost|127\.0\.0\.1|0\.0\.0\.0|metadata)", re.I)
EXPLOIT_PATTERN = re.compile(r"(webshell|base64_decode|system\(|passthru\(|eval\(|cmd=|reverse shell|chmod\s+\+x)", re.I)
UPLOAD_PATTERN = re.compile(r"\.(php|phtml|asp|aspx|jsp|sh|exe|dll|bat|cmd|ps1|py)$", re.I)
EXPORT_PATTERN = re.compile(r"(export|download|csv|xlsx|dump|archive|backup)", re.I)


@dataclass
class Signal:
    name: str
    weight: float
    confidence: float
    reason: str
    phase_hint: str = ""


def _signal_record(signal: Signal, *, event_type: str) -> dict[str, Any]:
    return {
        "signal": signal.name,
        "weight": signal.weight,
        "confidence": signal.confidence,
        "contributing_event_type": event_type,
        "reason": signal.reason,
        "phase_hint": signal.phase_hint,
    }


def _signal_summary_text(signal_record: dict[str, Any]) -> str:
    mapping = {
        "scanner_behavior": "Scanner or scripted probing detected",
        "sensitive_path": "Repeated sensitive endpoint access",
        "login_failure": "Multiple login failures in short window",
        "injection_pattern": "SQL injection or traversal pattern detected",
        "confirmed_exploit": "Command execution or webshell marker detected",
        "exfiltration_probe": "Bulk download or export probing detected",
        "suspicious_upload": "Suspicious upload verdict observed",
        "canary_hit": "Canary token or beacon triggered",
        "privileged_access": "Sensitive admin or report access observed",
    }
    signal_name = str(signal_record.get("signal", ""))
    return mapping.get(signal_name, str(signal_record.get("reason", signal_name or "Unknown signal")))


def build_explanation_summary(state: AttackerState) -> tuple[list[str], str]:
    records = list(state.last_signals or [])
    records.sort(key=lambda item: float(item.get("weight", 0.0)), reverse=True)
    top_signals = [_signal_summary_text(record) for record in records[:3]]
    if not top_signals:
        top_signals = ["No strong signals recorded"]

    phase_phrase = {
        "noise_or_observation": "low-signal observation",
        "reconnaissance": "reconnaissance activity",
        "surface_mapping": "surface mapping",
        "probing": "probing behavior",
        "credential_access": "credential access attempts",
        "authentication_bypass_attempt": "authentication bypass attempts",
        "data_access_attempt": "data access attempts",
        "exploitation_attempt": "exploitation behavior",
        "execution_attempt": "execution-oriented behavior",
        "exfiltration_attempt": "exfiltration behavior",
        "post_exploitation": "post-exploitation behavior",
    }.get(state.current_phase, state.current_phase)

    explanation_summary = (
        f"High-risk {phase_phrase} detected based on "
        f"{', '.join(top_signals[:3]).rstrip('.')}."
    )
    return top_signals, explanation_summary


def _payload_text(payload: Any) -> str:
    if payload is None:
        return ""
    if isinstance(payload, str):
        return payload
    try:
        return json.dumps(payload, default=str)
    except Exception:
        return str(payload)


def _phase_rank(phase: str) -> int:
    return PHASE_PRIORITY.get(phase, 0)


def _next_action(phase: str) -> str:
    return {
        "reconnaissance": "Map more surfaces and probe hidden paths",
        "surface_mapping": "Search for admin, API, and backup endpoints",
        "probing": "Test forms, auth flows, and edge-case APIs",
        "resource_enumeration": "Enumerate users, exports, and objects",
        "credential_access": "Repeat login attempts or try auth bypass",
        "authentication_bypass_attempt": "Push toward protected data or admin access",
        "data_access_attempt": "Attempt bulk export or object disclosure",
        "exploitation_attempt": "Seek code execution or payload delivery",
        "execution_attempt": "Seek persistence or command reuse",
        "persistence_attempt": "Maintain foothold and revisit sensitive surfaces",
        "exfiltration_attempt": "Increase download volume or conceal activity",
        "defense_evasion": "Slow cadence or rotate tooling",
        "post_exploitation": "Pivot to adjacent systems or repeat access",
    }.get(phase, "Continue probing")


def _normalize_list(values: list[str], new_value: str, limit: int = 25) -> list[str]:
    if not new_value:
        return values
    if new_value in values:
        return values
    return (values + [new_value])[-limit:]


def _cache_key(session_id: str) -> str:
    return f"asg:state:{session_id}"


def _state_to_cache_dict(state: AttackerState) -> dict[str, Any]:
    return {
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
        "updated_at": state.updated_at.isoformat() if state.updated_at else None,
    }


def _hydrate_cached_state(session_id: str, cached: dict[str, Any]) -> AttackerState:
    state = AttackerState(session_id=session_id)
    for key, value in cached.items():
        if hasattr(state, key):
            setattr(state, key, value)
    return state


def get_attacker_state(session_id: str) -> AttackerState | None:
    state = AttackerState.objects.filter(session_id=session_id[:80]).first()
    if state:
        return state
    cached = cache.get(_cache_key(session_id[:80]))
    if isinstance(cached, dict) and cached.get("session_id") == session_id[:80]:
        return _hydrate_cached_state(session_id[:80], cached)
    return None


def _detect_signal_bundle(request: HttpRequest, event_type: str, path: str, payload_text: str, source_model: str, state: AttackerState) -> tuple[str, list[Signal], float, float, float, str]:
    combined = f"{path} {payload_text} {request.META.get('QUERY_STRING', '')}"
    user_agent = request.META.get("HTTP_USER_AGENT", "")
    phase = state.current_phase or "noise_or_observation"
    signals: list[Signal] = []
    risk_delta = 0.0
    confidence_delta = 0.0
    intent_delta = 0.0
    reason = "routine observation"

    if SCANNER_PATTERN.search(user_agent):
        signals.append(Signal("scanner_behavior", 20, 0.7, "Scanner or scripted user-agent detected", "probing"))
        phase = max(phase, "probing", key=_phase_rank)
        risk_delta += 20
        confidence_delta += 0.18
        reason = "scanner signature"

    if SENSITIVE_PATHS.search(path):
        signals.append(Signal("sensitive_path", 10, 0.45, "Sensitive path requested", "surface_mapping"))
        phase = max(phase, "surface_mapping", key=_phase_rank)
        risk_delta += 10
        confidence_delta += 0.08
        reason = "sensitive surface access"

    if SQLI_PATTERN.search(combined) or XSS_PATTERN.search(combined) or LFI_PATTERN.search(combined) or SSRF_PATTERN.search(combined):
        signals.append(Signal("injection_pattern", 25, 0.9, "Injection or traversal marker detected", "authentication_bypass_attempt"))
        phase = max(phase, "authentication_bypass_attempt", key=_phase_rank)
        risk_delta += 25
        confidence_delta += 0.25
        reason = "injection marker"

    if COMMAND_PATTERN.search(combined) or EXPLOIT_PATTERN.search(combined):
        signals.append(Signal("confirmed_exploit", 50, 0.97, "Command or webshell-like marker detected", "execution_attempt"))
        phase = max(phase, "execution_attempt", key=_phase_rank)
        risk_delta += 50
        confidence_delta += 0.35
        reason = "exploit marker"

    if EXPORT_PATTERN.search(combined):
        signals.append(Signal("exfiltration_probe", 18, 0.7, "Bulk download or export behavior", "exfiltration_attempt"))
        phase = max(phase, "exfiltration_attempt", key=_phase_rank)
        risk_delta += 18
        confidence_delta += 0.15
        reason = "exfiltration probe"

    if event_type == "LOGIN_ATTEMPT" or path.startswith("/login") or path.startswith("/api/login"):
        attempt = LoginAttempt.objects.filter(session_id=state.session_id).order_by("-timestamp").first()
        if attempt and not attempt.success:
            signals.append(Signal("login_failure", 15, 0.72, "Failed login attempt", "credential_access"))
            phase = max(phase, "credential_access", key=_phase_rank)
            risk_delta += 15
            confidence_delta += 0.2
            reason = "login failure"
        elif attempt and attempt.success:
            phase = max(phase, "credential_access", key=_phase_rank)
            confidence_delta += 0.08

    if source_model == "UploadArtifact" or "upload" in path.lower():
        upload = UploadArtifact.objects.filter(metadata__session_id=state.session_id).order_by("-timestamp").first()
        if upload and upload.verdict != "clean":
            signals.append(Signal("suspicious_upload", 30, 0.85, f"Suspicious upload verdict: {upload.verdict}", "exploitation_attempt"))
            phase = max(phase, "exploitation_attempt", key=_phase_rank)
            risk_delta += 30
            confidence_delta += 0.24
            reason = "suspicious upload"

    if source_model == "CanaryToken" or "/beacon/" in path:
        signals.append(Signal("canary_hit", 35, 0.95, "Canary token or beacon hit", "post_exploitation"))
        phase = max(phase, "post_exploitation", key=_phase_rank)
        risk_delta += 35
        confidence_delta += 0.3
        reason = "canary hit"

    if event_type in {"API_HIT", "REQUEST", "FORM_SUBMISSION"} and any(token in path.lower() for token in ["/api/internal/exec", "/merchant", "/admin", "/research/report", "/api/docs", "/api/live/feed"]):
        signals.append(Signal("privileged_access", 40, 0.7, "Sensitive admin or report endpoint accessed", "data_access_attempt"))
        phase = max(phase, "data_access_attempt", key=_phase_rank)
        risk_delta += 40
        confidence_delta += 0.17
        reason = "privileged access"

    if not signals:
        if any(token in path.lower() for token in ["/shop", "/blog", "/product", "/", "/research/"]):
            phase = max(phase, "reconnaissance", key=_phase_rank)
            risk_delta += 2
            confidence_delta += 0.03
            reason = "routine browsing"
        elif PROBING_PATH_PATTERN.search(path):
            phase = max(phase, "probing", key=_phase_rank)
            risk_delta += 5
            confidence_delta += 0.08
            reason = "probing path pattern"

    if source_model == "TelemetryEvent":
        phase = max(phase, "reconnaissance", key=_phase_rank)
        confidence_delta += 0.04

    intent_delta = sum(signal.weight for signal in signals) * 0.7
    if phase in {"execution_attempt", "persistence_attempt", "exfiltration_attempt", "post_exploitation"}:
        intent_delta += 10

    return phase, signals, risk_delta, confidence_delta, intent_delta, reason


def _snapshot_for_state(state: AttackerState, signals: list[Signal]) -> dict[str, Any]:
    signal_records = [_signal_record(signal, event_type=str(state.last_event_type or "")) for signal in signals[:8]]
    return {
        "session_id": state.session_id,
        "current_phase": state.current_phase,
        "previous_phase": state.previous_phase,
        "phase_confidence": round(state.phase_confidence, 3),
        "risk_score": round(state.risk_score, 2),
        "intent_score": round(state.intent_score, 2),
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
        "likely_next_action": _next_action(state.current_phase),
        "recent_signals": signal_records,
        "meta": state.meta,
    }


def _maybe_emit_state_alert(request: HttpRequest, state: AttackerState, signals: list[Signal], previous_phase: str) -> None:
    trigger = None
    if state.risk_score >= 85:
        trigger = "risk_threshold_high"
    elif state.risk_score >= 70:
        trigger = "risk_threshold"
    if state.current_phase in {"execution_attempt", "exfiltration_attempt", "post_exploitation"}:
        trigger = f"phase_{state.current_phase}"

    if not trigger:
        return

    detail = (
        f"ASG state alert: phase={state.current_phase} risk={state.risk_score:.1f} "
        f"confidence={state.phase_confidence:.2f} signals={', '.join(signal.name for signal in signals[:5]) or 'none'}"
    )

    from .deception import enqueue_alert_event

    alert = enqueue_alert_event(
        request,
        alert_type="ASG_STATE_ALERT",
        detail=detail[:300],
        channels={"discord": "", "telegram": "", "email": ""},
    )
    alert.metadata = {
        **(alert.metadata or {}),
        "asg": {
            "session_id": state.session_id,
            "current_phase": state.current_phase,
            "previous_phase": previous_phase,
            "risk_score": round(state.risk_score, 2),
            "phase_confidence": round(state.phase_confidence, 3),
            "signals": [signal.name for signal in signals[:5]],
            "trigger": trigger,
        },
    }
    alert.save(update_fields=["metadata"])
    state.alert_count += 1
    state.save(update_fields=["alert_count"])


def update_attacker_state(
    session_id: str,
    event_type: str,
    path: str,
    request: HttpRequest,
    source_model: str,
    payload: Any = None,
) -> AttackerState:
    session_id = str(session_id or get_or_create_honey_session_id(request))[:80]
    payload_text = _payload_text(payload)
    now = timezone.now()

    with transaction.atomic():
        state = AttackerState.objects.select_for_update().filter(session_id=session_id).first()
        if state is None:
            state = AttackerState(session_id=session_id)

        previous_phase = state.current_phase or "noise_or_observation"
        phase, signals, risk_delta, confidence_delta, intent_delta, reason = _detect_signal_bundle(
            request=request,
            event_type=event_type,
            path=path or request.path,
            payload_text=payload_text,
            source_model=source_model,
            state=state,
        )

        age_minutes = 0.0
        if state.last_observed_at:
            age_minutes = max(0.0, (now - state.last_observed_at).total_seconds() / 60.0)
        decay = min(0.995, max(0.82, 0.985 ** age_minutes))
        state.current_phase = phase if _phase_rank(phase) >= _phase_rank(previous_phase) else previous_phase
        if state.current_phase in {"defense_evasion"}:
            state.current_phase = phase
        state.previous_phase = previous_phase
        state.phase_confidence = min(1.0, max(0.0, (state.phase_confidence * 0.92) + confidence_delta))
        state.risk_score = min(100.0, max(0.0, (state.risk_score * decay) + risk_delta))
        state.intent_score = min(100.0, max(0.0, (state.intent_score * 0.95) + intent_delta))
        state.last_event_type = event_type[:80]
        state.last_observed_path = (path or request.path)[:1000]
        state.last_observed_at = now
        state.event_count += 1
        if signals:
            state.suspicious_event_count += 1

        ip_address = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT", "")[:1000]
        state.primary_ip = state.primary_ip or ip_address or None
        state.primary_user_agent = state.primary_user_agent or user_agent
        state.last_signals = [_signal_record(signal, event_type=event_type) for signal in signals[:8]]

        meta = dict(state.meta or {})
        meta["ips_seen"] = _normalize_list(list(meta.get("ips_seen", [])), ip_address)
        meta["user_agents_seen"] = _normalize_list(list(meta.get("user_agents_seen", [])), user_agent)
        meta["source_models"] = _normalize_list(list(meta.get("source_models", [])), source_model)
        meta["last_reason"] = reason
        meta["last_risk_delta"] = round(risk_delta, 2)
        meta["last_confidence_delta"] = round(confidence_delta, 3)
        meta["likely_next_action"] = _next_action(state.current_phase)
        state.meta = meta
        state.unique_ips_count = len(meta["ips_seen"])
        state.unique_user_agents_count = len(meta["user_agents_seen"])
        state.state_snapshot = _snapshot_for_state(state, signals)
        state.save()

        if state.current_phase != previous_phase:
            StateTransition.objects.create(
                attacker_state=state,
                session_id=session_id,
                from_phase=previous_phase,
                to_phase=state.current_phase,
                trigger_event_type=event_type[:80],
                trigger_path=(path or request.path)[:1000],
                trigger_reason=reason[:300],
                risk_delta=round(risk_delta, 2),
                confidence_delta=round(confidence_delta, 3),
                event_reference={
                    "source_model": source_model,
                    "payload": payload_text[:1000],
                    "signals": [_signal_record(signal, event_type=event_type) for signal in signals[:6]],
                },
            )

        if state.risk_score >= 70 or state.current_phase in {"execution_attempt", "exfiltration_attempt", "post_exploitation"}:
            _maybe_emit_state_alert(request, state, signals, previous_phase)

        cache.set(_cache_key(session_id), _state_to_cache_dict(state), timeout=60 * 20)

    try:
        from .deception import upsert_attack_journey

        upsert_attack_journey(
            session_id=session_id,
            entry_point=path[:200],
            notes=f"ASG phase={state.current_phase} risk={state.risk_score:.1f} confidence={state.phase_confidence:.2f}",
        )
    except Exception:
        pass

    emit_structured_event(
        "asg_state_update",
        session_id=session_id,
        event_type=event_type,
        source_model=source_model,
        phase=state.current_phase,
        previous_phase=previous_phase,
        risk_score=round(state.risk_score, 2),
        phase_confidence=round(state.phase_confidence, 3),
        trigger_reason=reason,
        signals=[_signal_record(signal, event_type=event_type) for signal in signals[:6]],
    )
    return state


def build_state_summary(limit: int = 25) -> list[dict[str, Any]]:
    states = AttackerState.objects.order_by("-risk_score", "-updated_at")[:limit]
    return [
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
            "campaign_id": state.campaign_id,
            "likely_next_action": (state.state_snapshot or {}).get("likely_next_action", _next_action(state.current_phase)),
        }
        for state in states
    ]
