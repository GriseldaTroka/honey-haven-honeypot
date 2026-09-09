from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from datetime import timedelta
from typing import Any

from django.db.models import Avg, Count, Max
from django.utils import timezone

from .models import AlertEvent, AttackJourney, DetectionAlert, HoneypotLog, IOCIndicator, LoginAttempt, PaymentRecord, SupportTicket, TelemetryEvent, UploadArtifact
from .utils import COMMAND_PATTERN, PROBING_PATH_PATTERN, SCANNER_PATTERN, SQLI_PATTERN


OPEN_STATUSES = {"OPEN", "INVESTIGATING"}
CLOSED_STATUSES = {"RESOLVED", "FALSE_POSITIVE"}


def _iso(value: Any) -> str | None:
    return value.isoformat() if hasattr(value, "isoformat") else None


def _serialize_journey(journey: AttackJourney | None) -> dict[str, Any] | None:
    if not journey:
        return None
    return {
        "id": journey.id,
        "session_id": journey.session_id,
        "campaign_id": journey.campaign_id,
        "risk_score": journey.risk_score,
        "confidence_score": journey.confidence_score,
        "intent_score": journey.intent_score,
        "phases": journey.phases,
        "tools_used": journey.tools_used,
        "escalation_attempts": journey.escalation_attempts,
        "recon_path": journey.recon_path,
        "payload_evolution": journey.payload_evolution,
        "event_count": journey.event_count,
        "first_seen": _iso(journey.first_seen),
        "last_seen": _iso(journey.last_seen),
    }


def _serialize_ioc(indicator: IOCIndicator) -> dict[str, Any]:
    return {
        "id": indicator.id,
        "session_id": indicator.session_id,
        "ioc_type": indicator.ioc_type,
        "ioc_value": indicator.ioc_value,
        "source_model": indicator.source_model,
        "source_object_id": indicator.source_object_id,
        "source_event": indicator.source_event,
        "attack_phase": indicator.attack_phase,
        "evidence_summary": indicator.evidence_summary,
        "first_seen": _iso(indicator.first_seen),
        "last_seen": _iso(indicator.last_seen),
    }


def _serialize_evidence_item(model_name: str, item: Any, *, session_id: str, summary: str) -> dict[str, Any]:
    return {
        "model": model_name,
        "id": item.id,
        "session_id": session_id,
        "timestamp": _iso(getattr(item, "timestamp", None)),
        "summary": summary,
    }


def _fingerprint(*parts: Any) -> str:
    raw = "|".join(str(part) for part in parts if part not in (None, ""))
    return hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:40]


def _response_recommendation(severity: str) -> list[str]:
    severity = severity.upper()
    if severity == "CRITICAL":
        return ["isolate source IP", "investigate related sessions", "rotate credentials"]
    if severity == "HIGH":
        return ["review uploaded artifacts", "inspect attack journey"]
    if severity == "MEDIUM":
        return ["monitor activity"]
    return ["record intelligence"]


def _session_iocs(session_id: str) -> list[IOCIndicator]:
    return list(IOCIndicator.objects.filter(session_id=session_id).select_related("attack_journey").order_by("first_seen", "id"))


def _session_journey(session_id: str) -> AttackJourney | None:
    return AttackJourney.objects.filter(session_id=session_id).first()


def _session_alert_events(session_id: str) -> list[AlertEvent]:
    return list(AlertEvent.objects.filter(metadata__session_id=session_id).order_by("timestamp", "id"))


def _session_telemetry(session_id: str) -> list[TelemetryEvent]:
    return list(TelemetryEvent.objects.filter(session_id=session_id).order_by("timestamp", "id"))


def _session_honeypot_logs(session_id: str) -> list[HoneypotLog]:
    return list(HoneypotLog.objects.filter(session_id=session_id).order_by("timestamp", "id"))


def _session_logins(session_id: str) -> list[LoginAttempt]:
    return list(LoginAttempt.objects.filter(session_id=session_id).order_by("timestamp", "id"))


def _session_uploads(session_id: str) -> list[UploadArtifact]:
    return list(UploadArtifact.objects.filter(metadata__session_id=session_id).order_by("timestamp", "id"))


def _session_payments(session_id: str) -> list[PaymentRecord]:
    return list(PaymentRecord.objects.filter(metadata__session_id=session_id).order_by("timestamp", "id"))


def _session_tickets(session_id: str) -> list[SupportTicket]:
    return list(SupportTicket.objects.filter(metadata__session_id=session_id).order_by("timestamp", "id"))


def _detect_brute_force(session_id: str, *, ip_address: str = "", source_event: str = "", source_object_id: int | None = None) -> dict[str, Any] | None:
    cutoff = timezone.now() - timedelta(minutes=5)
    query = LoginAttempt.objects.filter(success=False, timestamp__gte=cutoff)
    if session_id:
        query = query.filter(session_id=session_id)
    if ip_address:
        query = query.filter(ip_address=ip_address)
    failures = list(query.order_by("timestamp", "id"))
    if len(failures) < 5:
        return None

    latest = failures[-1]
    journey = _session_journey(session_id)
    related_iocs = [_serialize_ioc(item) for item in _session_iocs(session_id)]
    severity = "CRITICAL" if len(failures) >= 10 else "HIGH"
    confidence = min(0.99, 0.7 + (len(failures) * 0.03))
    fingerprint = _fingerprint("BRUTE_FORCE_ACTIVITY", session_id, ip_address or latest.ip_address or "unknown")
    evidence = [_serialize_evidence_item("LoginAttempt", attempt, session_id=session_id, summary=f"failed login for {attempt.username or 'anonymous'}") for attempt in failures]
    return {
        "rule_name": "BRUTE_FORCE_ACTIVITY",
        "severity": severity,
        "confidence": round(confidence, 2),
        "description": f"{len(failures)} failed login attempts from the same source within 5 minutes.",
        "related_session": session_id,
        "related_journey": _serialize_journey(journey),
        "related_campaign": journey.campaign_id if journey else "",
        "related_iocs": related_iocs,
        "evidence": evidence,
        "evidence_source_model": "LoginAttempt",
        "evidence_source_object_id": latest.id,
        "evidence_source_event": "LoginAttempt",
        "evidence_fingerprint": fingerprint,
        "evidence_summary": f"{len(failures)} failed login attempts from {ip_address or latest.ip_address or 'unknown'}",
        "response_recommendation": _response_recommendation(severity),
        "metadata": {
            "failed_login_count": len(failures),
            "source_ip": ip_address or latest.ip_address or "",
            "window_minutes": 5,
        },
    }


def _detect_sql_injection(session_id: str) -> dict[str, Any] | None:
    honeypot_logs = _session_honeypot_logs(session_id)
    telemetry_events = _session_telemetry(session_id)
    suspicious_logs = [
        log for log in honeypot_logs
        if SQLI_PATTERN.search(f"{log.requested_url} {log.query_params} {log.payload}")
        or log.attack_classification == "SQL_INJECTION_ATTEMPT"
    ]
    suspicious_telemetry = [
        event for event in telemetry_events
        if SQLI_PATTERN.search(f"{event.path} {event.details}") or PROBING_PATH_PATTERN.search(event.path or "")
    ]
    probe_count = len(suspicious_logs) + len(suspicious_telemetry)
    if probe_count == 0:
        return None

    journey = _session_journey(session_id)
    related_iocs = [_serialize_ioc(item) for item in _session_iocs(session_id)]
    severity = "CRITICAL" if probe_count >= 4 else ("HIGH" if probe_count >= 2 else "MEDIUM")
    confidence = min(0.99, 0.75 + (probe_count * 0.05))
    latest_source = suspicious_logs[-1] if suspicious_logs else suspicious_telemetry[-1]
    evidence = [
        _serialize_evidence_item("HoneypotLog", item, session_id=session_id, summary=f"SQLi probe on {item.requested_url}")
        for item in suspicious_logs
    ] + [
        _serialize_evidence_item("TelemetryEvent", item, session_id=session_id, summary=f"telemetry path {item.path}")
        for item in suspicious_telemetry
    ]
    return {
        "rule_name": "SQL_INJECTION_ACTIVITY",
        "severity": severity,
        "confidence": round(confidence, 2),
        "description": f"Repeated SQL injection-style probing detected ({probe_count} indicators).",
        "related_session": session_id,
        "related_journey": _serialize_journey(journey),
        "related_campaign": journey.campaign_id if journey else "",
        "related_iocs": related_iocs,
        "evidence": evidence,
        "evidence_source_model": getattr(latest_source, "__class__", type(latest_source)).__name__,
        "evidence_source_object_id": latest_source.id,
        "evidence_source_event": "HoneypotLog" if suspicious_logs else "TelemetryEvent",
        "evidence_fingerprint": _fingerprint("SQL_INJECTION_ACTIVITY", session_id),
        "evidence_summary": f"SQL injection behavior detected across {probe_count} probes",
        "response_recommendation": _response_recommendation(severity),
        "metadata": {
            "probe_count": probe_count,
            "honeypot_log_ids": [item.id for item in suspicious_logs],
            "telemetry_event_ids": [item.id for item in suspicious_telemetry],
        },
    }


def _detect_malicious_upload(session_id: str) -> dict[str, Any] | None:
    uploads = _session_uploads(session_id)
    suspicious_uploads = [
        upload for upload in uploads
        if upload.verdict != "clean" or upload.entropy > 6.5 or any(upload.filename.lower().endswith(ext) for ext in (".php", ".phtml", ".aspx", ".jsp", ".sh", ".exe"))
    ]
    if not suspicious_uploads:
        return None

    journey = _session_journey(session_id)
    related_iocs = [_serialize_ioc(item) for item in _session_iocs(session_id)]
    latest = suspicious_uploads[-1]
    severity = "CRITICAL" if latest.verdict == "webshell-suspected" or latest.entropy >= 7.5 else "HIGH"
    confidence = min(0.99, 0.82 + (max(latest.entropy, 1.0) / 20.0))
    evidence = [
        _serialize_evidence_item("UploadArtifact", item, session_id=session_id, summary=f"{item.filename} ({item.verdict})")
        for item in suspicious_uploads
    ]
    return {
        "rule_name": "MALICIOUS_UPLOAD",
        "severity": severity,
        "confidence": round(confidence, 2),
        "description": f"Suspicious upload activity detected for {latest.filename}.",
        "related_session": session_id,
        "related_journey": _serialize_journey(journey),
        "related_campaign": journey.campaign_id if journey else "",
        "related_iocs": related_iocs,
        "evidence": evidence,
        "evidence_source_model": "UploadArtifact",
        "evidence_source_object_id": latest.id,
        "evidence_source_event": "UploadArtifact",
        "evidence_fingerprint": _fingerprint("MALICIOUS_UPLOAD", session_id, latest.id),
        "evidence_summary": f"{latest.filename} flagged as {latest.verdict}",
        "response_recommendation": _response_recommendation(severity),
        "metadata": {
            "upload_ids": [item.id for item in suspicious_uploads],
            "entropy": latest.entropy,
            "verdict": latest.verdict,
        },
    }


def _detect_account_compromise(session_id: str, *, ip_address: str = "") -> dict[str, Any] | None:
    successes = [attempt for attempt in _session_logins(session_id) if attempt.success]
    if not successes:
        return None

    cutoff = timezone.now() - timedelta(minutes=10)
    failures = LoginAttempt.objects.filter(success=False, timestamp__gte=cutoff)
    if session_id:
        failures = failures.filter(session_id=session_id)
    if ip_address:
        failures = failures.filter(ip_address=ip_address)
    failures = list(failures.order_by("timestamp", "id"))
    if len(failures) < 5:
        return None

    success_attempt = successes[-1]
    journey = _session_journey(session_id)
    related_iocs = [_serialize_ioc(item) for item in _session_iocs(session_id)]
    evidence = [
        _serialize_evidence_item("LoginAttempt", item, session_id=session_id, summary=f"failed login for {item.username or 'anonymous'}")
        for item in failures
    ] + [
        _serialize_evidence_item("LoginAttempt", success_attempt, session_id=session_id, summary=f"successful login for {success_attempt.username or 'anonymous'}")
    ]
    return {
        "rule_name": "ACCOUNT_COMPROMISE",
        "severity": "CRITICAL",
        "confidence": 0.96,
        "description": f"Successful login after repeated failures from {ip_address or success_attempt.ip_address or 'unknown source'}.",
        "related_session": session_id,
        "related_journey": _serialize_journey(journey),
        "related_campaign": journey.campaign_id if journey else "",
        "related_iocs": related_iocs,
        "evidence": evidence,
        "evidence_source_model": "LoginAttempt",
        "evidence_source_object_id": success_attempt.id,
        "evidence_source_event": "LoginAttempt",
        "evidence_fingerprint": _fingerprint("ACCOUNT_COMPROMISE", session_id, success_attempt.id),
        "evidence_summary": f"Successful login after {len(failures)} failures",
        "response_recommendation": _response_recommendation("CRITICAL"),
        "metadata": {
            "failed_login_count": len(failures),
            "success_login_id": success_attempt.id,
        },
    }


def _detect_attack_chain_progress(session_id: str) -> dict[str, Any] | None:
    journey = _session_journey(session_id)
    if not journey:
        return None

    phase_names = [str(phase.get("phase", phase)) if isinstance(phase, dict) else str(phase) for phase in (journey.phases or [])]
    phase_buckets = set()
    for phase in phase_names:
        lowered = phase.lower()
        if lowered in {"reconnaissance", "surface_mapping", "probing", "resource_enumeration"}:
            phase_buckets.add("recon")
        elif lowered in {"credential_access", "authentication_bypass_attempt", "data_access_attempt"}:
            phase_buckets.add("access")
        elif lowered in {"exploitation_attempt", "execution_attempt", "persistence_attempt", "post_exploitation"}:
            phase_buckets.add("exploit")
    if len(phase_buckets) < 2 and journey.risk_score < 70 and journey.event_count < 5:
        return None

    iocs = _session_iocs(session_id)
    related_iocs = [_serialize_ioc(item) for item in iocs]
    alerts = _session_alert_events(session_id)
    telemetry = _session_telemetry(session_id)
    evidence = [
        _serialize_evidence_item("AttackJourney", journey, session_id=session_id, summary=f"journey with phases {', '.join(phase_names[:5])}")
    ]
    if alerts:
        evidence.extend(_serialize_evidence_item("AlertEvent", item, session_id=session_id, summary=item.detail) for item in alerts[-3:])
    if telemetry:
        evidence.extend(_serialize_evidence_item("TelemetryEvent", item, session_id=session_id, summary=item.path or item.event_type) for item in telemetry[-3:])

    severity = "CRITICAL" if journey.risk_score >= 90 or len(phase_buckets) >= 3 else "HIGH"
    confidence = min(0.99, 0.78 + (len(phase_buckets) * 0.07) + (min(journey.event_count, 20) * 0.005))
    return {
        "rule_name": "ATTACK_CHAIN_PROGRESS",
        "severity": severity,
        "confidence": round(confidence, 2),
        "description": "Multi-stage attacker behavior observed across reconnaissance and exploitation phases.",
        "related_session": session_id,
        "related_journey": _serialize_journey(journey),
        "related_campaign": journey.campaign_id,
        "related_iocs": related_iocs,
        "evidence": evidence,
        "evidence_source_model": "AttackJourney",
        "evidence_source_object_id": journey.id,
        "evidence_source_event": "AttackJourney",
        "evidence_fingerprint": _fingerprint("ATTACK_CHAIN_PROGRESS", session_id, journey.id),
        "evidence_summary": f"Attack journey progressed through {', '.join(sorted(phase_buckets)) or 'multiple'} stages",
        "response_recommendation": _response_recommendation(severity),
        "metadata": {
            "phase_buckets": sorted(phase_buckets),
            "phase_names": phase_names,
            "alert_ids": [alert.id for alert in alerts],
            "telemetry_ids": [item.id for item in telemetry],
            "ioc_ids": [indicator.id for indicator in iocs],
        },
    }


def evaluate_session_detections(session_id: str, *, trigger: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    trigger = trigger or {}
    ip_address = str(trigger.get("ip_address", "") or "")
    source_event = str(trigger.get("source_event", "") or "")
    source_model = str(trigger.get("source_model", "") or "")
    source_object_id = trigger.get("source_object_id")

    detections: list[dict[str, Any]] = []
    for detector in (
        lambda: _detect_brute_force(session_id, ip_address=ip_address, source_event=source_event, source_object_id=source_object_id),
        lambda: _detect_sql_injection(session_id),
        lambda: _detect_malicious_upload(session_id),
        lambda: _detect_account_compromise(session_id, ip_address=ip_address),
        lambda: _detect_attack_chain_progress(session_id),
    ):
        detection = detector()
        if detection:
            detections.append(detection)
    return detections


def _bounded_session_iocs(session_id: str, *, limit: int = 25) -> list[IOCIndicator]:
    if not session_id:
        return []
    return list(
        IOCIndicator.objects.filter(session_id=session_id)
        .select_related("attack_journey")
        .order_by("first_seen", "id")[:limit]
    )


def _bounded_session_iocs_by_session(session_ids: list[str], *, limit: int = 25) -> dict[str, list[IOCIndicator]]:
    session_ids = [str(session_id or "")[:80] for session_id in session_ids if session_id]
    if not session_ids:
        return {}

    ordered_session_ids = list(dict.fromkeys(session_ids))
    grouped: dict[str, list[IOCIndicator]] = {}
    for session_id in ordered_session_ids:
        related = list(
            IOCIndicator.objects.filter(session_id=session_id)
            .select_related("attack_journey")
            .order_by("first_seen", "id")[:limit]
        )
        if related:
            grouped[session_id] = related
    return grouped


def serialize_detection_alert(
    alert: DetectionAlert,
    *,
    include_evidence: bool = False,
    related_iocs_by_session: dict[str, list[IOCIndicator]] | None = None,
) -> dict[str, Any]:
    journey = alert.attack_journey
    if related_iocs_by_session is not None:
        related_iocs = [_serialize_ioc(item) for item in related_iocs_by_session.get(alert.session_id, [])]
    else:
        related_iocs = [_serialize_ioc(item) for item in _bounded_session_iocs(alert.session_id, limit=25)]
    payload = {
        "id": alert.id,
        "rule_name": alert.rule_name,
        "severity": alert.severity,
        "confidence_score": alert.confidence_score,
        "status": alert.status,
        "description": alert.description,
        "session_id": alert.session_id,
        "attack_journey": _serialize_journey(journey),
        "campaign_id": alert.campaign_id,
        "created_at": _iso(alert.created_at),
        "updated_at": _iso(alert.updated_at),
        "resolved_at": _iso(alert.resolved_at),
        "evidence_summary": alert.evidence_summary,
        "response_recommendation": alert.response_recommendation,
        "related_ioc_count": len(related_iocs),
        "related_iocs": related_iocs,
        "metadata": alert.metadata,
        "evidence_source_model": alert.evidence_source_model,
        "evidence_source_object_id": alert.evidence_source_object_id,
        "evidence_source_event": alert.evidence_source_event,
        "evidence_fingerprint": alert.evidence_fingerprint,
    }
    if include_evidence:
        payload["evidence"] = alert.metadata.get("evidence", []) if isinstance(alert.metadata, dict) else []
    return payload


def _default_status_history(alert: DetectionAlert) -> list[dict[str, Any]]:
    history = []
    if isinstance(alert.metadata, dict):
        maybe_history = alert.metadata.get("status_history", [])
        if isinstance(maybe_history, list):
            history = list(maybe_history)
    return history


def upsert_detection_alert(detection: dict[str, Any]) -> DetectionAlert:
    session_id = str(detection.get("related_session", "") or "")[:80]
    fingerprint = str(detection.get("evidence_fingerprint", "") or "")[:200]
    rule_name = str(detection.get("rule_name", "") or "")[:120]
    defaults = {
        "severity": detection.get("severity", "LOW"),
        "confidence_score": float(detection.get("confidence", 0.0) or 0.0),
        "description": str(detection.get("description", "") or "")[:500],
        "session_id": session_id,
        "attack_journey": _session_journey(session_id),
        "campaign_id": str(detection.get("related_campaign", "") or "")[:120],
        "evidence_source_model": str(detection.get("evidence_source_model", "") or "")[:80],
        "evidence_source_object_id": detection.get("evidence_source_object_id"),
        "evidence_source_event": str(detection.get("evidence_source_event", "") or "")[:80],
        "evidence_fingerprint": fingerprint,
        "evidence_summary": str(detection.get("evidence_summary", "") or "")[:500],
        "response_recommendation": detection.get("response_recommendation", _response_recommendation(str(detection.get("severity", "LOW")))),
        "metadata": {
            **(detection.get("metadata", {}) if isinstance(detection.get("metadata", {}), dict) else {}),
            "related_iocs": detection.get("related_iocs", []),
            "evidence": detection.get("evidence", []),
        },
    }
    alert, created = DetectionAlert.objects.get_or_create(rule_name=rule_name, session_id=session_id, evidence_fingerprint=fingerprint, defaults=defaults)
    if not created:
        current_status = alert.status
        current_history = _default_status_history(alert)
        alert.severity = defaults["severity"]
        alert.confidence_score = defaults["confidence_score"]
        alert.description = defaults["description"]
        alert.attack_journey = defaults["attack_journey"]
        alert.campaign_id = defaults["campaign_id"]
        alert.evidence_source_model = defaults["evidence_source_model"]
        alert.evidence_source_object_id = defaults["evidence_source_object_id"]
        alert.evidence_source_event = defaults["evidence_source_event"]
        alert.evidence_summary = defaults["evidence_summary"]
        alert.response_recommendation = defaults["response_recommendation"]
        alert.metadata = {**defaults["metadata"], "status_history": current_history}
        if current_status in CLOSED_STATUSES:
            alert.resolved_at = alert.resolved_at
        alert.save()
    return alert


def run_detection_pipeline(session_id: str, *, trigger: dict[str, Any] | None = None) -> list[DetectionAlert]:
    detections = evaluate_session_detections(session_id, trigger=trigger)
    alerts: list[DetectionAlert] = []
    for detection in detections:
        alerts.append(upsert_detection_alert(detection))
    return alerts


def list_detection_alerts(*, status: str | None = None, limit: int = 100) -> list[DetectionAlert]:
    query = DetectionAlert.objects.select_related("attack_journey").order_by("-created_at", "-updated_at")
    if status:
        query = query.filter(status=status)
    return list(query[:limit])


def get_detection_alert(alert_id: int) -> DetectionAlert | None:
    return DetectionAlert.objects.select_related("attack_journey").filter(id=alert_id).first()


def update_detection_alert_status(alert: DetectionAlert, status: str, *, changed_by: str = "") -> DetectionAlert:
    status = status.upper()
    if status not in {choice[0] for choice in DetectionAlert.STATUS_CHOICES}:
        raise ValueError("Invalid alert status")
    history = _default_status_history(alert)
    history.append({"status": status, "changed_at": timezone.now().isoformat(), "changed_by": changed_by})
    alert.status = status
    alert.metadata = {**(alert.metadata or {}), "status_history": history, "last_status_change": status, "changed_by": changed_by}
    if status in {"RESOLVED", "FALSE_POSITIVE"}:
        alert.resolved_at = alert.resolved_at or timezone.now()
    else:
        alert.resolved_at = None
    alert.save(update_fields=["status", "metadata", "resolved_at", "updated_at"])
    return alert


def build_detection_dashboard(*, limit: int = 100) -> dict[str, Any]:
    alerts = DetectionAlert.objects.select_related("attack_journey").order_by("-created_at", "-updated_at")
    active_alerts = alerts.filter(status__in=OPEN_STATUSES)
    unresolved = alerts.exclude(status__in=CLOSED_STATUSES)
    resolved_alerts = alerts.filter(status__in=CLOSED_STATUSES, resolved_at__isnull=False)

    unresolved_alerts = list(unresolved[:limit])
    recent_alerts = list(alerts[:limit])
    alert_session_ids = [alert.session_id for alert in unresolved_alerts + recent_alerts if alert.session_id]
    related_iocs_by_session = _bounded_session_iocs_by_session(alert_session_ids, limit=25)

    severity_counts = list(
        alerts.values("severity").annotate(total=Count("id")).order_by("-total", "severity")
    )
    rule_counts = list(
        alerts.values("rule_name").annotate(total=Count("id")).order_by("-total", "rule_name")
    )

    highest_risk_campaigns: list[dict[str, Any]] = []
    for campaign_id in alerts.exclude(campaign_id="").order_by().values_list("campaign_id", flat=True).distinct():
        campaign_alerts = list(alerts.filter(campaign_id=campaign_id))
        journeys = list(AttackJourney.objects.filter(campaign_id=campaign_id))
        highest_risk = max((journey.risk_score for journey in journeys), default=0.0)
        highest_risk_campaigns.append(
            {
                "campaign_id": campaign_id,
                "alert_count": len(campaign_alerts),
                "open_count": sum(1 for alert in campaign_alerts if alert.status in OPEN_STATUSES),
                "highest_risk_score": round(highest_risk, 2),
            }
        )
    highest_risk_campaigns.sort(key=lambda item: (item["highest_risk_score"], item["open_count"], item["alert_count"]), reverse=True)

    average_resolution_time = None
    if resolved_alerts.exists():
        resolution_minutes = [
            (alert.resolved_at - alert.created_at).total_seconds() / 60.0
            for alert in resolved_alerts
            if alert.resolved_at and alert.created_at
        ]
        if resolution_minutes:
            average_resolution_time = round(sum(resolution_minutes) / len(resolution_minutes), 2)

    return {
        "active_alerts": active_alerts.count(),
        "alerts_by_severity": severity_counts,
        "most_triggered_rules": rule_counts,
        "highest_risk_campaigns": highest_risk_campaigns[:limit],
        "unresolved_incidents": [serialize_detection_alert(alert, related_iocs_by_session=related_iocs_by_session) for alert in unresolved_alerts],
        "average_resolution_time_minutes": average_resolution_time,
        "recent_detections": [serialize_detection_alert(alert, related_iocs_by_session=related_iocs_by_session) for alert in recent_alerts],
    }


def build_detection_alert_detail(alert: DetectionAlert) -> dict[str, Any]:
    journey = alert.attack_journey
    session_iocs = _bounded_session_iocs(alert.session_id, limit=25)
    related_iocs = [_serialize_ioc(item) for item in session_iocs]
    evidence = []
    if isinstance(alert.metadata, dict):
        evidence = list(alert.metadata.get("evidence", []))
    timeline = []
    from .investigation import build_investigation_timeline

    # Avoid building a full workspace-wide timeline when the alert lacks
    # session or campaign context — that can trigger expensive full-table
    # scans and lead to request timeouts. Only build the investigation
    # timeline when we have a session_id or campaign_id to scope the query.
    if alert.session_id or alert.campaign_id:
        timeline = build_investigation_timeline(session_id=alert.session_id, campaign_id=alert.campaign_id, limit=25)
    else:
        timeline = []
    if isinstance(alert.metadata, dict):
        for change in alert.metadata.get("status_history", []):
            timeline.append(
                {
                    "timestamp": change.get("changed_at"),
                    "event_type": "alert_status_change",
                    "session_id": alert.session_id,
                    "campaign_id": alert.campaign_id,
                    "summary": f"Alert status changed to {change.get('status')}",
                    "source": "DetectionAlert",
                    "kind": "status_change",
                    "status": change.get("status"),
                    "changed_by": change.get("changed_by", ""),
                }
            )
    if alert.resolved_at:
        timeline.append(
            {
                "timestamp": _iso(alert.resolved_at),
                "event_type": "alert_resolved",
                "session_id": alert.session_id,
                "campaign_id": alert.campaign_id,
                "summary": f"Alert resolved: {alert.rule_name}",
                "source": "DetectionAlert",
                "kind": "resolved",
            }
        )
    timeline.sort(key=lambda item: item.get("timestamp") or "")
    timeline = timeline[:40]
    return {
        "alert": serialize_detection_alert(alert, include_evidence=True),
        "journey": _serialize_journey(journey),
        "campaign_id": alert.campaign_id,
        "related_iocs": related_iocs,
        "evidence": evidence,
        "timeline": timeline,
    }


def build_detection_alert_list_payload(*, limit: int = 100, status: str | None = None, severity: str | None = None) -> dict[str, Any]:
    # Respect optional server-side status and severity filters to avoid
    # returning a larger-than-needed payload to the UI.
    alerts = list_detection_alerts(status=status, limit=limit)
    if severity:
        alerts = [a for a in alerts if (a.severity or "").upper() == str(severity).upper()]
    session_ioc_counts = dict(
        IOCIndicator.objects.values("session_id").annotate(total=Count("id")).values_list("session_id", "total")
    )
    return {
        "alerts": [
            {
                "id": alert.id,
                "rule_name": alert.rule_name,
                "severity": alert.severity,
                "confidence_score": alert.confidence_score,
                "status": alert.status,
                "description": alert.description,
                "session_id": alert.session_id,
                "campaign_id": alert.campaign_id,
                "related_journey": _serialize_journey(alert.attack_journey),
                "ioc_count": session_ioc_counts.get(alert.session_id, 0),
                "created_at": _iso(alert.created_at),
                "response_recommendation": alert.response_recommendation,
            }
            for alert in alerts
        ],
        "legacy_alert_events": [
            {
                "timestamp": _iso(item["timestamp"]),
                "alert_type": item["alert_type"],
                "detail": item["detail"],
                "requested_url": item["requested_url"],
            }
            for item in AlertEvent.objects.values("timestamp", "alert_type", "detail", "requested_url")[:50]
        ],
    }
