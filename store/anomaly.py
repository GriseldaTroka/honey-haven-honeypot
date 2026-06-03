from __future__ import annotations

from typing import List

from django.utils import timezone

from .models import HoneypotLog, AlertEvent
from .deception import emit_structured_event


def detect_spikes(minutes: int = 10, threshold: int = 100) -> List[dict]:
    """Simple rule: if number of requests in last `minutes` exceeds `threshold`, create an alert."""
    cutoff = timezone.now() - timezone.timedelta(minutes=minutes)
    count = HoneypotLog.objects.filter(timestamp__gte=cutoff).count()
    findings = []
    if count >= threshold:
        detail = f"Traffic spike: {count} requests in last {minutes}m"
        AlertEvent.objects.create(alert_type="TRAFFIC_SPIKE", detail=detail, dispatch_status="pending")
        emit_structured_event("anomaly_detected", kind="traffic_spike", count=count, minutes=minutes)
        findings.append({"type": "traffic_spike", "count": count, "minutes": minutes})
    return findings
