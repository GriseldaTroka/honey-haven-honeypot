from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from django.db.models import Avg, Count
from django.db.models.functions import TruncHour
from django.utils import timezone

from .asg import PHASE_PRIORITY
from .detection import build_detection_dashboard
from .investigation import build_campaign_dashboard_aggregates, build_campaign_summaries
from .models import AnalystNote, AttackJourney, AttackerState, InvestigationBookmark, StateTransition


PHASE_ORDER = [phase for phase, _ in sorted(PHASE_PRIORITY.items(), key=lambda item: item[1])]


def _path_signature(journey: AttackJourney) -> str:
    phases = list(journey.phases or [])
    if phases:
        phase_names = [phase.get("phase") if isinstance(phase, dict) else str(phase) for phase in phases]
        return " → ".join([name for name in phase_names if name][:5])
    if journey.entry_point:
        return journey.entry_point[:120]
    return journey.session_id


def _depth_bucket(event_count: int) -> str:
    if event_count <= 5:
        return "1-5"
    if event_count <= 10:
        return "6-10"
    if event_count <= 20:
        return "11-20"
    return "21+"


def build_attack_flow_analytics(*, limit: int = 500) -> dict[str, Any]:
    transitions = list(
        StateTransition.objects.values("from_phase", "to_phase")
        .annotate(count=Count("id"))
        .order_by("-count", "from_phase", "to_phase")[:limit]
    )

    average_risk_per_phase = list(
        AttackerState.objects.values("current_phase")
        .annotate(average_risk=Avg("risk_score"), average_confidence=Avg("phase_confidence"), session_count=Count("id"))
        .order_by("-average_risk", "current_phase")
    )

    risk_over_time = list(
        AttackerState.objects.annotate(bucket=TruncHour("updated_at"))
        .values("bucket")
        .annotate(average_risk=Avg("risk_score"), average_confidence=Avg("phase_confidence"), state_count=Count("id"))
        .order_by("bucket")
    )

    journeys = list(AttackJourney.objects.all()[:limit])
    path_counter = Counter(_path_signature(journey) for journey in journeys)
    most_common_attack_paths = [
        {"path": path, "count": count, "avg_events": round(sum(j.event_count for j in journeys if _path_signature(j) == path) / count, 2) if count else 0}
        for path, count in path_counter.most_common(10)
    ]

    depth_counter = Counter(_depth_bucket(journey.event_count) for journey in journeys)
    session_depth_distribution = [
        {"bucket": bucket, "count": depth_counter.get(bucket, 0)}
        for bucket in ["1-5", "6-10", "11-20", "21+"]
    ]

    top_risk_sessions = list(
        AttackerState.objects.order_by("-risk_score", "-updated_at")
        .values("session_id", "current_phase", "risk_score", "phase_confidence", "event_count", "last_event_type", "last_observed_path")[:10]
    )

    sankey_links = [
        {"source": item["from_phase"] or "unknown", "target": item["to_phase"] or "unknown", "value": item["count"]}
        for item in transitions
    ]
    sankey_nodes = list(dict.fromkeys([link["source"] for link in sankey_links] + [link["target"] for link in sankey_links] + PHASE_ORDER))

    return {
        "generated_at": timezone.now().isoformat(),
        "session_count": AttackerState.objects.count(),
        "transition_counts": transitions,
        "average_risk_per_phase": average_risk_per_phase,
        "most_common_attack_paths": most_common_attack_paths,
        "session_depth_distribution": session_depth_distribution,
        "risk_over_time": [
            {
                "bucket": item["bucket"].isoformat() if item["bucket"] else None,
                "average_risk": item["average_risk"],
                "average_confidence": item["average_confidence"],
                "state_count": item["state_count"],
            }
            for item in risk_over_time
        ],
        "sankey": {
            "nodes": sankey_nodes,
            "links": sankey_links,
        },
        "top_risk_sessions": top_risk_sessions,
    }


def build_session_inventory(*, limit: int = 20) -> list[dict[str, Any]]:
    """Return a lightweight list of recent sessions for the SOC overview.

    Kept intentionally small and stable so the dashboard can render even
    when some analytics sub-systems are unavailable.
    """
    sessions = []
    try:
        journeys = list(AttackJourney.objects.order_by("-last_seen")[:limit])
        for j in journeys:
            sessions.append(
                {
                    "session_id": j.session_id,
                    "entry_point": j.entry_point,
                    "event_count": j.event_count,
                    "risk_score": j.risk_score,
                    "last_seen": j.last_seen.isoformat() if j.last_seen else None,
                    "campaign_id": j.campaign_id,
                }
            )
    except Exception:
        # Best-effort: if DB state is problematic, return empty list rather than raise
        sessions = []

    return sessions


def build_soc_overview(*, limit: int = 20) -> dict[str, Any]:
    attack_flow = build_attack_flow_analytics(limit=limit)
    detection_dashboard = build_detection_dashboard(limit=limit)
    campaign_dashboard = build_campaign_dashboard_aggregates(limit=limit)
    sessions = build_session_inventory(limit=limit)
    campaigns = build_campaign_summaries(limit=limit)

    return {
        "generated_at": timezone.now().isoformat(),
        "summary": {
            "session_count": AttackerState.objects.count(),
            "journey_count": AttackJourney.objects.count(),
            "alert_count": detection_dashboard.get("active_alerts", 0) + len(detection_dashboard.get("unresolved_incidents", [])),
            "campaign_count": len(campaigns),
            "note_count": AnalystNote.objects.count(),
            "bookmark_count": InvestigationBookmark.objects.count(),
        },
        "attack_flow": attack_flow,
        "detection": detection_dashboard,
        "campaign_intelligence": campaign_dashboard,
        "recent_sessions": sessions[:limit],
        "recent_campaigns": campaigns[:limit],
        "recent_notes": [
            {
                "id": note.id,
                "title": note.title,
                "session_id": note.session_id,
                "campaign_id": note.campaign_id,
                "pinned": note.pinned,
                "updated_at": note.updated_at.isoformat() if note.updated_at else None,
            }
            for note in AnalystNote.objects.select_related("author").order_by("-pinned", "-updated_at")[:limit]
        ],
        "recent_bookmarks": [
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
        ],
    }
