from __future__ import annotations

from datetime import timedelta
from collections import Counter, defaultdict
from typing import Any

from django.db.models import Avg, Count, Max, Min, Q
from django.db.models.functions import Coalesce
from django.utils import timezone

from .models import AlertEvent, AttackJourney, AttackerState, DetectionAlert, IOCIndicator, HoneypotLog, LoginAttempt, PaymentRecord, SupportTicket, TelemetryEvent, ThreatIntelSnapshot, UploadArtifact


def _iso(value: Any) -> str | None:
    return value.isoformat() if hasattr(value, "isoformat") else None


def _unique_sorted(values: list[str]) -> list[str]:
    return sorted(dict.fromkeys([value for value in values if value]))


def _phase_name(phase: Any) -> str:
    if isinstance(phase, dict):
        return str(phase.get("phase", "") or "")
    return str(phase or "")


def _flatten_text_values(values: Any) -> list[str]:
    flattened: list[str] = []
    if not isinstance(values, list):
        return flattened
    for item in values:
        if isinstance(item, dict):
            for key in ("payload", "detail", "value", "text", "summary", "message", "body"):
                raw = item.get(key)
                if raw:
                    flattened.append(str(raw))
                    break
        elif item:
            flattened.append(str(item))
    return flattened


def _session_campaign_map() -> dict[str, str]:
    mapping: dict[str, str] = {}
    for journey in AttackJourney.objects.exclude(campaign_id="").values("session_id", "campaign_id"):
        mapping[str(journey["session_id"])] = str(journey["campaign_id"])
    return mapping


def _campaign_sessions(campaign_id: str) -> list[str]:
    return list(AttackJourney.objects.filter(campaign_id=campaign_id).values_list("session_id", flat=True))


def _campaign_journeys(campaign_id: str) -> list[AttackJourney]:
    return list(AttackJourney.objects.filter(campaign_id=campaign_id).order_by("last_seen", "session_id"))


def _ioc_group_details(ioc_type: str, ioc_value: str) -> dict[str, Any]:
    indicators = list(
        IOCIndicator.objects.filter(ioc_type=ioc_type, ioc_value=ioc_value)
        .select_related("attack_journey")
        .only(
            "id",
            "session_id",
            "source_model",
            "source_object_id",
            "ioc_type",
            "ioc_value",
            "confidence_score",
            "source_event",
            "evidence_summary",
            "attack_phase",
            "asg_risk_score",
            "asg_confidence",
            "attack_journey",
            "first_seen",
            "last_seen",
            "metadata",
            "attack_journey__session_id",
            "attack_journey__campaign_id",
        )
        .order_by("first_seen", "id")
    )
    sessions = _unique_sorted([indicator.session_id for indicator in indicators if indicator.session_id])
    journeys = _unique_sorted([indicator.attack_journey.session_id for indicator in indicators if indicator.attack_journey])
    campaigns = _unique_sorted([indicator.attack_journey.campaign_id for indicator in indicators if indicator.attack_journey and indicator.attack_journey.campaign_id])
    return {
        "first_seen": _iso(min((indicator.first_seen for indicator in indicators), default=None)),
        "last_seen": _iso(max((indicator.last_seen for indicator in indicators), default=None)),
        "occurrence_count": len(indicators),
        "session_count": len(sessions),
        "journey_count": len(journeys),
        "campaign_count": len(campaigns),
        "sessions": sessions,
        "journeys": journeys,
        "campaigns": campaigns,
        "indicators": indicators,
    }


_IOC_RELATIONSHIP_FIELDS = (
    "id",
    "session_id",
    "source_model",
    "source_object_id",
    "ioc_type",
    "ioc_value",
    "confidence_score",
    "source_event",
    "evidence_summary",
    "attack_phase",
    "asg_risk_score",
    "asg_confidence",
    "attack_journey",
    "first_seen",
    "last_seen",
    "metadata",
    "attack_journey__session_id",
    "attack_journey__campaign_id",
    "attack_journey__tools_used",
    "attack_journey__phases",
)


def serialise_ioc_indicator(indicator: IOCIndicator) -> dict[str, Any]:
    campaign_id = indicator.attack_journey.campaign_id if indicator.attack_journey and indicator.attack_journey.campaign_id else ""
    return {
        "id": indicator.id,
        "session_id": indicator.session_id,
        "ioc_type": indicator.ioc_type,
        "ioc_value": indicator.ioc_value,
        "confidence_score": indicator.confidence_score,
        "source_model": indicator.source_model,
        "source_object_id": indicator.source_object_id,
        "source_event": indicator.source_event,
        "evidence_summary": indicator.evidence_summary,
        "attack_phase": indicator.attack_phase,
        "asg_risk_score": indicator.asg_risk_score,
        "asg_confidence": indicator.asg_confidence,
        "attack_journey": indicator.attack_journey.session_id if indicator.attack_journey else None,
        "campaign_id": campaign_id,
        "first_seen": _iso(indicator.first_seen),
        "last_seen": _iso(indicator.last_seen),
        "metadata": indicator.metadata,
    }


def build_ioc_index(*, limit: int = 250) -> list[dict[str, Any]]:
    grouped = (
        IOCIndicator.objects.values("ioc_type", "ioc_value")
        .annotate(
            representative_id=Min("id"),
            first_seen=Min("first_seen"),
            last_seen=Max("last_seen"),
            occurrence_count=Count("id"),
            session_count=Count("session_id", distinct=True),
            journey_count=Count("attack_journey", distinct=True),
            campaign_count=Count("attack_journey__campaign_id", distinct=True),
        )
        .order_by("-occurrence_count", "-last_seen", "ioc_type", "ioc_value")[:limit]
    )
    return [
        {
            "id": row["representative_id"],
            "ioc_type": row["ioc_type"],
            "ioc_value": row["ioc_value"],
            "first_seen": _iso(row["first_seen"]),
            "last_seen": _iso(row["last_seen"]),
            "occurrence_count": row["occurrence_count"],
            "session_count": row["session_count"],
            "journey_count": row["journey_count"],
            "campaign_count": row["campaign_count"],
        }
        for row in grouped
    ]


def get_ioc_detail(ioc_id: int) -> dict[str, Any] | None:
    indicator = IOCIndicator.objects.select_related("attack_journey").filter(id=ioc_id).first()
    if not indicator:
        return None

    correlation = _ioc_group_details(indicator.ioc_type, indicator.ioc_value)
    details = {
        **serialise_ioc_indicator(indicator),
        "sessions": correlation["sessions"],
        "journeys": correlation["journeys"],
        "campaign_ids": correlation["campaigns"],
        "provenance": {
            "source_model": indicator.source_model,
            "source_object_id": indicator.source_object_id,
            "source_event": indicator.source_event,
            "evidence_summary": indicator.evidence_summary,
            "attack_phase": indicator.attack_phase,
            "asg_risk_score": indicator.asg_risk_score,
            "asg_confidence": indicator.asg_confidence,
        },
        "correlation": {
            "first_seen": correlation["first_seen"],
            "last_seen": correlation["last_seen"],
            "occurrence_count": correlation["occurrence_count"],
            "session_count": correlation["session_count"],
            "journey_count": correlation["journey_count"],
            "campaign_count": correlation["campaign_count"],
        },
    }
    return details


def get_ioc_relationships(ioc_id: int) -> dict[str, Any] | None:
    target = (
        IOCIndicator.objects.select_related("attack_journey")
        .only(*_IOC_RELATIONSHIP_FIELDS)
        .filter(id=ioc_id)
        .first()
    )
    if not target:
        return None

    base_sessions = [target.session_id] if target.session_id else []
    base_journeys = [target.attack_journey_id] if target.attack_journey_id else []
    base_campaigns = [target.attack_journey.campaign_id] if target.attack_journey and target.attack_journey.campaign_id else []

    related_indicators = list(
        IOCIndicator.objects.filter(ioc_type=target.ioc_type, ioc_value=target.ioc_value)
        .select_related("attack_journey")
        .only(*_IOC_RELATIONSHIP_FIELDS)
        .order_by("first_seen", "id")
    )

    same_session = (
        IOCIndicator.objects.filter(session_id__in=base_sessions)
        .exclude(id=target.id)
        .select_related("attack_journey")
        .only(*_IOC_RELATIONSHIP_FIELDS)
    )
    same_journey = (
        IOCIndicator.objects.filter(attack_journey_id__in=base_journeys)
        .exclude(id=target.id)
        .select_related("attack_journey")
        .only(*_IOC_RELATIONSHIP_FIELDS)
    )
    same_campaign = (
        IOCIndicator.objects.filter(attack_journey__campaign_id__in=base_campaigns)
        .exclude(id=target.id)
        .select_related("attack_journey")
        .only(*_IOC_RELATIONSHIP_FIELDS)
    )

    shared_sessions = _unique_sorted([indicator.session_id for indicator in related_indicators if indicator.session_id])
    shared_journeys = _unique_sorted([indicator.attack_journey.session_id for indicator in related_indicators if indicator.attack_journey])
    shared_campaigns = _unique_sorted([indicator.attack_journey.campaign_id for indicator in related_indicators if indicator.attack_journey and indicator.attack_journey.campaign_id])
    related_tools, related_phases = _ioc_related_tool_and_phase_counts(related_indicators)

    def _bucket(queryset, relation: str) -> dict[str, Any]:
        indicators = list(queryset.order_by("-last_seen", "id"))
        sessions = _unique_sorted([indicator.session_id for indicator in indicators if indicator.session_id])
        journeys = _unique_sorted([indicator.attack_journey.session_id for indicator in indicators if indicator.attack_journey])
        campaigns = _unique_sorted([indicator.attack_journey.campaign_id for indicator in indicators if indicator.attack_journey and indicator.attack_journey.campaign_id])
        return {
            "relation": relation,
            "count": len(indicators),
            "sessions": sessions,
            "journeys": journeys,
            "campaigns": campaigns,
            "indicators": [serialise_ioc_indicator(indicator) for indicator in indicators],
        }

    return {
        "ioc": serialise_ioc_indicator(target),
        "shared_sessions": len(shared_sessions),
        "shared_journeys": len(shared_journeys),
        "shared_campaigns": len(shared_campaigns),
        "shared_session_ids": shared_sessions,
        "shared_journey_ids": shared_journeys,
        "shared_campaign_ids": shared_campaigns,
        "related_tools": related_tools,
        "related_phases": related_phases,
        "repeated_appearance_timeline": _ioc_occurrence_timeline(related_indicators),
        "relationships": {
            "same_session": _bucket(same_session, "session"),
            "same_journey": _bucket(same_journey, "journey"),
            "same_campaign": _bucket(same_campaign, "campaign"),
        },
    }


def _ioc_occurrence_timeline(indicators: list[IOCIndicator]) -> list[dict[str, Any]]:
    timeline: list[dict[str, Any]] = []
    for indicator in sorted(indicators, key=lambda item: (item.first_seen, item.last_seen, item.id)):
        timeline.append(
            {
                "timestamp": _iso(indicator.first_seen or indicator.last_seen),
                "session_id": indicator.session_id,
                "attack_journey": indicator.attack_journey.session_id if indicator.attack_journey else None,
                "campaign_id": indicator.attack_journey.campaign_id if indicator.attack_journey and indicator.attack_journey.campaign_id else "",
                "source_model": indicator.source_model,
                "source_object_id": indicator.source_object_id,
                "source_event": indicator.source_event,
            }
        )
    return timeline


def _ioc_related_tool_and_phase_counts(indicators: list[IOCIndicator]) -> tuple[list[str], list[str]]:
    tool_counter: Counter[str] = Counter()
    phase_counter: Counter[str] = Counter()
    for indicator in indicators:
        journey = indicator.attack_journey
        if not journey:
            continue
        tool_counter.update(str(tool) for tool in (journey.tools_used or []) if tool)
        phase_counter.update(_phase_name(phase) for phase in (journey.phases or []) if _phase_name(phase))
    return [tool for tool, _count in tool_counter.most_common()], [phase for phase, _count in phase_counter.most_common()]


def get_ioc_evidence_bundle(ioc_id: int) -> dict[str, Any] | None:
    target = IOCIndicator.objects.select_related("attack_journey").filter(id=ioc_id).first()
    if not target:
        return None

    related_indicators = list(
        IOCIndicator.objects.filter(ioc_type=target.ioc_type, ioc_value=target.ioc_value)
        .select_related("attack_journey")
        .order_by("first_seen", "id")
    )
    evidence_objects = [
        {
            "ioc_id": indicator.id,
            "ioc_type": indicator.ioc_type,
            "ioc_value": indicator.ioc_value,
            "source_model": indicator.source_model,
            "source_object_id": indicator.source_object_id,
            "source_event": indicator.source_event,
            "evidence_summary": indicator.evidence_summary,
            "timestamp": _iso(indicator.first_seen),
            "session_id": indicator.session_id,
            "attack_journey": indicator.attack_journey.session_id if indicator.attack_journey else None,
            "campaign_id": indicator.attack_journey.campaign_id if indicator.attack_journey and indicator.attack_journey.campaign_id else "",
        }
        for indicator in related_indicators
    ]

    return {
        "ioc": serialise_ioc_indicator(target),
        "evidence_objects": evidence_objects,
        "count": len(evidence_objects),
    }


def _journey_payload_tokens(journey: AttackJourney) -> set[str]:
    tokens: set[str] = set()
    for value in _flatten_text_values(journey.payload_evolution or []):
        lowered = str(value).strip().lower()
        if lowered:
            tokens.add(lowered)
    return tokens


def _journey_ioc_values(journey: AttackJourney) -> set[str]:
    return set(
        IOCIndicator.objects.filter(attack_journey=journey).values_list("ioc_value", flat=True)
    )


def compare_journeys(journey_1: AttackJourney, journey_2: AttackJourney, journey_ioc_map: dict[int, set[str]] | None = None) -> dict[str, Any]:
    phases_1 = {_phase_name(phase).lower() for phase in (journey_1.phases or []) if _phase_name(phase)}
    phases_2 = {_phase_name(phase).lower() for phase in (journey_2.phases or []) if _phase_name(phase)}
    tools_1 = {str(tool).lower() for tool in (journey_1.tools_used or []) if tool}
    tools_2 = {str(tool).lower() for tool in (journey_2.tools_used or []) if tool}
    payloads_1 = _journey_payload_tokens(journey_1)
    payloads_2 = _journey_payload_tokens(journey_2)
    escalation_1 = {str(item).lower() for item in (journey_1.escalation_attempts or []) if item}
    escalation_2 = {str(item).lower() for item in (journey_2.escalation_attempts or []) if item}
    if journey_ioc_map is not None:
        iocs_1 = {value.lower() for value in (journey_ioc_map.get(journey_1.id) or set()) if value}
        iocs_2 = {value.lower() for value in (journey_ioc_map.get(journey_2.id) or set()) if value}
    else:
        iocs_1 = {value.lower() for value in _journey_ioc_values(journey_1) if value}
        iocs_2 = {value.lower() for value in _journey_ioc_values(journey_2) if value}

    def ratio(left: set[str], right: set[str]) -> float:
        if not left and not right:
            return 1.0
        return len(left & right) / max(len(left | right), 1)

    shared_features: list[str] = []
    for label, values in (
        ("attack phase", phases_1 & phases_2),
        ("attacker tool", tools_1 & tools_2),
        ("payload pattern", payloads_1 & payloads_2),
        ("same IOC", iocs_1 & iocs_2),
        ("escalation behavior", escalation_1 & escalation_2),
    ):
        for value in sorted(values):
            shared_features.append(f"{label}: {value}")

    score = round(
        (
            ratio(phases_1, phases_2) * 25
            + ratio(tools_1, tools_2) * 20
            + ratio(payloads_1, payloads_2) * 20
            + ratio(iocs_1, iocs_2) * 25
            + ratio(escalation_1, escalation_2) * 10
        ),
        2,
    )
    return {
        "journey_1": journey_1.id,
        "journey_2": journey_2.id,
        "session_1": journey_1.session_id,
        "session_2": journey_2.session_id,
        "similarity_score": min(max(score, 0.0), 100.0),
        "shared_features": shared_features,
    }


def build_journey_similarity_pairs(*, limit: int = 20) -> list[dict[str, Any]]:
    journeys = list(
        AttackJourney.objects.only(
            "id",
            "session_id",
            "last_seen",
            "phases",
            "tools_used",
            "payload_evolution",
            "escalation_attempts",
        ).order_by("-last_seen", "session_id")[: max(limit * 4, 10)]
    )
    pairs: list[dict[str, Any]] = []
    journey_ioc_map = _journey_ioc_value_map(journey_ids=[journey.id for journey in journeys])

    for index, journey_1 in enumerate(journeys):
        for journey_2 in journeys[index + 1 :]:
            comparison = compare_journeys(journey_1, journey_2, journey_ioc_map=journey_ioc_map)
            if comparison["similarity_score"] <= 0:
                continue
            pairs.append(comparison)
    pairs.sort(key=lambda item: (item["similarity_score"], item["journey_1"], item["journey_2"]), reverse=True)
    return pairs[:limit]


def get_journey_investigation_view(journey_id: int) -> dict[str, Any] | None:
    journey = AttackJourney.objects.filter(id=journey_id).first()
    if not journey:
        return None

    related_iocs = list(IOCIndicator.objects.filter(attack_journey=journey).select_related("attack_journey").order_by("-last_seen", "id"))
    evidence_objects = [
        {
            "ioc_id": indicator.id,
            "ioc_type": indicator.ioc_type,
            "ioc_value": indicator.ioc_value,
            "source_model": indicator.source_model,
            "source_object_id": indicator.source_object_id,
            "source_event": indicator.source_event,
            "evidence_summary": indicator.evidence_summary,
            "timestamp": _iso(indicator.first_seen),
            "session_id": indicator.session_id,
            "attack_journey": indicator.attack_journey.session_id if indicator.attack_journey else None,
            "campaign_id": indicator.attack_journey.campaign_id if indicator.attack_journey and indicator.attack_journey.campaign_id else "",
        }
        for indicator in related_iocs
    ]

    similar_journeys = [
        comparison
        for comparison in build_journey_similarity_pairs(limit=50)
        if comparison["journey_1"] == journey.id or comparison["journey_2"] == journey.id
    ][:10]

    return {
        "journey": serialise_journey(journey),
        "session_id": journey.session_id,
        "campaign_id": journey.campaign_id,
        "risk_score": journey.risk_score,
        "confidence_score": journey.confidence_score,
        "intent_score": journey.intent_score,
        "first_seen": _iso(journey.first_seen),
        "last_seen": _iso(journey.last_seen),
        "attack_phases": journey.phases,
        "tools_used": journey.tools_used,
        "escalation_attempts": journey.escalation_attempts,
        "reconnaissance_path": journey.recon_path,
        "payload_evolution": journey.payload_evolution,
        "related_iocs": [serialise_ioc_indicator(item) for item in related_iocs],
        "evidence_objects": evidence_objects,
        "timeline_events": build_investigation_timeline(session_id=journey.session_id, limit=500),
        "similar_journeys": similar_journeys,
    }


def build_investigation_graph(*, limit: int = 250, session_id: str = "") -> dict[str, list[dict[str, Any]]]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    session_id = str(session_id or "").strip()

    def add_node(node_id: str, node_type: str, label: str, **properties: Any) -> None:
        nodes.setdefault(
            node_id,
            {
                "id": node_id,
                "type": node_type,
                "label": label,
                **{key: value for key, value in properties.items() if value not in (None, "", [], {})},
            },
        )

    def add_edge(source: str, target: str, edge_type: str, **properties: Any) -> None:
        edge = {"source": source, "target": target, "type": edge_type}
        edge.update({key: value for key, value in properties.items() if value not in (None, "", [], {})})
        if edge not in edges:
            edges.append(edge)

    journeys_query = AttackJourney.objects.exclude(session_id="").order_by("-last_seen", "session_id")
    iocs_query = IOCIndicator.objects.select_related("attack_journey").order_by("-last_seen", "id")

    if session_id:
        journeys_query = journeys_query.filter(session_id=session_id)
        iocs_query = iocs_query.filter(session_id=session_id)

    journeys = list(journeys_query[:limit])
    iocs = list(iocs_query[: limit * 6])

    for journey in journeys:
        journey_node = f"journey:{journey.id}"
        add_node(journey_node, "AttackJourney", journey.session_id, session_id=journey.session_id, campaign_id=journey.campaign_id, risk_score=journey.risk_score, confidence_score=journey.confidence_score)
        if journey.campaign_id:
            campaign_node = f"campaign:{journey.campaign_id}"
            add_node(campaign_node, "Campaign", journey.campaign_id, campaign_id=journey.campaign_id)
            add_edge(journey_node, campaign_node, "JOURNEY_PART_OF_CAMPAIGN")

    for indicator in iocs:
        ioc_node = f"ioc:{indicator.id}"
        session_node = f"session:{indicator.session_id or (indicator.attack_journey.session_id if indicator.attack_journey else indicator.id)}"
        journey_node = f"journey:{indicator.attack_journey.id}" if indicator.attack_journey else ""
        evidence_node = f"evidence:{indicator.source_model}:{indicator.source_object_id or indicator.id}"

        add_node(ioc_node, "IOC", f"{indicator.ioc_type}: {indicator.ioc_value}", ioc_type=indicator.ioc_type, ioc_value=indicator.ioc_value, source_model=indicator.source_model, source_object_id=indicator.source_object_id, source_event=indicator.source_event)
        add_node(session_node, "Session", indicator.session_id or (indicator.attack_journey.session_id if indicator.attack_journey else "unknown"), session_id=indicator.session_id or (indicator.attack_journey.session_id if indicator.attack_journey else ""))
        add_node(evidence_node, "Evidence", f"{indicator.source_model or 'unknown'}:{indicator.source_object_id or indicator.id}", source_model=indicator.source_model, source_object_id=indicator.source_object_id, source_event=indicator.source_event, evidence_summary=indicator.evidence_summary)

        add_edge(ioc_node, session_node, "IOC_FOUND_IN_SESSION")
        add_edge(ioc_node, evidence_node, "IOC_CREATED_FROM_EVIDENCE")
        if journey_node:
            add_edge(ioc_node, journey_node, "IOC_LINKED_TO_JOURNEY")

    if not session_id:
        for comparison in build_journey_similarity_pairs(limit=limit):
            journey_1 = f"journey:{comparison['journey_1']}"
            journey_2 = f"journey:{comparison['journey_2']}"
            add_edge(journey_1, journey_2, "JOURNEY_SIMILAR_TO", similarity_score=comparison["similarity_score"], shared_features=comparison["shared_features"])

    return {"nodes": list(nodes.values()), "edges": edges}


def build_most_connected_iocs(*, limit: int = 20) -> list[dict[str, Any]]:
    connected: list[dict[str, Any]] = []
    for row in (
        IOCIndicator.objects.values("ioc_type", "ioc_value")
        .annotate(
            first_seen=Min("first_seen"),
            last_seen=Max("last_seen"),
            occurrence_count=Count("id"),
            session_count=Count("session_id", distinct=True),
            journey_count=Count("attack_journey", distinct=True),
            campaign_count=Count("attack_journey__campaign_id", distinct=True),
        )
    ):
        connected_score = row["occurrence_count"] + row["session_count"] + row["journey_count"] + row["campaign_count"]
        connected.append(
            {
                "ioc_type": row["ioc_type"],
                "ioc_value": row["ioc_value"],
                "first_seen": _iso(row["first_seen"]),
                "last_seen": _iso(row["last_seen"]),
                "occurrence_count": row["occurrence_count"],
                "session_count": row["session_count"],
                "journey_count": row["journey_count"],
                "campaign_count": row["campaign_count"],
                "connected_score": connected_score,
            }
        )
    connected.sort(key=lambda item: (item["connected_score"], item["occurrence_count"], item["last_seen"] or ""), reverse=True)
    return connected[:limit]


def _journey_ioc_value_map(*, journey_ids: list[int] | None = None) -> dict[int, set[str]]:
    journey_ioc_map: dict[int, set[str]] = defaultdict(set)
    queryset = IOCIndicator.objects.all()
    if journey_ids is not None:
        queryset = queryset.filter(attack_journey_id__in=journey_ids)
    for jid, ioc_value in queryset.values_list("attack_journey_id", "ioc_value"):
        if ioc_value:
            journey_ioc_map[jid].add(str(ioc_value))
    return journey_ioc_map


def build_most_reused_attacker_tools(*, limit: int = 20) -> list[dict[str, Any]]:
    counter: Counter[str] = Counter()
    for tools_used in AttackJourney.objects.values_list("tools_used", flat=True):
        counter.update(str(tool) for tool in (tools_used or []) if tool)
    return [{"tool": tool, "count": count} for tool, count in counter.most_common(limit)]


def build_most_similar_attack_journeys(*, limit: int = 20) -> list[dict[str, Any]]:
    return build_journey_similarity_pairs(limit=limit)


def build_campaigns_with_expanding_activity(*, limit: int = 20) -> list[dict[str, Any]]:
    recent_threshold = timezone.now() - timedelta(days=7)
    campaign_rows: list[dict[str, Any]] = []
    aggregated_rows = (
        AttackJourney.objects.exclude(campaign_id="")
        .values("campaign_id")
        .annotate(
            total_journeys=Count("id"),
            recent_journey_count=Count("id", filter=Q(last_seen__gte=recent_threshold)),
            first_seen=Min(Coalesce("first_seen", "last_seen")),
            last_seen=Max("last_seen"),
        )
    )
    for row in aggregated_rows:
        recent_count = int(row["recent_journey_count"] or 0)
        total_journeys = int(row["total_journeys"] or 0)
        campaign_rows.append(
            {
                "campaign_id": row["campaign_id"],
                "total_journeys": total_journeys,
                "recent_journey_count": recent_count,
                "older_journey_count": total_journeys - recent_count,
                "activity_trend_score": recent_count - (total_journeys - recent_count),
                "first_seen": _iso(row["first_seen"]),
                "last_seen": _iso(row["last_seen"]),
            }
        )
    campaign_rows.sort(key=lambda item: (item["activity_trend_score"], item["total_journeys"], item["last_seen"] or ""), reverse=True)
    return campaign_rows[:limit]


def build_recently_discovered_indicators(*, limit: int = 20) -> list[dict[str, Any]]:
    rows = (
        IOCIndicator.objects
        .order_by("-first_seen", "-last_seen", "id")
        .values(
            "id",
            "session_id",
            "ioc_type",
            "ioc_value",
            "confidence_score",
            "source_model",
            "source_object_id",
            "source_event",
            "evidence_summary",
            "attack_phase",
            "asg_risk_score",
            "asg_confidence",
            "attack_journey_id",
            "first_seen",
            "last_seen",
            "metadata",
            "attack_journey__session_id",
            "attack_journey__campaign_id",
        )[:limit]
    )
    return [
        {
            "id": row["id"],
            "session_id": row["session_id"],
            "ioc_type": row["ioc_type"],
            "ioc_value": row["ioc_value"],
            "confidence_score": row["confidence_score"],
            "source_model": row["source_model"],
            "source_object_id": row["source_object_id"],
            "source_event": row["source_event"],
            "evidence_summary": row["evidence_summary"],
            "attack_phase": row["attack_phase"],
            "asg_risk_score": row["asg_risk_score"],
            "asg_confidence": row["asg_confidence"],
            "attack_journey": row["attack_journey__session_id"],
            "campaign_id": row["attack_journey__campaign_id"] or "",
            "first_seen": _iso(row["first_seen"]),
            "last_seen": _iso(row["last_seen"]),
            "metadata": row["metadata"],
        }
        for row in rows
    ]


def build_highest_risk_unresolved_journeys(*, limit: int = 20) -> list[dict[str, Any]]:
    unresolved = AttackJourney.objects.filter(campaign_id="").order_by("-risk_score", "-last_seen", "session_id")[:limit]
    return [serialise_journey(journey) for journey in unresolved]


def build_campaign_summaries(*, limit: int = 250) -> list[dict[str, Any]]:
    journeys = list(AttackJourney.objects.exclude(campaign_id="").order_by("campaign_id", "last_seen")[: limit * 5])
    grouped: dict[str, list[AttackJourney]] = defaultdict(list)
    for journey in journeys:
        if journey.campaign_id:
            grouped[journey.campaign_id].append(journey)

    # Batch-fetch related data to avoid N+1 queries per campaign
    all_sessions = []
    all_journey_ids = []
    for campaign_journeys in grouped.values():
        all_sessions.extend([j.session_id for j in campaign_journeys if j.session_id])
        all_journey_ids.extend([j.id for j in campaign_journeys])

    # Deduplicate
    all_sessions = _unique_sorted(all_sessions)
    all_journey_ids = sorted(dict.fromkeys(all_journey_ids))

    attacker_state_map = {item["session_id"]: item.get("primary_ip") for item in AttackerState.objects.filter(session_id__in=all_sessions).values("session_id", "primary_ip")}

    ioc_rows_by_journey: dict[int, list[tuple[str, str]]] = defaultdict(list)
    if all_journey_ids:
        for ioc in IOCIndicator.objects.filter(attack_journey_id__in=all_journey_ids).values_list("attack_journey_id", "ioc_type", "ioc_value"):
            jid, ioc_type, ioc_value = ioc
            ioc_rows_by_journey[jid].append((ioc_type, ioc_value))

    summaries: list[dict[str, Any]] = []
    for campaign_id, campaign_journeys in grouped.items():
        sessions = _unique_sorted([journey.session_id for journey in campaign_journeys])
        attacker_keys = _unique_sorted([str(attacker_state_map.get(s) or s) for s in sessions]) or sessions
        journey_ids = [journey.id for journey in campaign_journeys]

        # Collect IOC rows for this campaign from the pre-fetched map
        ioc_rows = [pair for jid in journey_ids for pair in ioc_rows_by_journey.get(jid, [])]

        phases = Counter(_phase_name(phase) for journey in campaign_journeys for phase in (journey.phases or []))
        tools = Counter(str(tool) for journey in campaign_journeys for tool in (journey.tools_used or []) if tool)
        payloads = Counter(value for journey in campaign_journeys for value in _flatten_text_values(journey.payload_evolution or []))
        ioc_types = Counter(ioc_type for ioc_type, _ioc_value in ioc_rows if ioc_type)

        summaries.append(
            {
                "campaign_id": campaign_id,
                "total_journeys": len(campaign_journeys),
                "total_sessions": len(sessions),
                "total_attackers": len(attacker_keys),
                "ioc_count": len(ioc_rows),
                "unique_ioc_count": len(set(ioc_rows)),
                "average_risk_score": round(sum(journey.risk_score for journey in campaign_journeys) / len(campaign_journeys), 2) if campaign_journeys else 0.0,
                "average_confidence_score": round(sum(journey.confidence_score for journey in campaign_journeys) / len(campaign_journeys), 2) if campaign_journeys else 0.0,
                "dominant_attack_phases": [phase for phase, _count in phases.most_common(5)],
                "dominant_tools": [tool for tool, _count in tools.most_common(5)],
                "dominant_ioc_types": [ioc_type for ioc_type, _count in ioc_types.most_common(5)],
                "most_common_payloads": [payload for payload, _count in payloads.most_common(5)],
                "first_seen": _iso(min((journey.first_seen or journey.last_seen for journey in campaign_journeys), default=None)),
                "last_seen": _iso(max((journey.last_seen for journey in campaign_journeys), default=None)),
            }
        )

    summaries.sort(key=lambda item: (item["last_seen"] or "", item["campaign_id"]), reverse=True)
    return summaries[:limit]


def get_campaign_summary(campaign_id: str) -> dict[str, Any] | None:
    campaign_journeys = _campaign_journeys(campaign_id)
    if not campaign_journeys:
        return None

    sessions = _unique_sorted([journey.session_id for journey in campaign_journeys])
    journey_ids = [journey.id for journey in campaign_journeys]
    ioc_rows = list(
        IOCIndicator.objects.filter(attack_journey_id__in=journey_ids)
        .values_list("ioc_type", "ioc_value")
        .order_by()
    )
    attacker_states = list(AttackerState.objects.filter(session_id__in=sessions))

    phase_counter = Counter(_phase_name(phase) for journey in campaign_journeys for phase in (journey.phases or []))
    tool_counter = Counter(str(tool) for journey in campaign_journeys for tool in (journey.tools_used or []) if tool)
    payload_counter = Counter(value for journey in campaign_journeys for value in _flatten_text_values(journey.payload_evolution or []))
    ioc_type_counter = Counter(ioc_type for ioc_type, _ioc_value in ioc_rows if ioc_type)

    summary = {
        "campaign_id": campaign_id,
        "total_journeys": len(campaign_journeys),
        "total_sessions": len(sessions),
        "total_attackers": len(_unique_sorted([str(state.primary_ip or state.session_id) for state in attacker_states]) or sessions),
        "ioc_count": len(ioc_rows),
        "unique_ioc_count": len(set(ioc_rows)),
        "average_risk_score": round(sum(journey.risk_score for journey in campaign_journeys) / len(campaign_journeys), 2) if campaign_journeys else 0.0,
        "average_confidence_score": round(sum(journey.confidence_score for journey in campaign_journeys) / len(campaign_journeys), 2) if campaign_journeys else 0.0,
        "dominant_attack_phases": [phase for phase, _count in phase_counter.most_common(5)],
        "dominant_tools": [tool for tool, _count in tool_counter.most_common(5)],
        "dominant_ioc_types": [ioc_type for ioc_type, _count in Counter(ioc_type for ioc_type, _ioc_value in ioc_rows if ioc_type).most_common(5)],
        "most_common_payloads": [payload for payload, _count in payload_counter.most_common(5)],
        "first_seen": _iso(min((journey.first_seen or journey.last_seen for journey in campaign_journeys), default=None)),
        "last_seen": _iso(max((journey.last_seen for journey in campaign_journeys), default=None)),
    }

    return {
        "campaign_id": campaign_id,
        "summary": summary,
        "journeys": [serialise_journey(journey) for journey in campaign_journeys],
        "sessions": sessions,
        "ioc_statistics": {
            "ioc_count": summary["ioc_count"],
            "unique_ioc_count": summary["unique_ioc_count"],
            "top_ioc_types": summary["dominant_ioc_types"],
        },
        "timeline_summary": [],
    }


def build_campaign_journeys(campaign_id: str) -> list[dict[str, Any]]:
    return [serialise_journey(journey) for journey in _campaign_journeys(campaign_id)]


def serialise_journey(journey: AttackJourney) -> dict[str, Any]:
    return {
        "session_id": journey.session_id,
        "entry_point": journey.entry_point,
        "recon_path": journey.recon_path,
        "payload_evolution": journey.payload_evolution,
        "escalation_attempts": journey.escalation_attempts,
        "tools_used": journey.tools_used,
        "seconds_spent": journey.seconds_spent,
        "risk_score": journey.risk_score,
        "confidence_score": journey.confidence_score,
        "intent_score": journey.intent_score,
        "first_seen": _iso(journey.first_seen),
        "event_count": journey.event_count,
        "phases": journey.phases,
        "ips": journey.ips,
        "user_agents": journey.user_agents,
        "campaign_id": journey.campaign_id,
        "notes": journey.notes,
        "last_seen": _iso(journey.last_seen),
    }


def build_investigation_timeline(*, session_id: str = "", campaign_id: str = "", limit: int = 500) -> list[dict[str, Any]]:
    session_id = str(session_id or "")[:80]
    campaign_id = str(campaign_id or "")[:120]
    campaign_sessions = set(_campaign_sessions(campaign_id)) if campaign_id else set()

    def _scope_session_ids() -> list[str]:
        if session_id:
            return [session_id]
        if campaign_id:
            return sorted(campaign_sessions)
        return []

    session_ids = _scope_session_ids()

    def _in_scope(record_session_id: str) -> bool:
        if session_id and record_session_id != session_id:
            return False
        if campaign_id and record_session_id not in campaign_sessions:
            return False
        return True

    events: list[dict[str, Any]] = []

    def add_event(*, timestamp, event_type: str, session: str, campaign: str, risk: float | None, confidence: float | None, summary: str, source: str, kind: str) -> None:
        if not timestamp:
            return
        if session_id and session != session_id:
            return
        if campaign_id and campaign != campaign_id:
            return
        events.append(
            {
                "timestamp": _iso(timestamp),
                "event_type": event_type,
                "session_id": session,
                "campaign_id": campaign,
                "risk": risk,
                "confidence": confidence,
                "summary": summary,
                "source": source,
                "kind": kind,
            }
        )

    if session_ids:
        honeypot_queryset = HoneypotLog.objects.filter(session_id__in=session_ids).order_by("timestamp")[:limit * 2]
        telemetry_queryset = TelemetryEvent.objects.filter(session_id__in=session_ids).order_by("timestamp")[:limit * 2]
        login_queryset = LoginAttempt.objects.filter(session_id__in=session_ids).order_by("timestamp")[:limit * 2]
        alert_event_queryset = AlertEvent.objects.filter(metadata__session_id__in=session_ids).order_by("timestamp")[:limit * 2]
        upload_queryset = UploadArtifact.objects.filter(metadata__session_id__in=session_ids).order_by("timestamp")[:limit * 2]
        payment_queryset = PaymentRecord.objects.filter(metadata__session_id__in=session_ids).order_by("timestamp")[:limit * 2]
        ticket_queryset = SupportTicket.objects.filter(metadata__session_id__in=session_ids).order_by("timestamp")[:limit * 2]
        ioc_queryset = IOCIndicator.objects.filter(session_id__in=session_ids).select_related("attack_journey").order_by("first_seen")[:limit * 4]
        journey_queryset = AttackJourney.objects.filter(session_id__in=session_ids).order_by("first_seen", "last_seen")[:limit * 2]
        alert_queryset = DetectionAlert.objects.filter(session_id__in=session_ids).select_related("attack_journey").order_by("created_at", "id")[:limit * 2]
    else:
        honeypot_queryset = HoneypotLog.objects.all().order_by("timestamp")[:limit * 2]
        telemetry_queryset = TelemetryEvent.objects.all().order_by("timestamp")[:limit * 2]
        login_queryset = LoginAttempt.objects.all().order_by("timestamp")[:limit * 2]
        alert_event_queryset = AlertEvent.objects.all().order_by("timestamp")[:limit * 2]
        upload_queryset = UploadArtifact.objects.all().order_by("timestamp")[:limit * 2]
        payment_queryset = PaymentRecord.objects.all().order_by("timestamp")[:limit * 2]
        ticket_queryset = SupportTicket.objects.all().order_by("timestamp")[:limit * 2]
        ioc_queryset = IOCIndicator.objects.select_related("attack_journey").order_by("first_seen")[:limit * 4]
        journey_queryset = AttackJourney.objects.order_by("first_seen", "last_seen")[:limit * 2]
        alert_queryset = DetectionAlert.objects.select_related("attack_journey").order_by("created_at", "id")[:limit * 2]

    for item in honeypot_queryset:
        if not _in_scope(item.session_id or ""):
            continue
        event_type = "recon"
        if item.attack_classification == "SQL_INJECTION_ATTEMPT":
            event_type = "sql_injection"
        elif item.event_type == "LOGIN_ATTEMPT" or item.attack_classification == "BRUTE_FORCE_ATTACK":
            event_type = "login_attempt"
        elif item.event_type == "API_HIT":
            event_type = "api_probe"
        summary = item.requested_url or item.suspicion_reason or item.event_type
        add_event(timestamp=item.timestamp, event_type=event_type, session=item.session_id or "", campaign=_session_campaign_map().get(item.session_id or "", ""), risk=None, confidence=None, summary=summary, source="HoneypotLog", kind="request")

    for item in telemetry_queryset:
        if not _in_scope(item.session_id or ""):
            continue
        add_event(timestamp=item.timestamp, event_type="telemetry", session=item.session_id or "", campaign=_session_campaign_map().get(item.session_id or "", ""), risk=None, confidence=None, summary=item.path or item.event_type, source="TelemetryEvent", kind="telemetry")

    for item in login_queryset:
        if not _in_scope(item.session_id or ""):
            continue
        event_type = "login_attempt"
        summary = item.requested_url or item.username or "login"
        add_event(timestamp=item.timestamp, event_type=event_type, session=item.session_id or "", campaign=_session_campaign_map().get(item.session_id or "", ""), risk=None, confidence=None, summary=summary, source="LoginAttempt", kind="login")

    for item in alert_event_queryset:
        session = str((item.metadata or {}).get("session_id", ""))
        if not _in_scope(session):
            continue
        add_event(timestamp=item.timestamp, event_type="alert", session=session, campaign=_session_campaign_map().get(session, ""), risk=None, confidence=None, summary=item.detail, source="AlertEvent", kind="alert")

    for item in upload_queryset:
        session = str((item.metadata or {}).get("session_id", ""))
        if not _in_scope(session):
            continue
        add_event(timestamp=item.timestamp, event_type="upload", session=session, campaign=_session_campaign_map().get(session, ""), risk=None, confidence=None, summary=f"{item.filename} ({item.verdict})", source="UploadArtifact", kind="upload")

    for item in payment_queryset:
        metadata = item.metadata or {}
        session = str(metadata.get("session_id", ""))
        if not _in_scope(session):
            continue
        add_event(timestamp=item.timestamp, event_type="payment", session=session, campaign=_session_campaign_map().get(session, ""), risk=None, confidence=None, summary=f"{item.payment_id} ({item.status})", source="PaymentRecord", kind="payment")

    for item in ticket_queryset:
        metadata = item.metadata or {}
        session = str(metadata.get("session_id", ""))
        if not _in_scope(session):
            continue
        add_event(timestamp=item.timestamp, event_type="support_abuse", session=session, campaign=_session_campaign_map().get(session, ""), risk=None, confidence=None, summary=f"{item.ticket_id} ({item.status})", source="SupportTicket", kind="support")

    for item in ioc_queryset:
        session = item.session_id or (item.attack_journey.session_id if item.attack_journey else "")
        campaign = item.attack_journey.campaign_id if item.attack_journey and item.attack_journey.campaign_id else _session_campaign_map().get(session, "")
        if not _in_scope(session):
            continue
        add_event(timestamp=item.first_seen, event_type="ioc_discovery", session=session, campaign=campaign, risk=item.asg_risk_score, confidence=item.asg_confidence, summary=f"{item.ioc_type}: {item.ioc_value}", source="IOCIndicator", kind="ioc")

    for journey in journey_queryset:
        if not _in_scope(journey.session_id):
            continue
        add_event(timestamp=journey.first_seen or journey.last_seen, event_type="journey_creation", session=journey.session_id, campaign=journey.campaign_id, risk=journey.risk_score, confidence=journey.confidence_score, summary=f"Journey created for {journey.session_id}", source="AttackJourney", kind="journey_start")
        add_event(timestamp=journey.last_seen, event_type="journey_completion", session=journey.session_id, campaign=journey.campaign_id, risk=journey.risk_score, confidence=journey.confidence_score, summary=f"Journey completed for {journey.session_id}", source="AttackJourney", kind="journey_end")

    for alert in alert_queryset:
        if not _in_scope(alert.session_id or ""):
            continue
        add_event(timestamp=alert.created_at, event_type="detection_triggered", session=alert.session_id, campaign=alert.campaign_id, risk=alert.confidence_score, confidence=alert.confidence_score, summary=f"Detection triggered: {alert.rule_name}", source="DetectionAlert", kind="detection_triggered")
        add_event(timestamp=alert.created_at, event_type="alert_created", session=alert.session_id, campaign=alert.campaign_id, risk=alert.confidence_score, confidence=alert.confidence_score, summary=f"Alert created: {alert.rule_name}", source="DetectionAlert", kind="alert_created")
        if isinstance(alert.metadata, dict):
            for change in alert.metadata.get("status_history", []):
                add_event(timestamp=change.get("changed_at"), event_type="analyst_status_change", session=alert.session_id, campaign=alert.campaign_id, risk=alert.confidence_score, confidence=alert.confidence_score, summary=f"Alert status changed to {change.get('status')}", source="DetectionAlert", kind="status_change")
        if alert.resolved_at:
            add_event(timestamp=alert.resolved_at, event_type="alert_resolved", session=alert.session_id, campaign=alert.campaign_id, risk=alert.confidence_score, confidence=alert.confidence_score, summary=f"Alert resolved: {alert.rule_name}", source="DetectionAlert", kind="alert_resolved")

    events.sort(key=lambda entry: entry["timestamp"] or "")
    return events[:limit]


def build_campaign_dashboard_aggregates(*, limit: int = 250, campaign_summaries: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    ioc_type_rows = list(
        IOCIndicator.objects.values("ioc_type")
        .annotate(total=Count("id"))
        .order_by("-total", "ioc_type")[:10]
    )
    ioc_group_rows = list(
        IOCIndicator.objects.values("ioc_type", "ioc_value")
        .annotate(total=Count("id"))
        .order_by("-total", "ioc_type", "ioc_value")[:20]
    )

    if campaign_summaries is None:
        campaign_summaries = build_campaign_summaries(limit=limit)

    ip_counter = Counter()
    url_counter = Counter()
    email_counter = Counter()
    hash_counter = Counter()
    ip_rows = IOCIndicator.objects.filter(ioc_type="ip").values("ioc_value").annotate(total=Count("id")).order_by("-total", "ioc_value")[:10]
    url_rows = IOCIndicator.objects.filter(ioc_type="url").values("ioc_value").annotate(total=Count("id")).order_by("-total", "ioc_value")[:10]
    email_rows = IOCIndicator.objects.filter(ioc_type="email").values("ioc_value").annotate(total=Count("id")).order_by("-total", "ioc_value")[:10]
    hash_rows = IOCIndicator.objects.filter(ioc_type="hash").values("ioc_value").annotate(total=Count("id")).order_by("-total", "ioc_value")[:10]

    for row in ip_rows:
        ip_counter[str(row["ioc_value"])] += int(row["total"])
    for row in url_rows:
        url_counter[str(row["ioc_value"])] += int(row["total"])
    for row in email_rows:
        email_counter[str(row["ioc_value"])] += int(row["total"])
    for row in hash_rows:
        hash_counter[str(row["ioc_value"])] += int(row["total"])

    phase_counter = Counter()
    tool_counter = Counter()
    trend_counter = Counter()
    for phases, tools, campaign_id in AttackJourney.objects.exclude(session_id="").values_list("phases", "tools_used", "campaign_id").iterator(chunk_size=200):
        if campaign_id:
            trend_counter[str(campaign_id)] += 1
        for phase in phases or []:
            phase_counter[_phase_name(phase)] += 1
        for tool in tools or []:
            if tool:
                tool_counter[str(tool)] += 1

    def _enrich_ip(value: str, count: int) -> dict[str, Any]:
        snapshot = (
            ThreatIntelSnapshot.objects.filter(ip_address=value)
            .order_by("-timestamp")
            .first()
        )
        return {
            "value": value,
            "count": count,
            "country": snapshot.country if snapshot else "",
            "asn": snapshot.asn if snapshot else "",
            "reputation_score": snapshot.reputation_score if snapshot else None,
            "vpn": snapshot.vpn if snapshot else None,
            "tor": snapshot.tor if snapshot else None,
        }

    return {
        "top_ioc_types": ioc_type_rows,
        "most_repeated_ips": [_enrich_ip(value, count) for value, count in ip_counter.most_common(10)],
        "most_repeated_urls": [{"value": value, "count": count} for value, count in url_counter.most_common(10)],
        "most_repeated_emails": [{"value": value, "count": count} for value, count in email_counter.most_common(10)],
        "most_repeated_hashes": [{"value": value, "count": count} for value, count in hash_counter.most_common(10)],
        "highest_risk_campaigns": sorted(campaign_summaries, key=lambda item: item["average_risk_score"], reverse=True)[:10],
        "newest_campaigns": sorted(campaign_summaries, key=lambda item: item["last_seen"] or "", reverse=True)[:10],
        "campaign_trend_counts": [{"campaign_id": campaign_id, "count": count} for campaign_id, count in trend_counter.most_common(20)],
        "most_common_attack_phases": [{"value": phase, "count": count} for phase, count in phase_counter.most_common(10)],
        "most_common_attacker_tools": [{"value": tool, "count": count} for tool, count in tool_counter.most_common(10)],
        "ioc_type_counts": ioc_type_rows,
        "ioc_value_counts": ioc_group_rows,
        "most_connected_iocs": build_most_connected_iocs(limit=limit),
        "most_reused_attacker_tools": build_most_reused_attacker_tools(limit=limit),
        "most_similar_attack_journeys": build_most_similar_attack_journeys(limit=limit),
        "campaigns_with_expanding_activity": build_campaigns_with_expanding_activity(limit=limit),
        "recently_discovered_indicators": build_recently_discovered_indicators(limit=limit),
        "highest_risk_unresolved_journeys": build_highest_risk_unresolved_journeys(limit=limit),
    }


def _campaign_journeys_by_session() -> dict[str, list[AttackJourney]]:
    grouped: dict[str, list[AttackJourney]] = defaultdict(list)
    for journey in AttackJourney.objects.exclude(campaign_id=""):
        grouped[journey.campaign_id].append(journey)
    return grouped