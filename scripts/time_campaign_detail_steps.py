import os
import sys
import time
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'honeytrap.settings')

import django

django.setup()

from store.investigation import _campaign_journeys, _flatten_text_values, _iso, _phase_name, _unique_sorted, build_investigation_timeline
from store.models import AttackJourney, AttackerState, IOCIndicator

campaign_id = 'MIXED_CAMPAIGN_751604'


def timed(label, fn):
    start = time.perf_counter()
    value = fn()
    elapsed = (time.perf_counter() - start) * 1000
    print(f'{label}: {elapsed:.2f} ms')
    return value


def main():
    journeys = timed('campaign_journeys', lambda: _campaign_journeys(campaign_id))
    sessions = timed('sessions', lambda: _unique_sorted([journey.session_id for journey in journeys]))
    journey_ids = [journey.id for journey in journeys]
    ioc_rows = timed('ioc_rows', lambda: list(IOCIndicator.objects.filter(attack_journey_id__in=journey_ids).values_list('ioc_type', 'ioc_value').order_by()))
    attacker_states = timed('attacker_states', lambda: list(AttackerState.objects.filter(session_id__in=sessions)))
    timeline = timed('timeline', lambda: build_investigation_timeline(campaign_id=campaign_id, limit=500))
    phase_counter = timed('phase_counter', lambda: Counter(_phase_name(phase) for journey in journeys for phase in (journey.phases or [])))
    tool_counter = timed('tool_counter', lambda: Counter(str(tool) for journey in journeys for tool in (journey.tools_used or []) if tool))
    payload_counter = timed('payload_counter', lambda: Counter(value for journey in journeys for value in _flatten_text_values(journey.payload_evolution or [])))
    ioc_type_counter = timed('ioc_type_counter', lambda: Counter(ioc_type for ioc_type, _ioc_value in ioc_rows if ioc_type))

    summary = {
        'campaign_id': campaign_id,
        'total_journeys': len(journeys),
        'total_sessions': len(sessions),
        'total_attackers': len(_unique_sorted([str(state.primary_ip or state.session_id) for state in attacker_states]) or sessions),
        'ioc_count': len(ioc_rows),
        'unique_ioc_count': len(set(ioc_rows)),
        'average_risk_score': round(sum(journey.risk_score for journey in journeys) / len(journeys), 2) if journeys else 0.0,
        'average_confidence_score': round(sum(journey.confidence_score for journey in journeys) / len(journeys), 2) if journeys else 0.0,
        'dominant_attack_phases': [phase for phase, _count in phase_counter.most_common(5)],
        'dominant_tools': [tool for tool, _count in tool_counter.most_common(5)],
        'dominant_ioc_types': [ioc_type for ioc_type, _count in ioc_type_counter.most_common(5)],
        'most_common_payloads': [payload for payload, _count in payload_counter.most_common(5)],
        'first_seen': _iso(min((journey.first_seen or journey.last_seen for journey in journeys), default=None)),
        'last_seen': _iso(max((journey.last_seen for journey in journeys), default=None)),
    }
    print('summary keys', list(summary.keys()))
    print('timeline len', len(timeline))


if __name__ == '__main__':
    main()
