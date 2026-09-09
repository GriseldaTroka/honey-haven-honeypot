import os
import sys
import time
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'honeytrap.settings')

import django

django.setup()

from django.db import connection
from django.test.utils import CaptureQueriesContext

from store.models import AttackJourney, AttackerState, IOCIndicator
from store.investigation import _unique_sorted, _phase_name, _flatten_text_values


def timed(label, fn):
    start = time.perf_counter()
    value = fn()
    elapsed = (time.perf_counter() - start) * 1000
    print(f'{label}: {elapsed:.2f} ms')
    return value, elapsed


def probe_campaign(campaign_id: str):
    print(f'\nCAMPAIGN {campaign_id}')
    journeys, ms = timed('  journeys query', lambda: list(AttackJourney.objects.filter(campaign_id=campaign_id).order_by('last_seen', 'session_id')))
    sessions, ms = timed('  sessions derive', lambda: _unique_sorted([j.session_id for j in journeys]))
    attacker_keys, ms = timed(
        '  attacker state query',
        lambda: _unique_sorted([str(item['primary_ip'] or item['session_id']) for item in AttackerState.objects.filter(session_id__in=sessions).values('session_id', 'primary_ip')]) or sessions,
    )
    with CaptureQueriesContext(connection) as ctx:
        iocs, ioc_ms = timed(
            '  IOC query',
            lambda: list(IOCIndicator.objects.filter(attack_journey__campaign_id=campaign_id).select_related('attack_journey')),
        )
    print(f'  IOC query count: {len(ctx)}')
    phases = Counter(_phase_name(phase) for journey in journeys for phase in (journey.phases or []))
    tools = Counter(str(tool) for journey in journeys for tool in (journey.tools_used or []) if tool)
    payloads = Counter(value for journey in journeys for value in _flatten_text_values(journey.payload_evolution or []))
    print(f'  journeys={len(journeys)} sessions={len(sessions)} attacker_keys={len(attacker_keys)} iocs={len(iocs)}')
    print(f'  top phases={phases.most_common(3)}')
    print(f'  top tools={tools.most_common(3)}')
    print(f'  top payloads={payloads.most_common(3)}')


def main():
    campaigns = list(AttackJourney.objects.exclude(campaign_id='').values_list('campaign_id', flat=True).distinct())
    print(f'campaign count: {len(campaigns)}')
    for campaign_id in campaigns:
        probe_campaign(campaign_id)


if __name__ == '__main__':
    main()
