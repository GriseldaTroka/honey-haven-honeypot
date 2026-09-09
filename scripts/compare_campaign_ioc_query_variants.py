import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'honeytrap.settings')

import django

django.setup()

from store.models import AttackJourney, IOCIndicator

campaign_id = 'MIXED_CAMPAIGN_751604'
journey_ids = list(AttackJourney.objects.filter(campaign_id=campaign_id).values_list('id', flat=True))
print('journey_count', len(journey_ids))

variants = [
    ('current_join_ordered', IOCIndicator.objects.filter(attack_journey__campaign_id=campaign_id).select_related('attack_journey')),
    ('current_join_unordered', IOCIndicator.objects.filter(attack_journey__campaign_id=campaign_id).select_related('attack_journey').order_by()),
    ('id_in_unordered', IOCIndicator.objects.filter(attack_journey_id__in=journey_ids).select_related('attack_journey').order_by()),
    ('values_id_in', IOCIndicator.objects.filter(attack_journey_id__in=journey_ids).values_list('ioc_type', 'ioc_value')),
    ('values_id_in_unordered', IOCIndicator.objects.filter(attack_journey_id__in=journey_ids).values_list('ioc_type', 'ioc_value').order_by()),
]

for name, qs in variants:
    start = time.perf_counter()
    rows = list(qs)
    elapsed = (time.perf_counter() - start) * 1000
    print(name, 'rows', len(rows), 'ms', round(elapsed, 2))
    print('  explain:')
    print(qs.explain())
