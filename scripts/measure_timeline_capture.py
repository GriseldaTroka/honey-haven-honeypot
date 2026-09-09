import os
import time
import json

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'honeytrap.settings')
import django
django.setup()

from django.test import Client
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.contrib.auth.models import User
from store.models import HoneypotLog, LoginAttempt, AlertEvent, TelemetryEvent, AttackJourney


def seed_sample(n=300):
    HoneypotLog.objects.all().delete()
    LoginAttempt.objects.all().delete()
    AlertEvent.objects.all().delete()
    TelemetryEvent.objects.all().delete()
    AttackJourney.objects.all().delete()
    for i in range(n):
        HoneypotLog.objects.create(ip_address=f'198.51.100.{i%255}', user_agent='UA', requested_url=f'/page/{i}', event_type='REQUEST', attack_classification='NORMAL_TRAFFIC', status_code=200)
        LoginAttempt.objects.create(username=f'user{i}', password_submitted='p', ip_address=f'198.51.100.{i%255}', success=(i%5==0))
        AlertEvent.objects.create(alert_type='TEST', detail='d', ip_address=f'198.51.100.{i%255}', metadata={'session_id': f'session{i%50}'})
        TelemetryEvent.objects.create(session_id=f'session{i%50}', event_type='E', path=f'/api/{i}', details={'k': 'v'})
        if i%10==0:
            AttackJourney.objects.create(session_id=f'session{i%50}', entry_point='/start', recon_path=['/a','/b'], tools_used=['curl'], notes='n')


def measure(limit):
    client = Client()
    user = User.objects.create_user(username=f'meas_{limit}', password='x')
    user.is_staff = True
    user.save(update_fields=['is_staff'])
    client.force_login(user)

    with CaptureQueriesContext(connection) as ctx:
        start = time.perf_counter()
        resp = client.get(f'/research/timeline/json/?limit={limit}')
        elapsed = time.perf_counter() - start
    return {'limit': limit, 'status': resp.status_code, 'elapsed_sec': elapsed, 'queries': len(ctx.captured_queries), 'events_returned': len(resp.json().get('events', []))}


if __name__ == '__main__':
    print('Seeding sample data (this will delete existing timeline tables entries in DB)')
    seed_sample(400)
    results = []
    for l in (120, 250):
        results.append(measure(l))
    print(json.dumps(results, indent=2))
