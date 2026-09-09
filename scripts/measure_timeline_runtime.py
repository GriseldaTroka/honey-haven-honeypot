from django.test.utils import CaptureQueriesContext
from django.test import RequestFactory
from django.db import connection
from django.contrib.auth import get_user_model
from django.conf import settings
import time, json

# Ensure query capture is enabled
try:
    settings.DEBUG = True
except Exception:
    pass

User = get_user_model()
# create or get a staff user for measurement
user, created = User.objects.get_or_create(username='m_timeline_measure')
user.is_staff = True
user.is_active = True
user.set_password('x')
user.save()

from store import views

results = []
for limit in (250, 120, 50):
    rf = RequestFactory()
    req = rf.get(f"/research/timeline/json/?limit={limit}")
    req.user = user
    start = time.perf_counter()
    with CaptureQueriesContext(connection) as ctx:
        resp = views.attacker_timeline_json(req)
    elapsed = time.perf_counter() - start
    content = resp.content.decode('utf-8') if hasattr(resp, 'content') else ''
    try:
        payload = json.loads(content)
        events = payload.get('events', []) if isinstance(payload, dict) else []
    except Exception:
        events = []
    # capture slowest queries
    captured = getattr(ctx, 'captured_queries', [])
    parsed = []
    for q in captured:
        try:
            t = float(q.get('time') or 0.0)
        except Exception:
            t = 0.0
        parsed.append({'sql': q.get('sql')[:500], 'time': t})
    parsed_sorted = sorted(parsed, key=lambda x: x['time'], reverse=True)[:5]
    results.append({
        'limit': limit,
        'status': getattr(resp, 'status_code', None),
        'elapsed_sec': elapsed,
        'events_returned': len(events) if isinstance(events, list) else None,
        'response_size_bytes': len(content),
        'query_count': len(parsed),
        'slowest_queries': parsed_sorted,
    })

print(json.dumps(results, indent=2))
