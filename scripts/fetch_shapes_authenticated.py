import os
import json
import django
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'honeytrap.settings')
django.setup()

from django.test import Client
from django.contrib.auth import get_user_model
import time as _time
import sys

User = get_user_model()

def get_staff_user():
    try:
        return User.objects.filter(is_active=True).filter(is_staff=True).order_by('id').first()
    except Exception:
        return None

client = Client()
user = get_staff_user()
if not user:
    # create a temporary staff user (no sensitive output)
    user = User.objects.create(username='copilot_test_user', is_staff=True, is_superuser=True)

client.force_login(user)

# session id may be passed as first arg, otherwise use default
session_id = sys.argv[1] if len(sys.argv) > 1 else '9e9049174a15509c662f0715fec063bb'
base='http://127.0.0.1:8000'
endpoints=[
    f'/api/state/attacker/{session_id}/',
    f'/api/session/{session_id}/',
    f'/api/session/{session_id}/iocs/',
    f'/research/timeline/json/?limit=300&session={session_id}',
    f'/api/alerts/?session_id={session_id}',
    f'/api/dashboard/overview/?limit=20',
]

def sample(obj, keys):
    out = {}
    for k in keys:
        out[k] = obj.get(k, 'MISSING') if isinstance(obj, dict) else 'NOT_DICT'
    return out

for ep in endpoints:
    url = base + ep
    print('---', ep)
    # include HTTP_HOST to avoid DisallowedHost (test client default is 'testserver')
    try:
        t0 = _time.perf_counter()
        r = client.get(ep, HTTP_HOST='127.0.0.1:8000')
        elapsed = _time.perf_counter() - t0
    except Exception as e:
        elapsed = _time.perf_counter() - t0 if 't0' in locals() else None
        print('request-exception:', type(e).__name__, e)
        print('elapsed_sec:', elapsed)
        print()
        continue
    print('status', r.status_code, 'elapsed_sec', round(elapsed, 3))
    content_type = r.headers.get('Content-Type', '')
    if 'application/json' not in content_type:
        # try to parse as JSON anyway
        try:
            data = r.json()
        except Exception as e:
            text = r.content.decode(errors='replace')[:400]
            print('content-not-json-sample:', repr(text))
            continue
    else:
        data = r.json()

    if isinstance(data, dict):
        print('type: dict keys:', list(data.keys())[:20])
    else:
        print('type:', type(data), 'len:', len(data) if hasattr(data, '__len__') else 'unknown')

    # representative samples per endpoint
    if ep.startswith('/api/state/attacker/'):
        if isinstance(data, dict):
            keys = ['session_id','risk_score','confidence_score','intent_score','current_phase','start_time','updated_at','duration_seconds']
            print('sample:', sample(data, keys))
    elif ep.startswith('/api/session/') and ep.endswith('/iocs/'):
            # API returns a dict with 'iocs' list
            if isinstance(data, dict) and 'iocs' in data:
                iocs = data.get('iocs') or []
                print('iocs len', len(iocs))
                if iocs:
                    print('first ioc keys', list(iocs[0].keys())[:40])
                    print('first ioc sample', {k: iocs[0].get(k, 'MISSING') for k in ['id','indicator','location','value','confidence','first_seen']})
            elif isinstance(data, list):
                print('list len', len(data))
                if data:
                    print('first item keys', list(data[0].keys())[:20])
    elif ep.startswith('/api/session/'):
        if isinstance(data, dict):
            keys = ['session_id','campaign_id','current_risk_score','confidence','current_phase','start_time','updated_at','duration_seconds','first_seen','last_seen']
            print('sample:', sample(data, keys))
    elif ep.startswith('/research/timeline'):
        if isinstance(data, dict):
            print('top-level keys', list(data.keys()))
            events = data.get('events') or data.get('results') or data.get('data') or []
            print('events_len', len(events) if hasattr(events, '__len__') else 'unknown')
            if events:
                print('first event sample keys', list(events[0].keys())[:20])
                # print session_id value if present for verification
                first_sid = events[0].get('session_id') if isinstance(events[0], dict) else None
                print('first event session_id', first_sid)
    elif ep.startswith('/api/alerts/'):
        if isinstance(data, dict):
            print('top-level keys', list(data.keys()))
            alerts = data.get('alerts') or data.get('results') or data.get('data') or []
            print('alerts_len', len(alerts) if hasattr(alerts, '__len__') else 'unknown')
            if alerts:
                print('first alert sample keys', list(alerts[0].keys())[:20])
    elif ep.startswith('/api/dashboard/overview'):
        if isinstance(data, dict):
            print('top-level keys', list(data.keys())[:40])
            # sample highest risk campaigns, recent campaigns, bookmarks
            for key in ['campaign_intelligence','highest_risk_campaigns','recent_campaigns','recent_bookmarks']:
                if key in data:
                    v = data[key]
                    if isinstance(v, list):
                        print(key, 'len', len(v))
                        if v:
                            print(key, 'first sample keys', list(v[0].keys())[:40])
                    else:
                        print(key, 'type', type(v))

    print()
