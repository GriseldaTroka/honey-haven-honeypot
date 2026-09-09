import os
import sys
import json
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'honeytrap.settings')

import django

django.setup()

from django.contrib.auth import get_user_model
from django.test import Client


def probe(client, path):
    try:
        resp = client.get(path, HTTP_HOST='127.0.0.1')
        try:
            body = resp.content.decode('utf-8')
        except Exception:
            body = str(resp.content[:200])
        # Try to parse JSON
        parsed = None
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = body
        return resp.status_code, parsed
    except Exception:
        return 'exception', traceback.format_exc()


def main():
    campaign_id = 'MIXED_CAMPAIGN_751604'
    paths = [
        f'/api/bookmarks/?campaign_id={campaign_id}',
        f'/api/campaigns/{campaign_id}/journeys/',
        f'/api/campaigns/{campaign_id}/',
        f'/api/alerts/?campaign={campaign_id}',
        f'/api/notes/?campaign_id={campaign_id}',
    ]

    print('Probing unauthenticated client:')
    anon = Client()
    for p in paths:
        status, body = probe(anon, p)
        print(p)
        print('  status:', status)
        print('  body:', json.dumps(body) if not isinstance(body, str) else body[:200])

    print('\nProbing authenticated soc-staff user (force_login):')
    User = get_user_model()
    try:
        user = User.objects.get(username='soc-staff')
    except Exception as e:
        print('  Could not find user soc-staff:', e)
        return
    auth = Client()
    auth.force_login(user)
    for p in paths:
        status, body = probe(auth, p)
        print(p)
        print('  status:', status)
        # pretty-print JSON body shapes
        if isinstance(body, dict):
            keys = list(body.keys())
            print('  keys:', keys)
        else:
            print('  body:', str(body)[:200])

    print('\nProbing an authenticated NON-staff user (if available):')
    try:
        nonstaff = User.objects.filter(is_staff=False).exclude(username='soc-staff').first()
        if not nonstaff:
            print('  No non-staff user found to test.')
            return
        print('  testing as', nonstaff.username)
        ns = Client()
        ns.force_login(nonstaff)
        for p in paths:
            status, body = probe(ns, p)
            print(p)
            print('  status:', status)
            print('  body:', body if isinstance(body, str) else list(body.keys()))
    except Exception as e:
        print('  error probing non-staff user:', e)


if __name__ == '__main__':
    main()
