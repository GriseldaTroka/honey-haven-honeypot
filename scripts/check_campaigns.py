#!/usr/bin/env python3
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'honeytrap.settings')
import django

django.setup()

from django.contrib.auth import get_user_model
from django.test import Client
from django.test.utils import override_settings


def main():
    user = get_user_model().objects.filter(is_staff=True).first()
    if not user:
        print('NO_STAFF_USER')
        return
    client = Client()
    client.force_login(user)

    with override_settings(ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1']):
        resp = client.get('/api/campaigns/?limit=100')
        print('STATUS', resp.status_code)
        try:
            data = resp.json()
        except Exception as e:
            print('JSON_ERROR', e)
            return

        print('TOP_KEYS', list(data.keys())[:20])
        campaigns = data.get('campaigns', [])
        print('COUNT', len(campaigns))
        for i, c in enumerate(campaigns[:2]):
            print('\n--- CAMPAIGN', i + 1)
            for key in ['campaign_id', 'total_sessions', 'total_journeys', 'total_attackers', 'ioc_count', 'unique_ioc_count', 'average_risk_score', 'average_confidence_score']:
                val = c.get(key)
                print(f"{key}: {val!r} (type={type(val).__name__})")
            ts = c.get('total_sessions')
            print('total_sessions_is_numeric_and_non_null:', isinstance(ts, (int, float)) and ts is not None)


if __name__ == '__main__':
    main()
