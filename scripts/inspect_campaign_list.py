#!/usr/bin/env python3
import os
import json
import sys

# Ensure project root is on sys.path so Django settings package can be imported
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

    path = '/api/campaigns/?limit=100'
    with override_settings(ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1']):
        resp = client.get(path)
        print('PATH', path)
        print('STATUS', resp.status_code)
        try:
            data = resp.json()
            print('TOP_KEYS', list(data.keys()))
            sample = json.dumps(data, sort_keys=True)[:2000]
            print('BODY_SAMPLE', sample)
            # Pretty-print first campaign if available
            campaigns = data.get('campaigns') or []
            if campaigns:
                print('\nFIRST_CAMPAIGN_KEYS', list(campaigns[0].keys()))
                print('FIRST_CAMPAIGN_SAMPLE', json.dumps(campaigns[0], sort_keys=True)[:1200])
        except Exception as e:
            print('JSON_ERROR', e, resp.content[:1000])


if __name__ == '__main__':
    main()
