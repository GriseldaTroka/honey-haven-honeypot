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

    session_id = '8352864667db6b0f2d39dd1ddaa4cd86'
    campaign_id = 'MIXED_CAMPAIGN_751604'
    paths = [
        f'/api/campaigns/{campaign_id}/',
        f'/api/session/{session_id}/',
        f'/api/session/{session_id}/iocs/',
        f'/api/investigation/graph/?limit=250&session_id={session_id}',
    ]

    with override_settings(ALLOWED_HOSTS=['testserver', 'localhost', '127.0.0.1']):
        for path in paths:
            resp = client.get(path)
            print('PATH', path)
            print('STATUS', resp.status_code)
            try:
                data = resp.json()
                print('TOP_KEYS', list(data.keys()))
                print('BODY_SAMPLE', json.dumps(data, sort_keys=True)[:1200])
            except Exception as e:
                print('JSON_ERROR', e, resp.content[:1000])
            print('---')

        # Also test unauthenticated access to campaign detail
        anon = Client()
        resp = anon.get(f'/api/campaigns/{campaign_id}/')
        print('ANON_CAMPAIGN_STATUS', resp.status_code)
        try:
            print('ANON_BODY', json.dumps(resp.json(), sort_keys=True))
        except Exception as e:
            print('ANON_JSON_ERROR', e, resp.content[:1000])


if __name__ == '__main__':
    main()
