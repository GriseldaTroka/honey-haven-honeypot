import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'honeytrap.settings')

import django

django.setup()

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import Client
from django.test.utils import CaptureQueriesContext

User = get_user_model()
user = User.objects.get(username='soc-staff')

ENDPOINTS = [
    ('alerts', '/api/alerts/'),
    ('campaigns', '/api/campaigns/?limit=100'),
    ('overview', '/api/dashboard/overview/'),
]


def timed_request(path: str) -> dict:
    client = Client()
    client.force_login(user)
    start = time.perf_counter()
    with CaptureQueriesContext(connection) as ctx:
        response = client.get(path, HTTP_HOST='127.0.0.1')
    elapsed = time.perf_counter() - start
    body = response.content.decode('utf-8', errors='replace')
    try:
        parsed = json.loads(body)
    except Exception:
        parsed = None
    return {
        'path': path,
        'status': response.status_code,
        'content_type': response.headers.get('Content-Type', ''),
        'elapsed_ms': round(elapsed * 1000, 2),
        'query_count': len(ctx),
        'json_keys': list(parsed.keys())[:10] if isinstance(parsed, dict) else None,
        'body_start': body[:200].replace('\n', ' '),
    }


def run_sequential() -> list[dict]:
    return [timed_request(path) for _name, path in ENDPOINTS]


def run_concurrent() -> list[dict]:
    with ThreadPoolExecutor(max_workers=len(ENDPOINTS)) as executor:
        futures = {executor.submit(timed_request, path): (name, path) for name, path in ENDPOINTS}
        results = []
        for future in as_completed(futures):
            results.append(future.result())
    return results


def main() -> None:
    print('SEQUENTIAL')
    sequential = [timed_request(path) for _name, path in ENDPOINTS]
    for item in sequential:
        print(json.dumps(item, indent=2))

    print('CONCURRENT')
    concurrent = run_concurrent()
    for item in concurrent:
        print(json.dumps(item, indent=2))


if __name__ == '__main__':
    main()
