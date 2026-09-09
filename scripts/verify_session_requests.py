import json
import urllib.error
import urllib.request

key = 'dw4kf2jnlwas2iph0h1mqrdvyrlf62ua'
url_base = 'http://127.0.0.1:8000'
endpoints = [
    '/api/dashboard/overview/?limit=20',
    '/api/sessions/?limit=100',
    '/api/campaigns/?limit=100',
    '/api/alerts/?limit=100',
    '/api/iocs/?limit=100',
    '/api/notes/',
    '/api/bookmarks/',
    '/api/search/?q=surface_mapping',
]

opener = urllib.request.build_opener()
opener.addheaders = [
    ('Cookie', f'sessionid={key}'),
    ('User-Agent', 'verification-script'),
    ('Accept', 'application/json'),
]

for ep in endpoints:
    full = url_base + ep
    try:
        with opener.open(full, timeout=15) as response:
            body = response.read().decode('utf-8', errors='replace')
            print(ep, response.status, response.headers.get('content-type', '')[:80])
            try:
                parsed = json.loads(body)
                if isinstance(parsed, list):
                    print('  items:', len(parsed), 'sample:', json.dumps(parsed[:3], default=str))
                elif isinstance(parsed, dict):
                    print('  keys:', list(parsed.keys())[:10])
            except Exception as exc:
                print('  not json or parse error', exc)
    except urllib.error.HTTPError as exc:
        print(ep, 'ERROR', exc.code, exc.headers.get('content-type', '')[:80])
        print('  body_start:', exc.read().decode('utf-8', errors='replace')[:200])
    except Exception as exc:
        print(ep, 'ERROR', exc)
