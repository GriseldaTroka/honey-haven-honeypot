import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import urllib.request
import urllib.parse
import http.cookiejar
import urllib.error

BASE_BACKEND = 'http://127.0.0.1:8000'
BASE_FRONTEND = 'http://127.0.0.1:5173'


def show_resp(resp, body):
    url = getattr(resp, 'geturl', lambda: None)() or getattr(resp, 'url', None) or ''
    print('URL:', url)
    code = getattr(resp, 'status', None) or getattr(resp, 'getcode', lambda: None)() or getattr(resp, 'statuscode', None)
    print('Status:', code)
    ct = None
    try:
        ct = resp.getheader('Content-Type')
    except Exception:
        try:
            ct = resp.headers.get('Content-Type')
        except Exception:
            ct = None
    print('Content-Type:', ct)
    text = body.decode('utf-8', errors='replace') if isinstance(body, bytes) else str(body)
    print('Body start:', text[:400].replace('\n', ' '))
    print('---')


def http_get(opener, url):
    req = urllib.request.Request(url, method='GET')
    try:
        resp = opener.open(req)
        body = resp.read()
        return resp, body
    except urllib.error.HTTPError as e:
        # return the HTTPError (has .read()) so caller can inspect status/body
        try:
            body = e.read()
        except Exception:
            body = b''
        return e, body


def http_post(opener, url, data, headers=None):
    data_enc = urllib.parse.urlencode(data).encode('utf-8')
    req = urllib.request.Request(url, data=data_enc, headers=headers or {}, method='POST')
    try:
        resp = opener.open(req)
        body = resp.read()
        return resp, body
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b''
        return e, body


def main():
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    # GET login page to set CSRF cookie
    lp_resp, lp_body = http_get(opener, f'{BASE_BACKEND}/login/?next=/soc')
    print('Fetched login page status:', lp_resp.getcode())
    csrftoken = None
    for c in cj:
        if c.name == 'csrftoken' or c.name == 'csrf':
            csrftoken = c.value
    print('CSRF cookie present:', bool(csrftoken))

    headers = {'Referer': f'{BASE_BACKEND}/login/'}
    if csrftoken:
        headers['X-CSRFToken'] = csrftoken

    login_data = {'username': 'soc-staff', 'password': 'pass', 'next': '/soc'}
    resp, body = http_post(opener, f'{BASE_BACKEND}/login/', login_data, headers=headers)
    print('Login POST status:', resp.getcode())
    print('Final URL after login (may be redirect target):', resp.geturl())
    has_session = any(c.name == 'sessionid' for c in cj)
    print('Sessionid cookie present after login:', has_session)
    print('---')

    targets = [
        ('staff-status', '/api/internal/staff-status/'),
        ('dashboard', '/api/dashboard/overview/'),
    ]

    sample_session = '6b854c548c4e21277a7678bb8453d975'
    targets.append(('session-detail', f'/api/session/{sample_session}/'))
    # Additional investigative targets
    targets.append(('notes-campaign', f'/api/notes/?campaign_id=MIXED_CAMPAIGN_751604'))
    targets.append(('bookmarks', f'/api/bookmarks/'))
    targets.append(('campaign-journeys', f'/api/campaigns/MIXED_CAMPAIGN_751604/journeys/'))
    targets.append(('campaign-alerts', f'/api/alerts/?campaign=MIXED_CAMPAIGN_751604'))

    for name, path in targets:
        print('DIRECT BACKEND ->', path)
        r1, b1 = http_get(opener, f'{BASE_BACKEND}{path}')
        show_resp(r1, b1)

        time.sleep(0.2)

        print('PROXIED FRONTEND ->', path)
        r2, b2 = http_get(opener, f'{BASE_FRONTEND}{path}')
        show_resp(r2, b2)


if __name__ == '__main__':
    main()
