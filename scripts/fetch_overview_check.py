import time
import http.cookiejar as cookiejar
import urllib.request as request
import urllib.parse as parse

login_url = 'http://127.0.0.1:8000/login/'
overview_url = 'http://127.0.0.1:8000/api/dashboard/overview/?limit=20'

cj = cookiejar.CookieJar()
opener = request.build_opener(request.HTTPCookieProcessor(cj))

resp = opener.open(login_url)
csrftoken = None
for c in cj:
    if c.name == 'csrftoken':
        csrftoken = c.value

print('got_login_get', getattr(resp, 'status', None) or resp.getcode())
print('csrftoken', bool(csrftoken))

payload = {
    'username': 'soc-staff',
    'password': 'pass',
    'next': 'http://127.0.0.1:5173/soc',
    'csrfmiddlewaretoken': csrftoken,
}

data = parse.urlencode(payload).encode()
req = request.Request(login_url, data=data, headers={'Referer': login_url})
post_resp = opener.open(req)
print('post_status', getattr(post_resp, 'status', None) or post_resp.getcode())

start = time.time()
overview_resp = opener.open(overview_url)
elapsed = time.time() - start
body = overview_resp.read().decode()
print('overview_status', getattr(overview_resp, 'status', None) or overview_resp.getcode(), 'elapsed_s', round(elapsed,3))
print('body_len', len(body))
print('body_preview', body[:2000])
print('cookies:', [(c.name, c.value) for c in cj])
