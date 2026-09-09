import time
import http.cookiejar as cookiejar
import urllib.request as request
import urllib.parse as parse

login_url = 'http://127.0.0.1:8000/login/'
status_url = 'http://127.0.0.1:8000/api/internal/staff-status/'

cj = cookiejar.CookieJar()
opener = request.build_opener(request.HTTPCookieProcessor(cj))

start = time.time()
resp = opener.open(login_url)
elapsed_get = time.time() - start

csrftoken = None
for c in cj:
    if c.name == 'csrftoken':
        csrftoken = c.value

print('got_login_get', getattr(resp, 'status', None) or resp.getcode(), 'elapsed_s', round(elapsed_get,3))
print('csrftoken', bool(csrftoken))

payload = {
    'username': 'soc-staff',
    'password': 'pass',
    'next': 'http://127.0.0.1:5173/soc',
    'csrfmiddlewaretoken': csrftoken,
}
data = parse.urlencode(payload).encode()
req = request.Request(login_url, data=data, headers={'Referer': login_url})
start = time.time()
post_resp = opener.open(req)
elapsed_post = time.time() - start
print('post_status', getattr(post_resp, 'status', None) or post_resp.getcode(), 'elapsed_s', round(elapsed_post,3))

start = time.time()
status_resp = opener.open(status_url)
elapsed_status = time.time() - start
body = status_resp.read().decode()
print('status_code', getattr(status_resp, 'status', None) or status_resp.getcode(), 'elapsed_s', round(elapsed_status,3))
print('body', body)
