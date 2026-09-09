import os
import sys
import django
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'honeytrap.settings')
django.setup()

from django.test import Client

c = Client()
username='soc-staff'
password='pass'

logged = c.login(username=username, password=password)
print('logged_in', logged)
start=time.time()
# Provide HTTP_HOST to avoid DisallowedHost when using test Client against live settings
resp=c.get('/api/dashboard/overview/?limit=20', HTTP_HOST='127.0.0.1')
elapsed=time.time()-start
print('status', resp.status_code, 'elapsed_s', round(elapsed,3))
print('content_len', len(resp.content))
print('content_preview', resp.content.decode()[:2000])
