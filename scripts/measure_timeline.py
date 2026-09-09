import os
import time
import json

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'honeytrap.settings')
import django
from django.test import Client
from django.db import connection

django.setup()

client = Client()
# create a staff user session
from django.contrib.auth.models import User
user = User.objects.create_user(username='temp_staff', password='x')
user.is_staff = True
user.save(update_fields=['is_staff'])
client.force_login(user)

for limit in (120, 250):
    connection.queries_log.clear() if hasattr(connection, 'queries_log') else None
    connection.queries.clear()
    start_q = len(connection.queries)
    start = time.perf_counter()
    resp = client.get(f'/research/timeline/json/?limit={limit}')
    elapsed = time.perf_counter() - start
    end_q = len(connection.queries)
    print(json.dumps({'limit': limit, 'status': resp.status_code, 'elapsed_sec': elapsed, 'queries': end_q - start_q, 'events_returned': len(resp.json().get('events', []))}))
