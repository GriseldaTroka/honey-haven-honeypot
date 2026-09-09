import time
import os
import sys
import django

# Ensure project root is on sys.path so `honeytrap` package imports correctly
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'honeytrap.settings')
django.setup()

from django.contrib.auth import get_user_model
from django.test import Client

User = get_user_model()

username = 'soc-staff'
password = 'pass'

user, created = User.objects.get_or_create(username=username, defaults={'email': 'soc-staff@example.local'})
if created:
    user.set_password(password)
    user.is_staff = True
    user.is_superuser = False
    user.save()
    print('Created staff user')
else:
    if not user.check_password(password) or not user.is_staff:
        user.set_password(password)
        user.is_staff = True
        user.save()
        print('Updated staff user')
    else:
        print('Staff user exists')

client = Client()
start = time.time()
logged_in = client.login(username=username, password=password)
login_time = time.time() - start
print('login_ok', logged_in, 'login_time_s', round(login_time, 3))

start = time.time()
resp = client.get('/api/internal/staff-status/')
elapsed = time.time() - start
print('status_code', resp.status_code, 'elapsed_s', round(elapsed, 3))
print('content', resp.content.decode())
