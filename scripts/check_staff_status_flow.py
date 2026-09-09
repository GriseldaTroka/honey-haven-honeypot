import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'honeytrap.settings')

import django
django.setup()

from django.contrib.auth import get_user_model
from django.test import Client

User = get_user_model()

def main():
    client = Client()
    print('Anonymous GET /api/internal/staff-status/')
    r = client.get('/api/internal/staff-status/')
    print(r.status_code, r.content.decode())

    username = 'soc-staff'
    password = 'pass'
    user, created = User.objects.get_or_create(username=username, defaults={'email': 'soc-staff@example.local'})
    if created:
        user.set_password(password)
        user.is_staff = True
        user.save()
        print('Created staff user')

    ok = client.login(username=username, password=password)
    print('client.login ->', ok)

    print('Authenticated GET /api/internal/staff-status/')
    r2 = client.get('/api/internal/staff-status/')
    print(r2.status_code, r2.content.decode())

    print('GET /soc (should render HTML)')
    r3 = client.get('/soc')
    print(r3.status_code, len(r3.content))

if __name__ == '__main__':
    main()
