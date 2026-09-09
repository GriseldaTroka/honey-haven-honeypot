import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'honeytrap.settings')

import django

django.setup()

from django.contrib.auth import get_user_model
from django.test import Client

User = get_user_model()
user = User.objects.get(username='soc-staff')
client = Client()
client.force_login(user)
client.raise_request_exception = True

for campaign_id in ['MIXED_CAMPAIGN_751604', 'MIXED_CAMPAIGN_B7345D', 'MIXED_CAMPAIGN_6D0123']:
    print('==', campaign_id)
    try:
        response = client.get(f'/api/campaigns/{campaign_id}/', HTTP_HOST='127.0.0.1')
        print('status', response.status_code)
        print(response.content[:200].decode('utf-8', errors='replace'))
    except Exception:
        traceback.print_exc()
