import time
from django.test import Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from store.models import DetectionAlert, AttackJourney

User = get_user_model()
# find or create a staff user for force_login
u = User.objects.filter(is_staff=True).first()
if not u:
    u = User.objects.create(username='temp_staff_for_test', is_staff=True, is_superuser=True)

c = Client()
c.force_login(u)

sid = f'verify-alert-review-session-{int(time.time() * 1000)}'
journey = AttackJourney.objects.create(session_id=sid, entry_point='/login', campaign_id='campaign-verify')
alert = DetectionAlert.objects.create(
    rule_name='DETAIL_VERIFY_RULE',
    severity='HIGH',
    confidence_score=0.9,
    status='OPEN',
    description='verify detail GET',
    session_id=sid,
    attack_journey=journey,
    campaign_id='campaign-verify',
    evidence_source_model='HoneypotLog',
    evidence_source_event='request',
    evidence_fingerprint='verify-fingerprint-1',
    evidence_summary='verify detail GET',
    response_recommendation=['review session'],
)

start = time.time()
# include HTTP_HOST to avoid DisallowedHost in test env
patch = c.patch(reverse('alert_detail_api', args=[alert.id]), data='{"status":"RESOLVED"}', content_type='application/json', HTTP_HOST='localhost')
get_resp = c.get(reverse('alert_detail_api', args=[alert.id]), HTTP_HOST='localhost')
elapsed = time.time() - start

print('PATCH_STATUS', patch.status_code)
try:
    print('PATCH_JSON_STATUS', patch.json().get('alert', {}).get('status'))
except Exception:
    print('PATCH_BODY', patch.content)
print('GET_STATUS', get_resp.status_code)
print('ELAPSED_SECONDS', round(elapsed, 3))
try:
    j = get_resp.json()
    print('STATUS_AFTER_GET', j.get('alert', {}).get('status'))
    print('TIMELINE_LEN', len(j.get('timeline', [])))
except Exception as e:
    print('GET_BODY', get_resp.content)
    print('GET_ERROR', e)

print('Done')
