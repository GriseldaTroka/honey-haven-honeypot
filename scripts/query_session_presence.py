import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'honeytrap.settings')
import django
django.setup()

from store.models import HoneypotLog, LoginAttempt, TelemetryEvent, AlertEvent, AttackJourney, AttackerState
from store.utils import derive_session_id

target = None
if len(sys.argv) > 1:
    target = sys.argv[1]
else:
    target = '70b76b91baf94755f913b57e'

def safe_count_qs(qs):
    try:
        return qs.count()
    except Exception as e:
        # fallback to iterating
        c = 0
        for _ in qs:
            c += 1
        return c

print('Checking presence of session_id:', target)

# HoneypotLog
hp_qs = HoneypotLog.objects.filter(session_id=target)
try:
    hp_count = hp_qs.count()
except Exception:
    hp_count = safe_count_qs(HoneypotLog.objects.all().iterator())
print('HoneypotLog matches:', hp_count)
if hp_count:
    hp = HoneypotLog.objects.filter(session_id=target).first()
    print(' HoneypotLog sample id, requested_url, timestamp:', hp.id, hp.requested_url, hp.timestamp)

# LoginAttempt
la_qs = LoginAttempt.objects.filter(session_id=target)
la_count = safe_count_qs(la_qs)
print('LoginAttempt matches:', la_count)
if la_count:
    la = LoginAttempt.objects.filter(session_id=target).first()
    print(' LoginAttempt sample id, username, timestamp:', la.id, la.username, la.timestamp)

# TelemetryEvent
te_qs = TelemetryEvent.objects.filter(session_id=target)
te_count = safe_count_qs(te_qs)
print('TelemetryEvent matches:', te_count)
if te_count:
    te = TelemetryEvent.objects.filter(session_id=target).first()
    print(' TelemetryEvent sample id, event_type, timestamp:', te.id, te.event_type, te.timestamp)

# AlertEvent: metadata may contain session_id; avoid JSON contains lookup on SQLite
ae_matches = []
try:
    ae_qs = AlertEvent.objects.filter(metadata__contains={'session_id': target})
    ae_count = ae_qs.count()
    ae_matches = list(ae_qs[:5])
except Exception:
    # fallback: scan recent alerts for matching metadata
    ae_count = 0
    for a in AlertEvent.objects.order_by('-timestamp')[:1000]:
        md = a.metadata or {}
        if isinstance(md, dict) and str(md.get('session_id','')) == target:
            ae_count += 1
            if len(ae_matches) < 5:
                ae_matches.append(a)
print('AlertEvent matches (approx):', ae_count)
if ae_matches:
    a = ae_matches[0]
    print(' AlertEvent sample id, alert_type, timestamp, metadata keys:', a.id, a.alert_type, a.timestamp, list((a.metadata or {}).keys()))

# AttackJourney
aj_qs = AttackJourney.objects.filter(session_id=target)
aj_count = safe_count_qs(aj_qs)
print('AttackJourney matches:', aj_count)
if aj_count:
    aj = AttackJourney.objects.filter(session_id=target).first()
    print(' AttackJourney sample id, campaign_id, first_seen, last_seen:', aj.id, aj.campaign_id, aj.first_seen, aj.last_seen)

# AttackerState
as_qs = AttackerState.objects.filter(session_id=target)
as_count = safe_count_qs(as_qs)
print('AttackerState matches:', as_count)
if as_count:
    ats = AttackerState.objects.filter(session_id=target).first()
    print(' AttackerState sample id, risk_score, updated_at:', ats.id, ats.risk_score, ats.updated_at)

print('\nDetermine origin: inspect recent timeline sources that might have produced this session id')
recent_hp = HoneypotLog.objects.filter(session_id__isnull=False).order_by('-timestamp')[:200]
found = False
for r in recent_hp:
    if r.session_id == target:
        print('Found in HoneypotLog id', r.id, 'requested_url', r.requested_url, 'timestamp', r.timestamp)
        found = True
        break
if not found:
    print('Not found in recent HoneypotLog sample')

print('\nScan recent HoneypotLog entries and compute derived session ids to find a match')
match_found = None
for r in HoneypotLog.objects.order_by('-timestamp')[:5000]:
    ds = derive_session_id(ip_address=r.ip_address or '', user_agent=(r.user_agent or '')[:1000])
    if ds.startswith(target[:len(ds)]) and ds.startswith(target[:6]):
        # exact match
        if ds == target:
            match_found = ('honeypot', r.id, r.requested_url, r.timestamp)
            break
        # also test prefix match just in case
    if ds == target:
        match_found = ('honeypot', r.id, r.requested_url, r.timestamp)
        break
if match_found:
    print('Derived session id matched from HoneypotLog:', match_found)
else:
    print('No derived match found in recent HoneypotLog sample')

print('\nCheck if timeline derives session id anywhere else (AttackJourney, Alerts metadata) by computing derived ids')
def find_in_qs(qs, fields, limit=2000):
    for obj in qs.order_by('-id')[:limit]:
        ip = getattr(obj, 'ip_address', '') or ''
        ua = getattr(obj, 'user_agent', '') or ''
        ds = derive_session_id(ip_address=ip, user_agent=ua)
        if ds == target:
            return obj
    return None

found = find_in_qs(LoginAttempt.objects, ['ip_address','user_agent'], limit=2000)
if found:
    print('Derived match from LoginAttempt id', found.id)
else:
    print('No derived match in LoginAttempt sample')

print('\nFind one session_id that has both AttackerState and AttackJourney')
state_ids = set(AttackerState.objects.values_list('session_id', flat=True))
journey_ids = set(AttackJourney.objects.values_list('session_id', flat=True))
common = state_ids.intersection(journey_ids)
if common:
    sample_id = next(iter(common))
    print('Found sample session_id with both:', sample_id)
    s_as = AttackerState.objects.filter(session_id=sample_id).first()
    s_aj = AttackJourney.objects.filter(session_id=sample_id).first()
    print(' AttackerState id, updated_at:', getattr(s_as,'id',None), getattr(s_as,'updated_at',None))
    print(' AttackJourney id, campaign_id:', getattr(s_aj,'id',None), getattr(s_aj,'campaign_id',None))
else:
    print('No session id has both AttackerState and AttackJourney')
