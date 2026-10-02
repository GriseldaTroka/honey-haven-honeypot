import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'honeytrap.settings')
import django
django.setup()

from store.models import LoginAttempt, HoneypotLog
from store.utils import derive_session_id

target = '70b76b91baf94755f913b57e'

la = LoginAttempt.objects.filter(id=3).first()
if la:
    ip = la.ip_address or ''
    ua = la.user_agent or ''
    ds = derive_session_id(ip_address=ip, user_agent=ua)
    print('LoginAttempt id=3 ip:', ip)
    print('LoginAttempt id=3 user_agent:', ua[:200])
    print('Derived session id from id=3:', ds)
    print('Matches target:', ds == target)
else:
    print('LoginAttempt id=3 not found')

# Also try to find any HoneypotLog record whose derived session id equals target and print one sample
found = None
for r in HoneypotLog.objects.order_by('-timestamp')[:5000]:
    ds = derive_session_id(ip_address=r.ip_address or '', user_agent=(r.user_agent or '')[:1000])
    if ds == target:
        found = r
        break
if found:
    print('HoneypotLog sample id', found.id, 'requested_url', found.requested_url, 'timestamp', found.timestamp)
else:
    print('No HoneypotLog derived match found in sample')
