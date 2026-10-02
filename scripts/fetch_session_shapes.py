import json, urllib.request, urllib.error
session_id='70b76b91baf94755f913b57e'
base='http://127.0.0.1:8000'
endpoints=[
    f'/api/state/attacker/{session_id}/',
    f'/api/session/{session_id}/',
    f'/api/session/{session_id}/iocs/',
    f'/research/timeline/json/?limit=300&session={session_id}',
    f'/api/alerts/?session_id={session_id}',
]
for ep in endpoints:
    url=base+ep
    print('---', ep)
    try:
        req=urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=20) as r:
            b=r.read()
            print('status', r.getcode(), 'len', len(b))
            try:
                 # show beginning of payload to inspect prefix
                 sample = b.decode(errors='replace')[:400]
                 print('sample:', repr(sample))
                 j=json.loads(b.decode())
                 print('keys:', list(j.keys()) if isinstance(j, dict) else type(j))
                 print(json.dumps(j, indent=2)[:1000])
            except Exception as e:
                print('json error', e)
    except urllib.error.HTTPError as e:
        print('HTTPError', e.code, e.reason)
    except Exception as e:
        print('ERR', type(e), e)
