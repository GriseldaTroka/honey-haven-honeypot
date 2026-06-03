Examples for configuring honeypot containers to notify the Honey Haven app webhook.

Cowrie (example snippet for `cowrie.cfg` or pipeline):

```ini
# If cowrie supports an event-forwarder or logrotate hook, point to:
post_command = curl -X POST -H 'Content-Type: application/json' -d '{"source":"cowrie","event":"login_success","data": {"ip": "%(src_ip)s", "user": "%(username)s", "user_agent": "%(user_agent)s"}}' http://web:8000/webhook/honeypot/
```

Dionaea: use an external script that watches `dionaea` logs and posts JSON to the webhook URL. The provided `scripts/forward_logs.py` can be used as a lightweight forwarder.

Conpot: configure `conpot` logging hooks or run a sidecar to read `/var/log/conpot` and POST events to `/webhook/honeypot/`.

Note: adjust `http://web:8000` to the reachable address in your deployment (compose service name `web` is correct when colocated in the same compose network).
