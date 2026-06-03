"""Redis-backed debounce aggregator for AttackJourney session batching.

Adds session ids to a Redis set to deduplicate and batch them for periodic processing.
"""
from __future__ import annotations

import os
import time
import uuid
from typing import Iterable, List, Optional


def _get_redis_client():
    try:
        import redis
    except Exception:
        return None
    url = os.environ.get("REDIS_URL", os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0"))
    return redis.from_url(url, decode_responses=True)


KEY_PREFIX = os.environ.get("HONEYPOT_DEBOUNCE_KEY", "honeytrap:journey_pending")


def add_session(session_id: str) -> bool:
    """Add a session_id to the Redis set. Returns True if added or queued, False on immediate fallback failure."""
    r = _get_redis_client()
    if not r:
        return False
    try:
        # use SADD (idempotent)
        r.sadd(KEY_PREFIX, session_id)
        # set a TTL so stale keys expire: 1 day
        r.expire(KEY_PREFIX, 86400)
        return True
    except Exception:
        return False


def drain_sessions(max_count: Optional[int] = None, *, timeout_sec: int = 5) -> List[str]:
    """Atomically move the pending set to a processing key and return the members.

    Uses RENAME to avoid races: the original key is moved and a new key can be created for new incoming events.
    """
    r = _get_redis_client()
    if not r:
        return []
    key = KEY_PREFIX
    proc_key = f"{KEY_PREFIX}:processing:{int(time.time())}-{uuid.uuid4().hex[:8]}"
    try:
        # If key doesn't exist, nothing to do
        if not r.exists(key):
            return []
        # Atomic rename: moves the key to proc_key
        r.rename(key, proc_key)
    except Exception:
        # If rename fails (key may have been moved by other worker), try to read members directly
        try:
            members = list(r.smembers(key))
            if members and max_count:
                return members[:max_count]
            return members
        except Exception:
            return []
    try:
        members = list(r.smembers(proc_key))
        # optionally limit
        if max_count and len(members) > max_count:
            members = members[:max_count]
        return members
    finally:
        try:
            r.delete(proc_key)
        except Exception:
            pass
*** End Patch