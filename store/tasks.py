from celery import shared_task
from typing import List
from django.utils import timezone

from .deception import upsert_attack_journey, build_attack_journeys


@shared_task(bind=True, max_retries=3, default_retry_delay=5)
def update_attack_journey_task(self, session_id: str, entry_point: str | None = None) -> dict:
    """Idempotent task: update or create a journey for a single session id."""
    try:
        upsert_attack_journey(session_id=session_id, entry_point=entry_point)
        return {"session_id": session_id, "status": "ok", "ts": timezone.now().isoformat()}
    except Exception as exc:
        raise self.retry(exc=exc)


@shared_task(bind=True)
def process_journeys_batch(self, session_ids: List[str]) -> dict:
    """Process a batch of session_ids (idempotent)."""
    processed = []
    for sid in set(session_ids):
        try:
            upsert_attack_journey(session_id=sid)
            processed.append(sid)
        except Exception:
            # continue; tasks should be idempotent and best-effort
            continue
    return {"processed": len(processed), "session_ids": processed}


@shared_task(bind=True)
def rebuild_journeys_window(self, hours: int = 24, limit: int = 500) -> dict:
    """Batch job to rebuild journeys for a recent window; useful for cron jobs."""
    journeys = build_attack_journeys(lookback_hours=hours, limit=limit)
    count = 0
    for j in journeys:
        try:
            upsert_attack_journey(session_id=j["session_id"], entry_point=j.get("first_seen"))
            count += 1
        except Exception:
            continue
    return {"rebuilt": count}


@shared_task(bind=True)
def drain_debounce_buffer(self, max_batch: int = 1000) -> dict:
    """Drain Redis debounce buffer and process collected session ids in batches."""
    try:
        from . import debounce
    except Exception:
        return {"processed": 0, "error": "debounce module not available"}

    session_ids = debounce.drain_sessions(max_count=max_batch)
    if not session_ids:
        return {"processed": 0}
    # call batch processor
    try:
        process_journeys_batch.delay(session_ids)
        return {"processed": len(session_ids)}
    except Exception:
        # fallback to synchronous
        process_journeys_batch(session_ids)
        return {"processed": len(session_ids), "fallback": True}
