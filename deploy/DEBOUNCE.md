Debounce Aggregator — Design & Operations

Overview

- New Redis-backed debounce layer collects `session_id`s into a Redis set to deduplicate activity and reduce task churn.
- A periodic worker drains the Redis buffer and processes session ids in batches via `store.tasks.process_journeys_batch`.

Key components

- `store/debounce.py`:
  - `add_session(session_id)` — adds `session_id` to Redis set (`SADD`) and sets TTL; returns True if queued.
  - `drain_sessions(max_count)` — atomically renames the pending key and returns members for processing. Ensures minimal races.

- `store/tasks.py::drain_debounce_buffer` — Celery task that calls `debounce.drain_sessions()` and dispatches a `process_journeys_batch` for the collected session ids.

Integration flow

1. `log_event()` writes `HoneypotLog` synchronously (fast path) then calls `debounce.add_session(session_id)`.
2. If `add_session` succeeds, request returns immediately and session will be processed later in batch.
3. A periodic worker (e.g., Celery beat) runs `drain_debounce_buffer` every N seconds (recommended 5–10s). It drains the set and enqueues `process_journeys_batch`.
4. `process_journeys_batch` calls `upsert_attack_journey` for each session id (idempotent).

Batch window design

- Default window: 5–10 seconds is recommended (tradeoff between latency and task volume).
- The Redis set deduplicates session ids; multiple events from same session within the window result in one session processed.
- The `drain_debounce_buffer` task should run frequently (every 5s) to keep journey updates near-real-time while reducing task churn.

Fault tolerance & fallback

- If Redis is unavailable or `add_session` fails, `log_event()` falls back to enqueueing `update_attack_journey_task` (Celery) or calling `upsert_attack_journey` synchronously — ensuring no data loss.
- `drain_sessions` uses `RENAME` to atomically move the key to a processing key to avoid races; if RENAME fails, it reads members and attempts deletion.
- `process_journeys_batch` and `update_attack_journey_task` are idempotent to permit retries without duplication.

Scaling

- Use Redis for low-overhead deduplication. `SADD` and `SMEMBERS` are O(1)/O(N) respectively; draining can be limited with `max_count` to bound work per run.
- For very high volumes, implement a sharded set pattern (key suffix by hash shard) to parallelize draining across workers.
- Consider using a Redis Stream if ordered consumption or per-event persistence is required.

Deployment notes

- Requirements: `redis` Python package, a running Redis instance (or use same Redis as Celery broker).
- Configure environment variable `REDIS_URL` or `CELERY_BROKER_URL`.
- Start a periodic runner (Celery beat or cron) to call `store.tasks.drain_debounce_buffer` every 5 seconds.

