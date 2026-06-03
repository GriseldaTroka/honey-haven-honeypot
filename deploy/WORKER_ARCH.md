Background Worker Architecture — Celery integration

Overview

- The app now uses Celery for background processing of heavy analytics tasks (AttackJourney aggregation, phase detection, batch rebuilding).
- Realtime request logging (`log_event`) no longer performs heavy aggregation inline. Instead it enqueues `update_attack_journey_task`.
- Tasks are idempotent and safe to retry.

Components

- `honeytrap/celery.py`: Celery app factory. Reads broker/backend from `CELERY_BROKER_URL` or `REDIS_URL`.
- `store/tasks.py`: Celery tasks:
  - `update_attack_journey_task(session_id, entry_point)` — idempotent task to upsert a journey.
  - `process_journeys_batch(session_ids)` — batch processing by session ids.
  - `rebuild_journeys_window(hours, limit)` — batch rebuild for a lookback window.

- `store/deception.upsert_attack_journey()` — core idempotent upsert function used by tasks.

Queue and idempotence

- Tasks deduplicate session ids internally and `upsert_attack_journey` is idempotent (get_or_create + recompute).
- `update_attack_journey_task` is retry-safe (`max_retries=3` by default).
- For preventing duplicate processing, the suggested deployment is to use a single queue for real-time updates and a separate queue for batch rebuilds.

Batching and debounce

- The `process_journeys_batch` task accepts a list of session ids and deduplicates them. Operators can implement a small debounce aggregator (e.g., collect session ids into Redis sets and schedule a batch task every N seconds) to reduce task volume.

Running workers

- Install Celery and a broker (Redis recommended):

  ```powershell
  .venv\Scripts\Activate.ps1
  pip install celery redis
  ```

- Start a worker:

  ```powershell
  CELERY_BROKER_URL=redis://localhost:6379/0 python -m celery -A honeytrap worker -Q default -l info
  ```

- Run periodic rebuild (cron or systemd timer):

  ```powershell
  python manage.py process_journeys --hours 24 --limit 500
  ```

Deployment notes

- Ensure `CELERY_BROKER_URL` and `CELERY_RESULT_BACKEND` are set in environment.
- Use supervisors (systemd, Kubernetes CronJob/Deployment) to run workers and schedule periodic rebuild jobs.
- Monitor worker queues and task latency (Prometheus exporter for Celery recommended).

Safety and fallback

- If Celery is unavailable, `log_event()` falls back to synchronous execution of `update_attack_journey_task` or direct `upsert_attack_journey` to avoid data loss — this keeps behavior backwards compatible during transition.

Scaling

- For heavy volumes, consider:
  - Using Redis clusters or RabbitMQ for broker
  - Multiple worker replicas consuming from the same queue
  - Debounce aggregation to reduce task churn
  - Partitioning by session hash to route related sessions to the same worker for cache locality

