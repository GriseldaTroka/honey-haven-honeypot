AttackJourney Persistence — Design & Operational Notes

Data model

- `AttackJourney` (models/AttackJourney):
  - `session_id` (unique): derived fingerprint used to correlate events across logs.
  - `entry_point`: first observed URL or named entry that began the journey.
  - `first_seen` / `last_seen`: timestamps marking lifecycle; `last_seen` is auto-updated.
  - `seconds_spent`: derived duration between first and last seen.
  - `event_count`: aggregated number of correlated events (requests, telemetry, login attempts, alerts).
  - `phases`: JSON array of detected phases (e.g., `reconnaissance`, `credential_attempts`, `injection_attempts`, `escalation`, `data_exfiltration`, `observation`).
  - `ips` / `user_agents`: JSON arrays of observed IPs and UAs for the journey (for quick lookup/filtering).
  - `campaign_id`: placeholder field for future campaign enrichment / clustering output.
  - Indices on `last_seen`, `event_count`, and `campaign_id` to support efficient time-based and severity queries.

Update logic

- `utils.log_event()` invokes `upsert_attack_journey(session_id, entry_point=...)` after writing `HoneypotLog` entries. This keeps journeys up to date in near-real-time without requiring the operator to run background jobs.

- `deception.upsert_attack_journey(session_id, **fields)` performs:
  1. `get_or_create` for the `AttackJourney` record.
  2. Recomputes summary metrics by scanning related event tables (`HoneypotLog`, `TelemetryEvent`, `LoginAttempt`, `AlertEvent`) and deriving the canonical session fingerprint for each event.
  3. Updates `first_seen`, `last_seen`, `seconds_spent`, `event_count`, `ips`, `user_agents`, and `phases`.
  4. Persists the record.

Correlation heuristics

- Primary correlation key: `session_id` produced by `derive_session_id(ip, ua, accept-language, cookie_seed, path)` in `store/utils.py`.
- For events without an explicit `session_id` (older telemetry rows), the same derive function is applied per-row to attempt matching.
- Fallback grouping uses `ip_address` + `user_agent` fingerprint when session derivation fails.
- Time proximity: journeys are bounded by `first_seen` / `last_seen`. The management tooling uses a default lookback window (24 hours) to limit processing.

Migration requirements

- The `AttackJourney` model was extended with new fields. Run:

  ```bash
  python manage.py makemigrations store
  python manage.py migrate
  ```

- Depending on dataset size, consider creating the migration during low-traffic windows and verify index creation time on your DB (Postgres recommended for JSON/query performance).

Performance considerations

- The upsert logic recomputes aggregates by scanning event tables. For large installations:
  - Move aggregation to a background worker (Celery/RQ) and use the provided management command `process_journeys` to batch-process windows of activity.
  - Add materialized views or pre-aggregated counters (e.g., per-session counters) to avoid scanning full tables.
  - Use Postgres partitioning for `HoneypotLog` and `TelemetryEvent` (time-based) to accelerate range queries.
  - Use the `campaign_id` field to store clustering/campaign results so that subsequent queries can filter by campaign cheaply.

Background processing

- A management command `python manage.py process_journeys` is provided to batch-run journey aggregation over a lookback window. It is suitable to run as a cron job or a scheduled Kubernetes CronJob.

Future architecture notes

- Campaign tracking: introduce a `Campaign` model and a `journey_campaigns` m2m table. Clustering algorithms can assign `campaign_id` and populate relationships.
- Attacker clustering: export journey feature vectors (phases, event counts, timing) to an ML pipeline; persist clustering labels to `campaign_id` and a `cluster_score` field.
- Threat-intel enrichment: integrate `ThreatIntelSnapshot` and external feeds to annotate `ips` with ASN/provider/reputation and attach enrichment records to journeys.
- Cross-journey correlation: build inverted indexes for payload fingerprints (e.g., payload hashes) and use them to link journeys sharing identical payloads or indicators.

Advanced phase detection

- The system now computes ordered, sequence-based phases per `AttackJourney` using event sequences and timing analysis. Each journey stores:
  - `phases`: ordered list of objects `{phase, confidence, start, end, count}`.
  - `notes`: short narrative summarizing top phases and metrics.

- Detection approach: the detector analyzes ordered events for patterns (recon scans, clustered failed logins, repeated probing of config paths, injection payloads, upload/exploit indicators, scraping/download patterns, repeated admin accesses). It computes confidence scores and orders phases temporally.

- Performance: the detector samples recent events (configurable `max_events`) and is designed to run during `upsert_attack_journey` calls. For high-throughput deployments, prefer background batch processing (see `process_journeys`) and use Postgres partitioning / materialized views for scaling.

Operational checklist

- Ensure `DEFAULT_DB` is PostgreSQL for best JSON indexing and concurrency.
- Run migrations and monitor index creation time.
- If using real-time upsert in `log_event`, monitor request latency; move to background workers if latency impact is observed.

