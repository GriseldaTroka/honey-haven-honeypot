Attack Timeline & Deception Realism — Notes

- Timeline JSON endpoint: /research/timeline/json/ (staff-only). Returns chronological events across HoneypotLog, LoginAttempt, AlertEvent, TelemetryEvent, AttackJourney.
- Replay UI: lightweight controls (play/pause/speed). Works by highlighting server-rendered events and scrolling them into view. Frontend can be extended to fetch the JSON endpoint and render client-side for larger datasets.

Realism Tuning

- Deterministic seeding: fake payments/tickets now use _stable_seed and FAKE_API_USERS so the same persona appears across panels, orders, and tickets.
- Use shared registry (FAKE_API_USERS, FAKE_API_ORDERS) for cross-surface consistency. Extend by adding a small `fake_registry` that maps session_id -> persona.
- Timing/error patterns: use _apply_decoy_timing profile to stagger events and introduce small probability of 502/504/429 on internal endpoints.

Production Hardening Recommendations

- Restrict research endpoints to staff-only behind network controls. Keep `@user_passes_test(lambda user: user.is_staff)` on sensitive routes.
- Do not expose decoy data to public endpoints unless intentionally redacted. Review all JSON responses for sensitive leak vectors.
- Isolate telemetry and alerting outputs to a separate storage account/DB; do not mix with production logs.
- Ensure outbound alert webhooks (Discord/Telegram/email) are configured and rate-limited; consider disabling in public-facing instances.
- Use a proper secrets store (KeyVault / Vault) for webhook URLs and email credentials. Remove any fake tokens from repo.
- Configure Promtail/Loki/Grafana with RBAC and network restrictions; avoid public dashboards.

Next Steps

- Add client-side JSON fetching and timeline rendering for large result sets.
- Add a `fake_registry` module to centralize persona mapping and identity allocation across all decoy generators.
- Add probabilistic error responses for decoy APIs and document configuration knobs.
