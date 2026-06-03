Production hardening checklist for Honey Haven

Follow these steps before exposing the honeypot to any public network.

1. Secrets & environment
   - Remove any real secrets from the repository.
   - Set `SECRET_KEY` in environment (do NOT commit). Example: `export SECRET_KEY=$(openssl rand -hex 32)`
   - Ensure `HONEYPOT_DISCORD_WEBHOOK_URL`, `HONEYPOT_TELEGRAM_WEBHOOK_URL`, `HONEYPOT_ALERT_EMAIL` are set in production env or left empty if not used.
   - Use an `env_file` or secrets manager for Docker; avoid storing credentials in `docker-compose.yml`.

2. Django settings
   - Set `DEBUG = False` in `honeytrap/settings.py` or override via environment.
   - Set `ALLOWED_HOSTS` to specific hostnames/IPs.
   - Configure `SECURE_SSL_REDIRECT = True`, `SESSION_COOKIE_SECURE = True`, `CSRF_COOKIE_SECURE = True`.
   - Set `SECURE_HSTS_SECONDS` (e.g., 31536000) and enable HSTS preload only when ready.
   - Configure `DEFAULT_FROM_EMAIL` and an SMTP backend for email alerts if used.

3. Logging & observability
   - Ensure `logs/` is writable by the web process and `promtail` has read access.
   - Limit log retention and rotate logs (logrotate) to avoid disk exhaustion.
   - Configure Loki/Grafana access controls and change default Grafana admin password.

4. Network & container isolation
   - Run honeypot containers on an isolated network (`honeynet`) and restrict outbound access.
   - Use egress firewall rules to prevent compromised honeypot containers from contacting arbitrary hosts.
   - Configure resource limits for Docker containers (CPU, memory) to prevent noisy workloads from impacting host.

5. Alerting & outbound
   - Use rate limits and deduplication for outbound webhooks to avoid accidental spam.
   - Sanitize any attacker-supplied data before including it in outbound payloads.
   - If using email/webhooks, allowlist destinations to reduce risk of leaking sensitive artifacts.

6. Data retention & privacy
   - Decide retention policy for `db.sqlite3`/logs and implement automatic purge for older records.
   - Rotate or redact any captured PII from honeypot artifacts.

7. Operational
   - Run security scans for dependencies (`pip-audit`, `safety`) and patch vulnerabilities.
   - Use a process supervisor (systemd / docker) for production run; prefer Gunicorn + Nginx for web.
   - Harden host OS: apply security updates, disable unused services, enable audit logging.

8. Testing
   - Test failure modes (disk full, network partition) and ensure observability still signals health.
   - Perform a dry-run of alert delivery to verify formatting and routing.

9. Governance
   - Maintain an incident response runbook with steps to isolate and snapshot containers.
   - Record where canary tokens are planted and who has access to the management UI.

Notes:
- This checklist focuses on minimizing real operational risk when deploying deception tooling. Some items are context-specific; review for your environment before enabling public access.
