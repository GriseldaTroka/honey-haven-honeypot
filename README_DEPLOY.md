README — Deployment & Production Guidance
=========================================

This document provides guidance for deploying the Honey Haven honeypot stack in a production-like environment with safety, isolation and observability in mind.

1) Summary
----------
Run the stack using Docker Compose for development and testing. For production, build images and deploy via an orchestrator (Kubernetes, ECS) with secrets management, network isolation, and monitoring.

2) Folder structure (recommended)
---------------------------------
- /app (root) — project code
- /observability — Grafana/Loki/Promtail provisioning and dashboards
- /infra/systemd — host-based service units
- /infra/ansible — provisioning playbooks
- /infra/secrets — local secret examples only
- /scripts — helper scripts for provisioning and operations
- /logs — host-mounted logs (scraped by Promtail)
- /secrets — local secret files (ignored by git)

3) Environment variables & secrets
----------------------------------
- Use `.env` for local development. Do NOT commit.
- In production, use a secrets manager and inject secrets into containers.
- Prefer Docker secrets or mounted secret files for values like `DJANGO_SECRET_KEY`.
- Keep `.env.example` as the only committed env template and add comments for every variable.
- Important variables (examples):
  - `DJANGO_SECRET_KEY` or Docker secret `django_secret`
  - `DJANGO_DEBUG` (False in production)
  - `HONEYPOT_ALERT_DEDUP_WINDOW_MIN`
  - `HONEYPOT_ALERT_MAX_PER_WINDOW`
  - `HONEYPOT_SANDBOX_URL`, `HONEYPOT_SANDBOX_API_KEY`
  - Alert webhooks: `HONEYPOT_DISCORD_WEBHOOK_URL`, `HONEYPOT_TELEGRAM_WEBHOOK_URL`, `HONEYPOT_ALERT_EMAIL`

See `.env.example` for a template.

4) Docker Compose (production recommendations)
----------------------------------------------
- Use the `docker-compose.yml` provided in the repo for local and dev stacks.
- For production:
  - Build immutable images (`docker build`) and avoid bind-mounting source code.
  - Use a private registry for images.
  - Use Docker Swarm or Kubernetes for secrets and service management.
  - Mount only the log volume from the host and persistent volumes for database/stateful services.
  - Keep the reverse proxy on the public network; keep the backend network internal.

Start (dev):
```bash
cp .env.example .env
# edit .env
docker compose up -d --build --profile observability --profile honeypots
```

5) Systemd unit example (run a single service on the host)
---------------------------------------------------------
Create `/etc/systemd/system/honey-web.service`:

```ini
[Unit]
Description=Honey Haven Django Gunicorn
After=network.target

[Service]
User=www-data
Group=www-data
EnvironmentFile=/etc/honey/honey.env
WorkingDirectory=/opt/honey
ExecStart=/opt/honey/venv/bin/gunicorn honeytrap.wsgi:application -w 1 -b 127.0.0.1:8000
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

6) Database and backups
-----------------------
- Prefer Postgres in production. Use managed DB services when possible.
- Backups: nightly logical dumps (pg_dump), store in encrypted object storage with lifecycle rules.
- Test restore periodically.

7) Logging & observability
--------------------------
- Use structured JSON logs for telemetry events. Promtail -> Loki -> Grafana.
- Rotate logs: use Docker logging options or `logrotate` for host files.
- Ensure logs containing sensitive info are redacted before shipping.
- Preserve application logs on a dedicated host volume to simplify incident review and backup.

8) Security & isolation
------------------------
- Run honeypot services in a segregated network (`honeynet`) with no direct access to production networks.
- Apply least-privilege to any IAM/API keys used by the app or sandbox.
- Keep sandbox and analysis services offline by default; only enable them in an isolated lab network.
- All inbound/outbound alerting destinations should be allowlisted.
- Treat sample credentials in decoy files as bait only; never reuse any real secret values there.

9) Sandbox guidance (deferred)
------------------------------
- Do NOT enable a live malware sandbox in your production environment until you have a fully isolated lab with egress controls and monitoring.
- For now the included `sandbox_worker` will simulate verdicts unless `HONEYPOT_SANDBOX_URL` is provided.

10) Disaster recovery
---------------------
- Document RTO/RPO for the honeypot dataset.
- Make regular snapshots (DB and persistent volumes). Keep at least one offsite copy.

11) Updating & CI/CD
--------------------
- Build immutable Docker images in CI and tag with commit SHA.
- Use a staged rollout (canary) when deploying changes to production observability.

12) Contact & audit
-------------------
- Maintain an incident runbook describing how to handle high-volume alerts and false positives.
- Keep an audit trail of who accessed the logs and analysis features.

