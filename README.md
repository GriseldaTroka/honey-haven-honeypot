# Honey Haven Honeypot and SOC Dashboard

Honey Haven is a completed university/diploma project: a Django web honeypot presented as a premium honey storefront, paired with a React SOC dashboard for observing and researching attacker activity.

## Purpose

The application is a controlled decoy environment. It records interaction with realistic storefront pages, fake administration panels, exposed-file traps, decoy APIs, canary tokens, and external honeypot webhooks so attack behavior can be reviewed without exposing a real business system.

## Architecture and features

- Django 5.2 application in `honeytrap/` and `store/`
- Honey Haven storefront, authentication, checkout flow, blog, and product pages
- Decoy surfaces for common panels and files such as `/wp-admin/`, `/phpmyadmin/`, `/.env`, `/backup.sql`, and `/.git/*`
- Request, login, browser, upload, payment, support, canary, and external honeypot telemetry
- Honey session IDs, attacker state transitions, risk and intent scoring, attack journeys, campaign grouping, IOC persistence, and MITRE-oriented research data
- Staff-only investigation APIs for alerts, sessions, campaigns, IOCs, relationships, evidence, notes, bookmarks, graphs, and timelines
- React/Vite SOC dashboard in `soc-simulator/`
- Optional Docker services for alert workers, log forwarding, Loki, Grafana, Alertmanager, Cowrie, Dionaea, and Conpot

Telemetry is written to Django models and structured application logs. The middleware creates or reuses a honey session ID, while event handlers associate activity with `HoneypotLog`, `TelemetryEvent`, `LoginAttempt`, `UploadArtifact`, `AlertEvent`, `AttackJourney`, and related records. Staff endpoints expose bounded JSON payloads for the dashboard and research views; the timeline endpoint is `/research/timeline/json/`.

## Technology stack

- Python 3.12, Django 5.2, SQLite by default
- React 19, React Router, Vite, and oxlint
- Docker Compose, optional Grafana/Loki/Promtail/Alertmanager
- Django migrations in `store/migrations/`

## Repository structure

| Path | Purpose |
| --- | --- |
| `honeytrap/` | Django settings, URL entry point, WSGI, and ASGI |
| `store/` | Models, views, telemetry, deception, investigation, commands, and tests |
| `templates/` | Storefront, decoy, research, and staff pages |
| `static/` and `media/` | Frontend assets and blog media required by the site |
| `soc-simulator/` | React SOC dashboard and API client |
| `observability/` | Loki, Grafana, Promtail, and Alertmanager configuration |
| `deploy/` and `infra/` | Production examples, services, hardening, and provisioning material |
| `scripts/` | Operational checks, simulations, backups, and diagnostics |
| `tests/` and `store/tests/` | Django behavior and SOC workflow tests |

## Prerequisites

For local development, install Python 3.12 and Node.js/npm. Docker Desktop is required for the Compose stack. This project is intended for an isolated lab or research network, not direct exposure to the public Internet.

## Environment setup

Copy `.env.example` to `.env` and replace the placeholder values as appropriate. Important settings include:

- `DJANGO_SECRET_KEY`, `DJANGO_DEBUG`, `DJANGO_ALLOWED_HOSTS`, and `DJANGO_ALLOW_ALL_HOSTS`
- `HONEYTRAP_DB_PATH` for an explicit SQLite location
- `DJANGO_COOKIE_DOMAIN` and `DJANGO_CSRF_TRUSTED_ORIGINS` when using the SOC frontend
- `HONEYPOT_ALERT_DEDUP_WINDOW_MIN`, `HONEYPOT_ALERT_MAX_PER_WINDOW`, `HONEYPOT_SANDBOX_URL`, and `HONEYPOT_SANDBOX_API_KEY`
- Optional Discord, Telegram, and email alert destinations

Never commit `.env`, credentials, webhook URLs, or private keys. `infra/secrets/django_secret.example` is only a safe local Compose placeholder; use a separately provisioned secret for production.

## Local installation and startup

From the repository root in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python manage.py migrate
python manage.py check
python manage.py runserver 0.0.0.0:8000
```

Open the storefront at `http://127.0.0.1:8000/`. The real Django administration is at `/dj-admin/`; `/admin/` is intentionally a decoy surface. Create a staff user with `python manage.py createsuperuser` before using staff-only research views.

### SOC dashboard

In a second terminal:

```powershell
Push-Location soc-simulator
npm install
npm run dev -- --host 127.0.0.1
Pop-Location
```

Open `http://127.0.0.1:5173/soc`. Vite proxies API, authentication, static, and media requests to Django on port 8000. Log in with a Django staff account to use investigation data.

## Docker

Start the default web service with:

```powershell
docker compose up -d --build
```

Start the complete lab stack, including optional profiles, with:

```powershell
docker compose --profile observability --profile honeypots up -d --build
```

The web app is on port 8000, Grafana on 3000, and Alertmanager on 9093 when enabled. `sqlite-data` persists the container database. The `honeynet` network is internal. Stop services with `docker compose down` and inspect health with `docker compose ps`.

## Database and tests

Apply schema migrations with `python manage.py migrate`. Verify model changes have migrations with `python manage.py makemigrations --check --dry-run`. Run all Django tests with `python manage.py test`. Frontend checks are:

```powershell
Push-Location soc-simulator
npm run build
npm run lint
Pop-Location
```

The repository also includes CI definitions under `.github/workflows/`.

## Important endpoints

Storefront and decoy routes include `/`, `/shop/`, `/login/`, `/api/login`, `/admin/`, `/api/upload/trap/`, `/api/payments/webhook/`, `/support/chat/`, and `/webhook/honeypot/`. Staff/research routes include `/api/dashboard/overview/`, `/api/alerts/`, `/api/sessions/`, `/api/campaigns/`, `/api/iocs/`, `/api/session/<session_id>/`, `/api/state/attacker/current/`, `/research/timeline/json/`, `/research/journeys/json/`, and `/api/research/report/`.

## Security and academic context

This is a research honeypot. It deliberately accepts and stores attacker-supplied input, including submitted decoy credentials and payloads. Run it only with isolated data, controlled network access, and non-production credentials. The fake secrets and records returned by decoy endpoints are demonstrations, not valid credentials. Review `PRODUCTION_HARDENING.md`, `README_DEPLOY.md`, and `deploy/SECURITY.md` before deployment.

This repository is the archival source for a completed academic cybersecurity project and is provided for reproducibility, demonstration, and research documentation.
