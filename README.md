# Honey Haven Honeypot (Django)

A full-stack Django high-interaction honeypot disguised as a premium honey e-commerce website.

## Features

- Modern responsive storefront with polished UI and smooth reveal animations
- Pages: Home, Shop, Product Details, Login, Register, Checkout, Admin-like decoy panel
- Authentication with Django users (register/login/logout)
- High-interaction decoy routes: /admin, /login, /api/login
- Full request logging with threat telemetry and suspicious pattern tagging
- Stores attacker behavior instead of blocking it (research-first design)
- Additional decoy services: /wp-admin, /cpanel, /phpmyadmin, /grafana, /jenkins, /dashboard, /cms, /portal, /internal
- Fake exposure surfaces: /.env, /backup.sql, /backup.bak, /backup.zip, /config.php, /phpinfo.php, /.git/*, /employee.csv
- Fake APIs: /api/v1/users, /api/v1/orders, /api/internal/auth, /api/admin/export, /api/docs, /graphql, /debug, /api/internal/exec
- Operational endpoints: /api/upload/trap/, /api/live/feed/, /api/alerts/, /api/payments/webhook/, /api/threat/intel/<ip>/, /api/session/<id>/, /support/chat/, /merchant/
- Client-side telemetry: fingerprinting, behavior tracking, idle detection, and beacon-based logging

## Logged telemetry

The system captures and stores:

- Source IP address
- User-Agent
- Requested URL and HTTP method
- Query string and payload/form input
- Login attempts and submitted credentials
- Timestamp and response code
- Suspicion flags (SQL injection patterns, scanner signatures, repeated requests)

## Project structure

honeytrap/
- manage.py
- requirements.txt
- honeytrap/
  - settings.py
  - urls.py
  - asgi.py
  - wsgi.py
- store/
  - models.py
  - views.py
  - forms.py
  - middleware.py
  - utils.py
  - urls.py
  - migrations/0001_initial.py
- templates/
  - base.html
  - home.html
  - shop.html
  - product_detail.html
  - login.html
  - register.html
  - checkout.html
  - fake_admin.html
- static/
  - css/styles.css
  - js/main.js

## Setup instructions (Windows PowerShell)

1. Create and activate virtual environment

   python -m venv .venv
   .\.venv\Scripts\Activate.ps1

2. Install dependencies

   pip install -r requirements.txt

3. Run migrations

   python manage.py migrate

4. (Optional) Create Django superuser for real Django admin (/dj-admin)

   python manage.py createsuperuser

5. Start server

   python manage.py runserver

6. Open app

   http://127.0.0.1:8000/

## Container scaffold

- `Dockerfile` runs the Django app in a Python 3.12 slim container.
- `docker-compose.yml` includes the web app plus optional honeypot and observability profiles for Cowrie, Dionaea, Conpot, Loki, Grafana, Elasticsearch, and Kibana.
- The `honeynet` Docker network is marked internal so exposed trap services stay isolated from telemetry services.
- The `alert-worker` service runs `python manage.py dispatch_alerts --loop --interval 30` to send pending alerts from the database.
- Grafana and Loki are provisioned from `observability/provisioning/` and `observability/dashboards/` so the dashboard opens with a Honey Haven overview panel.

## Honeypot routes

- Storefront home: /
- Decoy login: /login/
- Decoy API login endpoint: /api/login
- Fake merchant admin panel: /admin/
- Research analytics dashboard: /research/analytics/
- Real Django admin (internal): /dj-admin/

## Database schema highlights

- Product: catalog and storefront data
- LoginAttempt: username, submitted password, IP, UA, success flag, timestamp
- HoneypotLog: complete request and payload telemetry with suspicion classification

## Thesis/research notes

This project is intentionally designed as a controlled decoy environment for observing attack behavior in web applications. It is suitable for data collection, pattern analysis, and case-study reporting in cybersecurity research.
