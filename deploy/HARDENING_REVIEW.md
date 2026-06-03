# Production Hardening Review

This document records a lightweight audit of the current honeypot architecture and the main hardening actions to keep it safe, stable, and research-oriented.

## Current posture
- The app now uses a dedicated production compose example, reverse proxy example, structured logging, worker separation, and internal networks.
- Decoy responses use a shared runtime profile so fake panels, APIs, and files look like they belong to one system.
- Host validation is now env-driven instead of relying on an open wildcard default.

## What looks good
- Internal honeynet separation is in place.
- Secret handling prefers environment variables and Docker secrets.
- Logging is structured and centralizable through Loki/Promtail.
- Long-running tasks are isolated into workers.
- The replay UI and analytics are staff-only.

## Remaining hardening priorities
### Container isolation
- Prefer non-root users in custom images.
- Tighten Linux capabilities and read-only mounts for production services.
- Keep the reverse proxy as the only public entry point.

### Secret handling
- Keep `.env` local only and use real secret managers in production.
- Rotate webhook URLs and API keys on a schedule.
- Never reuse fake decoy credentials in real systems.

### Network exposure
- Restrict inbound ports to the reverse proxy, SSH, and explicitly required monitoring ports.
- Keep observability and honeypot backends on internal networks.
- Apply host firewall rules and cloud security groups together.

### Logging safety
- Avoid putting sensitive uploads or credentials into long-lived logs.
- Keep log archives off-host and encrypted.
- Redact payloads before sharing them outside the lab.

### Fingerprinting resistance
- Keep response timing variable but believable.
- Use one coherent fake organization profile across panels, files, and API responses.
- Keep errors believable but not perfectly uniform.
- Avoid exposing operational headers or obvious debug artifacts in public-facing routes.

### Recovery and stability
- Test restore procedures regularly.
- Keep the backup script scoped to real project artifacts instead of a full working-tree archive.
- Re-run migrations and smoke tests after each deploy.

## Recommended operating pattern
1. Build the image.
2. Validate the environment file and secret mounts.
3. Start the reverse proxy and web app.
4. Enable workers after the web app is healthy.
5. Confirm logging, alerting, and backups.
6. Review the replay UI after suspicious activity.

## Common mistakes to avoid
- Exposing the honeypot containers directly to the internet.
- Leaving `DJANGO_DEBUG=True` in production.
- Shipping `.env`, secret files, or backups in git.
- Running sample malware or uploaded files on the production host.
- Treating fake credentials as if they were real credentials.

## Audit note
This is a living checklist. Revisit it after dependency changes, new decoy surfaces, or changes to the deployment topology.
