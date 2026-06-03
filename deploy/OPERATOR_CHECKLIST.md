# Operator Deployment Checklist

Use this checklist during deployment, maintenance, and incident response. Keep it compact and action-oriented.

## Recommended deployment workflow
1. Review `deploy/SECURITY.md` and `deploy/BACKUP_RUNBOOK.md`.
2. Copy `.env.example` to `.env` and validate every variable.
3. Verify Docker secrets and mount paths.
4. Run database migrations and system checks.
5. Start the stack with the production compose example.
6. Confirm logs, health checks, and alert delivery.
7. Take a post-deploy backup and record the deployment timestamp.

## Pre-deployment checks
- Confirm the host is patched and isolated from sensitive networks.
- Confirm the deployment target has enough disk, memory, and CPU.
- Confirm DNS, TLS certificates, and reverse proxy routing are ready.
- Confirm the backup destination exists and is writable.

## Environment variable validation
- Verify `DJANGO_SECRET_KEY` is set or Docker secrets are mounted.
- Verify `DJANGO_DEBUG=False` in production.
- Verify `DJANGO_ALLOWED_HOSTS` contains only approved hostnames.
- Verify alert destinations and sandbox placeholders are intentional.
- Verify `HONEYPOT_ALERT_DEDUP_WINDOW_MIN` and `HONEYPOT_ALERT_MAX_PER_WINDOW` are reasonable.

Quick check:
```bash
python -c "from pathlib import Path; print(Path('.env').read_text() if Path('.env').exists() else 'missing .env')"
```

## Docker and container verification
- Confirm `docker compose config` renders without errors.
- Confirm only intended ports are exposed.
- Confirm the backend network is internal.
- Confirm named volumes exist for logs and persistent data.
- Confirm restart policies are enabled for long-running services.

Quick checks:
```bash
docker compose config
docker compose ps
```

## Secret verification
- Confirm no real secrets are committed to git.
- Confirm `infra/secrets/django_secret` exists locally only, or is provided by the platform secret manager.
- Confirm fake decoy secrets remain fake and are not reused elsewhere.
- Confirm secret files are owned and readable only by the deployment user.

Quick check:
```bash
git status --short
```

## Backup verification
- Confirm the latest backup archive exists and is readable.
- Confirm the backup includes config, DB, and required volumes.
- Confirm the backup destination is off-host or encrypted.
- Confirm restore instructions were tested in a non-production environment.

Quick checks:
```bash
python scripts/backup_project.py --dry-run | Select-Object -First 20
dir backups
```

## Log monitoring
- Confirm application logs are being written to `logs/`.
- Confirm Promtail or the log forwarder is running.
- Confirm Grafana/Loki ingestion is active.
- Review alert volume and deduplication behavior after deploy.

Quick checks:
```bash
Get-Content logs\honey-web.log -Tail 50
docker compose logs -f promtail
```

## Security checks
- Confirm honeypot services are isolated on the honeynet network.
- Confirm the reverse proxy is the only public-facing entry point.
- Confirm uploads are treated as untrusted and quarantined.
- Confirm admin surfaces are limited to trusted operators.
- Confirm outbound alert targets are allowlisted.

## Update procedures
- Pull or build the new image version.
- Re-run migrations and system checks.
- Review changelog and dependency updates.
- Restart services one by one if possible.
- Capture a post-update backup and note version/tag.

## Incident response basics
- Identify the source, time window, and affected service.
- Preserve logs and artifact hashes before making changes.
- Isolate the host or container if compromise is suspected.
- Do not execute unknown samples on production infrastructure.
- Record actions and timestamps for later analysis.

## Service health verification
- Confirm web responses are reachable through the reverse proxy.
- Confirm workers are running and not looping on failures.
- Confirm alert dispatch is working but not flooding.
- Confirm database read/write operations are healthy.

Quick checks:
```bash
python manage.py check
python manage.py test tests.test_basic -v 0
docker compose ps
```

## Recovery validation
- Restore one backup in a test environment periodically.
- Confirm the app starts with the restored data.
- Confirm logs, alerts, and volume mounts survive the restore.
- Confirm the restore does not reintroduce secrets into git or logs.

## Common operator mistakes
- Leaving `DEBUG=True` in production.
- Exposing honeypot containers directly to the internet.
- Reusing fake credentials as real credentials.
- Archiving secrets together with logs and sample uploads.
- Forgetting to verify the restore path after a backup change.
- Skipping log review after a major deployment.

## Reminder
If something looks unusual, stop and verify it before expanding exposure. A honeypot is only useful when it remains controlled, observable, and recoverable.