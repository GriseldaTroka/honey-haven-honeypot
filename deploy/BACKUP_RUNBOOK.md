# Backup and Restore Runbook

This runbook covers routine backups, restore steps, retention, and disaster recovery for the Honey Haven honeypot stack.

## Scope
Back up:
- the database
- persistent Docker volumes
- logs that are needed for incident review
- deployment config and environment templates

Do not back up:
- transient cache data
- generated static assets that can be rebuilt
- unreviewed malware samples into general-purpose storage

## 1. Recommended backup schedule
- Database: daily
- Config files: on every deployment change
- Logs: rolling daily archive, with a longer retention window for suspicious events
- Volumes with important artifacts: after major incidents or on a daily cadence if required

## 2. Exact backup commands

### Local SQLite backup
If you are using the development database file:
```bash
mkdir -p backups
python -c "import shutil; shutil.copy2('db.sqlite3', 'backups/db.sqlite3.bak')"
```

### Django data export backup
If you want a logical export of Django objects:
```bash
mkdir -p backups
python manage.py dumpdata --natural-foreign --natural-primary > backups/dumpdata.json
```

### Docker volume backup example
Archive named Docker volumes from the running host:
```bash
mkdir -p backups/volumes
for volume in honey_grafana-data honey_loki-data honey_alertmanager-data honey_cowrie-data honey_dionaea-data honey_conpot-data; do
  docker run --rm -v ${volume}:/volume -v ${PWD}/backups/volumes:/backup alpine sh -c "cd /volume && tar czf /backup/${volume}.tar.gz ."
done
```

### Container log archive example
Archive application logs from the host-mounted log directory:
```bash
mkdir -p backups/logs
python -c "from pathlib import Path; import shutil, datetime; ts=datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S'); src=Path('logs'); dst=Path('backups/logs') / f'logs-{ts}.tar.gz'; shutil.make_archive(str(dst).removesuffix('.tar.gz'), 'gztar', root_dir=src)"
```

### Full compose config snapshot
Capture deployment config for recovery and audit:
```bash
mkdir -p backups/config
copy .env.example backups/config/
copy deploy\docker-compose.prod.yml backups/config/
copy deploy\nginx\default.conf backups/config/
```

## 3. Database backup examples

### SQLite
- Copy the file while the application is stopped or in a consistent snapshot state.
- Example:
```bash
python manage.py check
python manage.py migrate
python -c "import shutil; shutil.copy2('db.sqlite3', 'backups/db.sqlite3')"
```

### PostgreSQL
If you switch production to PostgreSQL, prefer `pg_dump`:
```bash
mkdir -p backups/postgres
pg_dump -h <db-host> -U <db-user> -Fc <db-name> > backups/postgres/honey-$(date +%Y%m%d%H%M%S).dump
```
Restore with:
```bash
pg_restore -h <db-host> -U <db-user> -d <db-name> --clean --if-exists backups/postgres/honey-YYYYMMDDHHMMSS.dump
```

## 4. Restore procedures

### Restore a SQLite database
1. Stop the application.
2. Replace the current `db.sqlite3` with the backup copy.
3. Run migrations if schema changes were introduced.
4. Start the stack and verify system checks.

Example:
```bash
docker compose down
copy backups\db.sqlite3.bak db.sqlite3
python manage.py migrate
python manage.py check
```

### Restore Docker volumes
1. Stop the affected services.
2. Remove the current volume only after confirming the backup is valid.
3. Recreate the volume and extract the archive into it.

Example:
```bash
docker compose down
for volume in honey_grafana-data honey_loki-data; do
  docker volume rm ${volume} 2> /dev/null || true
  docker volume create ${volume}
  docker run --rm -v ${volume}:/volume -v ${PWD}/backups/volumes:/backup alpine sh -c "cd /volume && tar xzf /backup/${volume}.tar.gz"
done
```

### Restore logs and artifacts
- Restore log archives into a separate review directory, not back into the live `logs/` directory unless you are rebuilding an analysis environment.
- Preserve original timestamps and hashes if the logs are evidence.

## 5. Retention recommendations
- Daily database backups: retain 14 to 30 days.
- Incident archives: retain for the duration of the investigation plus the approved retention window.
- Log archives: retain longer for research value, but separate from the live system.
- Configuration snapshots: retain one copy per deployment version.

## 6. Log archival suggestions
- Compress daily logs into timestamped archives.
- Store archives in encrypted object storage or an access-controlled backup share.
- Index archives by incident ID, date, and environment.
- Do not mix active logs with long-term archives.
- Keep an audit trail for every export or restore.

## 7. Disaster recovery guidance
- Document the recovery point objective and recovery time objective for each environment.
- Keep at least one off-host backup copy.
- Periodically test full restore in an isolated environment.
- Validate application health with `python manage.py check` and the smoke tests after recovery.
- Restore the reverse proxy and environment variables before bringing the web service back online.

## 8. Operational notes
- Back up secrets separately from runtime data and restrict access to them.
- Rotate backup storage credentials regularly.
- Verify archive integrity before deleting older copies.
- Treat recovered uploads and malware samples as untrusted until revalidated.
