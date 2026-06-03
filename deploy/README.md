# Deploy Examples

This folder contains production-oriented deployment examples for a Docker-first research honeypot setup.

## Contents
- `docker-compose.prod.yml`: production compose reference
- `nginx/default.conf`: reverse proxy example
- `SECURITY.md`: hardened deployment and security checklist
- `BACKUP_RUNBOOK.md`: backup, restore, and disaster recovery runbook
- `OPERATOR_CHECKLIST.md`: compact deployment and maintenance checklist
- `HARDENING_REVIEW.md`: current security and deployment audit notes

## How to use
1. Copy `.env.example` to `.env` and set production values.
2. Create your secret file at `infra/secrets/django_secret`.
3. Review the compose file and adjust image tags, volumes and domains.
4. Start the stack through your orchestrator or Docker Compose.

## Guidance
- Use immutable image tags in production instead of `latest`.
- Keep the backend network internal.
- Store logs in a persistent volume and rotate them externally.
- Terminate TLS at the reverse proxy or a load balancer.
- Inject secrets through Docker secrets or your platform secret manager.
- Keep the sandbox worker simulated unless it runs in an isolated lab.
