# Deployment Security Checklist

This checklist is for a research-grade honeypot deployment that must remain isolated, observable, and easy to operate safely.

## 1. Container hardening
- Run containers as a non-root user wherever the image supports it.
- Use minimal base images and pin versions for all runtime images.
- Prefer read-only filesystems for services that do not need write access.
- Remove unnecessary Linux capabilities.
- Set `no-new-privileges` where supported.
- Mount only the volumes a service actually needs.
- Keep bind mounts limited to logs, data, and explicit configuration files.

## 2. Docker security recommendations
- Use `restart: unless-stopped` for long-running services.
- Prefer named volumes for persistent runtime state.
- Avoid `latest` tags in production.
- Keep the honeypot network internal and separate from the public-facing reverse proxy network.
- Restrict exposed ports to only the reverse proxy and any intentionally public endpoints.
- Use Docker secrets for values that should not appear in environment variables or compose files.
- Keep `.env` local and uncommitted.

## 3. Isolation and network segmentation
- Put the web application, workers, and observability stack on an internal backend network.
- Put deceptive honeypot services on a separate internal honeynet network.
- Place the reverse proxy on the public-facing network only.
- Do not bridge honeypot containers directly to production or office networks.
- If possible, place the whole stack behind a dedicated host, VLAN, or cloud security group.

## 4. Secret management
- Store operational secrets in a secret manager or Docker secrets, not in source control.
- Keep `.env.example` as the only committed environment template.
- Rotate tokens and webhook URLs on a schedule.
- Use separate secrets for local, staging, and production environments.
- Do not reuse real credentials in decoy files or fake artifacts.
- Audit secret access and limit who can edit deployment files.

## 5. Reverse proxy recommendations
- Terminate TLS at the reverse proxy or load balancer.
- Set strict upstream timeouts and request size limits.
- Forward `X-Forwarded-For`, `X-Forwarded-Proto`, and `Host` headers explicitly.
- Serve static content from a controlled path or object storage.
- Keep access and error logs on a separate persistent volume.
- Consider IP allowlists or rate limits for admin surfaces.

## 6. Firewall guidance
- Only expose the reverse proxy, SSH for administration, and any monitoring endpoints you intentionally need.
- Block direct access to internal services, databases, and honeypot management surfaces.
- Use host firewall rules in addition to cloud security groups.
- Log dropped traffic where feasible.
- Re-evaluate rules after every port or service change.

## 7. Logging and monitoring recommendations
- Emit structured JSON logs for alerts and telemetry.
- Ship logs to Loki or another central store quickly.
- Keep log volumes persistent and backed up.
- Monitor worker health, queue backlogs, and high alert rates.
- Alert on repeated failures in alert delivery, sandbox processing, or database writes.
- Keep time synchronized across host, containers, and alerting systems.

## 8. Upload handling precautions
- Treat all uploads as hostile.
- Store uploaded artifacts outside the web root.
- Record only metadata and hashes unless you explicitly need the full sample for offline analysis.
- Quarantine suspicious uploads before any analysis step.
- Avoid automatic execution or preview of uploaded content.
- Strip active content from any extracted archives or previews.

## 9. Least-privilege recommendations
- Run each service under a dedicated user or container identity.
- Grant database access only to the tables and actions the service needs.
- Restrict outbound network access for workers and honeypots.
- Use read-only mounts for config when possible.
- Limit who can access backup, log, and artifact storage.

## 10. Backup security
- Encrypt backups at rest.
- Keep backup storage separate from the running host.
- Restrict backup restore permissions.
- Test restoration in an isolated environment.
- Rotate old backups according to retention policy.
- Include logs, config, and database data in recovery planning.

## 11. Update and patch management
- Patch the host OS regularly.
- Rebuild container images on dependency updates.
- Track library CVEs and base image advisories.
- Apply security fixes before feature work when the platform is exposed.
- Re-run tests and system checks after every patch cycle.

## 12. Operational safety
- Keep honeypot behavior simulated unless you have a fully isolated analysis lab.
- Avoid connecting honeypot services to sensitive internal networks.
- Rate-limit external alert channels so adversarial traffic cannot create an outbound flood.
- Review logs for attacker-controlled payloads before copying them into reports.
- Document a shutdown and containment procedure before going live.

## 13. Honeypot detection considerations
- Expect scanner traffic, credential stuffing, and low-and-slow probing.
- Assume attackers will fingerprint banners, headers, timing, and filesystem artifacts.
- Rotate decoy data and fake credentials periodically.
- Keep fake artifacts believable but clearly isolated from real systems.
- Watch for patterns that suggest the honeypot itself is being fingerprinted.
- Record repeated endpoint probes, user-agent strings, and request timing for research.

## 14. Common mistakes to avoid
- Committing `.env`, secret files, or backup archives.
- Exposing honeypot services directly on the public internet without isolation.
- Using the same credentials in multiple environments.
- Allowing workers to execute uploaded files or archives automatically.
- Running production with debug settings or permissive host headers.
- Keeping logs only inside containers with no persistent volume.
- Sending alerts to untrusted or unreviewed destinations.

## 15. Deployment hardening best practices
- Start with a minimal surface and add capabilities only when needed.
- Review every exposed port and every mounted volume.
- Keep production and research environments separate.
- Prefer immutable image builds and explicit tags.
- Document each change and verify it with a check or test.
- Rehearse incident response and recovery before public exposure.
