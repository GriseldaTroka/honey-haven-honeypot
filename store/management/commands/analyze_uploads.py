from __future__ import annotations

import json
from django.core.management.base import BaseCommand
from django.utils import timezone

from store.models import UploadArtifact
from store.deception import emit_external_alerts, emit_structured_event


class Command(BaseCommand):
    help = "Analyze recent uploaded artifacts and mark verdicts (scaffold/simulated)."

    def add_arguments(self, parser):
        parser.add_argument("--hours", type=int, default=24, help="How far back to analyze uploads")

    def handle(self, *args, **options):
        cutoff = timezone.now() - timezone.timedelta(hours=options.get("hours", 24))
        candidates = UploadArtifact.objects.filter(timestamp__gte=cutoff)[:200]
        if not candidates:
            self.stdout.write("No recent uploads to analyze.")
            return

        for artifact in candidates:
            # simple heuristic example: high entropy => suspicious
            verdict = artifact.verdict or "unknown"
            if artifact.entropy and artifact.entropy > 7.0:
                verdict = "analyzed:suspect-high-entropy"
            elif artifact.verdict in {"webshell-suspected", "suspicious-upload"}:
                verdict = f"analyzed:{artifact.verdict}"
            else:
                verdict = "analyzed:clean"

            artifact.verdict = verdict
            artifact.metadata = {**(artifact.metadata or {}), "analyzed_at": timezone.now().isoformat()}
            artifact.save(update_fields=["verdict", "metadata"])

            emit_structured_event("upload_analysis", filename=artifact.filename, sha256=artifact.sha256, entropy=artifact.entropy, verdict=artifact.verdict)

            # notify via external alert path if suspicious
            if verdict.startswith("analyzed:suspect"):
                try:
                    # best-effort, send a concise alert payload
                    emit_external_alerts(None, alert_type="SUSPICIOUS_UPLOAD_ANALYSIS", detail=f"Upload {artifact.filename} marked {artifact.verdict}")
                except Exception:
                    pass

        self.stdout.write(f"Analyzed {candidates.count()} uploads; verdicts updated.")
from django.core.management.base import BaseCommand
from django.utils import timezone

from store.models import UploadArtifact
from store.utils import emit_structured_event


class Command(BaseCommand):
    help = "Analyze queued upload artifacts (scaffold for sandbox integration)."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=20, help="Max artifacts to analyze at once")

    def handle(self, *args, **options):
        limit = options.get("limit", 20)
        candidates = UploadArtifact.objects.all().order_by("-timestamp")[:limit]
        if not candidates:
            self.stdout.write("No upload artifacts found.")
            return

        for art in candidates:
            # placeholder analysis: mark as analyzed and attach a fake verdict note
            note = art.metadata or {}
            note["analyzed_at"] = timezone.now().isoformat()
            note["analysis_note"] = f"scaffold-analysis: verdict={art.verdict}"
            art.metadata = note
            art.save(update_fields=["metadata"])
            emit_structured_event(
                "upload_analysis",
                filename=art.filename,
                sha256=art.sha256,
                verdict=art.verdict,
                analyzed_at=note["analyzed_at"],
            )
            self.stdout.write(f"Analyzed {art.filename} -> {art.verdict}")
