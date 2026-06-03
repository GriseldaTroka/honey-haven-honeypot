from __future__ import annotations

import json
import time
from urllib import request as urlrequest

from django.core.management.base import BaseCommand
from django.utils import timezone

from store.models import UploadArtifact
from store.deception import emit_structured_event


class Command(BaseCommand):
    help = "Poll UploadArtifact and forward them to a sandbox URL (simulated if none configured)."

    def add_arguments(self, parser):
        parser.add_argument("--loop", action="store_true")
        parser.add_argument("--interval", type=int, default=30)

    def handle(self, *args, **options):
        loop = options["loop"]
        interval = max(5, int(options["interval"]))

        sandbox_url = getenv = __import__("os").environ.get("HONEYPOT_SANDBOX_URL", "")

        def send_to_sandbox(artifact: UploadArtifact) -> dict:
            payload = {"filename": artifact.filename, "sha256": artifact.sha256, "size": artifact.metadata.get("size")}
            if sandbox_url:
                try:
                    req = urlrequest.Request(sandbox_url, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"})
                    resp = urlrequest.urlopen(req, timeout=5)
                    result = json.loads(resp.read().decode("utf-8") or "{}")
                    return result
                except Exception:
                    return {"status": "error", "reason": "sandbox-unreachable"}
            # simulate a sandbox verdict
            simulated = {"verdict": "malicious" if artifact.entropy and artifact.entropy > 7.5 else "clean", "score": round(artifact.entropy or 0.0, 2)}
            return simulated

        while True:
            candidates = UploadArtifact.objects.filter(metadata__has_key="analyzed_at").filter(metadata__has_key="sandboxed")==False if False else UploadArtifact.objects.filter(metadata__has_key="analyzed_at").exclude(metadata__has_key="sandboxed")[:50]
            for art in candidates:
                try:
                    result = send_to_sandbox(art)
                    art.metadata = {**(art.metadata or {}), "sandboxed": True, "sandbox_result": result, "sandboxed_at": timezone.now().isoformat()}
                    art.verdict = art.verdict if not result.get("verdict") else f"sandbox:{result.get('verdict')}"
                    art.save(update_fields=["metadata", "verdict"])
                    emit_structured_event("sandbox_result", filename=art.filename, sha256=art.sha256, result=result)
                except Exception:
                    pass

            if not loop:
                break
            time.sleep(interval)
