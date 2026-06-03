from __future__ import annotations

import json
import time

from django.core.management.base import BaseCommand
from django.utils import timezone

from store.deception import deliver_alert_payload
from store.models import AlertEvent


class Command(BaseCommand):
    help = "Dispatch pending alert events to configured notification channels."

    def add_arguments(self, parser):
        parser.add_argument("--loop", action="store_true", help="Continuously poll for pending alerts.")
        parser.add_argument("--interval", type=int, default=30, help="Polling interval in seconds when using --loop.")

    def handle(self, *args, **options):
        loop = options["loop"]
        interval = max(5, int(options["interval"]))

        while True:
            dispatched = 0
            pending = AlertEvent.objects.filter(dispatched_at__isnull=True).order_by("timestamp")[:50]

            for alert in pending:
                try:
                    candidate = {
                        "alert_type": alert.alert_type,
                        "detail": alert.detail,
                        "ip_address": alert.ip_address,
                        "user_agent": alert.user_agent,
                        "requested_url": alert.requested_url,
                    }

                    channels = alert.metadata or {}

                    def post_json(url: str, body: bytes) -> None:
                        from urllib import request as urlrequest

                        req = urlrequest.Request(url, data=body, headers={"Content-Type": "application/json"})
                        urlrequest.urlopen(req, timeout=2)  # noqa: S310 - intentional outbound dispatch

                    deliver_alert_payload(
                        candidate,
                        json.dumps(candidate).encode("utf-8"),
                        channels.get("discord", ""),
                        channels.get("telegram", ""),
                        channels.get("email", ""),
                        post_json,
                    )
                    alert.dispatched_at = timezone.now()
                    alert.dispatch_status = "sent"
                    alert.save(update_fields=["dispatched_at", "dispatch_status"])
                    dispatched += 1
                except Exception as exc:  # noqa: BLE001
                    alert.dispatch_status = "failed"
                    alert.metadata = {**(alert.metadata or {}), "dispatch_error": str(exc)}
                    alert.save(update_fields=["dispatch_status", "metadata"])

            self.stdout.write(self.style.SUCCESS(f"Dispatched {dispatched} alert(s)."))
            if not loop:
                break
            time.sleep(interval)
