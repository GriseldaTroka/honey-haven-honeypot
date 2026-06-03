from __future__ import annotations

import time

from django.core.management.base import BaseCommand

from store.anomaly import detect_spikes


class Command(BaseCommand):
    help = "Run anomaly detection heuristics periodically."

    def add_arguments(self, parser):
        parser.add_argument("--loop", action="store_true")
        parser.add_argument("--interval", type=int, default=60)

    def handle(self, *args, **options):
        loop = options["loop"]
        interval = max(10, int(options.get("interval", 60)))

        while True:
            findings = detect_spikes()
            if findings:
                self.stdout.write(self.style.WARNING(f"Findings: {findings}"))
            else:
                self.stdout.write(self.style.SUCCESS("No anomalies."))

            if not loop:
                break
            time.sleep(interval)
