from django.core.management.base import BaseCommand
from django.utils import timezone
from store.deception import build_attack_journeys, upsert_attack_journey


class Command(BaseCommand):
    help = "Process recent events and persist AttackJourney summaries."

    def add_arguments(self, parser):
        parser.add_argument("--hours", type=int, default=24, help="Lookback hours to scan events")
        parser.add_argument("--limit", type=int, default=500, help="Max journeys to process")

    def handle(self, *args, **options):
        hours = options.get("hours", 24)
        limit = options.get("limit", 500)
        self.stdout.write(f"Processing attack journeys for last {hours} hours (limit {limit})...")
        journeys = build_attack_journeys(lookback_hours=hours, limit=limit)
        count = 0
        for j in journeys:
            try:
                upsert_attack_journey(j["session_id"], entry_point=j.get("first_seen"))
                count += 1
            except Exception as e:
                self.stderr.write(f"Failed to upsert journey {j['session_id']}: {e}")
        self.stdout.write(f"Processed {count} journeys.")
