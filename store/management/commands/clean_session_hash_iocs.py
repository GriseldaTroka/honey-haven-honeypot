from django.core.management.base import BaseCommand
from django.db import models

from store.models import IOCIndicator


class Command(BaseCommand):
    help = "Remove IOCIndicator rows where a 'hash' IOC equals the session id (misclassified)."

    def handle(self, *args, **options):
        qs = IOCIndicator.objects.filter(ioc_type="hash")
        # Match rows where stored session_id equals the ioc_value, or linked attack_journey has same session_id
        bad_q = qs.filter(models.Q(session_id=models.F("ioc_value")) | models.Q(attack_journey__session_id=models.F("ioc_value")))
        count = bad_q.count()
        if count:
            self.stdout.write(f"Found {count} misclassified hash IOC(s). Deleting...")
            bad_q.delete()
            self.stdout.write(self.style.SUCCESS(f"Deleted {count} IOCIndicator rows."))
        else:
            self.stdout.write("No misclassified hash IOCs found.")
