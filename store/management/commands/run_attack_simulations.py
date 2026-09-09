from django.core.management.base import BaseCommand

from experiments.simulated_attacks import render_results_table, run_attack_evaluation_suite


class Command(BaseCommand):
    help = "Run controlled attack simulations and print evaluation results."

    def handle(self, *args, **options):
        results = run_attack_evaluation_suite()
        self.stdout.write(render_results_table(results))
