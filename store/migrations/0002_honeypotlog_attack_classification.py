from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("store", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="honeypotlog",
            name="attack_classification",
            field=models.CharField(
                choices=[
                    ("BRUTE_FORCE_ATTACK", "Brute Force Attack"),
                    ("SQL_INJECTION_ATTEMPT", "SQL Injection Attempt"),
                    ("SCANNER_BOT_ACTIVITY", "Scanner/Bot Activity"),
                    ("NORMAL_TRAFFIC", "Normal Traffic"),
                ],
                default="NORMAL_TRAFFIC",
                max_length=30,
            ),
        ),
    ]
