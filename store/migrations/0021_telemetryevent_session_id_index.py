from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("store", "0020_iocindicator_group_order_idx"),
    ]

    operations = [
        migrations.AlterField(
            model_name="telemetryevent",
            name="session_id",
            field=models.CharField(blank=True, db_index=True, max_length=80),
        ),
    ]