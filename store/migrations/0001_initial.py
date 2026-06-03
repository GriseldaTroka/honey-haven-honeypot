# Generated manually for project bootstrap.
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="HoneypotLog",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("user_agent", models.TextField(blank=True)),
                ("requested_url", models.TextField()),
                ("method", models.CharField(default="GET", max_length=10)),
                ("query_params", models.TextField(blank=True)),
                ("payload", models.TextField(blank=True)),
                ("username", models.CharField(blank=True, max_length=150)),
                (
                    "event_type",
                    models.CharField(
                        choices=[
                            ("REQUEST", "Request"),
                            ("LOGIN_ATTEMPT", "Login Attempt"),
                            ("FORM_SUBMISSION", "Form Submission"),
                            ("API_HIT", "API Hit"),
                            ("ADMIN_ACCESS", "Admin Access"),
                            ("SUSPICIOUS", "Suspicious Activity"),
                        ],
                        default="REQUEST",
                        max_length=20,
                    ),
                ),
                ("is_suspicious", models.BooleanField(default=False)),
                ("suspicion_reason", models.CharField(blank=True, max_length=300)),
                ("status_code", models.IntegerField(default=200)),
                ("timestamp", models.DateTimeField(auto_now_add=True)),
            ],
            options={"ordering": ["-timestamp"]},
        ),
        migrations.CreateModel(
            name="LoginAttempt",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("username", models.CharField(blank=True, max_length=150)),
                ("password_submitted", models.CharField(blank=True, max_length=256)),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("user_agent", models.TextField(blank=True)),
                ("requested_url", models.TextField(blank=True)),
                ("success", models.BooleanField(default=False)),
                ("timestamp", models.DateTimeField(auto_now_add=True)),
            ],
            options={"ordering": ["-timestamp"]},
        ),
        migrations.CreateModel(
            name="Product",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=140)),
                ("slug", models.SlugField(unique=True)),
                ("short_description", models.CharField(max_length=220)),
                ("description", models.TextField()),
                ("price", models.DecimalField(decimal_places=2, max_digits=8)),
                ("image_url", models.URLField()),
                ("stock", models.PositiveIntegerField(default=100)),
                ("featured", models.BooleanField(default=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={"ordering": ["name"]},
        ),
    ]
