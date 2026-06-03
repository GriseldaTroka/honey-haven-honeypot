from django.db import models


class Product(models.Model):
    name = models.CharField(max_length=140)
    slug = models.SlugField(unique=True)
    short_description = models.CharField(max_length=220)
    description = models.TextField()
    price = models.DecimalField(max_digits=8, decimal_places=2)
    image_url = models.URLField()
    stock = models.PositiveIntegerField(default=100)
    featured = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class HoneypotLog(models.Model):
    EVENT_TYPES = [
        ("REQUEST", "Request"),
        ("LOGIN_ATTEMPT", "Login Attempt"),
        ("FORM_SUBMISSION", "Form Submission"),
        ("API_HIT", "API Hit"),
        ("ADMIN_ACCESS", "Admin Access"),
        ("SUSPICIOUS", "Suspicious Activity"),
    ]
    ATTACK_CLASSIFICATIONS = [
        ("BRUTE_FORCE_ATTACK", "Brute Force Attack"),
        ("SQL_INJECTION_ATTEMPT", "SQL Injection Attempt"),
        ("SCANNER_BOT_ACTIVITY", "Scanner/Bot Activity"),
        ("NORMAL_TRAFFIC", "Normal Traffic"),
    ]

    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    requested_url = models.TextField()
    method = models.CharField(max_length=10, default="GET")
    query_params = models.TextField(blank=True)
    payload = models.TextField(blank=True)
    username = models.CharField(max_length=150, blank=True)
    event_type = models.CharField(max_length=20, choices=EVENT_TYPES, default="REQUEST")
    attack_classification = models.CharField(max_length=30, choices=ATTACK_CLASSIFICATIONS, default="NORMAL_TRAFFIC")
    is_suspicious = models.BooleanField(default=False)
    suspicion_reason = models.CharField(max_length=300, blank=True)
    status_code = models.IntegerField(default=200)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]


class AlertEvent(models.Model):
    alert_type = models.CharField(max_length=50)
    detail = models.CharField(max_length=300)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    requested_url = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    dispatched_at = models.DateTimeField(null=True, blank=True)
    dispatch_status = models.CharField(max_length=30, default="pending")
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]


class CanaryToken(models.Model):
    label = models.CharField(max_length=120)
    token = models.SlugField(max_length=80, unique=True)
    destination_url = models.URLField(blank=True)
    notes = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    hit_count = models.PositiveIntegerField(default=0)
    last_hit_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.label} ({self.token})"


class TelemetryEvent(models.Model):
    session_id = models.CharField(max_length=80, blank=True)
    event_type = models.CharField(max_length=80)
    path = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    details = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]


class UploadArtifact(models.Model):
    filename = models.CharField(max_length=255)
    sha256 = models.CharField(max_length=64)
    entropy = models.FloatField(default=0.0)
    verdict = models.CharField(max_length=80)
    uploader_ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]


class ThreatIntelSnapshot(models.Model):
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    country = models.CharField(max_length=80, blank=True)
    country_code = models.CharField(max_length=8, blank=True)
    asn = models.CharField(max_length=80, blank=True)
    isp = models.CharField(max_length=120, blank=True)
    hosting_provider = models.CharField(max_length=120, blank=True)
    vpn = models.BooleanField(default=False)
    tor = models.BooleanField(default=False)
    reputation_score = models.IntegerField(default=50)
    cluster_id = models.CharField(max_length=80, blank=True)
    campaign_id = models.CharField(max_length=80, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]


class AttackJourney(models.Model):
    session_id = models.CharField(max_length=80, unique=True)
    entry_point = models.CharField(max_length=200, blank=True)
    recon_path = models.JSONField(default=list, blank=True)
    payload_evolution = models.JSONField(default=list, blank=True)
    escalation_attempts = models.JSONField(default=list, blank=True)
    tools_used = models.JSONField(default=list, blank=True)
    seconds_spent = models.IntegerField(default=0)
    first_seen = models.DateTimeField(null=True, blank=True)
    event_count = models.IntegerField(default=0, db_index=True)
    phases = models.JSONField(default=list, blank=True)
    ips = models.JSONField(default=list, blank=True)
    user_agents = models.JSONField(default=list, blank=True)
    campaign_id = models.CharField(max_length=120, blank=True, db_index=True)
    notes = models.TextField(blank=True)
    last_seen = models.DateTimeField(auto_now=True, db_index=True)

    class Meta:
        indexes = [
            models.Index(fields=["last_seen"]),
            models.Index(fields=["event_count"]),
            models.Index(fields=["campaign_id"]),
        ]


class PaymentRecord(models.Model):
    payment_id = models.CharField(max_length=80)
    merchant_reference = models.CharField(max_length=80, blank=True)
    card_last4 = models.CharField(max_length=4, blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    currency = models.CharField(max_length=8, default="USD")
    status = models.CharField(max_length=30, default="pending")
    metadata = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]


class SupportTicket(models.Model):
    ticket_id = models.CharField(max_length=80)
    requester_email = models.EmailField(blank=True)
    subject = models.CharField(max_length=200)
    status = models.CharField(max_length=30, default="open")
    priority = models.CharField(max_length=20, default="normal")
    body = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]


class NoiseEvent(models.Model):
    event_type = models.CharField(max_length=80)
    payload = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]


class LoginAttempt(models.Model):
    username = models.CharField(max_length=150, blank=True)
    password_submitted = models.CharField(max_length=256, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    requested_url = models.TextField(blank=True)
    success = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]


class BlogPost(models.Model):
    title = models.CharField(max_length=180)
    slug = models.SlugField(unique=True)
    category = models.CharField(max_length=80)
    excerpt = models.CharField(max_length=260)
    content = models.TextField()
    image = models.FileField(upload_to="blog/", blank=True, null=True)
    is_published = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return self.title
