from django.conf import settings
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
    session_id = models.CharField(max_length=80, blank=True, db_index=True)
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
        indexes = [
            models.Index(fields=["timestamp"]),
        ]


class AttackerState(models.Model):
    session_id = models.CharField(max_length=80, unique=True, db_index=True)
    current_phase = models.CharField(max_length=40, default="noise_or_observation", db_index=True)
    previous_phase = models.CharField(max_length=40, blank=True)
    phase_confidence = models.FloatField(default=0.0)
    risk_score = models.FloatField(default=0.0, db_index=True)
    intent_score = models.FloatField(default=0.0)
    last_event_type = models.CharField(max_length=80, blank=True)
    last_observed_path = models.TextField(blank=True)
    last_observed_at = models.DateTimeField(null=True, blank=True, db_index=True)
    event_count = models.PositiveIntegerField(default=0)
    suspicious_event_count = models.PositiveIntegerField(default=0)
    alert_count = models.PositiveIntegerField(default=0)
    unique_ips_count = models.PositiveIntegerField(default=0)
    unique_user_agents_count = models.PositiveIntegerField(default=0)
    primary_ip = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    primary_user_agent = models.TextField(blank=True)
    geo_country = models.CharField(max_length=80, blank=True)
    asn = models.CharField(max_length=80, blank=True)
    campaign_id = models.CharField(max_length=120, blank=True, db_index=True)
    last_signals = models.JSONField(default=list, blank=True)
    state_snapshot = models.JSONField(default=dict, blank=True)
    meta = models.JSONField(default=dict, blank=True)
    first_seen_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True, db_index=True)

    class Meta:
        ordering = ["-updated_at"]
        indexes = [
            models.Index(fields=["current_phase"]),
            models.Index(fields=["risk_score"]),
            models.Index(fields=["updated_at"]),
            models.Index(fields=["campaign_id"]),
        ]

    def __str__(self) -> str:
        return f"{self.session_id} :: {self.current_phase} ({self.risk_score:.1f})"


class StateTransition(models.Model):
    attacker_state = models.ForeignKey(AttackerState, on_delete=models.CASCADE, related_name="transitions")
    session_id = models.CharField(max_length=80, db_index=True)
    from_phase = models.CharField(max_length=40, blank=True)
    to_phase = models.CharField(max_length=40, db_index=True)
    trigger_event_type = models.CharField(max_length=80)
    trigger_path = models.TextField(blank=True)
    trigger_reason = models.CharField(max_length=300, blank=True)
    risk_delta = models.FloatField(default=0.0)
    confidence_delta = models.FloatField(default=0.0)
    event_reference = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["session_id", "created_at"]),
            models.Index(fields=["to_phase"]),
        ]

    def __str__(self) -> str:
        return f"{self.session_id}: {self.from_phase} -> {self.to_phase}"


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
        indexes = [
            models.Index(fields=["timestamp"]),
        ]


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
    session_id = models.CharField(max_length=80, blank=True, db_index=True)
    event_type = models.CharField(max_length=80)
    path = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    details = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["timestamp"]),
        ]


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
    risk_score = models.FloatField(default=0.0)
    confidence_score = models.FloatField(default=0.0)
    intent_score = models.FloatField(default=0.0)
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


class AnalystNote(models.Model):
    session_id = models.CharField(max_length=80, blank=True, db_index=True)
    campaign_id = models.CharField(max_length=120, blank=True, db_index=True)
    alert_id = models.PositiveIntegerField(null=True, blank=True, db_index=True)
    title = models.CharField(max_length=180)
    body = models.TextField()
    pinned = models.BooleanField(default=False, db_index=True)
    tags = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True, db_index=True)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="analyst_notes")

    class Meta:
        ordering = ["-pinned", "-updated_at"]
        indexes = [
            models.Index(fields=["session_id"]),
            models.Index(fields=["campaign_id"]),
            models.Index(fields=["alert_id"]),
        ]

    def __str__(self) -> str:
        return self.title


class InvestigationBookmark(models.Model):
    session_id = models.CharField(max_length=80, blank=True, db_index=True)
    campaign_id = models.CharField(max_length=120, blank=True, db_index=True)
    alert_id = models.PositiveIntegerField(null=True, blank=True, db_index=True)
    ioc_id = models.PositiveIntegerField(null=True, blank=True, db_index=True)
    label = models.CharField(max_length=180)
    note = models.CharField(max_length=300, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="investigation_bookmarks")

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(fields=["user", "session_id", "campaign_id", "alert_id", "ioc_id", "label"], name="uniq_investigation_bookmark_user_scope"),
        ]

    def __str__(self) -> str:
        return self.label


class IOCIndicator(models.Model):
    IOC_TYPES = [
        ("ip", "IP Address"),
        ("url", "URL"),
        ("email", "Email"),
        ("hash", "Hash"),
    ]

    session_id = models.CharField(max_length=80, blank=True, db_index=True)
    source_model = models.CharField(max_length=80, blank=True, db_index=True)
    source_object_id = models.PositiveIntegerField(null=True, blank=True, db_index=True)
    ioc_type = models.CharField(max_length=20, choices=IOC_TYPES, db_index=True)
    ioc_value = models.CharField(max_length=512, db_index=True)
    confidence_score = models.FloatField(default=0.0)
    source_event = models.CharField(max_length=80, blank=True, db_index=True)
    evidence_summary = models.CharField(max_length=300, blank=True)
    attack_phase = models.CharField(max_length=40, blank=True, db_index=True)
    asg_risk_score = models.FloatField(null=True, blank=True)
    asg_confidence = models.FloatField(null=True, blank=True)
    attack_journey = models.ForeignKey(
        AttackJourney,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="iocs",
    )
    first_seen = models.DateTimeField(auto_now_add=True, db_index=True)
    last_seen = models.DateTimeField(auto_now=True, db_index=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-last_seen"]
        indexes = [
            models.Index(
                fields=["ioc_type", "ioc_value", "first_seen", "id"],
                name="store_ioc_group_order_idx",
            ),
        ]
        constraints = [
            models.UniqueConstraint(fields=["session_id", "ioc_type", "ioc_value", "source_event", "source_model", "source_object_id"], name="uniq_ioc_session_type_value_source"),
        ]

    def __str__(self) -> str:
        return f"{self.session_id or 'global'} :: {self.ioc_type} :: {self.ioc_value}"


class DetectionAlert(models.Model):
    SEVERITY_CHOICES = [
        ("LOW", "Low"),
        ("MEDIUM", "Medium"),
        ("HIGH", "High"),
        ("CRITICAL", "Critical"),
    ]
    STATUS_CHOICES = [
        ("OPEN", "Open"),
        ("INVESTIGATING", "Investigating"),
        ("RESOLVED", "Resolved"),
        ("FALSE_POSITIVE", "False Positive"),
    ]

    rule_name = models.CharField(max_length=120, db_index=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, db_index=True)
    confidence_score = models.FloatField(default=0.0)
    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default="OPEN", db_index=True)
    description = models.CharField(max_length=500)
    session_id = models.CharField(max_length=80, blank=True, db_index=True)
    attack_journey = models.ForeignKey(AttackJourney, on_delete=models.SET_NULL, null=True, blank=True, related_name="detection_alerts")
    campaign_id = models.CharField(max_length=120, blank=True, db_index=True)
    evidence_source_model = models.CharField(max_length=80, blank=True, db_index=True)
    evidence_source_object_id = models.PositiveIntegerField(null=True, blank=True, db_index=True)
    evidence_source_event = models.CharField(max_length=80, blank=True, db_index=True)
    evidence_fingerprint = models.CharField(max_length=200, blank=True, db_index=True)
    evidence_summary = models.CharField(max_length=500, blank=True)
    response_recommendation = models.JSONField(default=list, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True, db_index=True)
    resolved_at = models.DateTimeField(null=True, blank=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(fields=["rule_name", "session_id", "evidence_fingerprint"], name="uniq_detection_alert_rule_session_fingerprint"),
        ]
        indexes = [
            models.Index(fields=["status"]),
            models.Index(fields=["severity"]),
            models.Index(fields=["campaign_id"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.rule_name} :: {self.session_id or 'global'} :: {self.severity}"


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
    session_id = models.CharField(max_length=80, blank=True, db_index=True)
    user_agent = models.TextField(blank=True)
    requested_url = models.TextField(blank=True)
    success = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["timestamp"]),
        ]


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
