from django.contrib import admin

from .models import AlertEvent, AttackJourney, AttackerState, DetectionAlert, IOCIndicator, StateTransition, BlogPost, CanaryToken, HoneypotLog, LoginAttempt, NoiseEvent, PaymentRecord, SupportTicket, TelemetryEvent, ThreatIntelSnapshot, UploadArtifact, Product
from .investigation import get_campaign_summary
from .detection import serialize_detection_alert


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ("name", "price", "stock", "featured")
    search_fields = ("name", "slug")


@admin.register(HoneypotLog)
class HoneypotLogAdmin(admin.ModelAdmin):
    list_display = ("event_type", "attack_classification", "ip_address", "requested_url", "is_suspicious", "timestamp")
    list_filter = ("event_type", "attack_classification", "is_suspicious", "timestamp")
    search_fields = ("ip_address", "requested_url", "user_agent", "payload", "username")


@admin.register(AlertEvent)
class AlertEventAdmin(admin.ModelAdmin):
    list_display = ("alert_type", "dispatch_status", "ip_address", "requested_url", "timestamp")
    list_filter = ("alert_type", "dispatch_status", "timestamp")
    search_fields = ("alert_type", "detail", "ip_address", "requested_url")
    actions = ["mark_reviewed", "requeue_alerts"]

    @admin.action(description="Mark selected alerts reviewed")
    def mark_reviewed(self, request, queryset):
        queryset.update(dispatch_status="reviewed")

    @admin.action(description="Requeue selected alerts")
    def requeue_alerts(self, request, queryset):
        queryset.update(dispatch_status="pending", dispatched_at=None)


@admin.register(DetectionAlert)
class DetectionAlertAdmin(admin.ModelAdmin):
    list_display = ("rule_name", "severity", "status", "session_id", "campaign_id", "confidence_score", "created_at", "resolved_at")
    list_filter = ("severity", "status", "rule_name", "created_at", "resolved_at")
    search_fields = ("rule_name", "session_id", "campaign_id", "description", "evidence_summary")
    readonly_fields = ("created_at", "updated_at", "resolved_at", "response_recommendation", "metadata")

    @admin.display(description="Alert payload")
    def alert_payload(self, obj):
        return serialize_detection_alert(obj, include_evidence=True)


@admin.register(CanaryToken)
class CanaryTokenAdmin(admin.ModelAdmin):
    list_display = ("label", "token", "is_active", "hit_count", "last_hit_at", "created_at")
    list_filter = ("is_active", "created_at", "revoked_at")
    search_fields = ("label", "token", "destination_url", "notes")
    readonly_fields = ("hit_count", "last_hit_at", "created_at", "updated_at")


@admin.register(TelemetryEvent)
class TelemetryEventAdmin(admin.ModelAdmin):
    list_display = ("session_id", "event_type", "path", "ip_address", "timestamp")
    list_filter = ("event_type", "timestamp")
    search_fields = ("session_id", "path", "ip_address", "user_agent")


@admin.register(UploadArtifact)
class UploadArtifactAdmin(admin.ModelAdmin):
    list_display = ("filename", "verdict", "entropy", "uploader_ip", "timestamp")
    list_filter = ("verdict", "timestamp")
    search_fields = ("filename", "sha256", "uploader_ip")


@admin.register(ThreatIntelSnapshot)
class ThreatIntelSnapshotAdmin(admin.ModelAdmin):
    list_display = ("ip_address", "country", "asn", "vpn", "tor", "reputation_score", "timestamp")
    list_filter = ("country", "vpn", "tor", "timestamp")
    search_fields = ("ip_address", "country", "asn", "isp", "cluster_id", "campaign_id")


@admin.register(AttackJourney)
class AttackJourneyAdmin(admin.ModelAdmin):
    list_display = ("session_id", "campaign_id", "entry_point", "seconds_spent", "campaign_ioc_count", "campaign_unique_ioc_count", "last_seen")
    list_filter = ("campaign_id", "last_seen")
    search_fields = ("session_id", "campaign_id", "entry_point", "notes")
    readonly_fields = ("campaign_ioc_count", "campaign_unique_ioc_count", "campaign_average_risk_score", "campaign_average_confidence_score")

    @admin.display(description="Campaign IOC count")
    def campaign_ioc_count(self, obj):
        if not obj.campaign_id:
            return 0
        summary = get_campaign_summary(obj.campaign_id)
        return summary["summary"]["ioc_count"] if summary else 0

    @admin.display(description="Campaign unique IOC count")
    def campaign_unique_ioc_count(self, obj):
        if not obj.campaign_id:
            return 0
        summary = get_campaign_summary(obj.campaign_id)
        return summary["summary"]["unique_ioc_count"] if summary else 0

    @admin.display(description="Campaign average risk")
    def campaign_average_risk_score(self, obj):
        if not obj.campaign_id:
            return 0
        summary = get_campaign_summary(obj.campaign_id)
        return summary["summary"]["average_risk_score"] if summary else 0

    @admin.display(description="Campaign average confidence")
    def campaign_average_confidence_score(self, obj):
        if not obj.campaign_id:
            return 0
        summary = get_campaign_summary(obj.campaign_id)
        return summary["summary"]["average_confidence_score"] if summary else 0


@admin.register(IOCIndicator)
class IOCIndicatorAdmin(admin.ModelAdmin):
    list_display = ("session_id", "ioc_type", "ioc_value", "campaign_id", "confidence_score", "source_event", "last_seen")
    list_filter = ("ioc_type", "source_event", "attack_journey__campaign_id", "last_seen")
    search_fields = ("session_id", "ioc_value", "source_event", "attack_journey__campaign_id")

    @admin.display(description="Campaign")
    def campaign_id(self, obj):
        return obj.attack_journey.campaign_id if obj.attack_journey else ""


@admin.register(AttackerState)
class AttackerStateAdmin(admin.ModelAdmin):
    list_display = ("session_id", "current_phase", "risk_score", "phase_confidence", "event_count", "updated_at")
    list_filter = ("current_phase", "updated_at")
    search_fields = ("session_id", "primary_ip", "primary_user_agent", "campaign_id")


@admin.register(StateTransition)
class StateTransitionAdmin(admin.ModelAdmin):
    list_display = ("session_id", "from_phase", "to_phase", "trigger_event_type", "created_at")
    list_filter = ("from_phase", "to_phase", "created_at")
    search_fields = ("session_id", "trigger_event_type", "trigger_path", "trigger_reason")


@admin.register(PaymentRecord)
class PaymentRecordAdmin(admin.ModelAdmin):
    list_display = ("payment_id", "merchant_reference", "amount", "currency", "status", "timestamp")
    search_fields = ("payment_id", "merchant_reference", "card_last4")


@admin.register(SupportTicket)
class SupportTicketAdmin(admin.ModelAdmin):
    list_display = ("ticket_id", "subject", "status", "priority", "timestamp")
    list_filter = ("status", "priority", "timestamp")
    search_fields = ("ticket_id", "requester_email", "subject", "body")


@admin.register(NoiseEvent)
class NoiseEventAdmin(admin.ModelAdmin):
    list_display = ("event_type", "timestamp")
    search_fields = ("event_type",)


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ("username", "ip_address", "success", "timestamp")
    list_filter = ("success", "timestamp")
    search_fields = ("username", "ip_address", "user_agent")


@admin.register(BlogPost)
class BlogPostAdmin(admin.ModelAdmin):
    list_display = ("title", "category", "is_published", "created_at")
    list_filter = ("category", "is_published", "created_at")
    search_fields = ("title", "slug", "excerpt", "content")
    prepopulated_fields = {"slug": ("title",)}
