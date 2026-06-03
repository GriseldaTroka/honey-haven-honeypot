from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.urls import reverse

from store.models import AlertEvent, AttackJourney, HoneypotLog, LoginAttempt, TelemetryEvent
from store.utils import derive_session_id


class TimelineReplayTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="staff", password="pass12345")
        self.user.is_staff = True
        self.user.save(update_fields=["is_staff"])
        self.client.force_login(self.user)

    def test_timeline_view_renders(self):
        session_id = derive_session_id(ip_address="203.0.113.10", user_agent="Mozilla/5.0")
        HoneypotLog.objects.create(
            ip_address="203.0.113.10",
            user_agent="Mozilla/5.0",
            requested_url="/wp-admin/",
            method="GET",
            query_params="",
            payload="",
            username="",
            event_type="ADMIN_ACCESS",
            attack_classification="SCANNER_BOT_ACTIVITY",
            is_suspicious=True,
            suspicion_reason="Probing panels",
            status_code=200,
        )
        LoginAttempt.objects.create(
            username="admin",
            password_submitted="secret",
            ip_address="203.0.113.10",
            user_agent="Mozilla/5.0",
            requested_url="/login/",
            success=False,
        )
        AlertEvent.objects.create(
            alert_type="SUSPICIOUS_LOGIN",
            detail="Multiple failed login attempts",
            ip_address="203.0.113.10",
            user_agent="Mozilla/5.0",
            requested_url="/login/",
            dispatch_status="pending",
            metadata={"session_id": session_id},
        )
        TelemetryEvent.objects.create(
            session_id=session_id,
            event_type="FINGERPRINT_SIGNAL",
            path="/api/internal/telemetry/",
            ip_address="203.0.113.10",
            user_agent="Mozilla/5.0",
            details={"kind": "fingerprint"},
        )
        AttackJourney.objects.create(
            session_id=session_id,
            entry_point="/login/",
            recon_path=["/wp-admin/", "/login/"],
            payload_evolution=["user=admin", "password=secret"],
            escalation_attempts=["/api/internal/auth/"],
            tools_used=["curl"],
            seconds_spent=42,
            notes="Replay test session",
        )

        resp = self.client.get(reverse("attacker_timeline"), {"session": session_id})
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Attack Timeline Replay")
        self.assertContains(resp, session_id)
