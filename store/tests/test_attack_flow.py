from django.test import TestCase, Client, RequestFactory
from django.contrib.auth import get_user_model
from django.urls import reverse

from store.models import (
    AttackerState,
    StateTransition,
    AttackJourney,
    HoneypotLog,
    UploadArtifact,
    PaymentRecord,
    SupportTicket,
    TelemetryEvent,
    LoginAttempt,
    AlertEvent,
)
from store.asg import update_attacker_state


class AttackFlowIntegrationTests(TestCase):
    def setUp(self):
        User = get_user_model()
        # create a staff user and a regular user
        self.staff = User.objects.create_user("staff", "staff@example.com", "pw12345")
        self.staff.is_staff = True
        self.staff.save()

        self.regular = User.objects.create_user("regular", "user@example.com", "pw12345")

        self.client = Client()
        self.rf = RequestFactory()

    def test_analytics_endpoint_anonymous_blocked_and_staff_allowed(self):
        url = reverse("attack_flow_analytics_api")

        # anonymous should be redirected/denied
        resp = self.client.get(url)
        self.assertIn(resp.status_code, (302, 403))

        # regular authenticated (non-staff) should also be blocked
        self.client.force_login(self.regular)
        resp = self.client.get(url)
        self.assertIn(resp.status_code, (302, 403))
        self.client.logout()

        # staff should get JSON 200
        self.client.force_login(self.staff)
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp["Content-Type"].startswith("application/json"))
        body = resp.json()
        # verify expected keys exist
        for key in ("generated_at", "session_count", "sankey", "top_risk_sessions", "transition_counts"):
            self.assertIn(key, body)

    def test_analytics_handles_empty_and_with_data(self):
        self.client.force_login(self.staff)
        url = reverse("attack_flow_analytics_api")

        # empty state (no attacker states)
        resp = self.client.get(url)
        body = resp.json()
        self.assertEqual(body.get("session_count"), 0)

        # create sample records
        state = AttackerState.objects.create(session_id="s1", current_phase="reconnaissance", risk_score=12.5)
        AttackJourney.objects.create(session_id="s1", entry_point="/", event_count=3, phases=["reconnaissance"]) 
        # create a state transition
        StateTransition.objects.create(attacker_state=state, session_id="s1", from_phase="noise_or_observation", to_phase="reconnaissance", trigger_event_type="REQUEST", trigger_path="/", risk_delta=12.5)

        resp = self.client.get(url)
        body = resp.json()
        self.assertGreaterEqual(body.get("session_count", 0), 1)
        sankey = body.get("sankey") or {}
        self.assertIn("nodes", sankey)
        self.assertIn("links", sankey)

    def test_attacker_state_explain_auth_and_missing(self):
        explain_url = reverse("attacker_state_explain", kwargs={"session_id": "nope"})

        # anonymous blocked
        resp = self.client.get(explain_url)
        self.assertIn(resp.status_code, (302, 403))

        # regular blocked
        self.client.force_login(self.regular)
        resp = self.client.get(explain_url)
        self.assertIn(resp.status_code, (302, 403))
        self.client.logout()

        # staff access but missing session -> 404
        self.client.force_login(self.staff)
        resp = self.client.get(explain_url)
        self.assertEqual(resp.status_code, 404)

    def test_attacker_state_explain_returns_expected_fields(self):
        # create a realistic attacker state with signals
        session_id = "sess-explain-1"
        state = AttackerState.objects.create(
            session_id=session_id,
            current_phase="execution_attempt",
            risk_score=95.2,
            phase_confidence=0.92,
            last_event_type="API_HIT",
            last_signals=[{"signal": "sensitive_path", "weight": 10, "confidence": 0.45, "reason": "test"}],
        )

        self.client.force_login(self.staff)
        url = reverse("attacker_state_explain", kwargs={"session_id": session_id})
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        for key in ("session_id", "phase", "risk_score", "confidence", "top_signals", "explanation_summary"):
            self.assertIn(key, body)
        self.assertAlmostEqual(float(body.get("risk_score")), round(state.risk_score, 2))

    def test_asg_update_creates_state_and_transitions(self):
        session_id = "asg-run-1"
        # initial benign update should create state
        req = self.rf.get("/shop/", HTTP_USER_AGENT="unit-test-agent")
        state = update_attacker_state(session_id=session_id, event_type="REQUEST", path="/shop/", request=req, source_model="TelemetryEvent", payload={"k": "v"})
        self.assertIsNotNone(state)
        db_state = AttackerState.objects.filter(session_id=session_id).first()
        self.assertIsNotNone(db_state)
        # subsequent malicious update should increase risk and may create transition
        req2 = self.rf.get("/admin/", HTTP_USER_AGENT="scanner-bot")
        state2 = update_attacker_state(session_id=session_id, event_type="REQUEST", path="/admin/", request=req2, source_model="HoneypotLog", payload={"attack": "probe"})
        self.assertGreaterEqual(state2.risk_score, state.risk_score)
        transitions = StateTransition.objects.filter(session_id=session_id)
        self.assertTrue(transitions.exists())

    def test_attack_journeys_json_uses_canonical_session_and_all_sources(self):
        session_id = "journey-phase1-canonical"
        user_agent = "sqlmap/1.7"

        HoneypotLog.objects.create(
            ip_address="203.0.113.9",
            session_id=session_id,
            user_agent=user_agent,
            requested_url="/admin/phpmyadmin/",
            method="GET",
            query_params="",
            payload="",
            username="",
            event_type="ADMIN_ACCESS",
            attack_classification="SCANNER_BOT_ACTIVITY",
            is_suspicious=True,
            suspicion_reason="probe",
            status_code=200,
        )
        TelemetryEvent.objects.create(
            session_id=session_id,
            event_type="FINGERPRINT_SIGNAL",
            path="/api/internal/telemetry/",
            ip_address="203.0.113.9",
            user_agent=user_agent,
            details={"session_id": session_id, "kind": "fingerprint"},
        )
        LoginAttempt.objects.create(
            username="admin",
            password_submitted="secret",
            ip_address="203.0.113.9",
            session_id=session_id,
            user_agent=user_agent,
            requested_url="/login/",
            success=False,
        )
        AlertEvent.objects.create(
            alert_type="SUSPICIOUS_LOGIN",
            detail="Multiple failed login attempts",
            ip_address="203.0.113.9",
            user_agent=user_agent,
            requested_url="/login/",
            dispatch_status="pending",
            metadata={"session_id": session_id},
        )
        UploadArtifact.objects.create(
            filename="shell.php",
            sha256="a" * 64,
            entropy=7.9,
            verdict="webshell-suspected",
            uploader_ip="203.0.113.9",
            user_agent=user_agent,
            metadata={"session_id": session_id, "ip_address": "203.0.113.9", "user_agent": user_agent},
        )
        PaymentRecord.objects.create(
            payment_id="pay-journey-1",
            merchant_reference="ord-journey-1",
            card_last4="4242",
            amount="12.34",
            currency="USD",
            status="pending",
            metadata={"session_id": session_id, "ip_address": "203.0.113.9", "user_agent": user_agent},
        )
        SupportTicket.objects.create(
            ticket_id="tkt-journey-1",
            requester_email="attacker@example.com",
            subject="Help",
            status="open",
            priority="high",
            body="Need assistance",
            metadata={"session_id": session_id, "ip_address": "203.0.113.9", "user_agent": user_agent},
        )

        self.client.force_login(self.staff)
        resp = self.client.get(reverse("attack_journeys_json"), {"hours": 24, "limit": 50})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        journeys = [journey for journey in body.get("journeys", []) if journey.get("session_id") == session_id]
        self.assertEqual(len(journeys), 1)

        journey = journeys[0]
        self.assertEqual(journey.get("event_count"), 7)
        self.assertTrue(all(isinstance(phase, dict) for phase in journey.get("phases", [])))
        self.assertTrue(any(phase.get("phase") == "reconnaissance" for phase in journey.get("phases", [])))
        self.assertTrue(journey.get("tools_used"))
        self.assertIn("sqlmap", journey.get("tools_used", []))
        self.assertTrue(journey.get("escalation_attempts"))
        self.assertGreater(journey.get("risk_score", 0), 0)
        self.assertGreater(journey.get("confidence_score", 0), 0)
        self.assertGreater(journey.get("intent_score", 0), 0)
        self.assertTrue(journey.get("campaign_id"))
        self.assertEqual(
            {event.get("kind") for event in journey.get("sample_events", [])},
            {"request", "telemetry", "login", "alert", "upload", "payment", "support"},
        )
        self.assertTrue(all(isinstance(event.get("timestamp"), str) for event in journey.get("recon_path", [])))
        self.assertTrue(all(isinstance(event.get("timestamp"), str) for event in journey.get("payload_evolution", [])))
