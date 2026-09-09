from django.contrib.auth import get_user_model
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import Client, RequestFactory, TestCase
from django.urls import reverse

from store.deception import enqueue_alert_event, fake_payment_payload, fake_support_ticket, persist_fake_iocs, record_telemetry_event, upsert_attack_journey, upload_trap_report
from store.models import AlertEvent, AttackJourney, HoneypotLog, IOCIndicator, LoginAttempt, PaymentRecord, SupportTicket, TelemetryEvent, UploadArtifact


class IocPersistenceTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.staff = User.objects.create_user("staff", "staff@example.com", "pw12345")
        self.staff.is_staff = True
        self.staff.save()
        self.client = Client()
        self.client.force_login(self.staff)
        self.factory = RequestFactory()

    def _set_honey_session(self, session_id: str) -> None:
        session = self.client.session
        session["honey_session_id"] = session_id
        session.save()

    def _request_with_session(self, method: str, path: str, *, session_id: str, data=None, content_type: str = "application/json", user_agent: str = "test-agent"):
        request = getattr(self.factory, method.lower())(path, data=data, content_type=content_type, HTTP_USER_AGENT=user_agent)
        middleware = SessionMiddleware(lambda req: None)
        middleware.process_request(request)
        request.session["honey_session_id"] = session_id
        request.session.save()
        return request

    def test_ioc_endpoint_persists_and_links_to_journey(self):
        session_id = "ioc-extraction-session"
        AttackJourney.objects.create(session_id=session_id, entry_point="/api/research/ioc/")
        self._set_honey_session(session_id)

        payload = {
            "url": "https://evil.example/path",
            "email": "attacker@example.com",
            "hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "ip": "198.51.100.24",
        }
        response = self.client.post(reverse("ioc_extraction"), data=payload, content_type="application/json")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn("urls", body)
        self.assertIn("emails", body)
        self.assertIn("hashes", body)

        indicators = IOCIndicator.objects.filter(session_id=session_id)
        self.assertTrue(indicators.exists())
        self.assertTrue(all(indicator.attack_journey and indicator.attack_journey.session_id == session_id for indicator in indicators))
        self.assertTrue(any(indicator.source_model == "HoneypotLog" and indicator.source_object_id for indicator in indicators))

    def test_ioc_retrieval_api_returns_evidence_fields(self):
        session_id = "ioc-api-session"
        journey = AttackJourney.objects.create(session_id=session_id, entry_point="/session")
        persist_fake_iocs(
            session_id=session_id,
            source_event="HoneypotLog",
            source_model="HoneypotLog",
            source_object_id=777,
            text="https://api.example/path attacker@example.com abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            related_journey=journey,
            evidence_summary="API test evidence",
        )

        response = self.client.get(reverse("session_iocs", kwargs={"session_id": session_id}))
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["session_id"], session_id)
        self.assertTrue(body["iocs"])
        first_ioc = body["iocs"][0]
        self.assertIn("ioc_value", first_ioc)
        self.assertIn("source_model", first_ioc)
        self.assertIn("source_object_id", first_ioc)
        self.assertIn("confidence_score", first_ioc)
        self.assertIn("evidence_summary", first_ioc)
        self.assertIn("attack_phase", first_ioc)
        self.assertIn("asg_risk_score", first_ioc)
        self.assertIn("asg_confidence", first_ioc)
        self.assertIn("source_event", first_ioc)
        self.assertEqual(first_ioc["attack_journey"], session_id)
        self.assertIn("first_seen", first_ioc)
        self.assertIn("last_seen", first_ioc)

    def test_telemetry_event_linkage_uses_exact_source_object(self):
        session_id = "ioc-telemetry-session"
        AttackJourney.objects.create(session_id=session_id, entry_point="/telemetry")

        request = self._request_with_session(
            "post",
            "/api/internal/telemetry/",
            session_id=session_id,
            data='{"kind":"fingerprint","contact":"telemetry@example.com","hash":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}',
        )
        event = record_telemetry_event(
            session_id,
            "FINGERPRINT_SIGNAL",
            "/api/internal/telemetry/",
            {"kind": "fingerprint", "contact": "telemetry@example.com", "hash": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"},
            request,
        )

        indicator = IOCIndicator.objects.filter(session_id=session_id, source_model="TelemetryEvent", source_object_id=event.id).first()
        self.assertIsNotNone(indicator)
        self.assertEqual(indicator.source_model, "TelemetryEvent")
        self.assertEqual(indicator.source_object_id, event.id)
        self.assertEqual(indicator.session_id, session_id)
        self.assertIsNotNone(indicator.attack_journey)

    def test_alert_event_linkage_uses_exact_source_object(self):
        session_id = "ioc-alert-session"
        AttackJourney.objects.create(session_id=session_id, entry_point="/alerts")

        request = self._request_with_session("get", "/api/admin", session_id=session_id)
        alert = enqueue_alert_event(
            request,
            alert_type="SUSPICIOUS_LOGIN",
            detail="alert@example.com probe https://alert.example/path",
            channels={"discord": "", "telegram": "", "email": ""},
        )

        indicator = IOCIndicator.objects.filter(session_id=session_id, source_model="AlertEvent", source_object_id=alert.id).first()
        self.assertIsNotNone(indicator)
        self.assertEqual(indicator.source_model, "AlertEvent")
        self.assertEqual(indicator.source_object_id, alert.id)
        self.assertEqual(indicator.session_id, session_id)
        self.assertIsNotNone(indicator.attack_journey)

    def test_payment_record_linkage_uses_exact_source_object(self):
        session_id = "ioc-payment-session"
        AttackJourney.objects.create(session_id=session_id, entry_point="/payments")

        payment_record = PaymentRecord.objects.create(
            payment_id="PAY-IOC-2",
            merchant_reference="ORD-IOC-2",
            card_last4="4242",
            amount="12.34",
            currency="USD",
            status="pending",
            metadata={"session_id": session_id, "receipt_url": "https://pay.example/receipt", "contact": "finance@example.com"},
        )
        persist_fake_iocs(
            session_id=session_id,
            source_event="PaymentRecord",
            source_model="PaymentRecord",
            source_object_id=payment_record.id,
            text="https://pay.example/receipt finance@example.com",
            related_journey=AttackJourney.objects.get(session_id=session_id),
            evidence_summary="PaymentRecord provenance test",
        )

        indicator = IOCIndicator.objects.filter(session_id=session_id, source_model="PaymentRecord", source_object_id=payment_record.id).first()
        self.assertIsNotNone(indicator)
        self.assertEqual(indicator.source_model, "PaymentRecord")
        self.assertEqual(indicator.source_object_id, payment_record.id)
        self.assertEqual(indicator.session_id, session_id)
        self.assertIsNotNone(indicator.attack_journey)

    def test_support_ticket_linkage_uses_exact_source_object(self):
        session_id = "ioc-support-session"
        AttackJourney.objects.create(session_id=session_id, entry_point="/support")

        fake_support_ticket("Invoice export", "See https://support.example and email help@example.com", "attacker@example.com", session_id=session_id)
        support_ticket = SupportTicket.objects.filter(metadata__session_id=session_id).order_by("-timestamp").first()
        self.assertIsNotNone(support_ticket)

        indicator = IOCIndicator.objects.filter(session_id=session_id, source_model="SupportTicket", source_object_id=support_ticket.id).first()
        self.assertIsNotNone(indicator)
        self.assertEqual(indicator.source_model, "SupportTicket")
        self.assertEqual(indicator.source_object_id, support_ticket.id)
        self.assertEqual(indicator.session_id, session_id)
        self.assertIsNotNone(indicator.attack_journey)

    def test_login_attempt_linkage_uses_exact_source_object(self):
        session_id = "ioc-login-session"
        AttackJourney.objects.create(session_id=session_id, entry_point="/login")

        login_attempt = LoginAttempt.objects.create(
            username="admin",
            password_submitted="secret",
            ip_address="198.51.100.77",
            session_id=session_id,
            user_agent="sqlmap/1.7",
            requested_url="/login/",
            success=False,
        )
        persist_fake_iocs(
            session_id=session_id,
            source_event="LoginAttempt",
            source_model="LoginAttempt",
            source_object_id=login_attempt.id,
            text="https://login.example/path admin@example.com",
            related_journey=AttackJourney.objects.get(session_id=session_id),
            evidence_summary="LoginAttempt provenance test",
        )

        indicator = IOCIndicator.objects.filter(session_id=session_id, source_model="LoginAttempt", source_object_id=login_attempt.id).first()
        self.assertIsNotNone(indicator)
        self.assertEqual(indicator.source_model, "LoginAttempt")
        self.assertEqual(indicator.source_object_id, login_attempt.id)
        self.assertEqual(indicator.session_id, session_id)
        self.assertIsNotNone(indicator.attack_journey)

    def test_journey_aggregation_persists_all_event_sources(self):
        session_id = "ioc-journey-session"

        HoneypotLog.objects.create(
            ip_address="198.51.100.1",
            session_id=session_id,
            user_agent="curl/8.0",
            requested_url="https://honey.example/alpha?email=attacker@example.com&hash=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            method="GET",
            query_params="",
            payload="",
            username="",
            event_type="REQUEST",
            attack_classification="SCANNER_BOT_ACTIVITY",
            is_suspicious=True,
            suspicion_reason="probe",
            status_code=200,
        )
        TelemetryEvent.objects.create(
            session_id=session_id,
            event_type="FINGERPRINT_SIGNAL",
            path="/telemetry?next=https://tele.example",
            ip_address="198.51.100.1",
            user_agent="telemetry-bot",
            details={"contact": "telemetry@example.com", "hash": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"},
        )
        LoginAttempt.objects.create(
            username="admin",
            password_submitted="fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            ip_address="198.51.100.1",
            session_id=session_id,
            user_agent="sqlmap/1.7",
            requested_url="/login?next=https://login.example",
            success=False,
        )
        AlertEvent.objects.create(
            alert_type="SUSPICIOUS_LOGIN",
            detail="alert at https://alert.example/path for attacker@example.com",
            ip_address="198.51.100.1",
            user_agent="alert-bot",
            requested_url="/api/admin",
            dispatch_status="pending",
            metadata={"session_id": session_id},
        )
        UploadArtifact.objects.create(
            filename="payload.php",
            sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            entropy=7.9,
            verdict="webshell-suspected",
            uploader_ip="198.51.100.1",
            user_agent="upload@example.com",
            metadata={"session_id": session_id},
        )
        PaymentRecord.objects.create(
            payment_id="PAY-IOC-1",
            merchant_reference="ORD-IOC-1",
            card_last4="4242",
            amount="12.34",
            currency="USD",
            status="pending",
            metadata={"session_id": session_id, "contact": "finance@example.com", "receipt_url": "https://pay.example/receipt"},
        )
        SupportTicket.objects.create(
            ticket_id="TKT-IOC-1",
            requester_email="support@example.com",
            subject="Need help",
            status="open",
            priority="high",
            body="See https://support.example and email help@example.com",
            metadata={"session_id": session_id},
        )

        upsert_attack_journey(session_id=session_id, entry_point="/start")

        indicators = IOCIndicator.objects.filter(session_id=session_id)
        source_events = set(indicators.values_list("source_event", flat=True))

        self.assertTrue(indicators.exists())
        self.assertTrue(AttackJourney.objects.filter(session_id=session_id).exists())
        self.assertTrue(all(indicator.attack_journey_id for indicator in indicators))
        self.assertTrue({"HoneypotLog", "TelemetryEvent", "LoginAttempt", "AlertEvent", "UploadArtifact", "PaymentRecord", "SupportTicket"}.issubset(source_events))

    def test_research_report_persists_honeypotlog_provenance_and_stays_staff_scoped(self):
        session_id = "ioc-research-session"
        log = HoneypotLog.objects.create(
            ip_address="198.51.100.9",
            session_id=session_id,
            user_agent="curl/8.0",
            requested_url="/admin/phpmyadmin/?email=attacker@example.com",
            method="GET",
            query_params="",
            payload="probe https://report.example/path",
            username="",
            event_type="ADMIN_ACCESS",
            attack_classification="SCANNER_BOT_ACTIVITY",
            is_suspicious=True,
            suspicion_reason="probe",
            status_code=200,
        )

        self.client.logout()
        anon_response = self.client.get(reverse("attack_research_report"))
        self.assertEqual(anon_response.status_code, 200)
        self.assertIn("summary", anon_response.json())

        self.client.force_login(self.staff)
        response = self.client.get(reverse("attack_research_report"))
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn("classification", body)
        self.assertIn("iocs", body)

        indicator = IOCIndicator.objects.filter(session_id=session_id, source_model="HoneypotLog", source_object_id=log.id).first()
        self.assertIsNotNone(indicator)
        self.assertEqual(indicator.source_model, "HoneypotLog")
        self.assertEqual(indicator.source_object_id, log.id)
        self.assertEqual(indicator.session_id, session_id)

    def test_ioc_backfill_links_preexisting_row_to_journey(self):
        session_id = "ioc-backfill-session"
        log = HoneypotLog.objects.create(
            ip_address="198.51.100.11",
            session_id=session_id,
            user_agent="sqlmap/1.7",
            requested_url="/admin/?url=https://backfill.example/path",
            method="GET",
            query_params="",
            payload="https://backfill.example/path attacker@example.com",
            username="",
            event_type="REQUEST",
            attack_classification="SCANNER_BOT_ACTIVITY",
            is_suspicious=True,
            suspicion_reason="probe",
            status_code=200,
        )

        persist_fake_iocs(
            session_id=session_id,
            source_event="HoneypotLog",
            source_model="HoneypotLog",
            source_object_id=log.id,
            text="https://backfill.example/path attacker@example.com",
            evidence_summary="pre-backfill IOC",
        )

        indicator = IOCIndicator.objects.get(session_id=session_id, source_model="HoneypotLog", source_object_id=log.id, ioc_type="url")
        self.assertIsNone(indicator.attack_journey)

        journey = upsert_attack_journey(session_id=session_id, entry_point="/backfill")
        indicator.refresh_from_db()

        self.assertIsNotNone(journey)
        self.assertIsNotNone(indicator.attack_journey)
        self.assertEqual(indicator.attack_journey.session_id, session_id)

    def test_upload_artifact_linkage_uses_exact_source_object(self):
        session_id = "ioc-upload-source-session"
        AttackJourney.objects.create(session_id=session_id, entry_point="/upload")

        upload_trap_report(
            "payload.php",
            b"https://uploads.example/path abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "198.51.100.33",
            "curl/8.0",
            session_id=session_id,
        )

        artifact = UploadArtifact.objects.filter(metadata__session_id=session_id).order_by("-timestamp").first()
        self.assertIsNotNone(artifact)
        indicator = IOCIndicator.objects.filter(session_id=session_id, source_model="UploadArtifact", source_object_id=artifact.id).first()
        self.assertIsNotNone(indicator)
        self.assertEqual(indicator.source_model, "UploadArtifact")
        self.assertEqual(indicator.source_object_id, artifact.id)

    def test_duplicate_ioc_handling_updates_existing_rows(self):
        session_id = "ioc-dup-session"
        journey = AttackJourney.objects.create(session_id=session_id, entry_point="/dup")
        text = "https://dup.example/path attacker@example.com 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

        persist_fake_iocs(session_id=session_id, source_event="HoneypotLog", text=text, related_journey=journey)
        first_count = IOCIndicator.objects.filter(session_id=session_id, source_event="HoneypotLog").count()
        indicator = IOCIndicator.objects.get(session_id=session_id, source_event="HoneypotLog", ioc_type="url")
        first_seen = indicator.first_seen
        first_last_seen = indicator.last_seen

        persist_fake_iocs(session_id=session_id, source_event="HoneypotLog", text=text, related_journey=journey)
        indicator.refresh_from_db()

        self.assertEqual(IOCIndicator.objects.filter(session_id=session_id, source_event="HoneypotLog").count(), first_count)
        self.assertEqual(indicator.first_seen, first_seen)
        self.assertGreaterEqual(indicator.last_seen, first_last_seen)