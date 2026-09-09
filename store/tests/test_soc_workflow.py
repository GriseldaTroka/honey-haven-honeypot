from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from store.models import AnalystNote, AttackJourney, DetectionAlert, IOCIndicator, InvestigationBookmark


class SocWorkflowTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.staff = user_model.objects.create_user(username="analyst", password="password123")
        self.staff.is_staff = True
        self.staff.save(update_fields=["is_staff"])
        self.client = Client()
        self.client.force_login(self.staff)

        self.session_id = "soc-workflow-session"
        self.campaign_id = "campaign-soc-workflow"
        self.journey = AttackJourney.objects.create(
            session_id=self.session_id,
            campaign_id=self.campaign_id,
            entry_point="/login",
            event_count=4,
            risk_score=92,
            confidence_score=88,
            intent_score=75,
        )
        self.ioc = IOCIndicator.objects.create(
            session_id=self.session_id,
            ioc_type="url",
            ioc_value="https://malicious.example/path",
            confidence_score=91,
            source_model="HoneypotLog",
            source_object_id=11,
            source_event="HoneypotLog",
            evidence_summary="IOC evidence",
            attack_phase="reconnaissance",
            attack_journey=self.journey,
        )
        self.alert = DetectionAlert.objects.create(
            rule_name="TEST_RULE",
            severity="HIGH",
            confidence_score=0.84,
            status="OPEN",
            description="Test alert",
            session_id=self.session_id,
            attack_journey=self.journey,
            campaign_id=self.campaign_id,
            evidence_source_model="HoneypotLog",
            evidence_source_object_id=11,
            evidence_source_event="HoneypotLog",
            evidence_fingerprint="test-fingerprint",
            evidence_summary="Alert evidence",
            response_recommendation=["review session"],
        )

    def test_alert_filters_and_overview_payloads(self):
        overview_response = self.client.get(reverse("dashboard_overview"))
        self.assertEqual(overview_response.status_code, 200)
        overview = overview_response.json()
        self.assertIn("summary", overview)
        self.assertIn("attack_flow", overview)
        self.assertIn("detection", overview)
        self.assertIn("campaign_intelligence", overview)

        alert_response = self.client.get(reverse("alerts_feed"), {"severity": "HIGH", "status": "OPEN", "campaign": self.campaign_id, "search": "TEST_RULE"})
        self.assertEqual(alert_response.status_code, 200)
        alerts = alert_response.json()["alerts"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["session_id"], self.session_id)
        self.assertEqual(alerts[0]["campaign_id"], self.campaign_id)

    def test_notes_bookmarks_and_search_workflow(self):
        note_response = self.client.post(
            reverse("notes_feed"),
            data='{"title":"Initial triage","body":"Confirmed campaign linkage","session_id":"%s","campaign_id":"campaign-soc-workflow","alert_id":%d,"tags":["triage","campaign"]}' % (self.session_id, self.alert.id),
            content_type="application/json",
        )
        self.assertEqual(note_response.status_code, 201)
        note_id = note_response.json()["note"]["id"]

        patch_response = self.client.patch(
            reverse("note_detail", args=[note_id]),
            data='{"pinned":true}',
            content_type="application/json",
        )
        self.assertEqual(patch_response.status_code, 200)
        self.assertTrue(AnalystNote.objects.filter(id=note_id, pinned=True).exists())

        bookmark_response = self.client.post(
            reverse("bookmarks_feed"),
            data='{"label":"Follow this session","session_id":"%s","campaign_id":"%s","ioc_id":%d}' % (self.session_id, self.campaign_id, self.ioc.id),
            content_type="application/json",
        )
        self.assertEqual(bookmark_response.status_code, 201)
        bookmark_id = bookmark_response.json()["bookmark"]["id"]

        bookmark_list_response = self.client.get(reverse("bookmarks_feed"), {"campaign_id": self.campaign_id})
        self.assertEqual(bookmark_list_response.status_code, 200)
        self.assertEqual(len(bookmark_list_response.json()["bookmarks"]), 1)

        search_response = self.client.get(reverse("soc_search"), {"q": self.campaign_id})
        self.assertEqual(search_response.status_code, 200)
        search_body = search_response.json()
        self.assertTrue(search_body["sessions"])
        self.assertTrue(search_body["campaigns"])
        self.assertTrue(search_body["iocs"])
        self.assertTrue(search_body["alerts"])
        self.assertTrue(search_body["notes"])

        delete_response = self.client.delete(reverse("bookmark_detail", args=[bookmark_id]))
        self.assertEqual(delete_response.status_code, 200)
        self.assertFalse(InvestigationBookmark.objects.filter(id=bookmark_id).exists())

        note_delete_response = self.client.delete(reverse("note_detail", args=[note_id]))
        self.assertEqual(note_delete_response.status_code, 200)
        self.assertFalse(AnalystNote.objects.filter(id=note_id).exists())

    def test_notes_feed_returns_empty_list_for_campaign_without_notes(self):
        response = self.client.get(reverse("notes_feed"), {"campaign_id": self.campaign_id})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["notes"], [])

    def test_sessions_include_campaign_from_journey(self):
        # Create an AttackerState without a campaign_id but ensure an AttackJourney exists
        from store.models import AttackerState

        AttackerState.objects.create(session_id="missing-camp-session", risk_score=10.0, current_phase="noise_or_observation", campaign_id="")
        # Create a journey that links the session to a campaign
        from store.models import AttackJourney

        AttackJourney.objects.create(session_id="missing-camp-session", campaign_id="linked-campaign", entry_point="/", event_count=1)

        resp = self.client.get(reverse("sessions_feed"))
        self.assertEqual(resp.status_code, 200)
        sessions = resp.json().get("sessions", [])
        found = [s for s in sessions if s.get("session_id") == "missing-camp-session"]
        self.assertTrue(found)
        self.assertEqual(found[0].get("campaign_id"), "linked-campaign")
