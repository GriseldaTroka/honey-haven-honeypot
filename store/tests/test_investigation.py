from __future__ import annotations

import os
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import connection
from django.test import Client, TestCase
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone

from store.detection import build_detection_alert_detail, build_detection_alert_list_payload, build_detection_dashboard, run_detection_pipeline
from store.investigation import build_campaign_dashboard_aggregates, build_campaign_summaries, build_investigation_graph, build_investigation_timeline, build_journey_similarity_pairs, get_campaign_summary, get_ioc_detail, get_ioc_relationships
from store.models import AttackJourney, DetectionAlert, HoneypotLog, IOCIndicator, ThreatIntelSnapshot


class InvestigationLayerTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.staff_user = user_model.objects.create_user(username="analyst", password="password123")
        self.staff_user.is_staff = True
        self.staff_user.save(update_fields=["is_staff"])

        now = timezone.now()
        self.journey_one = AttackJourney.objects.create(
            session_id="session-alpha",
            campaign_id="campaign-red",
            entry_point="/login",
            recon_path=["/login", "/api"],
            payload_evolution=[{"payload": "SELECT 1"}],
            escalation_attempts=["bruteforce"],
            tools_used=["curl", "sqlmap"],
            seconds_spent=42,
            risk_score=88.5,
            confidence_score=91.25,
            intent_score=74,
            first_seen=now - timedelta(hours=2),
            event_count=3,
            phases=["recon", "credential_attack"],
            ips=["203.0.113.10"],
            user_agents=["Mozilla/5.0"],
            notes="campaign alpha",
        )
        self.journey_two = AttackJourney.objects.create(
            session_id="session-beta",
            campaign_id="campaign-red",
            entry_point="/shop",
            recon_path=["/shop", "/checkout"],
            payload_evolution=[{"payload": "passwd"}],
            escalation_attempts=["lateral"],
            tools_used=["wget"],
            seconds_spent=11,
            risk_score=63.0,
            confidence_score=73.0,
            intent_score=55,
            first_seen=now - timedelta(hours=4),
            event_count=2,
            phases=["recon"],
            ips=["198.51.100.77"],
            user_agents=["curl/8.0"],
            notes="campaign alpha second session",
        )

        self.ioc_one = IOCIndicator.objects.create(
            session_id="session-alpha",
            ioc_type="ip",
            ioc_value="203.0.113.10",
            confidence_score=88,
            source_model="HoneypotLog",
            source_object_id=11,
            source_event="request",
            attack_journey=self.journey_one,
            evidence_summary="shared ip",
            attack_phase="recon",
            asg_risk_score=75,
            asg_confidence=83,
        )
        self.ioc_two = IOCIndicator.objects.create(
            session_id="session-beta",
            ioc_type="ip",
            ioc_value="203.0.113.10",
            confidence_score=72,
            source_model="HoneypotLog",
            source_object_id=12,
            source_event="request",
            attack_journey=self.journey_two,
            evidence_summary="shared ip",
            attack_phase="recon",
            asg_risk_score=65,
            asg_confidence=71,
        )

        ThreatIntelSnapshot.objects.create(
            ip_address="203.0.113.10",
            country="US",
            asn="AS64500",
            reputation_score=9,
            vpn=False,
            tor=False,
        )

    def test_build_campaign_summaries_groups_sessions_and_iocs(self):
        summaries = build_campaign_summaries()
        self.assertEqual(len(summaries), 1)
        summary = summaries[0]
        self.assertEqual(summary["campaign_id"], "campaign-red")
        self.assertEqual(summary["total_journeys"], 2)
        self.assertEqual(summary["total_sessions"], 2)
        self.assertEqual(summary["ioc_count"], 2)
        self.assertIn("recon", summary["dominant_attack_phases"])

    def test_get_ioc_detail_includes_cross_session_correlation(self):
        detail = get_ioc_detail(self.ioc_one.id)
        self.assertIsNotNone(detail)
        self.assertEqual(detail["campaign_id"], "campaign-red")
        self.assertEqual(detail["correlation"]["occurrence_count"], 2)
        self.assertEqual(detail["correlation"]["session_count"], 2)
        self.assertIn("session-beta", detail["sessions"])

    def test_get_ioc_relationships_groups_session_journey_and_campaign(self):
        relationships = get_ioc_relationships(self.ioc_one.id)
        self.assertIsNotNone(relationships)
        self.assertEqual(relationships["relationships"]["same_campaign"]["count"], 1)
        self.assertEqual(relationships["relationships"]["same_journey"]["count"], 0)
        self.assertEqual(relationships["shared_sessions"], 2)
        self.assertEqual(relationships["shared_journeys"], 2)
        self.assertEqual(relationships["shared_campaigns"], 1)
        self.assertIn("curl", relationships["related_tools"])
        self.assertIn("recon", relationships["related_phases"])
        self.assertTrue(relationships["repeated_appearance_timeline"])

    def test_ioc_evidence_endpoint_returns_provenance(self):
        self.client.force_login(self.staff_user)

        response = self.client.get(reverse("ioc_evidence", args=[self.ioc_one.id]))
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["ioc"]["id"], self.ioc_one.id)
        self.assertTrue(body["evidence_objects"])
        first_evidence = body["evidence_objects"][0]
        self.assertEqual(first_evidence["source_model"], "HoneypotLog")
        self.assertEqual(first_evidence["source_object_id"], 11)
        self.assertEqual(first_evidence["session_id"], "session-alpha")

    def test_journey_detail_endpoint_returns_investigation_view(self):
        self.client.force_login(self.staff_user)

        response = self.client.get(reverse("journey_detail", args=[self.journey_one.id]))
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["session_id"], "session-alpha")
        self.assertEqual(body["campaign_id"], "campaign-red")
        self.assertIn("first_seen", body)
        self.assertIn("last_seen", body)
        self.assertIn("related_iocs", body)
        self.assertIn("evidence_objects", body)
        self.assertIn("timeline_events", body)
        self.assertTrue(body["timeline_events"])

    def test_journey_similarity_scoring_is_deterministic(self):
        similarities = build_journey_similarity_pairs(limit=10)
        self.assertTrue(similarities)
        top_pair = similarities[0]
        self.assertIn("similarity_score", top_pair)
        self.assertGreater(top_pair["similarity_score"], 0)
        self.assertTrue(top_pair["shared_features"])

    def test_investigation_graph_output_contains_nodes_and_edges(self):
        self.client.force_login(self.staff_user)

        response = self.client.get(reverse("investigation_graph"))
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn("nodes", body)
        self.assertIn("edges", body)
        node_types = {node["type"] for node in body["nodes"]}
        edge_types = {edge["type"] for edge in body["edges"]}
        self.assertIn("IOC", node_types)
        self.assertIn("Session", node_types)
        self.assertIn("AttackJourney", node_types)
        self.assertIn("Campaign", node_types)
        self.assertIn("Evidence", node_types)
        self.assertIn("IOC_FOUND_IN_SESSION", edge_types)
        self.assertIn("IOC_LINKED_TO_JOURNEY", edge_types)
        self.assertIn("IOC_CREATED_FROM_EVIDENCE", edge_types)
        self.assertIn("JOURNEY_PART_OF_CAMPAIGN", edge_types)

    def test_investigation_graph_can_be_scoped_to_session(self):
        self.client.force_login(self.staff_user)

        response = self.client.get(reverse("investigation_graph"), {"session_id": self.journey_one.session_id})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["nodes"])
        self.assertTrue(any(node["type"] == "AttackJourney" for node in body["nodes"]))
        self.assertTrue(any(node.get("session_id") == self.journey_one.session_id for node in body["nodes"]))
        self.assertTrue(any(node["type"] == "Campaign" for node in body["nodes"]))

    def test_get_campaign_summary_returns_journeys_and_timeline(self):
        summary = get_campaign_summary("campaign-red")
        self.assertIsNotNone(summary)
        self.assertEqual(summary["summary"]["total_journeys"], 2)
        self.assertEqual(len(summary["journeys"]), 2)
        self.assertEqual(summary["ioc_statistics"]["ioc_count"], 2)

    def test_build_investigation_timeline_includes_campaign_scope(self):
        timeline = build_investigation_timeline(campaign_id="campaign-red", limit=50)
        self.assertTrue(any(item["kind"] == "ioc" for item in timeline))
        self.assertTrue(all(item["campaign_id"] == "campaign-red" for item in timeline if item["campaign_id"]))

    def test_build_campaign_dashboard_aggregates_enriches_ips(self):
        aggregates = build_campaign_dashboard_aggregates()
        self.assertTrue(any(item["value"] == "203.0.113.10" for item in aggregates["most_repeated_ips"]))
        self.assertTrue(any(item["country"] == "US" for item in aggregates["most_repeated_ips"]))
        self.assertIn("most_connected_iocs", aggregates)
        self.assertIn("most_reused_attacker_tools", aggregates)
        self.assertIn("most_similar_attack_journeys", aggregates)
        self.assertIn("campaigns_with_expanding_activity", aggregates)
        self.assertIn("recently_discovered_indicators", aggregates)
        self.assertIn("highest_risk_unresolved_journeys", aggregates)

    def test_staff_api_routes_return_investigation_payloads(self):
        self.client.force_login(self.staff_user)

        response = self.client.get(reverse("ioc_index"))
        self.assertEqual(response.status_code, 200)
        self.assertIn("iocs", response.json())

        response = self.client.get(reverse("ioc_detail", args=[self.ioc_one.id]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["campaign_id"], "campaign-red")

        response = self.client.get(reverse("ioc_relationships", args=[self.ioc_one.id]))
        self.assertEqual(response.status_code, 200)
        self.assertIn("relationships", response.json())

        response = self.client.get(reverse("campaign_list"))
        self.assertEqual(response.status_code, 200)
        self.assertIn("campaigns", response.json())

        response = self.client.get(reverse("campaign_detail", args=["campaign-red"]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["campaign_id"], "campaign-red")
        self.assertIn("summary", response.json())
        self.assertIn("ioc_statistics", response.json())

        response = self.client.get(reverse("campaign_journeys", args=["campaign-red"]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["campaign_id"], "campaign-red")


class DetectionLayerTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.staff_user = user_model.objects.create_user(username="detection-analyst", password="password123")
        self.staff_user.is_staff = True
        self.staff_user.save(update_fields=["is_staff"])
        self.account_user = user_model.objects.create_user(username="account-user", password="correct-horse-battery-staple")
        self.client = Client()
        self.staff_client = Client()
        self.staff_client.force_login(self.staff_user)

    def _set_session(self, client: Client, session_id: str) -> None:
        session = client.session
        session["honey_session_id"] = session_id
        session.save()

    def _sqli_username(self) -> str:
        return "".join(["admin", "'", " OR ", "'", "1", "'", "=", "'", "1", "'"])

    def _post_login(self, *, session_id: str, username: str, password: str, ip_address: str = "198.51.100.77"):
        self._set_session(self.client, session_id)
        return self.client.post(
            reverse("login"),
            {"username": username, "password": password},
            REMOTE_ADDR=ip_address,
            HTTP_USER_AGENT="scanner/1.0",
        )

    def test_brute_force_rule_creates_single_alert(self):
        session_id = "det-bruteforce-session"
        AttackJourney.objects.create(session_id=session_id, entry_point="/login")

        for _ in range(10):
            self.assertEqual(self._post_login(session_id=session_id, username="admin", password="wrong-password").status_code, 200)

        alerts = DetectionAlert.objects.filter(rule_name="BRUTE_FORCE_ACTIVITY", session_id=session_id)
        self.assertEqual(alerts.count(), 1)
        self.assertEqual(alerts.first().severity, "CRITICAL")

    def test_sql_injection_rule_creates_alert(self):
        session_id = "det-sqli-session"
        AttackJourney.objects.create(session_id=session_id, entry_point="/login", campaign_id="campaign-sqli")

        HoneypotLog.objects.create(
            session_id=session_id,
            ip_address="198.51.100.77",
            user_agent="scanner/1.0",
            requested_url="/login",
            method="GET",
            query_params="id=1",
            payload="probe",
            event_type="REQUEST",
            attack_classification="SQL_INJECTION_ATTEMPT",
            is_suspicious=True,
            suspicion_reason="SQL injection pattern",
            status_code=200,
        )

        run_detection_pipeline(session_id, trigger={"source_model": "HoneypotLog", "source_event": "REQUEST"})

        alert = DetectionAlert.objects.filter(rule_name="SQL_INJECTION_ACTIVITY", session_id=session_id).first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.campaign_id, "campaign-sqli")

    def test_malicious_upload_rule_creates_alert(self):
        session_id = "det-upload-session"
        AttackJourney.objects.create(session_id=session_id, entry_point="/upload")
        self._set_session(self.client, session_id)

        response = self.client.post(
            reverse("upload_trap"),
            {"file": SimpleUploadedFile("asset.php", os.urandom(2048), content_type="application/x-php")},
            REMOTE_ADDR="203.0.113.55",
            HTTP_USER_AGENT="scanner/1.0",
        )
        self.assertEqual(response.status_code, 202)

        alert = DetectionAlert.objects.filter(rule_name="MALICIOUS_UPLOAD", session_id=session_id).first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.status, "OPEN")

    def test_account_compromise_rule_triggers_after_successful_login(self):
        session_id = "det-compromise-session"
        AttackJourney.objects.create(session_id=session_id, entry_point="/login")

        for _ in range(5):
            self._post_login(session_id=session_id, username="account-user", password="wrong-password")
        self.assertEqual(
            self._post_login(session_id=session_id, username="account-user", password="correct-horse-battery-staple").status_code,
            302,
        )

        alert = DetectionAlert.objects.filter(rule_name="ACCOUNT_COMPROMISE", session_id=session_id).first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, "CRITICAL")

    def test_alert_detail_payload_is_bounded_for_session_scope(self):
        session_id = "detail-budget-session"
        journey = AttackJourney.objects.create(session_id=session_id, entry_point="/login", campaign_id="campaign-budget")
        for index in range(120):
            HoneypotLog.objects.create(
                session_id=session_id,
                event_type="REQUEST",
                attack_classification="SCANNER_BOT_ACTIVITY",
                requested_url=f"/probe/{index}",
                suspicion_reason="scanner",
                status_code=200,
            )
        for index in range(40):
            IOCIndicator.objects.create(
                session_id=session_id,
                ioc_type="ip",
                ioc_value=f"203.0.113.{index}",
                confidence_score=0.8,
                source_model="HoneypotLog",
                source_object_id=index + 1,
                source_event="request",
                evidence_summary="scanner ip",
                attack_phase="reconnaissance",
                attack_journey=journey,
            )
        alert = DetectionAlert.objects.create(
            rule_name="DETAIL_BUDGET_RULE",
            severity="HIGH",
            confidence_score=0.9,
            status="OPEN",
            description="test alert detail bound",
            session_id=session_id,
            attack_journey=journey,
            campaign_id="campaign-budget",
            evidence_source_model="HoneypotLog",
            evidence_source_object_id=101,
            evidence_source_event="request",
            evidence_fingerprint="detail-budget-fingerprint",
            evidence_summary="budget test",
            response_recommendation=["review session"],
        )

        detail = build_detection_alert_detail(alert)
        self.assertLessEqual(len(detail["related_iocs"]), 25)
        self.assertLessEqual(len(detail["timeline"]), 80)

    def test_alert_list_payload_avoids_n_plus_one_ioc_count_queries(self):
        session_id = "list-budget-session"
        journey = AttackJourney.objects.create(session_id=session_id, entry_point="/login", campaign_id="campaign-list")
        for index in range(12):
            IOCIndicator.objects.create(
                session_id=session_id,
                ioc_type="ip",
                ioc_value=f"198.51.100.{index}",
                confidence_score=0.7,
                source_model="HoneypotLog",
                source_object_id=index + 1,
                source_event="request",
                evidence_summary="list count check",
                attack_phase="reconnaissance",
                attack_journey=journey,
            )
        for index in range(5):
            DetectionAlert.objects.create(
                rule_name=f"LIST_COUNT_RULE_{index}",
                severity="MEDIUM",
                confidence_score=0.75,
                status="OPEN",
                description="list count check",
                session_id=session_id,
                attack_journey=journey,
                campaign_id="campaign-list",
                evidence_source_model="HoneypotLog",
                evidence_source_object_id=index + 1,
                evidence_source_event="request",
                evidence_fingerprint=f"list-count-fingerprint-{index}",
                evidence_summary="list count check",
                response_recommendation=["review session"],
            )

        with CaptureQueriesContext(connection) as captured:
            payload = build_detection_alert_list_payload(limit=10)

        self.assertEqual(len(payload["alerts"]), 5)
        self.assertLess(len(captured.captured_queries), 15)

    def test_alert_api_and_dashboard_payloads(self):
        session_id = "det-dashboard-session"
        AttackJourney.objects.create(session_id=session_id, entry_point="/upload", campaign_id="campaign-dashboard")
        self._set_session(self.client, session_id)
        self.client.post(
            reverse("upload_trap"),
            {"file": SimpleUploadedFile("component.php", os.urandom(3072), content_type="application/x-php")},
            REMOTE_ADDR="198.51.100.88",
            HTTP_USER_AGENT="scanner/1.0",
        )

        list_response = self.staff_client.get(reverse("alerts_feed"))
        self.assertEqual(list_response.status_code, 200)
        list_body = list_response.json()
        self.assertTrue(list_body["alerts"])
        alert_id = list_body["alerts"][0]["id"]

        detail_response = self.staff_client.get(reverse("alert_detail_api", args=[alert_id]))
        self.assertEqual(detail_response.status_code, 200)
        self.assertIn("timeline", detail_response.json())

        patch_response = self.staff_client.patch(
            reverse("alert_detail_api", args=[alert_id]),
            data='{"status":"RESOLVED"}',
            content_type="application/json",
        )
        self.assertEqual(patch_response.status_code, 200)

        dashboard_response = self.staff_client.get(reverse("detection_dashboard"))
        self.assertEqual(dashboard_response.status_code, 200)
        dashboard = dashboard_response.json()
        self.assertIn("active_alerts", dashboard)
        self.assertGreaterEqual(dashboard["active_alerts"], 1)
        self.assertGreaterEqual(build_detection_dashboard(limit=10)["active_alerts"], 1)
