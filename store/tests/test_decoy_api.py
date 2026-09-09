from unittest.mock import patch

from django.db import OperationalError
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import Client, RequestFactory, TestCase
from django.urls import reverse

from store.models import HoneypotLog
from store.utils import log_event


class DecoyApiTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.factory = RequestFactory()

    def test_log_event_does_not_raise_when_database_write_fails(self):
        request = self.factory.get("/api", HTTP_USER_AGENT="test-agent")
        middleware = SessionMiddleware(lambda req: None)
        middleware.process_request(request)
        request.session.save()

        with patch("store.utils.HoneypotLog.objects.create", side_effect=OperationalError("db busy")):
            log_event(request, event_type="REQUEST", payload="probe")

    def test_literal_discovery_paths_return_200(self):
        responses = {
            "/api": self.client.get("/api"),
            "/api/health": self.client.get("/api/health"),
            "/hidden/status": self.client.get("/hidden/status"),
            "/admin": self.client.get("/admin"),
        }

        self.assertEqual(responses["/api"].status_code, 200)
        self.assertEqual(responses["/api/health"].status_code, 200)
        self.assertEqual(responses["/hidden/status"].status_code, 200)
        self.assertEqual(responses["/admin"].status_code, 200)

        self.assertEqual(responses["/api"].json()["service"], "Honey Haven API Gateway")
        self.assertEqual(responses["/api/health"].json()["status"], "healthy")
        self.assertEqual(responses["/hidden/status"].json()["status"], "restricted")

        self.assertTrue(HoneypotLog.objects.filter(requested_url="/api").exists())
        self.assertTrue(HoneypotLog.objects.filter(requested_url="/api/health").exists())
        self.assertTrue(HoneypotLog.objects.filter(requested_url="/hidden/status").exists())

    def test_literal_admin_and_decoy_paths_return_200(self):
        get_admin = self.client.get("/api/admin")
        post_admin = self.client.post("/api/admin", data='{"username":"root","password":"hunter2"}', content_type="application/json")
        get_decoy = self.client.get("/api/decoy")

        self.assertEqual(get_admin.status_code, 200)
        self.assertEqual(post_admin.status_code, 200)
        self.assertEqual(get_decoy.status_code, 200)

        self.assertEqual(get_admin.json()["panel"], "Honey Haven Admin API")
        self.assertEqual(post_admin.json()["panel"], "Honey Haven Admin API")
        self.assertEqual(get_decoy.json()["api"], "Honey Haven Hidden Decoy API")

        self.assertTrue(HoneypotLog.objects.filter(requested_url="/api/admin").exists())
        self.assertTrue(HoneypotLog.objects.filter(requested_url="/api/decoy").exists())

    def test_admin_and_internal_get_endpoints_return_fake_json(self):
        cases = [
            ("api_admin_root", {"status": "success", "panel": "Honey Haven Admin API"}),
            ("api_admin_users", {"total": 3}),
            ("api_admin_settings", {"settings": {"mfa_required": True}}),
            ("api_internal_status", {"status": "ok"}),
            ("api_internal_config", {"database": "honey_prod"}),
        ]

        for route_name, expected in cases:
            with self.subTest(route=route_name):
                url = reverse(route_name)
                before = HoneypotLog.objects.count()
                response = self.client.get(url)

                self.assertEqual(response.status_code, 200)
                body = response.json()
                for key, value in expected.items():
                    if isinstance(value, dict):
                        for nested_key, nested_value in value.items():
                            self.assertEqual(body[key][nested_key], nested_value)
                    else:
                        self.assertEqual(body[key], value)
                self.assertGreaterEqual(HoneypotLog.objects.count(), before + 1)
                self.assertTrue(HoneypotLog.objects.filter(requested_url=url).exists())

    def test_admin_login_records_probe_and_requires_post(self):
        url = reverse("api_admin_login")
        before = HoneypotLog.objects.count()
        response = self.client.post(
            url,
            data='{"username":"root","password":"hunter2","token":"abc123"}',
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["status"], "failure")
        self.assertGreaterEqual(HoneypotLog.objects.count(), before + 1)
        self.assertTrue(HoneypotLog.objects.filter(requested_url=url).exists())

    def test_admin_export_accepts_post_and_queues_job(self):
        url = reverse("api_admin_export_plain")
        response = self.client.post(
            url,
            data='{"type":"customers","format":"csv","database":"honey_prod"}',
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 202)
        data = response.json()
        self.assertEqual(data["status"], "queued")
        self.assertEqual(data["export_type"], "customers")
        self.assertEqual(data["format"], "csv")
        self.assertTrue(HoneypotLog.objects.filter(requested_url=url).exists())