from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, Client
from django.urls import reverse


class BasicViewsTest(TestCase):
    def setUp(self):
        self.client = Client()

    def test_canary_pixel(self):
        # non-existent token should still return GIF
        resp = self.client.get(reverse("canary_beacon", args=["no-token-123"]))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"], "image/gif")

    def test_honeypot_webhook(self):
        url = reverse("honeypot_webhook")
        resp = self.client.post(url, data={"source": "test", "event": "ping", "data": {}}, content_type="application/json")
        self.assertIn(resp.status_code, (200, 202))

    def test_surfaces_menu_hidden_for_non_staff(self):
        home = self.client.get(reverse("home"))
        self.assertContains(home, "Home")
        self.assertNotContains(home, "Surfaces")
        self.assertNotContains(home, "Attacker Timeline")

        user_model = get_user_model()
        user = user_model.objects.create_user(username="viewer", password="viewer-pass-123")
        self.client.force_login(user)

        member_home = self.client.get(reverse("home"))
        self.assertNotContains(member_home, "Surfaces")
        self.assertNotContains(member_home, "Research Analytics")

    def test_surfaces_menu_visible_for_staff(self):
        user_model = get_user_model()
        staff = user_model.objects.create_user(username="admin", password="admin-pass-123", is_staff=True)
        self.client.force_login(staff)

        staff_home = self.client.get(reverse("home"))
        self.assertContains(staff_home, "Surfaces")
        self.assertContains(staff_home, "Attacker Timeline")

    def test_successful_login_skips_heavy_detection_pipeline(self):
        user_model = get_user_model()
        user = user_model.objects.create_user(username="viewer", password="viewer-pass-123")

        with patch("store.detection.run_detection_pipeline") as mocked_detection:
            response = self.client.post(reverse("login"), {"username": "viewer", "password": "viewer-pass-123"})

        self.assertEqual(response.status_code, 302)
        self.assertFalse(mocked_detection.called)
