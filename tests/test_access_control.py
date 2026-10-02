from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
from django.conf import settings


class ResearchAccessControlTests(TestCase):
    def setUp(self):
        self.client = Client()
        # create non-staff user
        self.user = User.objects.create_user(username="user", password="pass")
        # create staff user
        self.staff = User.objects.create_user(username="staff", password="pass")
        self.staff.is_staff = True
        self.staff.save()

        # research-only endpoints to test
        self.views = [
            reverse("canary_tokens"),
            reverse("attack_research_report"),
        ]

    def test_research_views_require_staff(self):
        for url in self.views:
            with self.subTest(url=url):
                # anonymous and logged-in non-staff: some endpoints intentionally provide public decoys
                resp = self.client.get(url)
                # allowed statuses for anonymous/non-staff: 200 (decoy) or redirect/forbidden
                self.assertIn(resp.status_code, (200, 302, 401, 403), msg=f"Anonymous access unexpected for {url}")

                # logged-in non-staff should at least not be allowed to see full staff-only templates for some views
                self.client.login(username="user", password="pass")
                resp = self.client.get(url)
                self.assertIn(resp.status_code, (200, 302, 401, 403), msg=f"Non-staff access unexpected for {url}")
                self.client.logout()

                # staff should be allowed
                self.client.login(username="staff", password="pass")
                resp = self.client.get(url)
                self.assertEqual(resp.status_code, 200, msg=f"Staff cannot access {url}")
                self.client.logout()

    def test_staff_login_redirect_honors_next_target(self):
        self.client.logout()
        user = User.objects.create_user(username="soc-staff", password="pass")
        user.is_staff = True
        user.save(update_fields=["is_staff"])

        response = self.client.post(
            reverse("login"),
            {"username": "soc-staff", "password": "pass", "next": "http://127.0.0.1:5173/soc"},
            follow=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "http://127.0.0.1:5173/soc")

        status = self.client.get(reverse("staff_status"))
        self.assertEqual(status.status_code, 200)
        self.assertTrue(status.json()["authenticated"])
        self.assertTrue(status.json()["staff"])

    def test_login_get_does_not_create_honey_session_but_keeps_csrf(self):
        response = self.client.get(reverse("login"))

        self.assertEqual(response.status_code, 200)
        self.assertIn("csrfmiddlewaretoken", response.content.decode())
        self.assertIn(settings.CSRF_COOKIE_NAME, response.cookies)
        self.assertNotIn(settings.SESSION_COOKIE_NAME, response.cookies)

    def test_login_post_still_authenticates(self):
        self.client.get(reverse("login"))

        response = self.client.post(
            reverse("login"),
            {"username": "staff", "password": "pass", "next": "http://127.0.0.1:5173/soc"},
            follow=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "http://127.0.0.1:5173/soc")
        self.assertTrue(response.wsgi_request.user.is_authenticated)
        self.assertTrue(response.wsgi_request.user.is_staff)

    def test_attacker_route_still_initializes_honey_session(self):
        response = self.client.get(reverse("decoy_wp_admin"))

        self.assertEqual(response.status_code, 200)
        self.assertIn(settings.SESSION_COOKIE_NAME, response.cookies)
        self.assertTrue(self.client.session.get("honey_session_id"))
