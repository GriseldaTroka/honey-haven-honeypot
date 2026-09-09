from django.test import TestCase, Client, override_settings
from django.contrib.auth.models import User
from django.db import connection
import time
import json
from django.test.utils import CaptureQueriesContext


class TimelineMeasureTest(TestCase):
    @override_settings(DEBUG=True)
    def test_measure(self):
        client = Client()
        user = User.objects.create_user(username="m_staff", password="x")
        user.is_staff = True
        user.save(update_fields=["is_staff"])
        client.force_login(user)

        results = []
        for limit in (120, 250):
            connection.queries.clear()
            start_q = len(connection.queries)
            start = time.perf_counter()
            resp = client.get(f"/research/timeline/json/?limit={limit}")
            elapsed = time.perf_counter() - start
            end_q = len(connection.queries)
            events = resp.json().get("events") if resp.status_code == 200 else []
            results.append({"limit": limit, "status": resp.status_code, "elapsed_sec": elapsed, "queries": end_q - start_q, "events_returned": len(events)})

        print(json.dumps(results, indent=2))

    def test_measure_with_capture(self):
        from django.test import Client
        client = Client()
        user = User.objects.create_user(username="m_staff2", password="x")
        user.is_staff = True
        user.save(update_fields=["is_staff"])
        client.force_login(user)

        for limit in (120, 250):
            start = time.perf_counter()
            with CaptureQueriesContext(connection) as ctx:
                resp = client.get(f"/research/timeline/json/?limit={limit}")
            elapsed = time.perf_counter() - start
            events = resp.json().get("events") if resp.status_code == 200 else []
            print(json.dumps({"limit": limit, "status": resp.status_code, "elapsed_sec": elapsed, "queries": len(ctx.captured_queries), "events_returned": len(events)}, indent=2))
