from datetime import timedelta
from django.http import JsonResponse
import logging

from django.http import HttpResponsePermanentRedirect
from django.utils import timezone
from django.conf import settings as _settings
from .utils import get_client_ip, get_or_create_honey_session_id

from .utils import detect_suspicion, log_event, request_payload_to_text

logger = logging.getLogger(__name__)
DENYLIST = set(getattr(_settings, "HONEYTRAP_DENYLIST_IPS", []))


class AttackerLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Denylist check: block known malicious IPs early
        try:
            client_ip = get_client_ip(request)
            if client_ip in DENYLIST:
                logger.info("Blocking request from denylisted IP: %s", client_ip)
                return JsonResponse({"status": "blocked"}, status=403)
        except Exception:
            pass

        # Fast-path for lightweight internal endpoints polled by the SOC frontend.
        # These must not trigger logging, detection, ASG updates, or IO writes.
        if request.path in ("/api/internal/staff-status/", "/api/internal/status", "/api/internal/config") or (
            request.path == "/api/dashboard/overview/"
            and getattr(getattr(request, "user", None), "is_authenticated", False)
            and getattr(getattr(request, "user", None), "is_staff", False)
        ):
            return self.get_response(request)

        if request.method == "GET" and request.path == "/login/":
            return self.get_response(request)

        # Canonical visitor identity for the current Django session (best-effort).
        # Avoid creating or modifying the session here for fast internal endpoints.
        try:
            get_or_create_honey_session_id(request)
        except Exception:
            pass

        # Normalize host for local development to keep the Django session cookie on the
        # same loopback origin as the Vite proxy. Avoid redirecting away from the dev SPA
        # host to preserve the authenticated session between frontend and backend.
        host = request.get_host().split(":")[0]
        if host == "localhost" and request.method in ("GET", "HEAD") and not request.path.startswith("/api/"):
            port = request.get_port()
            new_host = f"127.0.0.1:{port}" if port else "127.0.0.1"
            url = f"{request.scheme}://{new_host}{request.get_full_path()}"
            return HttpResponsePermanentRedirect(url)

        if request.path.startswith("/static/") or request.path.startswith("/media/"):
            return self.get_response(request)

        request._request_time_window = timezone.now() - timedelta(minutes=1)
        payload = request_payload_to_text(request)
        is_suspicious, reason = detect_suspicion(request, payload)

        response = self.get_response(request)

        event = "REQUEST"
        if request.path.startswith("/api/"):
            event = "API_HIT"
        if request.path.startswith("/admin"):
            event = "ADMIN_ACCESS"

        log_event(
            request,
            event_type=event,
            payload=payload,
            username=getattr(request.user, "username", "") if getattr(request.user, "is_authenticated", False) else "",
            is_suspicious=is_suspicious,
            suspicion_reason=reason,
            status_code=response.status_code,
        )

        return response
