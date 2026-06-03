from datetime import timedelta
from django.http import JsonResponse
import logging

from django.http import HttpResponsePermanentRedirect
from django.utils import timezone
from django.conf import settings as _settings
from .utils import get_client_ip

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

        # Normalize host for local development to ensure a single origin for session cookies.
        # Only redirect for safe methods (GET/HEAD) to avoid breaking POST-based logins.
        host = request.get_host().split(":")[0]
        if host == "localhost" and request.method in ("GET", "HEAD"):
            # Redirect to 127.0.0.1 preserving scheme, port and path.
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

        # Debug: log staff/auth/session state to help validate auth propagation across tabs
        try:
            is_staff = getattr(request.user, "is_staff", False)
            uname = getattr(request.user, "username", None) if getattr(request.user, "is_authenticated", False) else None
            session_keys = list(request.session.keys()) if hasattr(request, "session") else []
            logger.debug("Auth debug: path=%s is_staff=%s user=%s session_keys=%s", request.path, is_staff, uname, session_keys)
        except Exception:
            logger.exception("Failed to log auth debug info")

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
