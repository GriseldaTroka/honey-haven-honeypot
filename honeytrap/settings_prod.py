from .settings import *  # noqa: F401,F403
import os

# Override for production
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", SECRET_KEY)
DEBUG = os.environ.get("DEBUG", "False").lower() in ("1", "true", "yes")
ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "").split(",") if os.environ.get("ALLOWED_HOSTS") else ["localhost"]

# Security recommendations
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_SSL_REDIRECT = os.environ.get("SECURE_SSL_REDIRECT", "True").lower() in ("1", "true", "yes")
SECURE_HSTS_SECONDS = int(os.environ.get("SECURE_HSTS_SECONDS", "31536000"))
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = False

# Logging: keep same handler but route higher-level errors to console
LOGGING["handlers"]["console"] = {"class": "logging.StreamHandler", "formatter": "plain"}
LOGGING["loggers"]["django"] = {"handlers": ["console"], "level": "ERROR", "propagate": False}
