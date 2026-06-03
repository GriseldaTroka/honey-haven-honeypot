from pathlib import Path
import logging
import os

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

# Read secret key from environment or Docker secret file (/run/secrets/django_secret)
_env_secret = os.environ.get("DJANGO_SECRET_KEY") or os.environ.get("SECRET_KEY")
if not _env_secret:
    # Docker secrets are mounted at /run/secrets/<name>
    try:
        with open("/run/secrets/django_secret", "r") as f:
            _env_secret = f.read().strip()
    except Exception:
        _env_secret = None

SECRET_KEY = _env_secret or "django-insecure-honeytrap-dev-key-change-in-production"

# DEV default; set to False in production via environment or a separate settings file
DEBUG = os.environ.get("DJANGO_DEBUG", "True").lower() in ("1", "true", "yes")
DJANGO_ALLOW_ALL_HOSTS = os.environ.get("DJANGO_ALLOW_ALL_HOSTS", "False").lower() in ("1", "true", "yes")
ALLOWED_HOSTS = [host.strip() for host in os.environ.get("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if host.strip()]
if DJANGO_ALLOW_ALL_HOSTS:
    ALLOWED_HOSTS = ["*"]


# Honeypot alerting and sandbox configuration (configurable via environment)
# Store these values in a `.env` file for local development or as environment
# variables in the container/orchestration environment (docker-compose, systemd,
# Kubernetes Secret, CI/CD pipeline). Example `.env` entries:
# HONEYPOT_ALERT_DEDUP_WINDOW_MIN=5
# HONEYPOT_ALERT_MAX_PER_WINDOW=10
# HONEYPOT_SANDBOX_URL=https://sandbox.example/api/v1/submit
# HONEYPOT_SANDBOX_API_KEY=xxx

HONEYPOT_ALERT_DEDUP_WINDOW_MIN = int(os.environ.get("HONEYPOT_ALERT_DEDUP_WINDOW_MIN", "5"))
HONEYPOT_ALERT_MAX_PER_WINDOW = int(os.environ.get("HONEYPOT_ALERT_MAX_PER_WINDOW", "10"))
HONEYPOT_SANDBOX_URL = os.environ.get("HONEYPOT_SANDBOX_URL", "").strip()
HONEYPOT_SANDBOX_API_KEY = os.environ.get("HONEYPOT_SANDBOX_API_KEY", "").strip()

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "store",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "store.middleware.AttackerLoggingMiddleware",
]

ROOT_URLCONF = "honeytrap.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "honeytrap.wsgi.application"
ASGI_APPLICATION = "honeytrap.asgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "home"
LOGOUT_REDIRECT_URL = "home"

# Session / cookie settings (local dev defaults)
# Use Lax to allow navigation-based logins while mitigating CSRF for cross-site requests.
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = False
# Optional comma-separated denylist for development (e.g. "1.2.3.4,5.6.7.8")
HONEYTRAP_DENYLIST_IPS = [i.strip() for i in os.environ.get("HONEYTRAP_DENYLIST_IPS", "").split(",") if i.strip()]

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "plain": {
            "format": "%(message)s",
        },
    },
    "handlers": {
        "honeypot_file": {
            "class": "logging.FileHandler",
            "filename": str(LOG_DIR / "honey-web.log"),
            "formatter": "plain",
        },
    },
    "loggers": {
        "honeytrap.events": {
            "handlers": ["honeypot_file"],
            "level": "INFO",
            "propagate": False,
        },
    },
}
