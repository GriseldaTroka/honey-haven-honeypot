try:
	from .celery import app as celery_app  # type: ignore
except Exception:
	# Celery may be optional in some dev environments; fall back gracefully.
	celery_app = None

# Expose Celery app when available
__all__ = ("celery_app",)
