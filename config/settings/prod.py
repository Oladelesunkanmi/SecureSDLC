"""Production settings: DEBUG off, HTTPS enforced, secrets from the environment.

Activate with ``DJANGO_SETTINGS_MODULE=config.settings.prod``. Importing this
module fails loudly when a required secret is missing, rather than starting the
application in an insecure state.
"""

from django.core.exceptions import ImproperlyConfigured

from .base import *  # noqa: F401,F403

if not SECRET_KEY:
    raise ImproperlyConfigured(
        "DJANGO_SECRET_KEY is empty. Set it in the environment before using "
        "config.settings.prod."
    )

DEBUG = False

ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS")
if not ALLOWED_HOSTS:
    raise ImproperlyConfigured(
        "DJANGO_ALLOWED_HOSTS is empty. Set it to the comma-separated hostnames "
        "this deployment answers on."
    )

# --- Transport and cookie hardening -------------------------------------

SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# One year, per current HSTS guidance. Only enable preload once the domain is
# permanently HTTPS-only.
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"

SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"
