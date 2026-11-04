"""Development settings: local machine, SQLite, DEBUG on.

Selected by default in ``manage.py``. Production must set
``DJANGO_SETTINGS_MODULE=config.settings.prod`` explicitly.
"""

from .base import *  # noqa: F401,F403

DEBUG = True

# A placeholder key so a fresh clone runs with no .env present. The prod module
# refuses to start with an empty key, so this can never reach production.
SECRET_KEY = SECRET_KEY or "dev-only-insecure-key-never-use-in-production"

ALLOWED_HOSTS = ["localhost", "127.0.0.1", "[::1]"]

# Emails print to the console instead of being sent.
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
