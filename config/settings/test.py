"""Test settings: fast password hashers to optimize test suite execution.

Activate with ``--settings=config.settings.test``.
Does NOT modify base.py, dev.py, or prod.py.
"""

from .base import *  # noqa: F401,F403

DEBUG = False

SECRET_KEY = "test-only-secret-key-for-running-automated-test-suite"

# Use MD5 password hasher for ultra-fast password hashing during tests
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.MD5PasswordHasher",
]

# In-memory email backend for tests
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"

