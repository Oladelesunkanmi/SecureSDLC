"""ASGI entry point.

Defaults to production settings; override DJANGO_SETTINGS_MODULE in the
environment to change it.
"""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.prod")

application = get_asgi_application()
