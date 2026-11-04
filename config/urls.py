"""Root URL configuration for the SecureSDLC framework.

App routes are added per phase, following CLAUDE.md section 6.
"""

from django.contrib import admin
from django.urls import path

urlpatterns = [
    path("admin/", admin.site.urls),
]
