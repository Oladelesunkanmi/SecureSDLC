"""Root URL configuration for the SecureSDLC framework.

App routes are added per phase, following CLAUDE.md section 6.
"""

from django.contrib import admin
from django.urls import path, include
from django.contrib.auth.decorators import login_required
from django.views.generic import RedirectView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/", include("accounts.urls")),
    path("projects/", include("projects.urls")),
    # Root redirects to the project list (the dashboard home per CLAUDE.md section 6).
    path("", login_required(RedirectView.as_view(pattern_name="projects:list")), name="home"),
]
