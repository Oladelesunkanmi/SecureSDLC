"""URL configuration for the dashboard app."""

from django.urls import path
from . import views

app_name = "dashboard"

urlpatterns = [
    path("dashboard/", views.GlobalDashboardView.as_view(), name="global"),
    path("projects/<int:project_id>/dashboard/", views.ProjectDashboardView.as_view(), name="project"),
]

