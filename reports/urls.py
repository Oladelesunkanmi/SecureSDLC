"""URL configuration for the reports app."""

from django.urls import path
from . import views

app_name = "reports"

urlpatterns = [
    path("report/", views.ReportDownloadView.as_view(), name="download"),
]

