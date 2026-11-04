"""URL configuration for the scans app."""

from django.urls import path
from . import views

app_name = "scans"

urlpatterns = [
    path("targets/", views.TargetRegisterView.as_view(), name="targets"),
    path("scans/", views.ScanListView.as_view(), name="list"),
    path("scans/new/", views.ScanCreateView.as_view(), name="create"),
    path("scans/<int:sid>/", views.ScanDetailView.as_view(), name="detail"),
    path("scans/<int:sid>/status/", views.ScanStatusJSONView.as_view(), name="status_json"),
]
