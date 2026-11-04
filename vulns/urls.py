"""URL configuration for the vulns app."""

from django.urls import path

from . import views

app_name = "vulns"

urlpatterns = [
    path("", views.VulnerabilityListView.as_view(), name="list"),
    path("new/", views.VulnerabilityCreateView.as_view(), name="create"),
    path("<int:vid>/", views.VulnerabilityDetailView.as_view(), name="detail"),
    path("<int:vid>/transition/", views.VulnerabilityTransitionView.as_view(), name="transition"),
]
