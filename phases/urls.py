"""URL configuration for the phases app."""

from django.urls import path

from . import views

app_name = "phases"

urlpatterns = [
    path("<str:kind>/", views.PhaseDetailView.as_view(), name="detail"),
    path("<str:kind>/advance/", views.PhaseAdvanceView.as_view(), name="advance"),
    path("<str:kind>/reopen/", views.PhaseReopenView.as_view(), name="reopen"),
]
