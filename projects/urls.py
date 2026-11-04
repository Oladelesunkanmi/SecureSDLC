"""URL configuration for the projects app."""

from django.urls import path, include

from . import views

app_name = "projects"

urlpatterns = [
    path("", views.ProjectListView.as_view(), name="list"),
    path("new/", views.ProjectCreateView.as_view(), name="create"),
    path("<int:pk>/", views.ProjectDetailView.as_view(), name="detail"),
    path("<int:pk>/members/", views.ProjectMembersView.as_view(), name="members"),
]

