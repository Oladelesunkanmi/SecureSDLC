from django.contrib import admin
from .models import Project, ProjectMember


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ("name", "sdlc_model", "created_by", "current_phase", "created_at")
    list_filter = ("sdlc_model",)


@admin.register(ProjectMember)
class ProjectMemberAdmin(admin.ModelAdmin):
    list_display = ("project", "user", "project_role")
    list_filter = ("project_role",)

