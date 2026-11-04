from django.contrib import admin
from .models import ScanTarget, Scan


@admin.register(ScanTarget)
class ScanTargetAdmin(admin.ModelAdmin):
    list_display = ("url", "project", "environment", "authorization_confirmed", "authorized_by", "authorized_at")
    list_filter = ("environment", "authorization_confirmed")
    search_fields = ("url", "authorized_by")


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ("id", "tool", "target", "project", "status", "requested_by", "started_at", "finished_at")
    list_filter = ("status", "tool")

