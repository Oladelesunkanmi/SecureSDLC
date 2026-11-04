from django.contrib import admin
from .models import Vulnerability, VulnerabilityEvent


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ("title", "project", "phase", "severity", "status", "cvss_score", "source")
    list_filter = ("severity", "status", "source", "owasp_category")
    search_fields = ("title", "description", "affected_component")


@admin.register(VulnerabilityEvent)
class VulnerabilityEventAdmin(admin.ModelAdmin):
    list_display = ("vulnerability", "from_status", "to_status", "actor", "created_at")
    list_filter = ("from_status", "to_status")
