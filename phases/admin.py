from django.contrib import admin
from .models import Phase, ChecklistItem, ChecklistResponse, GateDecision


@admin.register(Phase)
class PhaseAdmin(admin.ModelAdmin):
    list_display = ("project", "kind", "order", "status")
    list_filter = ("kind", "status")


@admin.register(ChecklistItem)
class ChecklistItemAdmin(admin.ModelAdmin):
    list_display = ("code", "phase_kind", "text", "required", "owasp_ref")
    list_filter = ("phase_kind", "required")
    search_fields = ("code", "text", "owasp_ref")


@admin.register(ChecklistResponse)
class ChecklistResponseAdmin(admin.ModelAdmin):
    list_display = ("project", "item", "done", "completed_by", "completed_at")
    list_filter = ("done", "item__phase_kind")
    search_fields = ("project__name", "item__code", "evidence")


@admin.register(GateDecision)
class GateDecisionAdmin(admin.ModelAdmin):
    list_display = ("project", "phase", "action", "allowed", "actor", "timestamp")
    list_filter = ("action", "allowed")
    search_fields = ("project__name", "reasons")
