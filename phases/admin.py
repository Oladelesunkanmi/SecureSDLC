from django.contrib import admin
from .models import Phase


@admin.register(Phase)
class PhaseAdmin(admin.ModelAdmin):
    list_display = ("project", "kind", "order", "status")
    list_filter = ("kind", "status")

